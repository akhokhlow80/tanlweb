package reqencrypt

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const KeySize = chacha20poly1305.KeySize

type Keys struct {
	Keys        [2][KeySize]byte
	RotateAfter time.Time
}

type KeyStore interface {
	GetKeys(ctx context.Context) (Keys, error)
	PutKeys(ctx context.Context, keys *Keys) error
}

type Cipher struct {
	sync.RWMutex
	aead  [2]cipher.AEAD
	store KeyStore
}

func (c *Cipher) rotateKeys(ctx context.Context, rotationInterval time.Duration, keys *Keys) error {
	keys.Keys[1] = keys.Keys[0]
	rand.Read(keys.Keys[0][:])

	defer c.Unlock()
	c.Lock()

	keys.RotateAfter = time.Now().Add(rotationInterval)

	newAead, err := chacha20poly1305.NewX(keys.Keys[0][:])
	if err != nil {
		return err
	}
	if err := c.store.PutKeys(ctx, keys); err != nil {
		return err
	}
	c.aead[1] = c.aead[0]
	c.aead[0] = newAead
	return nil
}

func (c *Cipher) rotateKeysRoutine(keys Keys, rotationInterval time.Duration) {
	for {
		time.Sleep(time.Until(keys.RotateAfter))

		err := c.rotateKeys(context.Background(), rotationInterval, &keys)
		if err != nil {
			panic(fmt.Sprintf("Failed to rotate keys: %s", err))
		}

		log.Printf("reqencrypt: Key rotated")
	}
}

func NewCipher(ctx context.Context, store KeyStore, rotateInterval time.Duration) (*Cipher, error) {
	keys, err := store.GetKeys(ctx)
	if err != nil {
		return nil, err
	}
	c := &Cipher{store: store}
	if time.Now().After(keys.RotateAfter) {
		err = c.rotateKeys(ctx, rotateInterval, &keys)
		if err != nil {
			return nil, err
		}
	}
	go c.rotateKeysRoutine(keys, rotateInterval)
	return c, nil
}

// blkSize must be a power of two
func padded(n int, blkSize int) int {
	return n + (blkSize-(n&(blkSize-1)))&(blkSize-1)
}

func (c *Cipher) Encrypt(path string) string {
	defer c.RUnlock()
	c.RLock()

	pathPadded := make([]byte, padded(len(path), 512))
	copy(pathPadded, path)

	sealed := make([]byte, 0, c.aead[0].NonceSize()+len(path)+c.aead[0].Overhead())
	nonce := sealed[:c.aead[0].NonceSize()]
	rand.Read(nonce)

	encrypted := c.aead[0].Seal(nonce, nonce, pathPadded, nil)

	return base64.StdEncoding.EncodeToString(encrypted)
}

func (c *Cipher) Decrypt(encryptedPathBase64 string) (string, bool) {
	encryptedPath, err := base64.StdEncoding.DecodeString(encryptedPathBase64)
	if err != nil {
		return "", false
	}

	defer c.RUnlock()
	c.RLock()

	for _, aead := range c.aead {
		if aead == nil {
			continue
		}
		if len(encryptedPath) < aead.NonceSize() {
			return "", false
		}
		nonce := encryptedPath[:aead.NonceSize()]
		ciphertext := encryptedPath[aead.NonceSize():]
		path, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			continue
		}

		pathLen := 0
		for _, c := range path {
			if c == 0 {
				break
			}
			pathLen++
		}

		return string(path[:pathLen]), true
	}
	return "", false
}

// Returns nil on decryption and parsing failures.
func DecryptURL(c *Cipher, u *url.URL) *url.URL {
	decryptedRawPath, ok := c.Decrypt(u.Path[1:]) // trim leading /
	if !ok {
		return nil
	}
	decryptedPathURL, err := url.Parse("/" + decryptedRawPath)
	if err != nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	u2.Path = decryptedPathURL.Path
	u2.Fragment = decryptedPathURL.Fragment
	u2.RawQuery = decryptedPathURL.RawQuery
	u2.RawPath = decryptedPathURL.RawPath
	u2.RawFragment = decryptedPathURL.RawFragment
	u2.ForceQuery = decryptedPathURL.ForceQuery
	return u2
}

// Responds with 401 on decryption and parsing failures.
func DecryptPathMiddleware(c *Cipher, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decryptedURL := DecryptURL(c, r.URL)
		if decryptedURL == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		r2 := new(http.Request)
		*r2 = *r
		r2.URL = decryptedURL
		h.ServeHTTP(w, r2)
	})
}
