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
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const KeySize = chacha20poly1305.KeySize

type Keys struct {
	Keys        [2]*[KeySize]byte
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
	keys.Keys[0] = new([KeySize]byte)
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

func (c *Cipher) rotateKeysRoutine(ctx context.Context, keys Keys, rotationInterval time.Duration) {
	timer := time.NewTimer(time.Until(keys.RotateAfter))
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		err := c.rotateKeys(context.Background(), rotationInterval, &keys)
		if err != nil {
			panic(fmt.Sprintf("Failed to rotate keys: %s", err))
		}

		log.Printf("reqencrypt: Key rotated")

		timer.Reset(time.Until(keys.RotateAfter))
	}
}

func NewCipher(ctx context.Context, store KeyStore, rotateInterval time.Duration) (*Cipher, error) {
	keys, err := store.GetKeys(ctx)
	if err != nil {
		return nil, err
	}
	c := &Cipher{store: store}
	if keys.Keys[0] != nil && time.Now().Before(keys.RotateAfter) {
		// If has key and pair is not expired, then just make aead.Cipher
		c.aead[0], err = chacha20poly1305.NewX(keys.Keys[0][:])
		if err != nil {
			return nil, err
		}
		if keys.Keys[1] != nil {
			c.aead[1], err = chacha20poly1305.NewX(keys.Keys[1][:])
			if err != nil {
				return nil, err
			}
		}
	} else {
		// If has no key, or it is expired, rotate and init aead.Cipher
		err = c.rotateKeys(ctx, rotateInterval, &keys)
		if err != nil {
			return nil, err
		}
		log.Printf("reqencrypt: Key rotated")
	}
	go c.rotateKeysRoutine(ctx, keys, rotateInterval)
	return c, nil
}

// blkSize must be a power of two
func padded(n int, blkSize int) int {
	return n + (blkSize-(n&(blkSize-1)))&(blkSize-1)
}

// Returns base64 raw url encoded (no padding) XChaCha20-Poly1305 encrypted path.
func (c *Cipher) Encrypt(log2Padding uint, path string) string {
	defer c.RUnlock()
	c.RLock()

	padding := 1 << log2Padding
	pathPadded := make([]byte, padded(len(path), padding))
	copy(pathPadded, path)

	sealed := make([]byte, 0, c.aead[0].NonceSize()+len(path)+c.aead[0].Overhead())
	nonce := sealed[:c.aead[0].NonceSize()]
	rand.Read(nonce)

	return base64.RawURLEncoding.EncodeToString(c.aead[0].Seal(nonce, nonce, pathPadded, nil))
}

// Decrypts base64 raw url encoded (no padding) XChaCha20-Poly1305 ciphertext.
func (c *Cipher) Decrypt(ciphertextBase64 string) (string, bool) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", false
	}

	defer c.RUnlock()
	c.RLock()

	for _, aead := range c.aead {
		if aead == nil {
			continue
		}
		if len(ciphertext) < aead.NonceSize() {
			return "", false
		}
		nonce := ciphertext[:aead.NonceSize()]
		ciphertext := ciphertext[aead.NonceSize():]
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
	path := strings.TrimPrefix(u.Path, "/")
	decryptedRawPath, ok := c.Decrypt(path)
	if !ok {
		return nil
	}
	decryptedPathURI, err := url.ParseRequestURI("/" + decryptedRawPath)
	if err != nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	u2.Path = decryptedPathURI.Path
	u2.Fragment = decryptedPathURI.Fragment
	u2.RawQuery = decryptedPathURI.RawQuery
	u2.RawPath = decryptedPathURI.RawPath
	u2.RawFragment = decryptedPathURI.RawFragment
	u2.ForceQuery = decryptedPathURI.ForceQuery
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
