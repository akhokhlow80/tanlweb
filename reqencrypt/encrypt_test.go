package reqencrypt_test

import (
	"akhokhlow80/tanlweb/reqencrypt"
	"context"
	"net/url"
	"reflect"
	"testing"
	"time"
)

type mockKeyStore struct {
	keys reqencrypt.Keys
}

var _ reqencrypt.KeyStore = (*mockKeyStore)(nil)

// GetKeys implements reqencrypt.KeyStore.
func (m *mockKeyStore) GetKeys(ctx context.Context) (reqencrypt.Keys, error) {
	return m.keys, nil
}

// PutKeys implements reqencrypt.KeyStore.
func (m *mockKeyStore) PutKeys(ctx context.Context, keys *reqencrypt.Keys) error {
	m.keys = *keys
	return nil
}

func TestEncryption(t *testing.T) {
	var store mockKeyStore
	cipher, err := reqencrypt.NewCipher(context.Background(), &store, time.Second*10000)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	const plaintext = "some%20path/123"
	enc := cipher.Encrypt(plaintext)
	dec, ok := cipher.Decrypt(enc)
	if !ok {
		t.Fatalf("Unexpected failure of the decryption")
	}
	if plaintext != dec {
		t.Fatalf("Plaintext doesn't match encrypted URL")
	}
}

func testURL(t *testing.T, c *reqencrypt.Cipher, host string, path string) {
	origURL, err := url.Parse(host + "/" + path)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	enc := host + "/" + url.PathEscape(c.Encrypt(path))
	encURL, err := url.Parse(enc)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	decURL := reqencrypt.DecryptURL(c, encURL)
	if decURL == nil {
		t.Fatalf("Unexpected DecryptURL failure")
	}
	if !reflect.DeepEqual(origURL, decURL) {
		t.Fatalf("Original and decrypted URLs are different: %v vs %v", origURL, decURL)
	}
}

func TestFullURL(t *testing.T) {
	var store mockKeyStore
	cipher, err := reqencrypt.NewCipher(context.Background(), &store, time.Second*1)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	testURL(t, cipher, "https://user:pass@example.com", "path%20with%20space/andslash%2F?q=go#frag%20ment")
	testURL(t, cipher, "https://[::1]:1432", "?")
	testURL(t, cipher, "http://host", "morethan512byteslongaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	testURL(t, cipher, "https://1.4.2.3:1432", "////a")
}

func TestExpiredKeypair(t *testing.T) {
	const rotationInterval = time.Millisecond * 100

	var store mockKeyStore
	cipher, err := reqencrypt.NewCipher(context.Background(), &store, rotationInterval)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	enc := cipher.Encrypt("test")
	time.Sleep(rotationInterval * 3)
	_, ok := cipher.Decrypt(enc)
	if ok {
		t.Errorf("Expected decrypt to fail on data encrypted with expired key")
	}
}

func TestKeyRotation(t *testing.T) {
	const rotationInterval = time.Millisecond * 10

	var store mockKeyStore
	cipher, err := reqencrypt.NewCipher(context.Background(), &store, rotationInterval)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	retry := true
	for range 100 {
		if !retry {
			break
		}
		enc := cipher.Encrypt("test0")
		time.Sleep(rotationInterval)
		_, ok := cipher.Decrypt(enc)
		if !ok {
			retry = true
			continue
		}

		enc = cipher.Encrypt("test0")
		time.Sleep(rotationInterval)
		_, ok = cipher.Decrypt(enc)
		if !ok {
			retry = true
			continue
		}

		retry = false
	}

	if retry {
		t.Fatalf("Unexpected decrypt failure")
	}
}
