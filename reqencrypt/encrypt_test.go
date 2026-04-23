package reqencrypt_test

import (
	"akhokhlow80/tanlweb/reqencrypt"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"
)

type mockKeyStore struct {
	sync.Mutex
	keys reqencrypt.Keys
}

var _ reqencrypt.KeyStore = (*mockKeyStore)(nil)

// GetKeys implements reqencrypt.KeyStore.
func (m *mockKeyStore) GetKeys(ctx context.Context) (reqencrypt.Keys, error) {
	defer m.Unlock()
	m.Lock()
	return m.keys, nil
}

// PutKeys implements reqencrypt.KeyStore.
func (m *mockKeyStore) PutKeys(ctx context.Context, keys *reqencrypt.Keys) error {
	defer m.Unlock()
	m.Lock()
	m.keys = *keys
	return nil
}

func (m *mockKeyStore) Copy() *mockKeyStore {
	defer m.Unlock()
	m.Lock()
	nm := new(mockKeyStore)
	nm.keys = m.keys
	return nm
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

	testURL(t, cipher, "https://user:pass@example.com", "path%20with%20space/andslash%2F?q=go")
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

func TestDecryptJunk(t *testing.T) {
	var store mockKeyStore
	cipher, err := reqencrypt.NewCipher(context.Background(), &store, time.Second*10000)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	_, ok := cipher.Decrypt(base64.StdEncoding.EncodeToString([]byte{
		0x28, 0x7d, 0xb3, 0xac, 0xb4, 0x2b, 0xd9, 0xdc, 0xd3, 0xc4, 0xe0, 0xd7,
		0x92, 0x27, 0xb1, 0x68, 0xb0, 0xd0, 0x2f, 0xbe, 0x74, 0x3b, 0xa4,
	}))
	if ok {
		t.Fatalf("Decrypt() was expected to fail")
	}
	_, ok = cipher.Decrypt("/5nTG5D/+ah/QRN???????JgYC6cqNfnIqX60NDF")
	if ok {
		t.Fatalf("Decrypt() was expected to fail")
	}

	enc := "https://localhost/" + url.PathEscape("uCu2T0VB/RfpiXmN4mO/dsNPbt/TWR7YX1DJVmTfP+XGxAwh+2CFMnv7IzdtEAAWJbA=")
	encURL, err := url.Parse(enc)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	decURL := reqencrypt.DecryptURL(cipher, encURL)
	if decURL != nil {
		t.Fatalf("DecryptURL() was expected to fail")
	}
}

func TestKeyRotationCancel(t *testing.T) {
	goroutineLeakCheck(t)

	ctx, cancel := context.WithCancel(context.Background())

	var store mockKeyStore
	_, err := reqencrypt.NewCipher(ctx, &store, time.Microsecond)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	cancel()
}

func TestKeyPreservation(t *testing.T) {
	const (
		rotationInterval = time.Millisecond * 50
		plaintext        = "test-key-preservation"
	)

	ctx1, cancel1 := context.WithCancel(context.Background())

	var store1 mockKeyStore
	cipher1, err := reqencrypt.NewCipher(ctx1, &store1, rotationInterval)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	enc := cipher1.Encrypt(plaintext)

	cancel1()

	ctx2, cancel2 := context.WithCancel(context.Background())
	store2 := store1.Copy()

	cipher2, err := reqencrypt.NewCipher(ctx2, store2, rotationInterval)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	decrypted, ok := cipher2.Decrypt(enc)
	if !ok {
		t.Fatalf("Unexpected Decrypt() failure")
	}
	if decrypted != plaintext {
		t.Fatalf("Decrypted text mismatches plaintext")
	}

	time.Sleep(rotationInterval + rotationInterval/2)

	cancel2()

	store3 := store2.Copy()

	cipher3, err := reqencrypt.NewCipher(context.Background(), store3, rotationInterval)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	decrypted, ok = cipher3.Decrypt(enc)
	if !ok {
		t.Fatalf("Unexpected Decrypt() failure")
	}
	if decrypted != plaintext {
		t.Fatalf("Decrypted text mismatches plaintext")
	}
}

func TestStoreWithExistingKeys(t *testing.T) {
	t.Run("1 key", func(t *testing.T) {
		t.Parallel()

		var store mockKeyStore
		store.keys.Keys[0] = new([reqencrypt.KeySize]byte)
		store.keys.RotateAfter = time.Now().Add(100 * time.Second)
		rand.Read(store.keys.Keys[0][:])
		cipher, err := reqencrypt.NewCipher(context.Background(), &store, time.Second*1)
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
	})
	t.Run("2 keys", func(t *testing.T) {
		t.Parallel()

		var store mockKeyStore
		store.keys.Keys[0] = new([reqencrypt.KeySize]byte)
		store.keys.Keys[1] = new([reqencrypt.KeySize]byte)
		store.keys.RotateAfter = time.Now().Add(100 * time.Second)
		rand.Read(store.keys.Keys[0][:])
		rand.Read(store.keys.Keys[1][:])
		cipher, err := reqencrypt.NewCipher(context.Background(), &store, time.Second*1)
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
	})
}

func TestMiddleware(t *testing.T) {
	var store mockKeyStore
	cipher, err := reqencrypt.NewCipher(context.Background(), &store, time.Second*100000)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	uri := "https://localhost:1234/" + cipher.Encrypt("ping?value=abc123")
	req := httptest.NewRequest("POST", uri, bytes.NewBufferString("hello"))

	handler := func(w http.ResponseWriter, r *http.Request) {
		var body [5]byte
		_, err := r.Body.Read(body[:])
		if err != nil {
			t.Fatal(err)
		}
		if string(body[:]) != "hello" {
			t.Fatalf("Body was modified by middleware")

		}

		println("URI ", r.URL.String())

		if r.URL.Path != "/ping" {
			t.Errorf("Path is corrupted")
		}
		if r.URL.Query().Get("value") != "abc123" {
			t.Errorf("Value is corrupted")
		}

		w.Write([]byte("pong"))
	}
	encryptedHandler := reqencrypt.DecryptPathMiddleware(cipher, http.HandlerFunc(handler))
	rec := httptest.NewRecorder()
	encryptedHandler.ServeHTTP(rec, req)
}

// Taken from https://git.zx2c4.com/wireguard-go/tree/device/device_test.go
func goroutineLeakCheck(t *testing.T) {
	goroutines := func() (int, []byte) {
		p := pprof.Lookup("goroutine")
		b := new(bytes.Buffer)
		p.WriteTo(b, 1)
		return p.Count(), b.Bytes()
	}

	startGoroutines, startStacks := goroutines()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		// Give goroutines time to exit, if they need it.
		for range 10000 {
			if runtime.NumGoroutine() <= startGoroutines {
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
		endGoroutines, endStacks := goroutines()
		t.Logf("starting stacks:\n%s\n", startStacks)
		t.Logf("ending stacks:\n%s\n", endStacks)
		t.Fatalf("expected %d goroutines, got %d, leak?", startGoroutines, endGoroutines)
	})
}
