package admin

import (
	"akhokhlow80/tanlweb/admin/reqencrypt"
	"akhokhlow80/tanlweb/db"
	"akhokhlow80/tanlweb/sqlgen"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
)

type requestEncryptionKeyStore struct {
	db *db.DB
}

var _ reqencrypt.KeyStore = (*requestEncryptionKeyStore)(nil)

// GetKeys implements reqencrypt.KeyStore.
func (r *requestEncryptionKeyStore) GetKeys(ctx context.Context) (reqencrypt.Keys, error) {
	defer r.db.RUnlock()
	r.db.RLock()

	dbRow, err := r.db.GetRequestEncryptionKeys(ctx)
	if err != nil {
		return reqencrypt.Keys{}, err
	}
	dbKeys := []*string{dbRow.Key0, dbRow.Key1}
	var keys reqencrypt.Keys
	for i, dbKey := range dbKeys {
		if dbKey == nil {
			continue
		}

		key, err := base64.StdEncoding.DecodeString(*dbKey)
		if err != nil {
			return reqencrypt.Keys{}, err
		}
		if len(key) != len(keys.Keys[i]) {
			return reqencrypt.Keys{}, fmt.Errorf("Request encryption key from DB has invalid size")
		}
		keyArr := [32]byte(key)
		keys.Keys[i] = &keyArr
	}
	keys.RotateAfter = dbRow.RotateAfter
	return keys, nil
}

// PutKeys implements reqencrypt.KeyStore.
func (r *requestEncryptionKeyStore) PutKeys(ctx context.Context, keys *reqencrypt.Keys) error {
	defer r.db.Unlock()
	r.db.Lock()

	var keysBase64 [2]*string
	for i := range keys.Keys {
		keysBase64[i] = new(string)
		*keysBase64[i] = base64.StdEncoding.EncodeToString(keys.Keys[0][:])
	}

	rows, err := r.db.UpdateRequestEncryptionKeys(ctx, sqlgen.UpdateRequestEncryptionKeysParams{
		Key0:        keysBase64[0],
		Key1:        keysBase64[1],
		RotateAfter: keys.RotateAfter,
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("No rows were updated by PutKeys()")
	}
	return nil
}

func (app *App) encryptURI(path string) string {
	return fmt.Sprintf("%s/%s", app.cfg.BaseURI, app.reqCipher.Encrypt(9 /* 512 */, path))
}
