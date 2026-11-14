package sim

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"sync"
)

// keyStore persists simulator RSA keys as PKCS#8 PEM in a JSON file.
// Test-only: the file contains private keys of the LOCAL test federation.
type keyStore struct {
	path  string
	mu    sync.Mutex
	keys  map[string]string
	dirty bool
}

func loadKeyStore(path string) (*keyStore, error) {
	ks := &keyStore{path: path, keys: map[string]string{}}
	if path == "" {
		return ks, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ks, nil
	}
	if err != nil {
		return nil, err
	}
	return ks, json.Unmarshal(b, &ks.keys)
}

func (ks *keyStore) get(name string) (*rsa.PrivateKey, error) {
	if ks == nil {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if p, ok := ks.keys[name]; ok {
		block, _ := pem.Decode([]byte(p))
		if block != nil {
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					return rk, nil
				}
			}
		}
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	ks.keys[name] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	ks.dirty = true
	return k, nil
}

func (ks *keyStore) save() error {
	if ks == nil || ks.path == "" || !ks.dirty {
		return nil
	}
	b, err := json.MarshalIndent(ks.keys, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(ks.path, b, 0o600)
}
