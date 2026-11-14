// Package seal encrypts secrets at rest (private keys, PII awaiting pick-up)
// with AES-256-GCM. Keys are supplied via environment as
// "kid1:base64key,kid2:base64key"; the first key encrypts, all keys decrypt,
// which allows rotation of the envelope key.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Sealer encrypts and decrypts small payloads.
type Sealer struct {
	primary string
	aeads   map[string]cipher.AEAD
}

// New parses a key specification.
func New(spec string) (*Sealer, error) {
	s := &Sealer{aeads: map[string]cipher.AEAD{}}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kid, b64, ok := strings.Cut(part, ":")
		if !ok || kid == "" || strings.ContainsAny(kid, "|") {
			return nil, errors.New("seal key spec must be kid:base64key[,kid:base64key]")
		}
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			key, err = base64.RawURLEncoding.DecodeString(b64)
		}
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("seal key %q must be 32 bytes base64", kid)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if s.primary == "" {
			s.primary = kid
		}
		s.aeads[kid] = g
	}
	if s.primary == "" {
		return nil, errors.New("no seal key configured")
	}
	return s, nil
}

// Seal encrypts plaintext binding it to aad (e.g. a row identifier).
func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	g := s.aeads[s.primary]
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := []byte(s.primary + "|")
	out = append(out, nonce...)
	return g.Seal(out, nonce, plaintext, aad), nil
}

// Open decrypts a value produced by Seal.
func (s *Sealer) Open(ciphertext, aad []byte) ([]byte, error) {
	i := strings.IndexByte(string(ciphertext), '|')
	if i <= 0 {
		return nil, errors.New("malformed sealed value")
	}
	g, ok := s.aeads[string(ciphertext[:i])]
	if !ok {
		return nil, errors.New("unknown seal key id")
	}
	rest := ciphertext[i+1:]
	if len(rest) < g.NonceSize() {
		return nil, errors.New("malformed sealed value")
	}
	return g.Open(nil, rest[:g.NonceSize()], rest[g.NonceSize():], aad)
}
