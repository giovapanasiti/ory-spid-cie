// Package keys manages federation, OIDC core and facade keys: generation,
// import, certificate attachment, rotation and JWKS publication.
package keys

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/enpam/iam/federation-broker/internal/fedjose"
	"github.com/enpam/iam/federation-broker/internal/model"
	"github.com/enpam/iam/federation-broker/internal/seal"
	"github.com/enpam/iam/federation-broker/internal/store"
)

// Manager wraps the store with crypto helpers.
type Manager struct {
	Store  *store.Store
	Sealer *seal.Sealer
}

func aad(kid string) []byte { return []byte("fed-key:" + kid) }

func validPurpose(p model.Profile, purpose string) error {
	switch p {
	case model.ProfileSPID, model.ProfileCIE:
		switch purpose {
		case model.PurposeFederation, model.PurposeCoreSig, model.PurposeCoreEnc:
			return nil
		}
	case model.ProfileFacade:
		if purpose == model.PurposeFacadeSig {
			return nil
		}
	}
	return fmt.Errorf("purpose %q not valid for profile %q", purpose, p)
}

// encAlg returns the JWE key management algorithm advertised for enc keys.
func encAlg(pub crypto.PublicKey) string {
	if _, ok := pub.(interface{ Size() int }); ok {
		return string(jose.RSA_OAEP_256)
	}
	return string(jose.ECDH_ES)
}

// Create stores a private key (generated or imported).
func (m *Manager) Create(ctx context.Context, p model.Profile, purpose, alg, keyType string, priv crypto.Signer, certs []*x509.Certificate, status string) (*model.KeyInfo, error) {
	if err := validPurpose(p, purpose); err != nil {
		return nil, err
	}
	if status != model.KeyNext && status != model.KeyActive {
		return nil, errors.New("new keys must be next or active")
	}
	pub := priv.Public()
	if _, isRSA := pub.(*rsa.PublicKey); p == model.ProfileSPID && purpose == model.PurposeCoreEnc && !isRSA {
		return nil, errors.New("SPID encryption keys must be RSA (RSA-OAEP)")
	}
	if len(certs) > 0 && !fedjose.PublicKeysEqual(certs[0].PublicKey, pub) {
		return nil, errors.New("certificate does not match the private key")
	}
	if purpose == model.PurposeCoreEnc {
		alg = encAlg(pub)
	} else {
		if alg == "" {
			a, err := fedjose.DefaultSigAlg(pub)
			if err != nil {
				return nil, err
			}
			alg = string(a)
		}
		if !fedjose.AlgCompatible(jose.SignatureAlgorithm(alg), pub) {
			return nil, fmt.Errorf("algorithm %s is not compatible with the key", alg)
		}
	}
	kid, err := fedjose.Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	use := fedjose.UseSig
	if purpose == model.PurposeCoreEnc {
		use = fedjose.UseEnc
	}
	jwk := fedjose.PublicJWK(pub, kid, use, alg, certs)
	jwkJSON, err := jwk.MarshalJSON()
	if err != nil {
		return nil, err
	}
	pemKey, err := fedjose.MarshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, err
	}
	sealed, err := m.Sealer.Seal(pemKey, aad(kid))
	if err != nil {
		return nil, err
	}
	rec := &store.KeyRecord{PrivateSealed: sealed}
	rec.Profile, rec.Purpose, rec.Kid, rec.Alg, rec.KeyType, rec.Status = p, purpose, kid, alg, keyType, status
	rec.PublicJWK = jwkJSON
	if len(certs) > 0 {
		rec.CertPEM = string(fedjose.EncodeCertificatesPEM(certs))
	}
	if status == model.KeyActive {
		// Ensure a single active key: insert as next, then activate atomically.
		rec.Status = model.KeyNext
	}
	if err := m.Store.InsertKey(ctx, rec); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, fmt.Errorf("%w: a key with kid %s already exists", store.ErrConflict, kid)
		}
		return nil, err
	}
	if status == model.KeyActive {
		if _, err := m.Store.ActivateKey(ctx, rec.ID); err != nil {
			return nil, err
		}
	}
	return m.Info(ctx, rec.ID)
}

// Generate creates a fresh key.
func (m *Manager) Generate(ctx context.Context, p model.Profile, purpose string, kt fedjose.KeyType, alg, status string) (*model.KeyInfo, error) {
	if purpose == model.PurposeCoreEnc && !strings.HasPrefix(string(kt), "RSA") {
		// SPID mandates RSA-OAEP(-256); ECDH-ES is CIE-only/recommended.
		if p == model.ProfileSPID {
			return nil, errors.New("SPID encryption keys must be RSA")
		}
	}
	priv, err := fedjose.GenerateKey(kt)
	if err != nil {
		return nil, err
	}
	return m.Create(ctx, p, purpose, alg, string(kt), priv, nil, status)
}

// Import stores a PEM private key with an optional certificate chain.
func (m *Manager) Import(ctx context.Context, p model.Profile, purpose, alg string, keyPEM, certPEM []byte, status string) (*model.KeyInfo, error) {
	priv, err := fedjose.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	if len(strings.TrimSpace(string(certPEM))) > 0 {
		if certs, err = fedjose.ParseCertificateChainPEM(certPEM); err != nil {
			return nil, err
		}
	}
	return m.Create(ctx, p, purpose, alg, "imported", priv, certs, status)
}

// Private unseals a key's private part.
func (m *Manager) Private(rec *store.KeyRecord) (crypto.Signer, error) {
	pemKey, err := m.Sealer.Open(rec.PrivateSealed, aad(rec.Kid))
	if err != nil {
		return nil, fmt.Errorf("unseal key %s: %w", rec.Kid, err)
	}
	return fedjose.ParsePrivateKeyPEM(pemKey)
}

// AttachCertificate validates and stores a certificate chain for a key.
func (m *Manager) AttachCertificate(ctx context.Context, id string, certPEM []byte) (*model.KeyInfo, error) {
	rec, err := m.Store.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	certs, err := fedjose.ParseCertificateChainPEM(certPEM)
	if err != nil {
		return nil, err
	}
	priv, err := m.Private(rec)
	if err != nil {
		return nil, err
	}
	if !fedjose.PublicKeysEqual(certs[0].PublicKey, priv.Public()) {
		return nil, errors.New("certificate does not match the key")
	}
	use := fedjose.UseSig
	if rec.Purpose == model.PurposeCoreEnc {
		use = fedjose.UseEnc
	}
	jwk := fedjose.PublicJWK(priv.Public(), rec.Kid, use, rec.Alg, certs)
	raw, err := jwk.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if err := m.Store.SetKeyCertificate(ctx, id, string(fedjose.EncodeCertificatesPEM(certs)), raw); err != nil {
		return nil, err
	}
	return m.Info(ctx, id)
}

// CSR creates a certificate signing request for a stored key.
func (m *Manager) CSR(ctx context.Context, id string, subj fedjose.SubjectInfo) ([]byte, error) {
	rec, err := m.Store.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	priv, err := m.Private(rec)
	if err != nil {
		return nil, err
	}
	return fedjose.CreateCSR(priv, subj)
}

// SelfSign issues and attaches a self-signed certificate (test environments).
func (m *Manager) SelfSign(ctx context.Context, id string, subj fedjose.SubjectInfo, days int) (*model.KeyInfo, error) {
	rec, err := m.Store.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	priv, err := m.Private(rec)
	if err != nil {
		return nil, err
	}
	cert, err := fedjose.CreateSelfSigned(priv, subj, time.Duration(days)*24*time.Hour)
	if err != nil {
		return nil, err
	}
	return m.AttachCertificate(ctx, id, fedjose.EncodeCertificatesPEM([]*x509.Certificate{cert}))
}

// Info returns the public view of a key.
func (m *Manager) Info(ctx context.Context, id string) (*model.KeyInfo, error) {
	rec, err := m.Store.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	return Describe(rec), nil
}

// Describe converts a record into its public view.
func Describe(rec *store.KeyRecord) *model.KeyInfo {
	info := rec.KeyInfo
	if rec.CertPEM != "" {
		if certs, err := fedjose.ParseCertificateChainPEM([]byte(rec.CertPEM)); err == nil {
			c := certs[0]
			ci := &model.CertInfo{
				Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: hex.EncodeToString(c.SerialNumber.Bytes()),
				NotBefore: c.NotBefore, NotAfter: c.NotAfter, Fingerprint: fedjose.CertFingerprint(c),
				SelfSigned: c.Subject.String() == c.Issuer.String(),
			}
			for _, u := range c.URIs {
				ci.URIs = append(ci.URIs, u.String())
			}
			info.Certificate = ci
		}
	}
	return &info
}

// Signing returns the active signing key for profile/purpose.
func (m *Manager) Signing(ctx context.Context, p model.Profile, purpose string) (fedjose.SigningKey, error) {
	recs, err := m.Store.ListKeys(ctx, p)
	if err != nil {
		return fedjose.SigningKey{}, err
	}
	for _, r := range recs {
		if r.Purpose == purpose && r.Status == model.KeyActive {
			priv, err := m.Private(r)
			if err != nil {
				return fedjose.SigningKey{}, err
			}
			return fedjose.SigningKey{Kid: r.Kid, Alg: jose.SignatureAlgorithm(r.Alg), Private: priv}, nil
		}
	}
	return fedjose.SigningKey{}, fmt.Errorf("no active %s key for %s", purpose, p)
}

// Decryption returns all published decryption keys for a profile (active
// first), so responses encrypted to a recently rotated key still decrypt.
func (m *Manager) Decryption(ctx context.Context, p model.Profile) ([]fedjose.EncryptionKey, error) {
	recs, err := m.Store.ListKeys(ctx, p)
	if err != nil {
		return nil, err
	}
	var active, other []fedjose.EncryptionKey
	for _, r := range recs {
		if r.Purpose != model.PurposeCoreEnc || !model.KeyPublished(r.Status) {
			continue
		}
		priv, err := m.Private(r)
		if err != nil {
			return nil, err
		}
		dec, ok := priv.(crypto.Decrypter)
		if !ok {
			continue
		}
		k := fedjose.EncryptionKey{Kid: r.Kid, Private: dec}
		if r.Status == model.KeyActive {
			active = append(active, k)
		} else {
			other = append(other, k)
		}
	}
	if len(active) == 0 {
		return nil, fmt.Errorf("no active encryption key for %s", p)
	}
	return append(active, other...), nil
}

// PublicJWKS returns published public keys for profile/purposes.
func (m *Manager) PublicJWKS(ctx context.Context, p model.Profile, purposes ...string) (jose.JSONWebKeySet, error) {
	recs, err := m.Store.ListKeys(ctx, p)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	want := map[string]bool{}
	for _, x := range purposes {
		want[x] = true
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, r := range recs {
		if !want[r.Purpose] || !model.KeyPublished(r.Status) {
			continue
		}
		var j jose.JSONWebKey
		if err := json.Unmarshal(r.PublicJWK, &j); err != nil {
			return set, err
		}
		set.Keys = append(set.Keys, j)
	}
	return set, nil
}

// EnsureActive generates an active key when none exists (bootstrap).
func (m *Manager) EnsureActive(ctx context.Context, p model.Profile, purpose string, kt fedjose.KeyType) error {
	recs, err := m.Store.ListKeys(ctx, p)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Purpose == purpose && r.Status == model.KeyActive {
			return nil
		}
	}
	_, err = m.Generate(ctx, p, purpose, kt, "", model.KeyActive)
	return err
}
