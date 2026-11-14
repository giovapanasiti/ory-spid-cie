// Package fedjose wraps go-jose with the strict defaults required by the
// SPID/CIE OIDC Federation profiles: explicit algorithm allow-lists, mandatory
// "kid" headers, typ checks, and helpers for key / certificate management.
//
// No cryptographic primitive is implemented here: all signing, verification,
// encryption and decryption is delegated to github.com/go-jose/go-jose/v4 and
// the Go standard library.
package fedjose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// KeyUse is the JWK "use" member.
type KeyUse string

const (
	UseSig KeyUse = "sig"
	UseEnc KeyUse = "enc"
)

// KeyType selects the algorithm family for key generation.
type KeyType string

const (
	KeyRSA2048 KeyType = "RSA-2048"
	KeyRSA3072 KeyType = "RSA-3072"
	KeyRSA4096 KeyType = "RSA-4096"
	KeyECP256  KeyType = "EC-P256"
	KeyECP384  KeyType = "EC-P384"
	KeyECP521  KeyType = "EC-P521"
)

// AllKeyTypes lists the supported key types (used by the admin UI).
var AllKeyTypes = []KeyType{KeyRSA2048, KeyRSA3072, KeyRSA4096, KeyECP256, KeyECP384, KeyECP521}

// GenerateKey creates a new private key of the given type.
func GenerateKey(t KeyType) (crypto.Signer, error) {
	switch t {
	case KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case KeyRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case KeyECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyECP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyECP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key type %q", t)
	}
}

// DefaultSigAlg returns the default JWS algorithm for a key.
func DefaultSigAlg(k crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch pk := k.(type) {
	case *rsa.PublicKey:
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		switch pk.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
	}
	return "", errors.New("unsupported public key type")
}

// AlgCompatible reports whether a JWS algorithm can be used with the key.
func AlgCompatible(alg jose.SignatureAlgorithm, k crypto.PublicKey) bool {
	switch pk := k.(type) {
	case *rsa.PublicKey:
		if pk.N.BitLen() < 2048 {
			return false
		}
		switch alg {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			return true
		}
	case *ecdsa.PublicKey:
		switch {
		case alg == jose.ES256 && pk.Curve == elliptic.P256():
			return true
		case alg == jose.ES384 && pk.Curve == elliptic.P384():
			return true
		case alg == jose.ES512 && pk.Curve == elliptic.P521():
			return true
		}
	}
	return false
}

// ParsePrivateKeyPEM parses a PKCS#8, PKCS#1 or SEC1 PEM-encoded private key.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // detection only; we refuse legacy encrypted PEM
		return nil, errors.New("encrypted PEM keys are not supported: decrypt the key before import")
	}
	var (
		k   any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signing key")
	}
	switch pk := signer.Public().(type) {
	case *rsa.PublicKey:
		if pk.N.BitLen() < 2048 {
			return nil, errors.New("RSA keys shorter than 2048 bits are rejected")
		}
	case *ecdsa.PublicKey:
	default:
		return nil, errors.New("only RSA and ECDSA keys are supported")
	}
	return signer, nil
}

// MarshalPrivateKeyPEM encodes a private key as PKCS#8 PEM.
func MarshalPrivateKeyPEM(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseCertificateChainPEM parses one or more PEM certificates (leaf first).
func ParseCertificateChainPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE PEM block found")
	}
	return certs, nil
}

// EncodeCertificatesPEM encodes certificates as PEM.
func EncodeCertificatesPEM(certs []*x509.Certificate) []byte {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return []byte(b.String())
}

// PublicKeysEqual compares two public keys.
func PublicKeysEqual(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if x, ok := a.(eq); ok {
		return x.Equal(b)
	}
	return false
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint (base64url), used as kid.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	j := jose.JSONWebKey{Key: pub}
	tp, err := j.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// CertFingerprint returns the SHA-256 fingerprint of a certificate (hex, colon separated).
func CertFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// SubjectInfo describes the X.509 subject used for CSRs and self-signed certs.
// Field names follow the AgID SPID certificate profile where applicable
// (organizationIdentifier, e.g. "PA:IT-c_h501" or "VATIT-12345678901").
type SubjectInfo struct {
	CommonName             string `json:"common_name"`
	Organization           string `json:"organization"`
	OrganizationIdentifier string `json:"organization_identifier,omitempty"`
	Country                string `json:"country"`
	Locality               string `json:"locality,omitempty"`
	EntityID               string `json:"entity_id,omitempty"` // placed in URI SAN
}

// oidOrganizationIdentifier is 2.5.4.97 (organizationIdentifier, X.520).
var oidOrganizationIdentifier = []int{2, 5, 4, 97}

func (s SubjectInfo) name() pkix.Name {
	n := pkix.Name{CommonName: s.CommonName}
	if s.Organization != "" {
		n.Organization = []string{s.Organization}
	}
	if s.Country != "" {
		n.Country = []string{s.Country}
	}
	if s.Locality != "" {
		n.Locality = []string{s.Locality}
	}
	if s.OrganizationIdentifier != "" {
		n.ExtraNames = append(n.ExtraNames, pkix.AttributeTypeAndValue{Type: oidOrganizationIdentifier, Value: s.OrganizationIdentifier})
	}
	return n
}

// Validate performs minimal subject validation.
func (s SubjectInfo) Validate() error {
	if strings.TrimSpace(s.CommonName) == "" {
		return errors.New("common_name is required")
	}
	if s.Country != "" && len(s.Country) != 2 {
		return errors.New("country must be an ISO 3166 alpha-2 code")
	}
	return nil
}

// CreateCSR produces a PEM PKCS#10 certificate signing request for the key.
func CreateCSR(k crypto.Signer, subj SubjectInfo) ([]byte, error) {
	if err := subj.Validate(); err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: subj.name()}
	if u := subjURI(subj); u != nil {
		tmpl.URIs = u
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// CreateSelfSigned creates a self-signed certificate. Intended for test
// environments only; production certificates must follow the issuing
// authority's profile.
func CreateSelfSigned(k crypto.Signer, subj SubjectInfo, validity time.Duration) (*x509.Certificate, error) {
	if err := subj.Validate(); err != nil {
		return nil, err
	}
	if validity <= 0 || validity > 5*365*24*time.Hour {
		return nil, errors.New("validity must be between 1 second and 5 years")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj.name(),
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
	}
	if _, ok := k.Public().(*rsa.PublicKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if u := subjURI(subj); u != nil {
		tmpl.URIs = u
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// PublicJWK builds the public JWK for a key, with optional x5c chain.
func PublicJWK(pub crypto.PublicKey, kid string, use KeyUse, alg string, certs []*x509.Certificate) jose.JSONWebKey {
	j := jose.JSONWebKey{Key: pub, KeyID: kid, Use: string(use), Algorithm: alg}
	if len(certs) > 0 {
		j.Certificates = certs
	}
	return j
}
