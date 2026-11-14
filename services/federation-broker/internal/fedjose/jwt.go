package fedjose

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

// Well known JWT "typ" header values used by OpenID Federation.
const (
	TypEntityStatement = "entity-statement+jwt"
	TypTrustMark       = "trust-mark+jwt"
	TypResolveResponse = "resolve-response+jwt"
	TypJWT             = "JWT"
)

// DefaultSigningAlgs is the signature allow-list applied when the caller does
// not provide one. "none" and HMAC algorithms are never allowed: HMAC with a
// public key would enable algorithm-confusion attacks.
var DefaultSigningAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.RS512, jose.ES256, jose.ES512, jose.PS256, jose.PS512}

// DefaultKeyEncAlgs / DefaultContentEncAlgs are the JWE allow-lists for
// encrypted UserInfo responses.
var (
	DefaultKeyEncAlgs     = []jose.KeyAlgorithm{jose.RSA_OAEP, jose.RSA_OAEP_256, jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A256KW}
	DefaultContentEncAlgs = []jose.ContentEncryption{jose.A128CBC_HS256, jose.A256CBC_HS512, jose.A128GCM, jose.A256GCM}
)

// ErrNoMatchingKey is returned when no JWK in the set matches the kid.
var ErrNoMatchingKey = errors.New("no matching key for kid")

// SigningKey is a private key ready for JWS signing.
type SigningKey struct {
	Kid     string
	Alg     jose.SignatureAlgorithm
	Private crypto.Signer
}

// Sign serialises claims as a compact JWS with kid and typ headers.
func Sign(claims any, k SigningKey, typ string) (string, error) {
	if k.Kid == "" {
		return "", errors.New("signing key has no kid")
	}
	if !AlgCompatible(k.Alg, k.Private.Public()) {
		return "", fmt.Errorf("algorithm %s incompatible with key", k.Alg)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), k.Kid)
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: k.Alg, Key: k.Private}, opts)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// AllowedAlgs is the JWS algorithm allow-list. Defaults to DefaultSigningAlgs.
	AllowedAlgs []jose.SignatureAlgorithm
	// ExpectedTyp, when not empty, must match the "typ" header (case-insensitive,
	// optional "application/" prefix as per RFC 7515 §4.1.9).
	ExpectedTyp string
}

// Verified is the result of a successful verification.
type Verified struct {
	Header  jose.Header
	Payload []byte
}

// Verify parses and verifies a compact JWS against a JWK set. The kid header
// is mandatory and must identify exactly one usable signing key.
func Verify(token string, keys jose.JSONWebKeySet, opt VerifyOptions) (*Verified, error) {
	algs := opt.AllowedAlgs
	if len(algs) == 0 {
		algs = DefaultSigningAlgs
	}
	if strings.Count(token, ".") != 2 {
		return nil, errors.New("not a compact JWS")
	}
	jws, err := jose.ParseSigned(token, algs)
	if err != nil {
		return nil, fmt.Errorf("parse jws: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("exactly one signature required")
	}
	h := jws.Signatures[0].Protected
	if opt.ExpectedTyp != "" && !TypMatches(typHeader(h), opt.ExpectedTyp) {
		return nil, fmt.Errorf("unexpected typ %q (want %q)", typHeader(h), opt.ExpectedTyp)
	}
	if h.KeyID == "" {
		return nil, errors.New("missing kid header")
	}
	if h.JSONWebKey != nil {
		// Embedded keys are attacker controlled; trust only the provided set.
		return nil, errors.New("embedded jwk header not accepted")
	}
	candidates := keys.Key(h.KeyID)
	var key *jose.JSONWebKey
	for i := range candidates {
		c := candidates[i]
		if c.Use != "" && c.Use != string(UseSig) {
			continue
		}
		if !c.IsPublic() {
			pub := c.Public()
			c = pub
		}
		if c.Algorithm != "" && c.Algorithm != h.Algorithm {
			continue
		}
		if !AlgCompatible(jose.SignatureAlgorithm(h.Algorithm), c.Key) {
			continue
		}
		key = &c
		break
	}
	if key == nil {
		return nil, fmt.Errorf("%w %q", ErrNoMatchingKey, h.KeyID)
	}
	payload, err := jws.Verify(key.Key)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	return &Verified{Header: h, Payload: payload}, nil
}

// UnverifiedClaims decodes the payload of a compact JWS WITHOUT verifying it.
// It must only be used to discover routing information (e.g. "iss") that is
// verified afterwards.
func UnverifiedClaims(token string, dest any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dest)
}

// TypMatches compares typ header values per RFC 7515 §4.1.9.
func TypMatches(got, want string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		return strings.TrimPrefix(s, "application/")
	}
	return norm(got) == norm(want)
}

func typHeader(h jose.Header) string {
	if v, ok := h.ExtraHeaders[jose.HeaderType]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// EncryptionKey is a private key used to decrypt JWE payloads.
type EncryptionKey struct {
	Kid     string
	Private crypto.Decrypter
}

// DecryptOptions configures Decrypt.
type DecryptOptions struct {
	KeyAlgs     []jose.KeyAlgorithm
	ContentAlgs []jose.ContentEncryption
}

// Decrypt decrypts a compact JWE with one of the given keys (selected by kid
// when present).
func Decrypt(token string, keys []EncryptionKey, opt DecryptOptions) ([]byte, jose.Header, error) {
	ka := opt.KeyAlgs
	if len(ka) == 0 {
		ka = DefaultKeyEncAlgs
	}
	ca := opt.ContentAlgs
	if len(ca) == 0 {
		ca = DefaultContentEncAlgs
	}
	jwe, err := jose.ParseEncryptedCompact(token, ka, ca)
	if err != nil {
		return nil, jose.Header{}, fmt.Errorf("parse jwe: %w", err)
	}
	kid := jwe.Header.KeyID
	for _, k := range keys {
		if kid != "" && k.Kid != kid {
			continue
		}
		pt, err := jwe.Decrypt(k.Private)
		if err == nil {
			return pt, jwe.Header, nil
		}
	}
	return nil, jose.Header{}, errors.New("jwe decryption failed")
}

// Encrypt produces a compact JWE for the recipient public JWK.
func Encrypt(plaintext []byte, recipient jose.JSONWebKey, alg jose.KeyAlgorithm, enc jose.ContentEncryption, cty string) (string, error) {
	opts := &jose.EncrypterOptions{}
	if cty != "" {
		opts = opts.WithContentType(jose.ContentType(cty))
	}
	e, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: recipient.Key, KeyID: recipient.KeyID}, opts)
	if err != nil {
		return "", err
	}
	obj, err := e.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// RandomToken returns n random bytes as base64url (no padding).
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func subjURI(s SubjectInfo) []*url.URL {
	if s.EntityID == "" {
		return nil
	}
	u, err := url.Parse(s.EntityID)
	if err != nil || u.Scheme == "" {
		return nil
	}
	return []*url.URL{u}
}
