package fedjose

import (
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func key(t *testing.T) SigningKey {
	t.Helper()
	k, err := GenerateKey(KeyRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := Thumbprint(k.Public())
	return SigningKey{Kid: kid, Alg: jose.RS256, Private: k}
}

func set(k SigningKey) jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{PublicJWK(k.Private.Public(), k.Kid, UseSig, string(k.Alg), nil)}}
}

func TestSignVerify(t *testing.T) {
	k := key(t)
	tok, err := Sign(map[string]any{"a": 1}, k, TypEntityStatement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tok, set(k), VerifyOptions{ExpectedTyp: TypEntityStatement}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tok, set(k), VerifyOptions{ExpectedTyp: TypTrustMark}); err == nil {
		t.Fatal("typ mismatch accepted")
	}
	if _, err := Verify(tok, set(key(t)), VerifyOptions{}); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestRejectsAlgNoneAndHMACConfusion(t *testing.T) {
	k := key(t)
	pub := k.Private.Public().(*rsa.PublicKey)
	secret, _ := json.Marshal(jose.JSONWebKey{Key: pub})
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, (&jose.SignerOptions{}).WithHeader("kid", k.Kid))
	obj, _ := sig.Sign([]byte(`{"sub":"x"}`))
	tok, _ := obj.CompactSerialize()
	if _, err := Verify(tok, set(k), VerifyOptions{}); err == nil {
		t.Fatal("HS256 confusion accepted")
	}
	none := "eyJhbGciOiJub25lIiwia2lkIjoieCJ9.eyJzdWIiOiJ4In0."
	if _, err := Verify(none, set(k), VerifyOptions{}); err == nil {
		t.Fatal("alg none accepted")
	}
}

func TestRequiresKid(t *testing.T) {
	k := key(t)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k.Private}, nil)
	obj, _ := signer.Sign([]byte(`{}`))
	tok, _ := obj.CompactSerialize()
	if _, err := Verify(tok, set(k), VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "kid") {
		t.Fatalf("missing kid accepted: %v", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	k := key(t)
	pub := PublicJWK(k.Private.Public(), "enc1", UseEnc, string(jose.RSA_OAEP_256), nil)
	jwe, err := Encrypt([]byte("hello"), pub, jose.RSA_OAEP_256, jose.A256CBC_HS512, "JWT")
	if err != nil {
		t.Fatal(err)
	}
	pt, _, err := Decrypt(jwe, []EncryptionKey{{Kid: "enc1", Private: k.Private.(*rsa.PrivateKey)}}, DecryptOptions{})
	if err != nil || string(pt) != "hello" {
		t.Fatalf("decrypt: %v", err)
	}
	// RSA1_5 is forbidden by the SPID/CIE crypto profile.
	if _, _, err := Decrypt(jwe, nil, DecryptOptions{KeyAlgs: []jose.KeyAlgorithm{jose.RSA1_5}}); err == nil {
		t.Fatal("disallowed key alg accepted")
	}
}

func TestCSRAndSelfSigned(t *testing.T) {
	k := key(t)
	subj := SubjectInfo{CommonName: "rp.example.org", Organization: "Example", OrganizationIdentifier: "PA:IT-c_h501", Country: "IT", EntityID: "https://rp.example.org/rp/spid"}
	csr, err := CreateCSR(k.Private, subj)
	if err != nil || !strings.Contains(string(csr), "CERTIFICATE REQUEST") {
		t.Fatalf("csr: %v", err)
	}
	c, err := CreateSelfSigned(k.Private, subj, 24*3600e9)
	if err != nil {
		t.Fatal(err)
	}
	if !PublicKeysEqual(c.PublicKey, k.Private.Public()) || len(c.URIs) != 1 {
		t.Fatal("certificate mismatch")
	}
}
