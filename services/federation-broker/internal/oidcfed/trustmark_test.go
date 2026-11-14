package oidcfed

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// unsignedMark builds a JWT-shaped string; verifyTrustMarks decides on the (unverified) issuer
// before any signature check, which is what these tests exercise.
func unsignedMark(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "RS256", "kid": "k", "typ": "trust-mark+jwt"}) + "." + enc(claims) + ".c2ln"
}

func TestTrustMarkOfAnotherPinnedFederationIsIgnoredNotRejected(t *testing.T) {
	const leaf, taA, taB = "https://rp.example/", "https://ta-a.example", "https://ta-b.example"
	r := &Resolver{Skew: 30 * time.Second, Anchors: []TrustAnchor{{EntityID: taA}, {EntityID: taB}}}
	now := time.Now().Unix()
	chain := &TrustChain{Anchor: taA, Statements: []*EntityStatement{
		{Iss: leaf, Sub: leaf, TrustMarks: []TrustMarkRef{
			{ID: "https://mark.example/b", TrustMark: unsignedMark(t, map[string]any{"iss": taB, "sub": leaf, "id": "https://mark.example/b", "iat": now})},
			{ID: "https://mark.example/x", TrustMark: unsignedMark(t, map[string]any{"iss": "https://unknown.example", "sub": leaf, "id": "https://mark.example/x", "iat": now})},
		}},
		{Iss: taA, Sub: taA},
	}}
	r.verifyTrustMarks(context.Background(), chain)

	if len(chain.TrustMarks) != 0 {
		t.Fatalf("a mark from another federation must not count as verified in this chain: %+v", chain.TrustMarks)
	}
	if len(chain.TrustMarkErrors) != 1 || !strings.Contains(chain.TrustMarkErrors[0], "https://unknown.example") {
		t.Fatalf("only the mark from an unknown, non-pinned issuer must be an error, got %v", chain.TrustMarkErrors)
	}
}
