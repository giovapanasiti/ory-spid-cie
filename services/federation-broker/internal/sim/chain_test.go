package sim

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/enpam/iam/federation-broker/internal/oidcfed"
	"github.com/enpam/iam/federation-broker/internal/rp"
	"github.com/enpam/iam/federation-broker/internal/safehttp"
)

type fetcher struct{ c *safehttp.Client }

func (f fetcher) Get(ctx context.Context, url, accept string) ([]byte, string, error) {
	return f.c.Get(ctx, url, accept)
}

func startSim(t *testing.T) (*Sim, string, oidcfed.Fetcher) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	f := fetcher{safehttp.New(safehttp.Policy{AllowHTTP: true, AllowPrivateNetworks: true})}
	s, err := New(Config{InternalBase: base, PublicBase: base, RPTrustMarkID: "https://registry.spid.gov.it/openid_relying_party/public/",
		Fetcher: f, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s.Handler()}
	go srv.Serve(ln) //nolint:errcheck
	t.Cleanup(func() { srv.Close() })
	return s, base, f
}

func TestTrustChainResolution(t *testing.T) {
	s, base, f := startSim(t)
	res := &oidcfed.Resolver{Fetcher: f, Algs: rp.AllowedSigAlgs, Skew: 30 * time.Second,
		Anchors: []oidcfed.TrustAnchor{{EntityID: s.TA.ID, JWKS: s.TAJWKS()}}}
	ctx := context.Background()

	chain, err := res.Resolve(ctx, base+"/op/spid-test", oidcfed.EntityTypeOP)
	if err != nil {
		t.Fatalf("valid OP: %v", err)
	}
	if chain.Anchor != s.TA.ID || len(chain.Statements) != 3 {
		t.Fatalf("unexpected chain: anchor=%s len=%d", chain.Anchor, len(chain.Statements))
	}
	if chain.Metadata[oidcfed.EntityTypeOP]["issuer"] != base+"/op/spid-test" {
		t.Fatal("metadata not propagated")
	}

	for _, bad := range []string{"rogue", "tampered", "does-not-exist"} {
		if _, err := res.Resolve(ctx, base+"/op/"+bad, oidcfed.EntityTypeOP); err == nil {
			t.Errorf("%s: expected trust failure", bad)
		}
	}
}

func TestTrustChainWrongPinnedKey(t *testing.T) {
	_, base, f := startSim(t)
	other, _ := newEntity(base+"/ta", "ta", "", "")
	res := &oidcfed.Resolver{Fetcher: f, Algs: rp.AllowedSigAlgs, Skew: 30 * time.Second,
		Anchors: []oidcfed.TrustAnchor{{EntityID: base + "/ta", JWKS: pubSet(other.FedKey)}}}
	_, err := res.Resolve(context.Background(), base+"/op/spid-test", oidcfed.EntityTypeOP)
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("expected pinned-key failure, got %v", err)
	}
}

func TestTrustChainExpired(t *testing.T) {
	s, base, f := startSim(t)
	res := &oidcfed.Resolver{Fetcher: f, Algs: rp.AllowedSigAlgs, Skew: 30 * time.Second,
		Anchors: []oidcfed.TrustAnchor{{EntityID: s.TA.ID, JWKS: s.TAJWKS()}},
		Now:     func() time.Time { return time.Now().Add(48 * time.Hour) }}
	if _, err := res.Resolve(context.Background(), base+"/op/spid-test", oidcfed.EntityTypeOP); err == nil {
		t.Fatal("expired statements must be rejected")
	}
}

func TestTrustChainAlgorithmAllowList(t *testing.T) {
	s, base, f := startSim(t)
	// Only ES256 allowed: RS256-signed statements must be rejected.
	res := &oidcfed.Resolver{Fetcher: f, Algs: []jose.SignatureAlgorithm{jose.ES256}, Skew: 30 * time.Second,
		Anchors: []oidcfed.TrustAnchor{{EntityID: s.TA.ID, JWKS: s.TAJWKS()}}}
	if _, err := res.Resolve(context.Background(), base+"/op/spid-test", oidcfed.EntityTypeOP); err == nil {
		t.Fatal("disallowed algorithm accepted")
	}
}
