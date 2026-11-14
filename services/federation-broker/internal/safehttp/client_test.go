package safehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestBlocksPrivateAddressesAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	c := New(Policy{AllowHTTP: true}) // private networks NOT allowed
	if _, _, err := c.Get(context.Background(), srv.URL, ""); err == nil || !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback target must be blocked, got %v", err)
	}
	ok := New(Policy{AllowHTTP: true, AllowPrivateNetworks: true})
	if _, _, err := ok.Get(context.Background(), srv.URL, ""); err != nil {
		t.Fatalf("allowed in dev mode: %v", err)
	}
}

func TestSchemeHostAndUserinfoChecks(t *testing.T) {
	c := New(Policy{AllowedHostSuffixes: []string{"spid.gov.it"}})
	for _, raw := range []string{"http://registry.spid.gov.it/x", "file:///etc/passwd", "gopher://x", "https://user:pw@registry.spid.gov.it/", "https://evil.example/", "https://spid.gov.it.evil.example/"} {
		u, _ := url.Parse(raw)
		if err := c.CheckURL(u); err == nil {
			t.Errorf("%s must be blocked", raw)
		}
	}
	for _, raw := range []string{"https://registry.spid.gov.it/x", "https://spid.gov.it/"} {
		u, _ := url.Parse(raw)
		if err := c.CheckURL(u); err != nil {
			t.Errorf("%s must be allowed: %v", raw, err)
		}
	}
}

func TestBodyLimitAndRedirectBounds(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(strings.Repeat("a", 2048))) }))
	defer big.Close()
	c := New(Policy{AllowHTTP: true, AllowPrivateNetworks: true, MaxBodyBytes: 1024})
	if _, _, err := c.Get(context.Background(), big.URL, ""); err == nil {
		t.Fatal("oversized body accepted")
	}
	var loop *httptest.Server
	loop = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, loop.URL+"/again", http.StatusFound) }))
	defer loop.Close()
	c2 := New(Policy{AllowHTTP: true, AllowPrivateNetworks: true, MaxRedirects: 2})
	if _, _, err := c2.Get(context.Background(), loop.URL, ""); err == nil {
		t.Fatal("redirect loop not bounded")
	}
}
