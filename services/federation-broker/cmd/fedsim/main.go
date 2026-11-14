// Command fedsim runs the LOCAL TEST SPID/CIE federation simulator
// (Trust Anchor + OpenID Providers). Development and CI only.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/enpam/iam/federation-broker/internal/safehttp"
	"github.com/enpam/iam/federation-broker/internal/sim"
)

type fetcher struct{ c *safehttp.Client }

func (f fetcher) Get(ctx context.Context, url, accept string) ([]byte, string, error) {
	return f.c.Get(ctx, url, accept)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		c := &http.Client{Timeout: 2 * time.Second}
		resp, err := c.Get("http://127.0.0.1" + envOr("FEDSIM_LISTEN", ":8070") + "/healthz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if os.Getenv("FEDSIM_I_UNDERSTAND_THIS_IS_TEST_ONLY") != "true" {
		log.Error("refusing to start: set FEDSIM_I_UNDERSTAND_THIS_IS_TEST_ONLY=true (test federation, never production)")
		os.Exit(2)
	}
	var rps []string
	for _, e := range strings.Split(os.Getenv("FEDSIM_RP_ENTITIES"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			rps = append(rps, e)
		}
	}
	httpc := safehttp.New(safehttp.Policy{AllowHTTP: true, AllowPrivateNetworks: true, Timeout: 5 * time.Second})
	s, err := sim.New(sim.Config{
		InternalBase:  strings.TrimRight(os.Getenv("FEDSIM_INTERNAL_URL"), "/"),
		PublicBase:    strings.TrimRight(os.Getenv("FEDSIM_PUBLIC_URL"), "/"),
		RPEntities:    rps,
		RPTrustMarkID: envOr("FEDSIM_RP_TRUST_MARK_ID", "https://registry.spid.gov.it/openid_relying_party/public/"),
		Fetcher:       fetcher{httpc},
		Log:           log,
		KeyFile:       os.Getenv("FEDSIM_KEY_FILE"),
	})
	if err != nil {
		log.Error("init", "err", err)
		os.Exit(1)
	}
	addr := envOr("FEDSIM_LISTEN", ":8070")
	log.Warn("LOCAL TEST FEDERATION simulator started — not an official conformance tool", "addr", addr, "trust_anchor", s.TA.ID)
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
