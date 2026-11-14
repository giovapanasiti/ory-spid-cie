// Command broker runs the SPID/CIE OpenID Connect Federation broker.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/enpam/iam/federation-broker/internal/audit"
	"github.com/enpam/iam/federation-broker/internal/fedjose"
	"github.com/enpam/iam/federation-broker/internal/keys"
	"github.com/enpam/iam/federation-broker/internal/model"
	"github.com/enpam/iam/federation-broker/internal/rp"
	"github.com/enpam/iam/federation-broker/internal/safehttp"
	"github.com/enpam/iam/federation-broker/internal/seal"
	"github.com/enpam/iam/federation-broker/internal/server"
	"github.com/enpam/iam/federation-broker/internal/store"
)

type bootstrap struct {
	Comment      string              `json:"_comment"`
	Profiles     []model.RPProfile   `json:"profiles"`
	Providers    []model.Provider    `json:"providers"`
	TrustAnchors []model.TrustAnchor `json:"trust_anchors"`
}

func main() {
	migrateOnly := flag.Bool("migrate", false, "apply database migrations and exit")
	health := flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit (container healthcheck)")
	flag.Parse()
	if *health {
		os.Exit(probe("http://127.0.0.1" + listenPort(os.Getenv("BROKER_LISTEN"), ":8090") + "/healthz"))
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log, *migrateOnly); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, migrateOnly bool) error {
	cfg, err := server.LoadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.DB.Close()
	if err := waitDB(ctx, st); err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	if migrateOnly {
		log.Info("migrations applied")
		return nil
	}
	sealer, err := seal.New(cfg.SealKeys)
	if err != nil {
		return err
	}
	km := &keys.Manager{Store: st, Sealer: sealer}
	if err := seed(ctx, cfg, st, km, log); err != nil {
		return err
	}
	httpc := safehttp.New(safehttp.Policy{
		AllowHTTP: cfg.AllowInsecureHTTP, AllowPrivateNetworks: cfg.AllowPrivateNetworks,
		AllowedHostSuffixes: cfg.OutboundAllowlist, Timeout: 10 * time.Second, MaxRedirects: 2, MaxBodyBytes: 512 * 1024,
	})
	svc := &rp.Service{Store: st, Keys: km, HTTP: httpc, Sealer: sealer,
		Resolvers: &rp.Resolvers{Store: st, HTTP: httpc, Options: rp.ResolverOptions{MaxDepth: 5, CacheTTL: 3600}}}
	au := audit.New(cfg.AuditURL, cfg.AuditToken, log)
	srv, err := server.New(cfg, st, km, svc, au, log)
	if err != nil {
		return err
	}
	srv.StartJanitor(ctx)
	pub := &http.Server{Addr: cfg.Listen, Handler: srv.PublicHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	adm := &http.Server{Addr: cfg.AdminListen, Handler: srv.AdminHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- pub.ListenAndServe() }()
	go func() { errc <- adm.ListenAndServe() }()
	log.Info("federation broker started", "public", cfg.Listen, "admin", cfg.AdminListen, "env", cfg.Env)
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = pub.Shutdown(shCtx)
	_ = adm.Shutdown(shCtx)
	return nil
}

func listenPort(v, def string) string {
	if v == "" {
		v = def
	}
	if i := strings.LastIndex(v, ":"); i >= 0 {
		return v[i:]
	}
	return def
}

func probe(url string) int {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func waitDB(ctx context.Context, st *store.Store) error {
	var err error
	for i := 0; i < 30; i++ {
		if err = st.DB.Ping(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("database not reachable: %w", err)
}

// seed loads the bootstrap file (first start only: existing rows are never
// overwritten, the database is the source of truth afterwards) and ensures
// active keys exist when autogeneration is enabled.
func seed(ctx context.Context, cfg *server.Config, st *store.Store, km *keys.Manager, log *slog.Logger) error {
	if cfg.BootstrapFile != "" {
		raw, err := os.ReadFile(cfg.BootstrapFile)
		if err != nil {
			return fmt.Errorf("bootstrap file: %w", err)
		}
		var b bootstrap
		if err := json.Unmarshal([]byte(os.ExpandEnv(string(raw))), &b); err != nil {
			return fmt.Errorf("bootstrap file: %w", err)
		}
		for i := range b.Profiles {
			p := b.Profiles[i]
			if err := p.Validate(); err != nil {
				return fmt.Errorf("bootstrap profile %s: %w", p.Profile, err)
			}
			if err := st.InsertProfileIfAbsent(ctx, &p); err != nil {
				return err
			}
		}
		existing, err := st.ListProviders(ctx, "", false)
		if err != nil {
			return err
		}
		for i := range b.Providers {
			p := b.Providers[i]
			dup := false
			for _, e := range existing {
				if e.Profile == p.Profile && e.EntityID == p.EntityID {
					dup = true
				}
			}
			if !dup {
				if err := st.UpsertProvider(ctx, &p); err != nil {
					return err
				}
			}
		}
		tas, err := st.ListTrustAnchors(ctx, "", false)
		if err != nil {
			return err
		}
		for i := range b.TrustAnchors {
			t := b.TrustAnchors[i]
			dup := false
			for _, e := range tas {
				if e.Profile == t.Profile && e.EntityID == t.EntityID {
					dup = true
				}
			}
			if !dup && len(t.JWKS.Keys) > 0 {
				if err := st.UpsertTrustAnchor(ctx, &t); err != nil {
					return err
				}
			}
		}
		log.Info("bootstrap configuration applied", "file", cfg.BootstrapFile)
	}
	if !cfg.AutogenerateKeys {
		return nil
	}
	if err := km.EnsureActive(ctx, model.ProfileFacade, model.PurposeFacadeSig, fedjose.KeyRSA2048); err != nil {
		return err
	}
	for _, p := range []model.Profile{model.ProfileSPID, model.ProfileCIE} {
		for _, purpose := range []string{model.PurposeFederation, model.PurposeCoreSig, model.PurposeCoreEnc} {
			if err := km.EnsureActive(ctx, p, purpose, fedjose.KeyRSA2048); err != nil {
				return fmt.Errorf("ensure %s/%s key: %w", p, purpose, err)
			}
		}
	}
	return nil
}
