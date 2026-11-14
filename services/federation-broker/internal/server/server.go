// Package server wires HTTP handlers for the federation broker.
//
// Two listeners are exposed:
//   - public (BROKER_LISTEN): federation endpoints, the OP redirect callback
//     and the OIDC facade consumed by Kratos (browser + server-to-server);
//   - admin (BROKER_ADMIN_LISTEN): configuration API used by the admin console
//     and internal API used by identity-service. Never expose it publicly.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"

	"github.com/enpam/iam/federation-broker/internal/audit"
	"github.com/enpam/iam/federation-broker/internal/keys"
	"github.com/enpam/iam/federation-broker/internal/model"
	"github.com/enpam/iam/federation-broker/internal/rp"
	"github.com/enpam/iam/federation-broker/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server holds dependencies.
type Server struct {
	Cfg   *Config
	Store *store.Store
	Keys  *keys.Manager
	RP    *rp.Service
	Audit *audit.Sink
	Log   *slog.Logger

	tmpl     *template.Template
	limiters sync.Map
}

var (
	mRequests = promauto.NewCounterVec(prometheus.CounterOpts{Name: "broker_http_requests_total", Help: "HTTP requests"}, []string{"listener", "route", "code"})
	mAuth     = promauto.NewCounterVec(prometheus.CounterOpts{Name: "broker_federated_auth_total", Help: "Federated authentication outcomes"}, []string{"profile", "outcome"})
	mLatency  = promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "broker_http_duration_seconds", Help: "Latency", Buckets: prometheus.DefBuckets}, []string{"listener", "route"})
)

// New builds the server.
func New(cfg *Config, st *store.Store, km *keys.Manager, svc *rp.Service, au *audit.Sink, log *slog.Logger) (*Server, error) {
	t, err := template.New("").Funcs(template.FuncMap{"profileLabel": profileLabel}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{Cfg: cfg, Store: st, Keys: km, RP: svc, Audit: au, Log: log, tmpl: t}, nil
}

func profileLabel(p model.Profile) string {
	if p == model.ProfileCIE {
		return "CIE"
	}
	return "SPID"
}

// PublicHandler returns the public router.
func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", s.ready)
	mux.Handle("GET /static/", http.FileServerFS(assets))
	// Federation (RP entity)
	mux.HandleFunc("GET /rp/{profile}/.well-known/openid-federation", s.entityConfiguration)
	mux.HandleFunc("GET /rp/{profile}/resolve", s.resolveEndpoint)
	mux.HandleFunc("GET /rp/{profile}/callback", s.limit(s.callback))
	// OIDC facade for Kratos
	mux.HandleFunc("GET /oidc/{profile}/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /oidc/{profile}/jwks", s.facadeJWKS)
	mux.HandleFunc("GET /oidc/{profile}/authorize", s.limit(s.authorize))
	mux.HandleFunc("POST /oidc/{profile}/select", s.limit(s.selectProvider))
	mux.HandleFunc("POST /oidc/{profile}/token", s.limit(s.token))
	mux.HandleFunc("GET /oidc/{profile}/userinfo", s.limit(s.userinfo))
	return s.middleware("public", mux)
}

// AdminHandler returns the admin/internal router.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.Handle("GET /metrics", promhttp.Handler())
	s.registerAdmin(mux)
	s.registerInternal(mux)
	return s.middleware("admin", mux)
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) middleware(listener string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		cid := r.Header.Get("X-Correlation-Id")
		if cid == "" || len(cid) > 64 || strings.ContainsAny(cid, "\r\n") {
			cid = newID()
		}
		ctx := audit.WithCorrelationID(r.Context(), cid)
		w.Header().Set("X-Correlation-Id", cid)
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self' https: data:; frame-ancestors 'none'; base-uri 'none'") // no form-action: the IdP chooser POST redirects to external OPs
		if s.Cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
		sw := &statusWriter{ResponseWriter: w, code: 200}
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic", "err", fmt.Sprint(rec), "correlation_id", cid)
				http.Error(sw, "internal error", http.StatusInternalServerError)
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			mRequests.WithLabelValues(listener, route, fmt.Sprint(sw.code)).Inc()
			mLatency.WithLabelValues(listener, route).Observe(time.Since(start).Seconds())
			s.Log.Info("http", "listener", listener, "method", r.Method, "route", route, "status", sw.code,
				"duration_ms", time.Since(start).Milliseconds(), "correlation_id", cid)
		}()
		next.ServeHTTP(sw, r.WithContext(ctx))
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limit applies a per-IP token bucket (BROKER_RATE_LIMIT_RPS / _BURST).
func (s *Server) limit(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Cfg.RateLimitRPS <= 0 {
			h(w, r)
			return
		}
		ip := clientIP(r)
		v, _ := s.limiters.LoadOrStore(ip, rate.NewLimiter(rate.Limit(s.Cfg.RateLimitRPS), max(s.Cfg.RateLimitBurst, 1)))
		if !v.(*rate.Limiter).Allow() {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h(w, r)
	}
}

// StartJanitor purges expired state and limiter entries periodically.
func (s *Server) StartJanitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := s.Store.PurgeAttributes(ctx, time.Duration(s.Cfg.AttributeTTLSeconds)*time.Second); err != nil {
					s.Log.Error("purge attributes", "err", err)
				} else if n > 0 {
					s.Log.Info("purged attribute payloads", "count", n)
				}
				if err := s.Store.PurgeExpired(ctx, time.Duration(s.Cfg.RetentionDays)*24*time.Hour); err != nil {
					s.Log.Error("purge expired", "err", err)
				}
				s.limiters.Clear()
			}
		}
	}()
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.DB.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready"))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, code int, errCode, desc string) {
	writeJSON(w, code, map[string]string{"error": errCode, "error_description": desc})
}

func tokenEqual(a, b string) bool {
	return len(a) > 0 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) profile(r *http.Request) (*model.RPProfile, error) {
	p, err := model.ParseProfile(r.PathValue("profile"))
	if err != nil {
		return nil, err
	}
	return s.Store.GetProfile(r.Context(), p)
}

func (s *Server) profileByName(ctx context.Context) func(model.Profile) (*model.RPProfile, error) {
	return func(p model.Profile) (*model.RPProfile, error) { return s.Store.GetProfile(ctx, p) }
}

// userError renders a safe error page (no tokens, no PII, no internals).
func (s *Server) userError(w http.ResponseWriter, r *http.Request, code int, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = s.tmpl.ExecuteTemplate(w, "error.html", map[string]any{
		"Reason": reason, "Message": userMessage(reason), "CorrelationID": audit.CorrelationID(r.Context()),
	})
}

func userMessage(reason string) string {
	switch reason {
	case rp.FailCancelled:
		return "Autenticazione annullata. / Authentication was cancelled."
	case rp.FailExpired, rp.FailReplay:
		return "La sessione di autenticazione è scaduta o non è valida. Riprova. / The authentication session expired or is invalid. Please try again."
	case rp.FailOPUnavailable:
		return "Il gestore dell'identità non è al momento disponibile. / The identity provider is currently unavailable."
	case rp.FailInsufficientLoA:
		return "Il livello di sicurezza dell'autenticazione non è sufficiente. / The authentication assurance level is insufficient."
	case rp.FailMissingAttribute:
		return "Il gestore dell'identità non ha fornito i dati necessari. / The identity provider did not release the required attributes."
	case rp.FailUntrusted:
		return "Impossibile verificare l'affidabilità del gestore dell'identità. / The identity provider could not be trusted."
	default:
		return "Si è verificato un errore durante l'autenticazione. / An authentication error occurred."
	}
}

var errUnauthorized = errors.New("unauthorized")
