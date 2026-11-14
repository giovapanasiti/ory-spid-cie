package server

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is read from environment variables (documented in .env.example and
// docs/deployment/docker.md).
type Config struct {
	Env                  string // development | production
	Listen               string
	AdminListen          string
	PublicURL            string // browser-facing base URL
	InternalURL          string // base URL used by Kratos (server-to-server)
	DatabaseURL          string
	SealKeys             string
	AdminToken           string
	InternalToken        string
	FacadeClientID       string
	FacadeClientSecret   string
	FacadeRedirectURIs   []string
	AllowInsecureHTTP    bool
	AllowPrivateNetworks bool
	OutboundAllowlist    []string
	AuditURL             string
	AuditToken           string
	BootstrapFile        string
	CookieSecure         bool
	AutogenerateKeys     bool
	AttributeTTLSeconds  int
	RetentionDays        int
	RateLimitRPS         int
	RateLimitBurst       int
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v, ok := os.LookupEnv(k)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(k string, def int) int {
	v, err := strconv.Atoi(env(k, ""))
	if err != nil {
		return def
	}
	return v
}

func list(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// LoadConfig reads and validates configuration.
func LoadConfig() (*Config, error) {
	c := &Config{
		Env:                  env("BROKER_ENV", "production"),
		Listen:               env("BROKER_LISTEN", ":8090"),
		AdminListen:          env("BROKER_ADMIN_LISTEN", ":8091"),
		PublicURL:            strings.TrimRight(env("BROKER_PUBLIC_URL", ""), "/"),
		InternalURL:          strings.TrimRight(env("BROKER_INTERNAL_URL", ""), "/"),
		DatabaseURL:          env("BROKER_DATABASE_URL", ""),
		SealKeys:             env("BROKER_SEAL_KEYS", ""),
		AdminToken:           env("BROKER_ADMIN_TOKEN", ""),
		InternalToken:        env("BROKER_INTERNAL_TOKEN", ""),
		FacadeClientID:       env("BROKER_FACADE_CLIENT_ID", "kratos"),
		FacadeClientSecret:   env("BROKER_FACADE_CLIENT_SECRET", ""),
		FacadeRedirectURIs:   list(env("BROKER_FACADE_REDIRECT_URIS", "")),
		AllowInsecureHTTP:    envBool("BROKER_ALLOW_INSECURE_HTTP", false),
		AllowPrivateNetworks: envBool("BROKER_ALLOW_PRIVATE_NETWORKS", false),
		OutboundAllowlist:    list(env("BROKER_OUTBOUND_HOST_ALLOWLIST", "")),
		AuditURL:             env("AUDIT_URL", ""),
		AuditToken:           env("AUDIT_TOKEN", ""),
		BootstrapFile:        env("BROKER_BOOTSTRAP_FILE", ""),
		CookieSecure:         envBool("BROKER_COOKIE_SECURE", true),
		AutogenerateKeys:     envBool("BROKER_AUTOGENERATE_KEYS", true),
		AttributeTTLSeconds:  envInt("BROKER_ATTRIBUTE_TTL_SECONDS", 900),
		RetentionDays:        envInt("BROKER_RETENTION_DAYS", 30),
		RateLimitRPS:         envInt("BROKER_RATE_LIMIT_RPS", 20),
		RateLimitBurst:       envInt("BROKER_RATE_LIMIT_BURST", 40),
	}
	if c.InternalURL == "" {
		c.InternalURL = c.PublicURL
	}
	var errs []string
	req := map[string]string{
		"BROKER_PUBLIC_URL": c.PublicURL, "BROKER_DATABASE_URL": c.DatabaseURL, "BROKER_SEAL_KEYS": c.SealKeys,
		"BROKER_ADMIN_TOKEN": c.AdminToken, "BROKER_INTERNAL_TOKEN": c.InternalToken, "BROKER_FACADE_CLIENT_SECRET": c.FacadeClientSecret,
	}
	for k, v := range req {
		if v == "" {
			errs = append(errs, k+" is required")
		}
	}
	for _, t := range []struct{ n, v string }{{"BROKER_ADMIN_TOKEN", c.AdminToken}, {"BROKER_INTERNAL_TOKEN", c.InternalToken}, {"BROKER_FACADE_CLIENT_SECRET", c.FacadeClientSecret}} {
		if t.v != "" && len(t.v) < 32 {
			errs = append(errs, t.n+" must be at least 32 characters")
		}
	}
	if len(c.FacadeRedirectURIs) == 0 {
		errs = append(errs, "BROKER_FACADE_REDIRECT_URIS is required")
	}
	if c.Env == "production" {
		if c.AllowInsecureHTTP || c.AllowPrivateNetworks {
			errs = append(errs, "insecure outbound settings are not allowed in production")
		}
		if !strings.HasPrefix(c.PublicURL, "https://") {
			errs = append(errs, "BROKER_PUBLIC_URL must be https in production")
		}
		if !c.CookieSecure {
			errs = append(errs, "BROKER_COOKIE_SECURE must be true in production")
		}
	} else if c.Env != "development" {
		errs = append(errs, fmt.Sprintf("BROKER_ENV must be development or production, got %q", c.Env))
	}
	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return c, nil
}
