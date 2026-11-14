// Package rp implements the SPID/CIE OpenID Connect Federation Relying Party:
// entity configuration, signed authorization requests, private_key_jwt token
// requests, ID token / encrypted UserInfo validation and attribute
// normalisation.
package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/enpam/iam/federation-broker/internal/fedjose"
	"github.com/enpam/iam/federation-broker/internal/model"
	"github.com/enpam/iam/federation-broker/internal/oidcfed"
	"github.com/enpam/iam/federation-broker/internal/safehttp"
	"github.com/enpam/iam/federation-broker/internal/store"
)

// AllowedSigAlgs is the JWS allow-list from the SPID/CIE crypto profile
// (cryptographic_algos.rst): RS256/RS512 mandatory, ES256/ES512/PS256/PS512
// recommended; none, HS* forbidden.
var AllowedSigAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.RS512, jose.ES256, jose.ES512, jose.PS256, jose.PS512}

// OPMetadata is the validated (trust-chain derived) OP metadata.
type OPMetadata struct {
	EntityID              string
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
	RevocationEndpoint    string
	JWKS                  jose.JSONWebKeySet
	ACRValuesSupported    []string
	IDTokenAlgs           []jose.SignatureAlgorithm
	Chain                 *oidcfed.TrustChain
}

// Resolvers keeps one trust-chain resolver per profile, rebuilt when trust
// anchors change.
type Resolvers struct {
	Store   *store.Store
	HTTP    *safehttp.Client
	mu      sync.Mutex
	byProf  map[model.Profile]*oidcfed.Resolver
	Options ResolverOptions
}

// ResolverOptions tunes resolution.
type ResolverOptions struct {
	MaxDepth int
	CacheTTL int // seconds
}

type httpFetcher struct{ c *safehttp.Client }

func (f httpFetcher) Get(ctx context.Context, url, accept string) ([]byte, string, error) {
	return f.c.Get(ctx, url, accept)
}

// For returns the resolver for a profile.
func (r *Resolvers) For(ctx context.Context, p model.Profile) (*oidcfed.Resolver, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if res, ok := r.byProf[p]; ok {
		return res, nil
	}
	tas, err := r.Store.ListTrustAnchors(ctx, p, true)
	if err != nil {
		return nil, err
	}
	anchors := make([]oidcfed.TrustAnchor, 0, len(tas))
	for _, ta := range tas {
		anchors = append(anchors, oidcfed.TrustAnchor{EntityID: ta.EntityID, JWKS: ta.JWKS})
	}
	res := &oidcfed.Resolver{
		Fetcher: httpFetcher{r.HTTP}, Anchors: anchors, Algs: AllowedSigAlgs,
		MaxDepth: r.Options.MaxDepth, MaxAuthorityHints: 5, Skew: 30e9,
	}
	if r.Options.CacheTTL > 0 {
		res.CacheTTL = secondsDur(r.Options.CacheTTL)
	}
	if r.byProf == nil {
		r.byProf = map[model.Profile]*oidcfed.Resolver{}
	}
	r.byProf[p] = res
	return res, nil
}

// Reset drops all resolvers (after trust anchor changes / manual refresh).
func (r *Resolvers) Reset() {
	r.mu.Lock()
	r.byProf = nil
	r.mu.Unlock()
}

// ResolveOP resolves and validates an OpenID Provider.
func (s *Service) ResolveOP(ctx context.Context, p model.Profile, cfg *model.RPProfile, entityID string) (*OPMetadata, error) {
	res, err := s.Resolvers.For(ctx, p)
	if err != nil {
		return nil, err
	}
	chain, err := res.Resolve(ctx, entityID, oidcfed.EntityTypeOP)
	if err != nil {
		return nil, err
	}
	if cfg.RequireOPTrustMark != "" && !chain.HasTrustMark(cfg.RequireOPTrustMark) {
		return nil, fmt.Errorf("%w: OP lacks required trust mark %s", oidcfed.ErrUntrusted, cfg.RequireOPTrustMark)
	}
	md := chain.Metadata[oidcfed.EntityTypeOP]
	op := &OPMetadata{EntityID: entityID, Chain: chain}
	op.Issuer = oidcfed.StringMeta(md, "issuer")
	op.AuthorizationEndpoint = oidcfed.StringMeta(md, "authorization_endpoint")
	op.TokenEndpoint = oidcfed.StringMeta(md, "token_endpoint")
	op.UserinfoEndpoint = oidcfed.StringMeta(md, "userinfo_endpoint")
	op.RevocationEndpoint = oidcfed.StringMeta(md, "revocation_endpoint")
	if op.Issuer == "" || op.AuthorizationEndpoint == "" || op.TokenEndpoint == "" || op.UserinfoEndpoint == "" {
		return nil, errors.New("OP metadata lacks issuer or required endpoints")
	}
	if op.Issuer != entityID {
		return nil, errors.New("OP issuer must equal its entity identifier")
	}
	for _, ep := range []string{op.AuthorizationEndpoint, op.TokenEndpoint, op.UserinfoEndpoint} {
		if err := oidcfed.ValidateEntityID(strings.SplitN(ep, "?", 2)[0]); err != nil {
			return nil, fmt.Errorf("invalid OP endpoint: %w", err)
		}
	}
	op.ACRValuesSupported = stringList(md["acr_values_supported"])
	switch {
	case md["jwks"] != nil:
		raw, _ := json.Marshal(md["jwks"])
		if err := json.Unmarshal(raw, &op.JWKS); err != nil {
			return nil, fmt.Errorf("OP jwks: %w", err)
		}
	case oidcfed.StringMeta(md, "signed_jwks_uri") != "":
		body, _, err := s.HTTP.Get(ctx, oidcfed.StringMeta(md, "signed_jwks_uri"), "application/jwk-set+jwt")
		if err != nil {
			return nil, fmt.Errorf("signed_jwks_uri: %w", err)
		}
		v, err := fedjose.Verify(strings.TrimSpace(string(body)), chain.Leaf().JWKS, fedjose.VerifyOptions{AllowedAlgs: AllowedSigAlgs, ExpectedTyp: "jwk-set+jwt"})
		if err != nil {
			return nil, fmt.Errorf("signed_jwks_uri: %w", err)
		}
		if err := json.Unmarshal(v.Payload, &op.JWKS); err != nil {
			return nil, err
		}
	default:
		// Plain jwks_uri is not accepted: keys must be bound to the trust chain.
		return nil, errors.New("OP metadata has neither jwks nor signed_jwks_uri")
	}
	if len(op.JWKS.Keys) == 0 {
		return nil, errors.New("OP publishes no keys")
	}
	op.IDTokenAlgs = intersectAlgs(AllowedSigAlgs, stringList(md["id_token_signing_alg_values_supported"]))
	if len(op.IDTokenAlgs) == 0 {
		return nil, errors.New("no acceptable id_token signing algorithm")
	}
	return op, nil
}

func stringList(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = t
	case string:
		out = []string{t}
	}
	return out
}

func intersectAlgs(allowed []jose.SignatureAlgorithm, offered []string) []jose.SignatureAlgorithm {
	if len(offered) == 0 {
		return allowed
	}
	var out []jose.SignatureAlgorithm
	for _, a := range allowed {
		for _, o := range offered {
			if string(a) == o {
				out = append(out, a)
			}
		}
	}
	return out
}
