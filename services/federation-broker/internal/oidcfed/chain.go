package oidcfed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/enpam/iam/federation-broker/internal/fedjose"
)

// Fetcher retrieves federation documents over HTTP (SSRF-hardened in prod).
type Fetcher interface {
	Get(ctx context.Context, url, accept string) ([]byte, string, error)
}

// TrustAnchor is a pinned federation root. Its keys are obtained out of band
// (federation onboarding) and are never learnt from the network.
type TrustAnchor struct {
	EntityID string             `json:"entity_id"`
	JWKS     jose.JSONWebKeySet `json:"jwks"`
}

// VerifiedTrustMark is a trust mark that passed validation.
type VerifiedTrustMark struct {
	Type   string `json:"id"`
	Issuer string `json:"iss"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp,omitempty"`
}

// TrustChain is a validated chain from a leaf entity to a Trust Anchor.
type TrustChain struct {
	Subject    string                    `json:"subject"`
	Anchor     string                    `json:"trust_anchor"`
	Statements []*EntityStatement        `json:"-"`
	Raw        []string                  `json:"-"`
	Path       []string                  `json:"path"`
	Exp        time.Time                 `json:"exp"`
	Metadata   map[string]map[string]any `json:"metadata"`
	TrustMarks []VerifiedTrustMark       `json:"trust_marks"`
	// TrustMarkErrors lists trust marks that were present but rejected.
	TrustMarkErrors []string  `json:"trust_mark_errors,omitempty"`
	ResolvedAt      time.Time `json:"resolved_at"`
}

// Leaf returns the leaf entity configuration.
func (c *TrustChain) Leaf() *EntityStatement { return c.Statements[0] }

// HasTrustMark reports whether a verified trust mark of the type is present.
func (c *TrustChain) HasTrustMark(typ string) bool {
	for _, t := range c.TrustMarks {
		if t.Type == typ {
			return true
		}
	}
	return false
}

// Resolver builds and validates trust chains bottom-up.
type Resolver struct {
	Fetcher           Fetcher
	Anchors           []TrustAnchor
	Algs              []jose.SignatureAlgorithm
	MaxDepth          int
	MaxAuthorityHints int
	Skew              time.Duration
	CacheTTL          time.Duration
	Now               func() time.Time

	mu    sync.Mutex
	cache map[string]*TrustChain
}

// ErrUntrusted is wrapped by every trust establishment failure.
var ErrUntrusted = errors.New("federation trust could not be established")

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) maxDepth() int {
	if r.MaxDepth > 0 {
		return r.MaxDepth
	}
	return 5
}

func (r *Resolver) anchor(id string) *TrustAnchor {
	for i := range r.Anchors {
		if r.Anchors[i].EntityID == id {
			return &r.Anchors[i]
		}
	}
	return nil
}

// Invalidate drops cached chains (all when entityID is empty).
func (r *Resolver) Invalidate(entityID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entityID == "" {
		r.cache = nil
		return
	}
	for k := range r.cache {
		if strings.HasPrefix(k, entityID+"|") {
			delete(r.cache, k)
		}
	}
}

// Resolve returns a validated trust chain for entityID with the final
// metadata for entityType (policies applied). It fails closed.
func (r *Resolver) Resolve(ctx context.Context, entityID, entityType string) (*TrustChain, error) {
	key := entityID + "|" + entityType
	r.mu.Lock()
	if c, ok := r.cache[key]; ok && r.now().Before(c.Exp) && (r.CacheTTL == 0 || r.now().Sub(c.ResolvedAt) < r.CacheTTL) {
		r.mu.Unlock()
		return c, nil
	}
	r.mu.Unlock()

	c, err := r.resolve(ctx, entityID, entityType, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]*TrustChain{}
	}
	r.cache[key] = c
	r.mu.Unlock()
	return c, nil
}

func (r *Resolver) resolve(ctx context.Context, entityID, entityType string, tmDepth int) (*TrustChain, error) {
	if len(r.Anchors) == 0 {
		return nil, errors.New("no trust anchors configured")
	}
	leaf, err := r.FetchEntityConfiguration(ctx, entityID)
	if err != nil {
		return nil, err
	}
	var up []*EntityStatement
	if ta := r.anchor(entityID); ta != nil {
		// The subject is itself a trust anchor: verify with pinned keys.
		if _, err := ParseAndVerify(leaf.Raw, ta.JWKS, r.Algs, r.now(), r.Skew); err != nil {
			return nil, fmt.Errorf("trust anchor %s: %w", entityID, err)
		}
	} else {
		if len(leaf.AuthorityHints) == 0 {
			return nil, fmt.Errorf("%s has no authority_hints", entityID)
		}
		var errs []string
		for i, hint := range leaf.AuthorityHints {
			if r.MaxAuthorityHints > 0 && i >= r.MaxAuthorityHints {
				break
			}
			up, err = r.buildUp(ctx, leaf, hint, 1, map[string]bool{entityID: true})
			if err == nil {
				break
			}
			errs = append(errs, fmt.Sprintf("%s: %v", hint, err))
		}
		if up == nil {
			return nil, fmt.Errorf("no valid path to a trust anchor (%s)", strings.Join(errs, "; "))
		}
	}
	stmts := append([]*EntityStatement{leaf}, up...)
	chain := &TrustChain{Subject: entityID, Statements: stmts, ResolvedAt: r.now()}
	chain.Anchor = stmts[len(stmts)-1].Iss
	exp := time.Unix(leaf.Exp, 0)
	for _, s := range stmts {
		chain.Raw = append(chain.Raw, s.Raw)
		chain.Path = append(chain.Path, s.Iss)
		if t := time.Unix(s.Exp, 0); t.Before(exp) {
			exp = t
		}
	}
	chain.Exp = exp
	if err := checkConstraints(stmts); err != nil {
		return nil, err
	}
	md, err := finalMetadata(stmts, entityType)
	if err != nil {
		return nil, err
	}
	chain.Metadata = map[string]map[string]any{entityType: md}
	if fe := leaf.FederationEntity(); fe != nil {
		chain.Metadata[EntityTypeFederation] = fe
	}
	if tmDepth == 0 {
		r.verifyTrustMarks(ctx, chain)
	}
	return chain, nil
}

// buildUp validates subject -> authority and continues towards an anchor.
func (r *Resolver) buildUp(ctx context.Context, subject *EntityStatement, authorityID string, depth int, visited map[string]bool) ([]*EntityStatement, error) {
	if depth > r.maxDepth() {
		return nil, errors.New("maximum chain depth exceeded")
	}
	if visited[authorityID] {
		return nil, errors.New("loop in authority_hints")
	}
	visited[authorityID] = true
	if err := ValidateEntityID(authorityID); err != nil {
		return nil, err
	}
	authEC, err := r.FetchEntityConfiguration(ctx, authorityID)
	if err != nil {
		return nil, err
	}
	authKeys := authEC.JWKS
	ta := r.anchor(authorityID)
	if ta != nil {
		if _, err := ParseAndVerify(authEC.Raw, ta.JWKS, r.Algs, r.now(), r.Skew); err != nil {
			return nil, fmt.Errorf("trust anchor configuration not signed by pinned keys: %w", err)
		}
		authKeys = ta.JWKS
	}
	fetchEndpoint := StringMeta(authEC.FederationEntity(), "federation_fetch_endpoint")
	if fetchEndpoint == "" {
		return nil, fmt.Errorf("%s exposes no federation_fetch_endpoint", authorityID)
	}
	u, err := FetchURL(fetchEndpoint, subject.Sub)
	if err != nil {
		return nil, err
	}
	body, _, err := r.Fetcher.Get(ctx, u, ContentTypeEntityStmt)
	if err != nil {
		return nil, fmt.Errorf("fetch subordinate statement: %w", err)
	}
	stmt, err := ParseAndVerify(strings.TrimSpace(string(body)), authKeys, r.Algs, r.now(), r.Skew)
	if err != nil {
		return nil, fmt.Errorf("subordinate statement from %s: %w", authorityID, err)
	}
	if stmt.Iss != authorityID || stmt.Sub != subject.Sub {
		return nil, errors.New("subordinate statement iss/sub mismatch")
	}
	if stmt.IsSelfSigned() {
		return nil, errors.New("subordinate statement must not be self-signed")
	}
	// The superior attests the subject's federation keys: the subject's
	// configuration must verify with them.
	if _, err := ParseAndVerify(subject.Raw, stmt.JWKS, r.Algs, r.now(), r.Skew); err != nil {
		return nil, fmt.Errorf("entity configuration of %s not signed with keys attested by %s: %w", subject.Sub, authorityID, err)
	}
	if ta != nil {
		return []*EntityStatement{stmt, authEC}, nil
	}
	if len(authEC.AuthorityHints) == 0 {
		return nil, fmt.Errorf("%s is not a trust anchor and has no authority_hints", authorityID)
	}
	var errs []string
	for i, hint := range authEC.AuthorityHints {
		if r.MaxAuthorityHints > 0 && i >= r.MaxAuthorityHints {
			break
		}
		rest, err := r.buildUp(ctx, authEC, hint, depth+1, visited)
		if err == nil {
			return append([]*EntityStatement{stmt}, rest...), nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", hint, err))
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

// FetchEntityConfiguration fetches and self-verifies an entity configuration.
func (r *Resolver) FetchEntityConfiguration(ctx context.Context, entityID string) (*EntityStatement, error) {
	if err := ValidateEntityID(entityID); err != nil {
		return nil, err
	}
	body, _, err := r.Fetcher.Get(ctx, WellKnownURL(entityID), ContentTypeEntityStmt)
	if err != nil {
		return nil, fmt.Errorf("fetch entity configuration %s: %w", entityID, err)
	}
	raw := strings.TrimSpace(string(body))
	var peek EntityStatement
	if err := fedjose.UnverifiedClaims(raw, &peek); err != nil {
		return nil, fmt.Errorf("decode entity configuration: %w", err)
	}
	ec, err := ParseAndVerify(raw, peek.JWKS, r.Algs, r.now(), r.Skew)
	if err != nil {
		return nil, fmt.Errorf("entity configuration %s: %w", entityID, err)
	}
	if ec.Iss != entityID || ec.Sub != entityID {
		return nil, fmt.Errorf("entity configuration iss/sub must equal %s", entityID)
	}
	return ec, nil
}

func checkConstraints(stmts []*EntityStatement) error {
	// stmts: [leaf EC, sub(leaf), sub(I1), ..., TA EC]. For a subordinate
	// statement at index i, the number of intermediates between it and the
	// leaf is i-1.
	for i := 1; i < len(stmts)-1; i++ {
		c := stmts[i].Constraints
		if c != nil && c.MaxPathLength != nil && i-1 > *c.MaxPathLength {
			return fmt.Errorf("max_path_length constraint of %s violated", stmts[i].Iss)
		}
	}
	return nil
}

// finalMetadata applies superior metadata overrides and merged policies
// (top-down) to the leaf metadata of entityType.
func finalMetadata(stmts []*EntityStatement, entityType string) (map[string]any, error) {
	leaf := stmts[0]
	md := map[string]any{}
	if m, ok := leaf.Metadata[entityType]; ok {
		for k, v := range m {
			md[k] = v
		}
	} else {
		return nil, fmt.Errorf("entity %s has no %s metadata", leaf.Sub, entityType)
	}
	policy := Policy{}
	// Subordinate statements are stmts[1 : len-1]; walk them from the anchor down.
	for i := len(stmts) - 2; i >= 1; i-- {
		s := stmts[i]
		if s.MetadataPolicy != nil {
			if p, ok := s.MetadataPolicy[entityType]; ok {
				merged, err := MergePolicies(policy, Policy(p))
				if err != nil {
					return nil, err
				}
				policy = merged
			}
		}
	}
	for i := 1; i < len(stmts)-1; i++ {
		if over, ok := stmts[i].Metadata[entityType]; ok {
			for k, v := range over {
				md[k] = v
			}
		}
	}
	return ApplyPolicy(md, policy)
}

// TrustMarkClaims is the payload of a trust mark JWT.
type TrustMarkClaims struct {
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	ID            string `json:"id,omitempty"`
	TrustMarkType string `json:"trust_mark_type,omitempty"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp,omitempty"`
	LogoURI       string `json:"logo_uri,omitempty"`
	Ref           string `json:"ref,omitempty"`
}

func (t TrustMarkClaims) Type() string {
	if t.TrustMarkType != "" {
		return t.TrustMarkType
	}
	return t.ID
}

func (r *Resolver) verifyTrustMarks(ctx context.Context, chain *TrustChain) {
	leaf := chain.Leaf()
	taEC := chain.Statements[len(chain.Statements)-1]
	for _, ref := range leaf.TrustMarks {
		tm, err := r.VerifyTrustMark(ctx, ref.TrustMark, leaf.Sub, taEC)
		if err != nil {
			chain.TrustMarkErrors = append(chain.TrustMarkErrors, fmt.Sprintf("%s: %v", ref.Type(), err))
			continue
		}
		if ref.Type() != "" && ref.Type() != tm.Type {
			chain.TrustMarkErrors = append(chain.TrustMarkErrors, fmt.Sprintf("%s: id mismatch", ref.Type()))
			continue
		}
		chain.TrustMarks = append(chain.TrustMarks, *tm)
	}
}

// VerifyTrustMark validates a trust mark for subject under trust anchor taEC.
func (r *Resolver) VerifyTrustMark(ctx context.Context, raw, subject string, taEC *EntityStatement) (*VerifiedTrustMark, error) {
	var peek TrustMarkClaims
	if err := fedjose.UnverifiedClaims(raw, &peek); err != nil {
		return nil, err
	}
	var keys jose.JSONWebKeySet
	switch {
	case peek.Iss == taEC.Sub:
		ta := r.anchor(taEC.Sub)
		if ta == nil {
			return nil, errors.New("trust anchor not configured")
		}
		keys = ta.JWKS
	default:
		allowed := false
		for _, iss := range taEC.TrustMarkIssuers[peek.Type()] {
			if iss == peek.Iss {
				allowed = true
			}
		}
		if !allowed {
			return nil, fmt.Errorf("issuer %s not authorised by trust anchor for %s", peek.Iss, peek.Type())
		}
		issuerChain, err := r.resolve(ctx, peek.Iss, EntityTypeFederation, 1)
		if err != nil {
			return nil, fmt.Errorf("trust mark issuer: %w", err)
		}
		if issuerChain.Anchor != taEC.Sub {
			return nil, errors.New("trust mark issuer chains to a different anchor")
		}
		keys = issuerChain.Leaf().JWKS
	}
	v, err := fedjose.Verify(raw, keys, fedjose.VerifyOptions{AllowedAlgs: r.Algs, ExpectedTyp: fedjose.TypTrustMark})
	if err != nil {
		return nil, err
	}
	var c TrustMarkClaims
	if err := json.Unmarshal(v.Payload, &c); err != nil {
		return nil, err
	}
	if c.Sub != subject {
		return nil, errors.New("trust mark subject mismatch")
	}
	if c.Type() == "" || c.Iat == 0 {
		return nil, errors.New("trust mark missing id or iat")
	}
	now := r.now()
	if time.Unix(c.Iat, 0).After(now.Add(r.Skew)) {
		return nil, errors.New("trust mark issued in the future")
	}
	if c.Exp != 0 && !time.Unix(c.Exp, 0).After(now.Add(-r.Skew)) {
		return nil, errors.New("trust mark expired")
	}
	return &VerifiedTrustMark{Type: c.Type(), Issuer: c.Iss, Iat: c.Iat, Exp: c.Exp}, nil
}
