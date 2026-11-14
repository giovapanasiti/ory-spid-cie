// Package oidcfed implements the OpenID Federation 1.0 mechanisms required by
// the Italian SPID/CIE OIDC Federation profile: Entity Configurations,
// Subordinate Statements, trust chain resolution and validation, metadata
// policy application and Trust Mark validation.
package oidcfed

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/enpam/iam/federation-broker/internal/fedjose"
)

// Entity type identifiers used in "metadata".
const (
	EntityTypeFederation   = "federation_entity"
	EntityTypeOP           = "openid_provider"
	EntityTypeRP           = "openid_relying_party"
	WellKnownPath          = "/.well-known/openid-federation"
	ContentTypeEntityStmt  = "application/entity-statement+jwt"
	ContentTypeTrustMark   = "application/trust-mark+jwt"
	ContentTypeResolveResp = "application/resolve-response+jwt"
)

// TrustMarkRef is an entry in the "trust_marks" claim.
type TrustMarkRef struct {
	ID            string `json:"id,omitempty"`
	TrustMarkType string `json:"trust_mark_type,omitempty"` // newer drafts renamed id -> trust_mark_type
	TrustMark     string `json:"trust_mark"`
}

// Type returns the trust mark identifier regardless of draft naming.
func (t TrustMarkRef) Type() string {
	if t.TrustMarkType != "" {
		return t.TrustMarkType
	}
	return t.ID
}

// Constraints restricts trust chains below an authority.
type Constraints struct {
	MaxPathLength *int `json:"max_path_length,omitempty"`
}

// EntityStatement is the payload of an Entity Configuration or Subordinate Statement.
type EntityStatement struct {
	Iss                string                               `json:"iss"`
	Sub                string                               `json:"sub"`
	Iat                int64                                `json:"iat"`
	Exp                int64                                `json:"exp"`
	JWKS               jose.JSONWebKeySet                   `json:"jwks"`
	AuthorityHints     []string                             `json:"authority_hints,omitempty"`
	Metadata           map[string]map[string]any            `json:"metadata,omitempty"`
	MetadataPolicy     map[string]map[string]map[string]any `json:"metadata_policy,omitempty"`
	TrustMarks         []TrustMarkRef                       `json:"trust_marks,omitempty"`
	TrustMarkIssuers   map[string][]string                  `json:"trust_mark_issuers,omitempty"`
	TrustMarkOwners    map[string]any                       `json:"trust_mark_owners,omitempty"`
	Constraints        *Constraints                         `json:"constraints,omitempty"`
	Crit               []string                             `json:"crit,omitempty"`
	MetadataPolicyCrit []string                             `json:"metadata_policy_crit,omitempty"`

	// Raw is the original compact JWS (not serialised).
	Raw string `json:"-"`
}

// IsSelfSigned reports whether this is an Entity Configuration.
func (e *EntityStatement) IsSelfSigned() bool { return e.Iss == e.Sub }

// FederationEntity returns the federation_entity metadata.
func (e *EntityStatement) FederationEntity() map[string]any {
	if e.Metadata == nil {
		return nil
	}
	return e.Metadata[EntityTypeFederation]
}

// StringMeta returns a string metadata value.
func StringMeta(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}

// supportedCrit lists the "crit" claims understood by this implementation.
var supportedCrit = map[string]bool{}

// ParseAndVerify verifies a statement JWS with the given keys and decodes it.
// It performs the structural checks common to every entity statement.
func ParseAndVerify(raw string, keys jose.JSONWebKeySet, algs []jose.SignatureAlgorithm, now time.Time, skew time.Duration) (*EntityStatement, error) {
	v, err := fedjose.Verify(raw, keys, fedjose.VerifyOptions{AllowedAlgs: algs, ExpectedTyp: fedjose.TypEntityStatement})
	if err != nil {
		return nil, err
	}
	var es EntityStatement
	if err := json.Unmarshal(v.Payload, &es); err != nil {
		return nil, fmt.Errorf("decode entity statement: %w", err)
	}
	es.Raw = raw
	if err := es.validateClaims(now, skew); err != nil {
		return nil, err
	}
	return &es, nil
}

func (e *EntityStatement) validateClaims(now time.Time, skew time.Duration) error {
	if err := ValidateEntityID(e.Iss); err != nil {
		return fmt.Errorf("iss: %w", err)
	}
	if err := ValidateEntityID(e.Sub); err != nil {
		return fmt.Errorf("sub: %w", err)
	}
	if e.Iat == 0 || e.Exp == 0 {
		return errors.New("iat and exp are required")
	}
	if time.Unix(e.Iat, 0).After(now.Add(skew)) {
		return errors.New("statement issued in the future")
	}
	if !time.Unix(e.Exp, 0).After(now.Add(-skew)) {
		return errors.New("statement expired")
	}
	if len(e.JWKS.Keys) == 0 {
		return errors.New("jwks is required")
	}
	for _, k := range e.JWKS.Keys {
		if !k.IsPublic() {
			return errors.New("jwks contains private key material")
		}
	}
	for _, c := range e.Crit {
		if !supportedCrit[c] {
			return fmt.Errorf("unsupported critical claim %q", c)
		}
	}
	for _, c := range e.MetadataPolicyCrit {
		if !supportedOperators[c] {
			return fmt.Errorf("unsupported critical metadata policy operator %q", c)
		}
	}
	return nil
}

// ValidateEntityID checks that an entity identifier is an absolute https (or
// http, for tests) URL without query or fragment.
func ValidateEntityID(id string) error {
	u, err := url.Parse(id)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("entity id %q must be an https URL", id)
	}
	if u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("invalid entity id %q", id)
	}
	return nil
}

// WellKnownURL returns the entity configuration URL for an entity id.
func WellKnownURL(entityID string) string {
	return strings.TrimRight(entityID, "/") + WellKnownPath
}

// FetchURL builds a fetch endpoint request URL for sub.
func FetchURL(endpoint, sub string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("sub", sub)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Sign serialises and signs the statement as an entity-statement+jwt.
func (e *EntityStatement) Sign(k fedjose.SigningKey) (string, error) {
	return fedjose.Sign(e, k, fedjose.TypEntityStatement)
}

// TrustMarkTyp is exported for issuers.
const TrustMarkTyp = fedjose.TypTrustMark
