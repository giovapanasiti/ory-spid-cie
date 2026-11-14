// Package model defines the federation configuration model managed through
// the admin API / admin console and persisted in PostgreSQL.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Profile identifies a federation profile.
type Profile string

const (
	ProfileSPID   Profile = "spid"
	ProfileCIE    Profile = "cie"
	ProfileFacade Profile = "facade"
)

// ParseProfile validates a federation profile name.
func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileSPID, ProfileCIE:
		return Profile(s), nil
	}
	return "", fmt.Errorf("unknown profile %q", s)
}

// Internal levels of assurance (identity proofing + authentication),
// aligned with eIDAS low / substantial / high. "none" = local unverified.
const (
	LoANone        = "urn:iam:loa:none"
	LoALow         = "urn:iam:loa:low"
	LoASubstantial = "urn:iam:loa:substantial"
	LoAHigh        = "urn:iam:loa:high"
)

// LoARank orders internal levels; unknown values rank -1.
func LoARank(l string) int {
	switch l {
	case LoANone:
		return 0
	case LoALow:
		return 1
	case LoASubstantial:
		return 2
	case LoAHigh:
		return 3
	}
	return -1
}

// SPID ACR values (Linee Guida OIDC SPID; listed for SPID and CIE OPs in the
// SPID/CIE OIDC docs v1.2.1, authorization_endpoint.rst / metadata_oidc_op.rst).
const (
	ACRSpidL1 = "https://www.spid.gov.it/SpidL1"
	ACRSpidL2 = "https://www.spid.gov.it/SpidL2"
	ACRSpidL3 = "https://www.spid.gov.it/SpidL3"
)

// Attribute claim names (SPID/CIE OIDC docs v1.2.1, attributi_utente.rst).
const (
	AttrPrefix        = "https://attributes.eid.gov.it/"
	AttrLegacyPrefix  = "https://attributes.spid.gov.it/"
	ClaimFiscalNumber = AttrPrefix + "fiscal_number"
)

// ACRMapping maps one federation ACR value to an internal LoA.
type ACRMapping struct {
	ACR string `json:"acr"`
	LoA string `json:"loa"`
}

// RPProfile is the Relying Party configuration for one federation.
type RPProfile struct {
	Profile          Profile        `json:"profile"`
	Enabled          bool           `json:"enabled"`
	Environment      string         `json:"environment"` // "local", "test", "production"
	EntityID         string         `json:"entity_id"`
	OrganizationName string         `json:"organization_name"`
	HomepageURI      string         `json:"homepage_uri"`
	PolicyURI        string         `json:"policy_uri"`
	LogoURI          string         `json:"logo_uri"`
	Contacts         []string       `json:"contacts"`
	ClientName       string         `json:"client_name"`
	RedirectURIs     []string       `json:"redirect_uris"`
	AuthorityHints   []string       `json:"authority_hints"`
	TrustMarks       []TrustMarkRef `json:"trust_marks"`
	// Scopes requested at the OP ("openid" is always included).
	Scopes []string `json:"scopes"`
	// RequestedClaims is the OIDC "claims" request parameter.
	RequestedClaims json.RawMessage `json:"requested_claims"`
	// RequiredAttributes must be present in UserInfo or the login fails.
	RequiredAttributes []string `json:"required_attributes"`
	// ACRMap maps OP ACR values to internal LoA (ordered low -> high).
	ACRMap []ACRMapping `json:"acr_map"`
	// DefaultLoA is requested when the caller requests nothing.
	DefaultLoA          string `json:"default_loa"`
	SigningAlg          string `json:"signing_alg"`
	UserinfoEncAlg      string `json:"userinfo_encrypted_response_alg"`
	UserinfoEncEnc      string `json:"userinfo_encrypted_response_enc"`
	EntityConfigTTL     int    `json:"entity_configuration_ttl_seconds"`
	RequireOPTrustMark  string `json:"require_op_trust_mark,omitempty"`
	ClockSkewSeconds    int    `json:"clock_skew_seconds"`
	MaxIDTokenAgeSecond int    `json:"max_id_token_age_seconds"`
	UILocales           string `json:"ui_locales"`
}

// TrustMarkRef is a trust mark obtained from the federation authority.
type TrustMarkRef struct {
	ID        string `json:"id"`
	TrustMark string `json:"trust_mark"`
}

// DefaultProfile returns sane defaults; entity IDs come from deployment config.
func DefaultProfile(p Profile, entityID, redirectURI string) RPProfile {
	return RPProfile{
		Profile:          p,
		Enabled:          false,
		Environment:      "local",
		EntityID:         entityID,
		OrganizationName: "Example Organisation (change me)",
		HomepageURI:      "https://www.example.org",
		PolicyURI:        "https://www.example.org/privacy",
		Contacts:         []string{"protocollo@pec.example.org"},
		ClientName:       "IAM Platform",
		RedirectURIs:     []string{redirectURI},
		Scopes:           []string{"openid"},
		RequestedClaims: json.RawMessage(`{"userinfo":{"given_name":{"essential":true},"family_name":{"essential":true},` +
			`"https://attributes.eid.gov.it/fiscal_number":{"essential":true},"email":null,"birthdate":null}}`),
		RequiredAttributes: []string{"given_name", "family_name", ClaimFiscalNumber},
		ACRMap: []ACRMapping{
			{ACR: ACRSpidL1, LoA: LoALow},
			{ACR: ACRSpidL2, LoA: LoASubstantial},
			{ACR: ACRSpidL3, LoA: LoAHigh},
		},
		DefaultLoA:          LoASubstantial,
		SigningAlg:          "RS256",
		UserinfoEncAlg:      "RSA-OAEP-256",
		UserinfoEncEnc:      "A256CBC-HS512",
		EntityConfigTTL:     86400,
		ClockSkewSeconds:    30,
		MaxIDTokenAgeSecond: 300,
		UILocales:           "it",
	}
}

// Validate checks a profile before persisting it.
func (p *RPProfile) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if _, err := ParseProfile(string(p.Profile)); err != nil {
		add("profile: %v", err)
	}
	switch p.Environment {
	case "local", "test", "production":
	default:
		add("environment must be local, test or production")
	}
	prod := p.Environment == "production"
	checkURL := func(field, v string, required bool) {
		if v == "" {
			if required {
				add("%s is required", field)
			}
			return
		}
		u, err := url.Parse(v)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.Fragment != "" {
			add("%s must be an absolute URL", field)
			return
		}
		if prod && u.Scheme != "https" {
			add("%s must use https in production", field)
		}
	}
	checkURL("entity_id", p.EntityID, true)
	if u, err := url.Parse(p.EntityID); err == nil && u.RawQuery != "" {
		add("entity_id must not contain a query")
	}
	checkURL("homepage_uri", p.HomepageURI, true)
	checkURL("policy_uri", p.PolicyURI, true)
	checkURL("logo_uri", p.LogoURI, false)
	if strings.TrimSpace(p.OrganizationName) == "" {
		add("organization_name is required")
	}
	if len(p.Contacts) == 0 {
		add("at least one contact is required")
	}
	if len(p.RedirectURIs) == 0 {
		add("at least one redirect_uri is required")
	}
	for _, r := range p.RedirectURIs {
		if strings.Contains(r, "*") {
			add("wildcard redirect_uris are not allowed")
		}
		checkURL("redirect_uris", r, true)
	}
	for _, h := range p.AuthorityHints {
		checkURL("authority_hints", h, true)
	}
	if p.Enabled && len(p.AuthorityHints) == 0 {
		add("an enabled profile needs at least one authority_hint")
	}
	for _, tm := range p.TrustMarks {
		if tm.ID == "" || strings.Count(tm.TrustMark, ".") != 2 {
			add("trust marks need an id and a compact JWT")
		}
	}
	if len(p.RequestedClaims) > 0 && !json.Valid(p.RequestedClaims) {
		add("requested_claims must be valid JSON")
	}
	if len(p.ACRMap) == 0 {
		add("acr_map must not be empty")
	}
	for _, m := range p.ACRMap {
		if m.ACR == "" || LoARank(m.LoA) < 1 {
			add("acr_map entries need an acr and a loa among low/substantial/high")
		}
	}
	if LoARank(p.DefaultLoA) < 1 {
		add("default_loa must be low, substantial or high")
	}
	switch jose.SignatureAlgorithm(p.SigningAlg) {
	case jose.RS256, jose.RS512, jose.ES256, jose.ES512, jose.PS256, jose.PS512:
	default:
		add("signing_alg %q not allowed (RS256, RS512, ES256, ES512, PS256, PS512)", p.SigningAlg)
	}
	switch jose.KeyAlgorithm(p.UserinfoEncAlg) {
	case jose.RSA_OAEP, jose.RSA_OAEP_256, jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A256KW:
	default:
		add("userinfo_encrypted_response_alg %q not allowed", p.UserinfoEncAlg)
	}
	switch jose.ContentEncryption(p.UserinfoEncEnc) {
	case jose.A128CBC_HS256, jose.A256CBC_HS512:
	default:
		add("userinfo_encrypted_response_enc must be A128CBC-HS256 or A256CBC-HS512")
	}
	if p.EntityConfigTTL < 60 || p.EntityConfigTTL > 7*86400 {
		add("entity_configuration_ttl_seconds must be between 60 and 604800")
	}
	if p.ClockSkewSeconds < 0 || p.ClockSkewSeconds > 300 {
		add("clock_skew_seconds must be between 0 and 300")
	}
	if p.MaxIDTokenAgeSecond < 30 || p.MaxIDTokenAgeSecond > 3600 {
		add("max_id_token_age_seconds must be between 30 and 3600")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// ACRForLoA returns the weakest ACR mapped to at least the requested LoA.
func (p *RPProfile) ACRForLoA(loa string) (string, bool) {
	want := LoARank(loa)
	best, bestRank := "", 99
	for _, m := range p.ACRMap {
		r := LoARank(m.LoA)
		if r >= want && r < bestRank {
			best, bestRank = m.ACR, r
		}
	}
	return best, best != ""
}

// LoAForACR maps an OP ACR to the internal LoA (empty when unknown).
func (p *RPProfile) LoAForACR(acr string) string {
	for _, m := range p.ACRMap {
		if m.ACR == acr {
			return m.LoA
		}
	}
	return ""
}

// Provider is an OpenID Provider (SPID IdP or CIE OP) offered to users.
type Provider struct {
	ID          string    `json:"id"`
	Profile     Profile   `json:"profile"`
	EntityID    string    `json:"entity_id"`
	DisplayName string    `json:"display_name"`
	LogoURI     string    `json:"logo_uri"`
	Enabled     bool      `json:"enabled"`
	SortOrder   int       `json:"sort_order"`
	CreatedAt   time.Time `json:"created_at"`
}

// TrustAnchor is a pinned trust anchor.
type TrustAnchor struct {
	ID          string             `json:"id"`
	Profile     Profile            `json:"profile"`
	EntityID    string             `json:"entity_id"`
	JWKS        jose.JSONWebKeySet `json:"jwks"`
	Description string             `json:"description"`
	Enabled     bool               `json:"enabled"`
	CreatedAt   time.Time          `json:"created_at"`
}

// Key purposes.
const (
	PurposeFederation = "federation"
	PurposeCoreSig    = "core-sig"
	PurposeCoreEnc    = "core-enc"
	PurposeFacadeSig  = "facade-sig"
)

// Key statuses: "next" keys are published ahead of use (pre-rotation),
// "active" keys sign/decrypt, "deprecated" keys are still published (and
// still decrypt) after rotation, "retired" keys are no longer published.
const (
	KeyNext       = "next"
	KeyActive     = "active"
	KeyDeprecated = "deprecated"
	KeyRetired    = "retired"
)

// KeyPublished reports whether keys with this status appear in JWKS.
func KeyPublished(status string) bool {
	return status == KeyNext || status == KeyActive || status == KeyDeprecated
}

// KeyInfo is the public view of a stored key (never includes private material).
type KeyInfo struct {
	ID          string          `json:"id"`
	Profile     Profile         `json:"profile"`
	Purpose     string          `json:"purpose"`
	Kid         string          `json:"kid"`
	Alg         string          `json:"alg"`
	KeyType     string          `json:"key_type"`
	Status      string          `json:"status"`
	PublicJWK   json.RawMessage `json:"public_jwk"`
	CertPEM     string          `json:"cert_pem,omitempty"`
	Certificate *CertInfo       `json:"certificate,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	ActivatedAt *time.Time      `json:"activated_at,omitempty"`
	RetiredAt   *time.Time      `json:"retired_at,omitempty"`
}

// CertInfo summarises an X.509 certificate.
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"sha256_fingerprint"`
	SelfSigned  bool      `json:"self_signed"`
	URIs        []string  `json:"uris,omitempty"`
}
