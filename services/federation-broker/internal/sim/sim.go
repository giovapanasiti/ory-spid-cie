// Package sim implements a LOCAL TEST federation: a Trust Anchor and SPID /
// CIE OpenID Providers with synthetic users and fault injection.
//
// It is a development and integration-test tool only. It uses the same
// protocol code (go-jose, oidcfed) as the broker so that tests exercise real
// signature, encryption and trust-chain validation, but it is NOT an official
// conformance tool and passing tests against it does not demonstrate SPID/CIE
// conformance. It must never be deployed to production.
package sim

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/enpam/iam/federation-broker/internal/fedjose"
	"github.com/enpam/iam/federation-broker/internal/model"
	"github.com/enpam/iam/federation-broker/internal/oidcfed"
	"github.com/enpam/iam/federation-broker/internal/rp"
)

// Config configures the simulator.
type Config struct {
	// InternalBase is used in entity identifiers and server-to-server URLs
	// (e.g. http://fedsim:8070); PublicBase is the browser-facing base
	// (e.g. http://localhost:8070).
	InternalBase string
	PublicBase   string
	// RPEntities lists RP entity IDs the TA accepts as subordinates
	// (emulates federation onboarding).
	RPEntities []string
	// RPTrustMarkID is the trust mark type issued to RPs.
	RPTrustMarkID string
	Fetcher       oidcfed.Fetcher
	Log           *slog.Logger
	// KeyFile persists generated keys so pinned TA keys survive restarts.
	KeyFile string
}

// Entity is a simulated federation entity.
type Entity struct {
	ID      string
	Kind    string // ta | op
	Profile model.Profile
	FedKey  fedjose.SigningKey
	CoreKey fedjose.SigningKey
	Name    string
	// Tamper makes the entity configuration fail signature validation.
	Tamper bool
	// Unregistered OPs are not known by the TA (untrusted issuer).
	Unregistered bool
}

// User is a synthetic test identity (never real citizen data).
type User struct {
	ID         string         `json:"id"`
	Label      string         `json:"label"`
	Attributes map[string]any `json:"attributes"`
}

// Users are synthetic test identities; fiscal codes are syntactically valid
// but fictitious.
var Users = []User{
	{ID: "u1", Label: "Ada Test (completo)", Attributes: map[string]any{
		"given_name": "Ada", "family_name": "Test", "email": "ada.test@example.org", "birthdate": "1985-12-10",
		model.ClaimFiscalNumber: "TINIT-TSTDAA85T50H501R", "phone_number": "+393330000001", "place_of_birth": "H501",
	}},
	{ID: "u2", Label: "Bruno Prova (completo)", Attributes: map[string]any{
		"given_name": "Bruno", "family_name": "Prova", "email": "bruno.prova@example.org", "birthdate": "1979-03-02",
		model.ClaimFiscalNumber: "TINIT-PRVBRN79C02F205X",
	}},
	{ID: "u3", Label: "Carla Senzamail (no email)", Attributes: map[string]any{
		"given_name": "Carla", "family_name": "Senzamail", "birthdate": "1990-07-21",
		model.ClaimFiscalNumber: "TINIT-SNZCRL90L61L219K",
	}},
}

// Scenarios selectable on the simulated login page.
var Scenarios = []struct{ ID, Label string }{
	{"success", "Successo / success"},
	{"missing_attributes", "Attributi mancanti (no fiscal_number)"},
	{"wrong_acr", "ACR inferiore al richiesto (SpidL1)"},
	{"expired_id_token", "ID token scaduto"},
	{"bad_signature", "Firma ID token non valida"},
	{"alg_confusion", "Algorithm confusion (HS256 con chiave pubblica)"},
	{"wrong_issuer", "Issuer errato"},
	{"wrong_audience", "Audience errata"},
	{"wrong_nonce", "Nonce errato"},
	{"replay_jti", "Replay jti ID token"},
	{"plain_userinfo", "UserInfo non cifrata"},
	{"wrong_iss_param", "Parametro iss errato nella redirect"},
}

type authCode struct {
	ClientID, RedirectURI, Nonce, Challenge, ACR, Scenario string
	User                                                   User
	Expires                                                time.Time
	Used                                                   bool
	RPChain                                                *oidcfed.TrustChain
	OP                                                     *Entity
}

type accessGrant struct {
	code    *authCode
	expires time.Time
}

// Sim is the simulator server.
type Sim struct {
	cfg      Config
	TA       *Entity
	OPs      map[string]*Entity // path segment -> entity
	mu       sync.Mutex
	codes    map[string]*authCode
	tokens   map[string]*accessGrant
	firstJTI string
	tmpl     *template.Template
	resolver *oidcfed.Resolver
}

func newEntity(id, kind, name string, p model.Profile) (*Entity, error) {
	return newEntityWithKeys(id, kind, name, p, nil)
}

func newEntityWithKeys(id, kind, name string, p model.Profile, ks *keyStore) (*Entity, error) {
	fk, err := ks.get(id + "#fed")
	if err != nil {
		return nil, err
	}
	ck, err := ks.get(id + "#core")
	if err != nil {
		return nil, err
	}
	e := &Entity{ID: id, Kind: kind, Name: name, Profile: p}
	fkid, _ := fedjose.Thumbprint(fk.Public())
	ckid, _ := fedjose.Thumbprint(ck.Public())
	e.FedKey = fedjose.SigningKey{Kid: fkid, Alg: jose.RS256, Private: fk}
	e.CoreKey = fedjose.SigningKey{Kid: ckid, Alg: jose.RS256, Private: ck}
	return e, nil
}

func pubSet(keys ...fedjose.SigningKey) jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{}
	for _, k := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.Private.Public(), KeyID: k.Kid, Use: "sig", Algorithm: string(k.Alg)})
	}
	return set
}

// New creates a simulator with fresh keys.
func New(cfg Config) (*Sim, error) {
	s := &Sim{cfg: cfg, OPs: map[string]*Entity{}, codes: map[string]*authCode{}, tokens: map[string]*accessGrant{}}
	ks, err := loadKeyStore(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	if s.TA, err = newEntityWithKeys(cfg.InternalBase+"/ta", "ta", "Test Trust Anchor", "", ks); err != nil {
		return nil, err
	}
	ops := []struct {
		path, name string
		p          model.Profile
		tamper     bool
		unreg      bool
	}{
		{"spid-test", "SPID Test IdP", model.ProfileSPID, false, false},
		{"spid-test-2", "SPID Test IdP 2", model.ProfileSPID, false, false},
		{"cie-test", "CIE Test OP", model.ProfileCIE, false, false},
		{"rogue", "Rogue OP (non registrato)", model.ProfileSPID, false, true},
		{"tampered", "Tampered OP (metadata alterati)", model.ProfileSPID, true, false},
	}
	for _, o := range ops {
		e, err := newEntityWithKeys(cfg.InternalBase+"/op/"+o.path, "op", o.name, o.p, ks)
		if err != nil {
			return nil, err
		}
		e.Tamper, e.Unregistered = o.tamper, o.unreg
		s.OPs[o.path] = e
	}
	if err := ks.save(); err != nil {
		return nil, err
	}
	s.tmpl = template.Must(template.New("login").Parse(loginTmpl))
	s.resolver = &oidcfed.Resolver{
		Fetcher: cfg.Fetcher, Algs: rp.AllowedSigAlgs, Skew: 30 * time.Second, MaxDepth: 3,
		Anchors: []oidcfed.TrustAnchor{{EntityID: s.TA.ID, JWKS: pubSet(s.TA.FedKey)}},
	}
	return s, nil
}

// TAJWKS returns the TA public federation keys (to pin in the broker).
func (s *Sim) TAJWKS() jose.JSONWebKeySet { return pubSet(s.TA.FedKey) }

// Handler returns the HTTP handler.
func (s *Sim) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /ta/.well-known/openid-federation", s.taEC)
	mux.HandleFunc("GET /ta/fetch", s.taFetch)
	mux.HandleFunc("GET /ta/list", s.taList)
	mux.HandleFunc("POST /ta/trust_mark_status", s.taTrustMarkStatus)
	mux.HandleFunc("GET /ta/dev/trust-mark", s.taIssueTrustMark)
	mux.HandleFunc("GET /ta/dev/jwks", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.TAJWKS()) })
	mux.HandleFunc("GET /op/{op}/.well-known/openid-federation", s.opEC)
	mux.HandleFunc("GET /op/{op}/authorization", s.opAuthorize)
	mux.HandleFunc("POST /op/{op}/login", s.opLogin)
	mux.HandleFunc("POST /op/{op}/token", s.opToken)
	mux.HandleFunc("GET /op/{op}/userinfo", s.opUserinfo)
	mux.HandleFunc("POST /op/{op}/revocation", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("GET /", s.index)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJWT(w http.ResponseWriter, ct, jwt string) {
	w.Header().Set("Content-Type", ct)
	w.Write([]byte(jwt))
}

func (s *Sim) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	var ops []map[string]string
	for path, e := range s.OPs {
		ops = append(ops, map[string]string{"path": path, "entity_id": e.ID, "profile": string(e.Profile), "name": e.Name})
	}
	writeJSON(w, 200, map[string]any{"warning": "LOCAL TEST FEDERATION — not an official conformance tool", "trust_anchor": s.TA.ID, "ops": ops})
}

// ---------------------------------------------------------------- TA

func (s *Sim) taEC(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	es := &oidcfed.EntityStatement{
		Iss: s.TA.ID, Sub: s.TA.ID, Iat: now.Unix(), Exp: now.Add(24 * time.Hour).Unix(), JWKS: pubSet(s.TA.FedKey),
		Metadata: map[string]map[string]any{oidcfed.EntityTypeFederation: {
			"organization_name":                     "Local Test Trust Anchor",
			"homepage_uri":                          s.cfg.PublicBase,
			"federation_fetch_endpoint":             s.TA.ID + "/fetch",
			"federation_list_endpoint":              s.TA.ID + "/list",
			"federation_trust_mark_status_endpoint": s.TA.ID + "/trust_mark_status",
		}},
		TrustMarkIssuers: map[string][]string{s.cfg.RPTrustMarkID: {s.TA.ID}},
	}
	jwt, _ := es.Sign(s.TA.FedKey)
	writeJWT(w, oidcfed.ContentTypeEntityStmt, jwt)
}

// subordinatePolicy is applied to RPs: the TA forces the RP grant/response types.
var subordinatePolicy = map[string]map[string]map[string]any{
	oidcfed.EntityTypeRP: {
		"response_types":            {"subset_of": []any{"code"}},
		"client_registration_types": {"subset_of": []any{"automatic"}, "essential": true},
	},
}

func (s *Sim) taFetch(w http.ResponseWriter, r *http.Request) {
	sub := r.URL.Query().Get("sub")
	var jwks jose.JSONWebKeySet
	var policy map[string]map[string]map[string]any
	found := false
	for _, op := range s.OPs {
		if op.ID == sub && !op.Unregistered {
			jwks, found = pubSet(op.FedKey), true
			if op.Tamper {
				// TA attests a different key than the one the OP signs with.
				other, _ := newEntity(op.ID, "op", "", "")
				jwks = pubSet(other.FedKey)
			}
		}
	}
	if !found && slices.Contains(s.cfg.RPEntities, sub) {
		// Onboarding emulation: learn the RP keys from its self-signed EC.
		res := &oidcfed.Resolver{Fetcher: s.cfg.Fetcher, Algs: rp.AllowedSigAlgs, Skew: 30 * time.Second}
		ec, err := res.FetchEntityConfiguration(r.Context(), sub)
		if err != nil {
			s.cfg.Log.Warn("fetch RP entity configuration", "sub", sub, "err", err)
			http.Error(w, "subordinate unavailable", http.StatusNotFound)
			return
		}
		jwks, found, policy = ec.JWKS, true, subordinatePolicy
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "error_description": "unknown subordinate"})
		return
	}
	now := time.Now()
	es := &oidcfed.EntityStatement{Iss: s.TA.ID, Sub: sub, Iat: now.Unix(), Exp: now.Add(12 * time.Hour).Unix(), JWKS: jwks, MetadataPolicy: policy}
	jwt, _ := es.Sign(s.TA.FedKey)
	writeJWT(w, oidcfed.ContentTypeEntityStmt, jwt)
}

func (s *Sim) taList(w http.ResponseWriter, _ *http.Request) {
	var out []string
	for _, op := range s.OPs {
		if !op.Unregistered {
			out = append(out, op.ID)
		}
	}
	out = append(out, s.cfg.RPEntities...)
	writeJSON(w, 200, out)
}

func (s *Sim) issueTrustMark(sub string) (string, error) {
	now := time.Now()
	return fedjose.Sign(map[string]any{
		"iss": s.TA.ID, "sub": sub, "id": s.cfg.RPTrustMarkID, "trust_mark_type": s.cfg.RPTrustMarkID,
		"iat": now.Unix(), "exp": now.Add(365 * 24 * time.Hour).Unix(), "organization_type": "public", "id_code": map[string]string{"ipa_code": "test"},
	}, s.TA.FedKey, fedjose.TypTrustMark)
}

// taIssueTrustMark is a DEVELOPMENT shortcut emulating the onboarding portal.
func (s *Sim) taIssueTrustMark(w http.ResponseWriter, r *http.Request) {
	sub := r.URL.Query().Get("sub")
	if !slices.Contains(s.cfg.RPEntities, sub) {
		http.Error(w, "unknown RP", http.StatusNotFound)
		return
	}
	tm, err := s.issueTrustMark(sub)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]string{"id": s.cfg.RPTrustMarkID, "trust_mark": tm})
}

func (s *Sim) taTrustMarkStatus(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	sub := r.PostForm.Get("sub")
	if tm := r.PostForm.Get("trust_mark"); tm != "" {
		var c oidcfed.TrustMarkClaims
		if _, err := fedjose.Verify(tm, s.TAJWKS(), fedjose.VerifyOptions{ExpectedTyp: fedjose.TypTrustMark}); err != nil || fedjose.UnverifiedClaims(tm, &c) != nil {
			writeJSON(w, 200, map[string]bool{"active": false})
			return
		}
		sub = c.Sub
	}
	writeJSON(w, 200, map[string]bool{"active": slices.Contains(s.cfg.RPEntities, sub)})
}

// ---------------------------------------------------------------- OP

func (s *Sim) op(r *http.Request) (*Entity, string, bool) {
	path := r.PathValue("op")
	e, ok := s.OPs[path]
	return e, path, ok
}

func (s *Sim) opEC(w http.ResponseWriter, r *http.Request) {
	op, path, ok := s.op(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	now := time.Now()
	acrs := []string{model.ACRSpidL1, model.ACRSpidL2, model.ACRSpidL3}
	md := map[string]any{
		"issuer":                                         op.ID,
		"authorization_endpoint":                         s.cfg.PublicBase + "/op/" + path + "/authorization",
		"token_endpoint":                                 op.ID + "/token",
		"userinfo_endpoint":                              op.ID + "/userinfo",
		"revocation_endpoint":                            op.ID + "/revocation",
		"jwks":                                           pubSet(op.CoreKey),
		"acr_values_supported":                           acrs,
		"scopes_supported":                               []string{"openid", "offline_access"},
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query", "form_post"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"subject_types_supported":                        []string{"pairwise"},
		"id_token_signing_alg_values_supported":          []string{"RS256", "RS512", "ES256"},
		"userinfo_signing_alg_values_supported":          []string{"RS256", "RS512"},
		"userinfo_encryption_alg_values_supported":       []string{"RSA-OAEP", "RSA-OAEP-256"},
		"userinfo_encryption_enc_values_supported":       []string{"A128CBC-HS256", "A256CBC-HS512"},
		"request_object_signing_alg_values_supported":    []string{"RS256", "RS512", "ES256"},
		"token_endpoint_auth_methods_supported":          []string{"private_key_jwt"},
		"code_challenge_methods_supported":               []string{"S256"},
		"claims_parameter_supported":                     true,
		"request_parameter_supported":                    true,
		"authorization_response_iss_parameter_supported": true,
	}
	es := &oidcfed.EntityStatement{
		Iss: op.ID, Sub: op.ID, Iat: now.Unix(), Exp: now.Add(24 * time.Hour).Unix(), JWKS: pubSet(op.FedKey),
		AuthorityHints: []string{s.TA.ID},
		Metadata: map[string]map[string]any{
			oidcfed.EntityTypeOP:         md,
			oidcfed.EntityTypeFederation: {"organization_name": op.Name, "homepage_uri": s.cfg.PublicBase},
		},
	}
	jwt, _ := es.Sign(op.FedKey)
	if op.Tamper {
		// Alter the payload after signing: signature check must fail.
		parts := strings.Split(jwt, ".")
		var payload map[string]any
		b, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(b, &payload)
		payload["metadata"].(map[string]any)[oidcfed.EntityTypeOP].(map[string]any)["token_endpoint"] = "http://attacker.invalid/token"
		b, _ = json.Marshal(payload)
		parts[1] = base64.RawURLEncoding.EncodeToString(b)
		jwt = strings.Join(parts, ".")
	}
	writeJWT(w, oidcfed.ContentTypeEntityStmt, jwt)
}

type requestObject struct {
	Iss                 string          `json:"iss"`
	Aud                 json.RawMessage `json:"aud"`
	ClientID            string          `json:"client_id"`
	ResponseType        string          `json:"response_type"`
	Scope               string          `json:"scope"`
	RedirectURI         string          `json:"redirect_uri"`
	State               string          `json:"state"`
	Nonce               string          `json:"nonce"`
	CodeChallenge       string          `json:"code_challenge"`
	CodeChallengeMethod string          `json:"code_challenge_method"`
	Prompt              string          `json:"prompt"`
	ACRValues           string          `json:"acr_values"`
	Exp                 int64           `json:"exp"`
	Iat                 int64           `json:"iat"`
}

func isAlnum(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func audList(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

// validateAuthRequest performs OP-side validation of the signed request
// object against the RP trust chain (trust mark checked first, as per
// trust_negotiation.rst).
func (s *Sim) validateAuthRequest(ctx context.Context, op *Entity, q url.Values) (*requestObject, *oidcfed.TrustChain, error) {
	raw := q.Get("request")
	if raw == "" {
		return nil, nil, errors.New("request object required")
	}
	clientID := q.Get("client_id")
	chain, err := s.resolver.Resolve(ctx, clientID, oidcfed.EntityTypeRP)
	if err != nil {
		return nil, nil, fmt.Errorf("RP trust chain: %w", err)
	}
	if !chain.HasTrustMark(s.cfg.RPTrustMarkID) {
		return nil, nil, fmt.Errorf("RP has no valid trust mark %s (%v)", s.cfg.RPTrustMarkID, chain.TrustMarkErrors)
	}
	md := chain.Metadata[oidcfed.EntityTypeRP]
	var rpKeys jose.JSONWebKeySet
	b, _ := json.Marshal(md["jwks"])
	if err := json.Unmarshal(b, &rpKeys); err != nil {
		return nil, nil, err
	}
	v, err := fedjose.Verify(raw, rpKeys, fedjose.VerifyOptions{AllowedAlgs: rp.AllowedSigAlgs})
	if err != nil {
		return nil, nil, fmt.Errorf("request object: %w", err)
	}
	var ro requestObject
	if err := json.Unmarshal(v.Payload, &ro); err != nil {
		return nil, nil, err
	}
	redirects := toStrings(md["redirect_uris"])
	switch {
	case ro.Iss != clientID || ro.ClientID != clientID:
		return nil, nil, errors.New("iss/client_id mismatch")
	case !slices.Contains(audList(ro.Aud), op.ID):
		return nil, nil, errors.New("aud must be the OP issuer")
	case ro.Exp < time.Now().Unix():
		return nil, nil, errors.New("request object expired")
	case ro.ResponseType != "code" || q.Get("response_type") != "code":
		return nil, nil, errors.New("response_type must be code")
	case ro.Scope != q.Get("scope") || !slices.Contains(strings.Fields(ro.Scope), "openid"):
		return nil, nil, errors.New("scope mismatch")
	case !slices.Contains(redirects, ro.RedirectURI):
		return nil, nil, errors.New("redirect_uri not registered")
	case len(ro.State) < 32 || !isAlnum(ro.State) || len(ro.Nonce) < 32 || !isAlnum(ro.Nonce):
		return nil, nil, errors.New("state/nonce must be >= 32 alphanumeric characters")
	case ro.CodeChallengeMethod != "S256" || ro.CodeChallenge == "":
		return nil, nil, errors.New("PKCE S256 required")
	case ro.Prompt != "consent" && ro.Prompt != "consent login":
		return nil, nil, errors.New("prompt must be consent or 'consent login'")
	case ro.ACRValues == "":
		return nil, nil, errors.New("acr_values required")
	}
	return &ro, chain, nil
}

func toStrings(v any) []string {
	var out []string
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func (s *Sim) opAuthorize(w http.ResponseWriter, r *http.Request) {
	op, path, ok := s.op(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ro, _, err := s.validateAuthRequest(r.Context(), op, r.URL.Query())
	if err != nil {
		s.cfg.Log.Warn("sim OP rejected authorization request", "op", path, "err", err)
		http.Error(w, "invalid_request: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.Execute(w, map[string]any{
		"OP": op, "Path": path, "Users": Users, "Scenarios": Scenarios, "Query": r.URL.RawQuery,
		"ACR": ro.ACRValues, "ACRs": []string{model.ACRSpidL1, model.ACRSpidL2, model.ACRSpidL3}, "Client": ro.ClientID,
	})
}

func (s *Sim) opLogin(w http.ResponseWriter, r *http.Request) {
	op, path, ok := s.op(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	q, err := url.ParseQuery(r.PostForm.Get("query"))
	if err != nil {
		http.Error(w, "bad query", 400)
		return
	}
	// Re-validate: the hidden query is client-controlled.
	ro, chain, err := s.validateAuthRequest(r.Context(), op, q)
	if err != nil {
		http.Error(w, "invalid_request: "+err.Error(), 400)
		return
	}
	redirect, _ := url.Parse(ro.RedirectURI)
	rq := redirect.Query()
	rq.Set("state", ro.State)
	issParam := op.ID
	if r.PostForm.Get("action") == "cancel" {
		rq.Set("error", "access_denied")
		rq.Set("iss", issParam)
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
		return
	}
	var user *User
	for i := range Users {
		if Users[i].ID == r.PostForm.Get("user") {
			user = &Users[i]
		}
	}
	if user == nil {
		http.Error(w, "unknown user", 400)
		return
	}
	scenario := r.PostForm.Get("scenario")
	acr := r.PostForm.Get("acr")
	if !slices.Contains([]string{model.ACRSpidL1, model.ACRSpidL2, model.ACRSpidL3}, acr) {
		acr = strings.Fields(ro.ACRValues)[0]
	}
	if scenario == "wrong_acr" {
		acr = model.ACRSpidL1
	}
	code := fedjose.RandomToken(32)
	s.mu.Lock()
	s.codes[code] = &authCode{ClientID: ro.ClientID, RedirectURI: ro.RedirectURI, Nonce: ro.Nonce, Challenge: ro.CodeChallenge,
		ACR: acr, Scenario: scenario, User: *user, Expires: time.Now().Add(time.Minute), RPChain: chain, OP: op}
	s.mu.Unlock()
	if scenario == "wrong_iss_param" {
		issParam = "http://evil.invalid/op"
	}
	rq.Set("code", code)
	rq.Set("iss", issParam)
	redirect.RawQuery = rq.Encode()
	s.cfg.Log.Info("sim OP authenticated test user", "op", path, "user", user.ID, "scenario", scenario, "acr", acr)
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (s *Sim) opToken(w http.ResponseWriter, r *http.Request) {
	op, _, ok := s.op(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	f := r.PostForm
	s.mu.Lock()
	c := s.codes[f.Get("code")]
	if c != nil && c.Used {
		c = nil
	} else if c != nil {
		c.Used = true
	}
	s.mu.Unlock()
	if c == nil || time.Now().After(c.Expires) || c.OP != op {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	if f.Get("grant_type") != "authorization_code" || f.Get("client_id") != c.ClientID ||
		f.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	// private_key_jwt: verify the client assertion with RP core keys from the trust chain.
	var rpKeys jose.JSONWebKeySet
	b, _ := json.Marshal(c.RPChain.Metadata[oidcfed.EntityTypeRP]["jwks"])
	_ = json.Unmarshal(b, &rpKeys)
	v, err := fedjose.Verify(f.Get("client_assertion"), rpKeys, fedjose.VerifyOptions{AllowedAlgs: rp.AllowedSigAlgs})
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	var ca struct {
		Iss, Sub, Jti string
		Aud           json.RawMessage
		Exp           int64
	}
	_ = json.Unmarshal(v.Payload, &ca)
	if ca.Iss != c.ClientID || ca.Sub != c.ClientID || !slices.Contains(audList(ca.Aud), op.ID+"/token") || ca.Exp < time.Now().Unix() || ca.Jti == "" {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	if rp.PKCEChallenge(f.Get("code_verifier")) != c.Challenge {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "PKCE"})
		return
	}
	now := time.Now()
	accessToken, _ := fedjose.Sign(map[string]any{"iss": op.ID, "sub": s.subject(op, c), "aud": op.ID, "client_id": c.ClientID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": uuid.NewString(), "scope": "openid"}, op.CoreKey, "at+jwt")
	s.mu.Lock()
	s.tokens[accessToken] = &accessGrant{code: c, expires: now.Add(5 * time.Minute)}
	s.mu.Unlock()
	idToken, err := s.idToken(op, c, accessToken)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func (s *Sim) subject(op *Entity, c *authCode) string {
	sum := sha256.Sum256([]byte(op.ID + "|" + c.ClientID + "|" + c.User.ID))
	return base64.RawURLEncoding.EncodeToString(sum[:20])
}

func (s *Sim) idToken(op *Entity, c *authCode, accessToken string) (string, error) {
	now := time.Now()
	atHash, _ := rp.AtHash(accessToken, "RS256")
	jti := uuid.NewString()
	s.mu.Lock()
	if s.firstJTI == "" {
		s.firstJTI = jti
	}
	if c.Scenario == "replay_jti" {
		jti = s.firstJTI
	}
	s.mu.Unlock()
	claims := map[string]any{
		"iss": op.ID, "sub": s.subject(op, c), "aud": []string{c.ClientID}, "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "nonce": c.Nonce, "acr": c.ACR, "at_hash": atHash, "jti": jti,
	}
	key := op.CoreKey
	switch c.Scenario {
	case "expired_id_token":
		claims["iat"], claims["nbf"], claims["exp"] = now.Add(-20*time.Minute).Unix(), now.Add(-20*time.Minute).Unix(), now.Add(-10*time.Minute).Unix()
	case "wrong_issuer":
		claims["iss"] = "http://evil.invalid/op"
	case "wrong_audience":
		claims["aud"] = []string{"http://other-rp.invalid/"}
	case "wrong_nonce":
		claims["nonce"] = "x" + c.Nonce
	case "bad_signature":
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		key = fedjose.SigningKey{Kid: op.CoreKey.Kid, Alg: jose.RS256, Private: other}
	case "alg_confusion":
		pub := op.CoreKey.Private.Public().(*rsa.PublicKey)
		secret, _ := json.Marshal(jose.JSONWebKey{Key: pub})
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, (&jose.SignerOptions{}).WithHeader("kid", op.CoreKey.Kid))
		if err != nil {
			return "", err
		}
		payload, _ := json.Marshal(claims)
		obj, err := sig.Sign(payload)
		if err != nil {
			return "", err
		}
		return obj.CompactSerialize()
	}
	return fedjose.Sign(claims, key, "")
}

func (s *Sim) opUserinfo(w http.ResponseWriter, r *http.Request) {
	op, _, ok := s.op(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := r.Header.Get("Authorization")
	tok := strings.TrimPrefix(h, "Bearer ")
	s.mu.Lock()
	g := s.tokens[tok]
	s.mu.Unlock()
	if g == nil || time.Now().After(g.expires) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	c := g.code
	now := time.Now()
	claims := map[string]any{"iss": op.ID, "sub": s.subject(op, c), "aud": c.ClientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	for k, v := range c.User.Attributes {
		if c.Scenario == "missing_attributes" && k == model.ClaimFiscalNumber {
			continue
		}
		claims[k] = v
	}
	signed, err := fedjose.Sign(claims, op.CoreKey, "")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "server_error"})
		return
	}
	if c.Scenario == "plain_userinfo" {
		writeJWT(w, "application/jwt", signed)
		return
	}
	md := c.RPChain.Metadata[oidcfed.EntityTypeRP]
	var rpKeys jose.JSONWebKeySet
	b, _ := json.Marshal(md["jwks"])
	_ = json.Unmarshal(b, &rpKeys)
	var encKey *jose.JSONWebKey
	for i := range rpKeys.Keys {
		if rpKeys.Keys[i].Use == "enc" {
			encKey = &rpKeys.Keys[i]
			break
		}
	}
	if encKey == nil {
		writeJSON(w, 500, map[string]string{"error": "RP has no encryption key"})
		return
	}
	alg := jose.KeyAlgorithm(oidcfed.StringMeta(md, "userinfo_encrypted_response_alg"))
	enc := jose.ContentEncryption(oidcfed.StringMeta(md, "userinfo_encrypted_response_enc"))
	if alg == "" {
		alg = jose.RSA_OAEP_256
	}
	if enc == "" {
		enc = jose.A256CBC_HS512
	}
	jwe, err := fedjose.Encrypt([]byte(signed), *encKey, alg, enc, "JWT")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJWT(w, "application/jose", jwe)
}

var _ crypto.Signer = (*rsa.PrivateKey)(nil)

const loginTmpl = `<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.OP.Name}} — LOCAL TEST</title>
<style>body{font-family:system-ui,sans-serif;background:#fff8e1;margin:0}main{max-width:36rem;margin:2rem auto;background:#fff;padding:2rem;border:3px dashed #b26a00;border-radius:8px}
.banner{background:#b26a00;color:#fff;padding:.5rem;font-weight:bold;text-align:center}label{display:block;margin:.6rem 0 .2rem}select,button{font-size:1rem;padding:.4rem;width:100%}button{margin-top:1rem}
.cancel{background:none;border:1px solid #999}</style></head><body>
<div class="banner">AMBIENTE DI TEST LOCALE — LOCAL TEST FEDERATION — NON È UN IdP REALE</div>
<main><h1>{{.OP.Name}}</h1><p>RP: <code>{{.Client}}</code><br>ACR richiesto: <code>{{.ACR}}</code></p>
<form method="post" action="/op/{{.Path}}/login">
<input type="hidden" name="query" value="{{.Query}}">
<label for="user">Utente di test (dati sintetici)</label>
<select id="user" name="user">{{range .Users}}<option value="{{.ID}}">{{.Label}}</option>{{end}}</select>
<label for="acr">Livello raggiunto</label>
<select id="acr" name="acr">{{range .ACRs}}<option value="{{.}}" {{if eq . $.ACR}}selected{{end}}>{{.}}</option>{{end}}</select>
<label for="scenario">Scenario</label>
<select id="scenario" name="scenario">{{range .Scenarios}}<option value="{{.ID}}">{{.Label}}</option>{{end}}</select>
<button type="submit" name="action" value="login" id="login">Autentica</button>
<button type="submit" name="action" value="cancel" class="cancel" id="cancel">Annulla</button>
</form></main></body></html>`
