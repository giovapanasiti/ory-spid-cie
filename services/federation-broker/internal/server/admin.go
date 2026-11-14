package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/enpam/iam/federation-broker/internal/fedjose"
	"github.com/enpam/iam/federation-broker/internal/keys"
	"github.com/enpam/iam/federation-broker/internal/model"
	"github.com/enpam/iam/federation-broker/internal/oidcfed"
	"github.com/enpam/iam/federation-broker/internal/store"
)

func newUUID() string { return uuid.NewString() }

// Platform admin roles (see docs/security/threat-model.md, admin RBAC).
var (
	readRoles  = []string{"viewer", "federation-admin", "security-auditor", "superadmin"}
	writeRoles = []string{"federation-admin", "superadmin"}
)

var reActor = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,128}$`)

type actor struct {
	ID    string
	Roles []string
}

func (a actor) has(roles []string) bool {
	for _, r := range a.Roles {
		if slices.Contains(roles, r) {
			return true
		}
	}
	return false
}

// adminAuth authenticates the admin console (service token) and enforces the
// role forwarded for the end user (already authorised by the console).
func (s *Server) adminAuth(roles []string, h func(http.ResponseWriter, *http.Request, actor)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenEqual(bearer(r), s.Cfg.AdminToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		a := actor{ID: r.Header.Get("X-Actor")}
		if !reActor.MatchString(a.ID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "X-Actor header required"})
			return
		}
		for _, role := range strings.Split(r.Header.Get("X-Actor-Roles"), ",") {
			if role = strings.TrimSpace(role); role != "" {
				a.Roles = append(a.Roles, role)
			}
		}
		if !a.has(roles) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		h(w, r, a)
	}
}

func (s *Server) internalAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenEqual(bearer(r), s.Cfg.InternalToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func storeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
}

func (s *Server) registerAdmin(mux *http.ServeMux) {
	R, W := readRoles, writeRoles
	mux.HandleFunc("GET /admin/meta", s.adminAuth(R, s.adminMeta))
	mux.HandleFunc("GET /admin/profiles", s.adminAuth(R, s.listProfiles))
	mux.HandleFunc("GET /admin/profiles/{profile}", s.adminAuth(R, s.getProfile))
	mux.HandleFunc("PUT /admin/profiles/{profile}", s.adminAuth(W, s.putProfile))
	mux.HandleFunc("GET /admin/profiles/{profile}/entity-configuration", s.adminAuth(R, s.previewEC))
	mux.HandleFunc("GET /admin/providers", s.adminAuth(R, s.listProviders))
	mux.HandleFunc("POST /admin/providers", s.adminAuth(W, s.saveProvider))
	mux.HandleFunc("PUT /admin/providers/{id}", s.adminAuth(W, s.saveProvider))
	mux.HandleFunc("DELETE /admin/providers/{id}", s.adminAuth(W, s.deleteProvider))
	mux.HandleFunc("GET /admin/trust-anchors", s.adminAuth(R, s.listTAs))
	mux.HandleFunc("POST /admin/trust-anchors", s.adminAuth(W, s.saveTA))
	mux.HandleFunc("PUT /admin/trust-anchors/{id}", s.adminAuth(W, s.saveTA))
	mux.HandleFunc("DELETE /admin/trust-anchors/{id}", s.adminAuth(W, s.deleteTA))
	mux.HandleFunc("POST /admin/trust-anchors/preview", s.adminAuth(W, s.previewTA))
	mux.HandleFunc("GET /admin/keys", s.adminAuth(R, s.listKeys))
	mux.HandleFunc("POST /admin/keys/generate", s.adminAuth(W, s.generateKey))
	mux.HandleFunc("POST /admin/keys/import", s.adminAuth(W, s.importKey))
	mux.HandleFunc("POST /admin/keys/{id}/activate", s.adminAuth(W, s.activateKey))
	mux.HandleFunc("POST /admin/keys/{id}/retire", s.adminAuth(W, s.retireKey))
	mux.HandleFunc("DELETE /admin/keys/{id}", s.adminAuth(W, s.deleteKey))
	mux.HandleFunc("POST /admin/keys/{id}/csr", s.adminAuth(W, s.keyCSR))
	mux.HandleFunc("POST /admin/keys/{id}/self-signed", s.adminAuth(W, s.keySelfSigned))
	mux.HandleFunc("PUT /admin/keys/{id}/certificate", s.adminAuth(W, s.keyCertificate))
	mux.HandleFunc("POST /admin/trust/resolve", s.adminAuth(R, s.trustResolve))
	mux.HandleFunc("POST /admin/trust/refresh", s.adminAuth(W, s.trustRefresh))
	mux.HandleFunc("GET /admin/status", s.adminAuth(R, s.status))
}

func (s *Server) adminMeta(w http.ResponseWriter, _ *http.Request, _ actor) {
	writeJSON(w, http.StatusOK, map[string]any{
		"environment": s.Cfg.Env, "public_url": s.Cfg.PublicURL, "key_types": fedjose.AllKeyTypes,
		"purposes":       map[string][]string{"spid": {"federation", "core-sig", "core-enc"}, "cie": {"federation", "core-sig", "core-enc"}, "facade": {"facade-sig"}},
		"signature_algs": []string{"RS256", "RS512", "PS256", "PS512", "ES256", "ES512"},
		"loa_levels":     []string{model.LoALow, model.LoASubstantial, model.LoAHigh},
	})
}

// --------------------------------------------------------------- profiles

func (s *Server) profileWarnings(ctx context.Context, cfg *model.RPProfile) []string {
	warn := []string{}
	if !strings.HasSuffix(strings.TrimRight(cfg.EntityID, "/"), "/rp/"+string(cfg.Profile)) {
		warn = append(warn, "entity_id path does not end with /rp/"+string(cfg.Profile)+": the reverse proxy must route its /.well-known/openid-federation to the broker")
	}
	if len(cfg.TrustMarks) == 0 {
		warn = append(warn, "no trust marks configured: SPID/CIE OPs reject RPs without a valid trust mark")
	}
	if cfg.Environment == "production" && strings.Contains(cfg.EntityID, "localhost") {
		warn = append(warn, "production profile uses a localhost entity_id")
	}
	for _, purpose := range []string{model.PurposeFederation, model.PurposeCoreSig, model.PurposeCoreEnc} {
		if _, err := s.Keys.Signing(ctx, cfg.Profile, purpose); err != nil && purpose != model.PurposeCoreEnc {
			warn = append(warn, "no active "+purpose+" key")
		}
	}
	if tas, err := s.Store.ListTrustAnchors(ctx, cfg.Profile, true); err == nil && len(tas) == 0 {
		warn = append(warn, "no trust anchor configured")
	}
	return warn
}

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request, _ actor) {
	out := []map[string]any{}
	for _, p := range []model.Profile{model.ProfileSPID, model.ProfileCIE} {
		cfg, err := s.Store.GetProfile(r.Context(), p)
		if err != nil {
			continue
		}
		out = append(out, map[string]any{"config": cfg, "warnings": s.profileWarnings(r.Context(), cfg)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request, _ actor) {
	cfg, err := s.profile(r)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "warnings": s.profileWarnings(r.Context(), cfg)})
}

func (s *Server) putProfile(w http.ResponseWriter, r *http.Request, a actor) {
	p, err := model.ParseProfile(r.PathValue("profile"))
	if err != nil {
		storeErr(w, err)
		return
	}
	var cfg model.RPProfile
	if err := decode(r, &cfg); err != nil {
		storeErr(w, fmt.Errorf("invalid body: %w", err))
		return
	}
	cfg.Profile = p
	if err := cfg.Validate(); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if err := s.Store.PutProfile(r.Context(), &cfg, a.ID); err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "admin.federation.profile_updated", "success", a.ID, map[string]any{"profile": p, "enabled": cfg.Enabled, "environment": cfg.Environment})
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "warnings": s.profileWarnings(r.Context(), &cfg)})
}

func (s *Server) previewEC(w http.ResponseWriter, r *http.Request, _ actor) {
	cfg, err := s.profile(r)
	if err != nil {
		storeErr(w, err)
		return
	}
	raw, es, err := s.RP.EntityConfiguration(r.Context(), cfg)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jwt": raw, "payload": es, "well_known_url": oidcfed.WellKnownURL(cfg.EntityID)})
}

// -------------------------------------------------------------- providers

func (s *Server) listProviders(w http.ResponseWriter, r *http.Request, _ actor) {
	out, err := s.Store.ListProviders(r.Context(), model.Profile(r.URL.Query().Get("profile")), false)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) saveProvider(w http.ResponseWriter, r *http.Request, a actor) {
	var pr model.Provider
	if err := decode(r, &pr); err != nil {
		storeErr(w, fmt.Errorf("invalid body: %w", err))
		return
	}
	if id := r.PathValue("id"); id != "" {
		pr.ID = id
	} else {
		pr.ID = ""
	}
	if _, err := model.ParseProfile(string(pr.Profile)); err != nil {
		storeErr(w, err)
		return
	}
	if err := oidcfed.ValidateEntityID(pr.EntityID); err != nil {
		storeErr(w, err)
		return
	}
	if strings.TrimSpace(pr.DisplayName) == "" || len(pr.DisplayName) > 120 {
		storeErr(w, errors.New("display_name is required (max 120 chars)"))
		return
	}
	if pr.LogoURI != "" && !strings.HasPrefix(pr.LogoURI, "https://") && !strings.HasPrefix(pr.LogoURI, "/") {
		storeErr(w, errors.New("logo_uri must be https or a relative path"))
		return
	}
	if err := s.Store.UpsertProvider(r.Context(), &pr); err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "admin.federation.provider_saved", "success", a.ID, map[string]any{"profile": pr.Profile, "entity_id": pr.EntityID, "enabled": pr.Enabled})
	writeJSON(w, http.StatusOK, pr)
}

func (s *Server) deleteProvider(w http.ResponseWriter, r *http.Request, a actor) {
	if err := s.Store.DeleteProvider(r.Context(), r.PathValue("id")); err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "admin.federation.provider_deleted", "success", a.ID, map[string]any{"id": r.PathValue("id")})
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------- trust anchors

func (s *Server) listTAs(w http.ResponseWriter, r *http.Request, _ actor) {
	out, err := s.Store.ListTrustAnchors(r.Context(), model.Profile(r.URL.Query().Get("profile")), false)
	if err != nil {
		storeErr(w, err)
		return
	}
	type view struct {
		model.TrustAnchor
		Thumbprints []string `json:"thumbprints"`
	}
	res := make([]view, 0, len(out))
	for _, ta := range out {
		v := view{TrustAnchor: ta}
		for _, k := range ta.JWKS.Keys {
			tp, _ := fedjose.Thumbprint(k.Key)
			v.Thumbprints = append(v.Thumbprints, tp)
		}
		res = append(res, v)
	}
	writeJSON(w, http.StatusOK, res)
}

func validateTAKeys(set jose.JSONWebKeySet) error {
	if len(set.Keys) == 0 {
		return errors.New("trust anchor jwks must contain at least one key")
	}
	for _, k := range set.Keys {
		if !k.IsPublic() {
			return errors.New("trust anchor jwks must contain public keys only")
		}
		if k.KeyID == "" {
			return errors.New("every trust anchor key needs a kid")
		}
	}
	return nil
}

func (s *Server) saveTA(w http.ResponseWriter, r *http.Request, a actor) {
	var ta model.TrustAnchor
	if err := decode(r, &ta); err != nil {
		storeErr(w, fmt.Errorf("invalid body: %w", err))
		return
	}
	ta.ID = r.PathValue("id")
	if _, err := model.ParseProfile(string(ta.Profile)); err != nil {
		storeErr(w, err)
		return
	}
	if err := oidcfed.ValidateEntityID(ta.EntityID); err != nil {
		storeErr(w, err)
		return
	}
	if err := validateTAKeys(ta.JWKS); err != nil {
		storeErr(w, err)
		return
	}
	if err := s.Store.UpsertTrustAnchor(r.Context(), &ta); err != nil {
		storeErr(w, err)
		return
	}
	s.RP.Resolvers.Reset()
	var tps []string
	for _, k := range ta.JWKS.Keys {
		tp, _ := fedjose.Thumbprint(k.Key)
		tps = append(tps, tp)
	}
	s.Audit.Emit(r.Context(), "admin.federation.trust_anchor_saved", "success", a.ID, map[string]any{"profile": ta.Profile, "entity_id": ta.EntityID, "thumbprints": tps, "enabled": ta.Enabled})
	writeJSON(w, http.StatusOK, ta)
}

func (s *Server) deleteTA(w http.ResponseWriter, r *http.Request, a actor) {
	if err := s.Store.DeleteTrustAnchor(r.Context(), r.PathValue("id")); err != nil {
		storeErr(w, err)
		return
	}
	s.RP.Resolvers.Reset()
	s.Audit.Emit(r.Context(), "admin.federation.trust_anchor_deleted", "success", a.ID, map[string]any{"id": r.PathValue("id")})
	w.WriteHeader(http.StatusNoContent)
}

// previewTA fetches a (self-signed) entity configuration so an operator can
// compare key thumbprints with values obtained out of band before pinning.
// Nothing is persisted.
func (s *Server) previewTA(w http.ResponseWriter, r *http.Request, _ actor) {
	var body struct {
		EntityID string `json:"entity_id"`
	}
	if err := decode(r, &body); err != nil || oidcfed.ValidateEntityID(body.EntityID) != nil {
		storeErr(w, errors.New("valid entity_id required"))
		return
	}
	res := &oidcfed.Resolver{Fetcher: httpFetcher{s}, Algs: fedjose.DefaultSigningAlgs, Skew: 30 * time.Second}
	ec, err := res.FetchEntityConfiguration(r.Context(), body.EntityID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	var tps []map[string]string
	for _, k := range ec.JWKS.Keys {
		tp, _ := fedjose.Thumbprint(k.Key)
		tps = append(tps, map[string]string{"kid": k.KeyID, "thumbprint_sha256": tp})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entity_id": ec.Sub, "jwks": ec.JWKS, "thumbprints": tps, "exp": ec.Exp,
		"federation_entity": ec.FederationEntity(),
		"warning":           "Verify these thumbprints through an authenticated out-of-band channel before pinning the trust anchor.",
	})
}

type httpFetcher struct{ s *Server }

func (f httpFetcher) Get(ctx context.Context, url, accept string) ([]byte, string, error) {
	return f.s.RP.HTTP.Get(ctx, url, accept)
}

// ------------------------------------------------------------------- keys

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request, _ actor) {
	recs, err := s.Store.ListKeys(r.Context(), model.Profile(r.URL.Query().Get("profile")))
	if err != nil {
		storeErr(w, err)
		return
	}
	out := make([]*model.KeyInfo, 0, len(recs))
	for _, rec := range recs {
		out = append(out, keys.Describe(rec))
	}
	writeJSON(w, http.StatusOK, out)
}

func keyProfile(p string) (model.Profile, error) {
	if p == string(model.ProfileFacade) {
		return model.ProfileFacade, nil
	}
	return model.ParseProfile(p)
}

func (s *Server) generateKey(w http.ResponseWriter, r *http.Request, a actor) {
	var body struct {
		Profile string `json:"profile"`
		Purpose string `json:"purpose"`
		KeyType string `json:"key_type"`
		Alg     string `json:"alg"`
		Status  string `json:"status"`
	}
	if err := decode(r, &body); err != nil {
		storeErr(w, err)
		return
	}
	p, err := keyProfile(body.Profile)
	if err != nil {
		storeErr(w, err)
		return
	}
	info, err := s.Keys.Generate(r.Context(), p, body.Purpose, fedjose.KeyType(body.KeyType), body.Alg, body.Status)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "key.generated", "success", a.ID, map[string]any{"profile": p, "purpose": body.Purpose, "kid": info.Kid, "status": info.Status})
	writeJSON(w, http.StatusCreated, info)
}

func (s *Server) importKey(w http.ResponseWriter, r *http.Request, a actor) {
	var body struct {
		Profile        string `json:"profile"`
		Purpose        string `json:"purpose"`
		Alg            string `json:"alg"`
		PrivateKeyPEM  string `json:"private_key_pem"`
		CertificatePEM string `json:"certificate_pem"`
		Status         string `json:"status"`
	}
	if err := decode(r, &body); err != nil {
		storeErr(w, err)
		return
	}
	p, err := keyProfile(body.Profile)
	if err != nil {
		storeErr(w, err)
		return
	}
	info, err := s.Keys.Import(r.Context(), p, body.Purpose, body.Alg, []byte(body.PrivateKeyPEM), []byte(body.CertificatePEM), body.Status)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "key.imported", "success", a.ID, map[string]any{"profile": p, "purpose": body.Purpose, "kid": info.Kid, "status": info.Status})
	writeJSON(w, http.StatusCreated, info)
}

func (s *Server) activateKey(w http.ResponseWriter, r *http.Request, a actor) {
	rec, err := s.Store.ActivateKey(r.Context(), r.PathValue("id"))
	if err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "key.rotated", "success", a.ID, map[string]any{"profile": rec.Profile, "purpose": rec.Purpose, "kid": rec.Kid})
	writeJSON(w, http.StatusOK, keys.Describe(rec))
}

func (s *Server) retireKey(w http.ResponseWriter, r *http.Request, a actor) {
	if err := s.Store.RetireKey(r.Context(), r.PathValue("id")); err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "key.retired", "success", a.ID, map[string]any{"id": r.PathValue("id")})
	info, _ := s.Keys.Info(r.Context(), r.PathValue("id"))
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request, a actor) {
	if err := s.Store.DeleteKey(r.Context(), r.PathValue("id")); err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "key.deleted", "success", a.ID, map[string]any{"id": r.PathValue("id")})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keyCSR(w http.ResponseWriter, r *http.Request, a actor) {
	var subj fedjose.SubjectInfo
	if err := decode(r, &subj); err != nil {
		storeErr(w, err)
		return
	}
	csr, err := s.Keys.CSR(r.Context(), r.PathValue("id"), subj)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "key.csr_created", "success", a.ID, map[string]any{"id": r.PathValue("id")})
	writeJSON(w, http.StatusOK, map[string]string{"csr_pem": string(csr)})
}

func (s *Server) keySelfSigned(w http.ResponseWriter, r *http.Request, a actor) {
	var body struct {
		fedjose.SubjectInfo
		Days int `json:"days"`
	}
	if err := decode(r, &body); err != nil {
		storeErr(w, err)
		return
	}
	if body.Days == 0 {
		body.Days = 365
	}
	info, err := s.Keys.SelfSign(r.Context(), r.PathValue("id"), body.SubjectInfo, body.Days)
	if err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "key.certificate_attached", "success", a.ID, map[string]any{"id": r.PathValue("id"), "self_signed": true})
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) keyCertificate(w http.ResponseWriter, r *http.Request, a actor) {
	var body struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := decode(r, &body); err != nil {
		storeErr(w, err)
		return
	}
	info, err := s.Keys.AttachCertificate(r.Context(), r.PathValue("id"), []byte(body.CertificatePEM))
	if err != nil {
		storeErr(w, err)
		return
	}
	s.Audit.Emit(r.Context(), "key.certificate_attached", "success", a.ID, map[string]any{"id": r.PathValue("id"), "fingerprint": info.Certificate.Fingerprint})
	writeJSON(w, http.StatusOK, info)
}

// ------------------------------------------------------------------ trust

func (s *Server) trustResolve(w http.ResponseWriter, r *http.Request, _ actor) {
	var body struct {
		Profile    string `json:"profile"`
		EntityID   string `json:"entity_id"`
		EntityType string `json:"entity_type"`
		NoCache    bool   `json:"no_cache"`
	}
	if err := decode(r, &body); err != nil {
		storeErr(w, err)
		return
	}
	p, err := model.ParseProfile(body.Profile)
	if err != nil {
		storeErr(w, err)
		return
	}
	if body.EntityType == "" {
		body.EntityType = oidcfed.EntityTypeOP
	}
	res, err := s.RP.Resolvers.For(r.Context(), p)
	if err != nil {
		storeErr(w, err)
		return
	}
	if body.NoCache {
		res.Invalidate(body.EntityID)
	}
	chain, err := res.Resolve(r.Context(), body.EntityID, body.EntityType)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"trusted": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"trusted": true, "chain": chain})
}

func (s *Server) trustRefresh(w http.ResponseWriter, r *http.Request, a actor) {
	s.RP.Resolvers.Reset()
	s.Audit.Emit(r.Context(), "admin.federation.trust_refreshed", "success", a.ID, nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request, _ actor) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	type provStatus struct {
		model.Provider
		Trusted    bool      `json:"trusted"`
		Error      string    `json:"error,omitempty"`
		ChainExp   time.Time `json:"chain_exp,omitempty"`
		TrustMarks []string  `json:"trust_marks,omitempty"`
	}
	out := map[string]any{"generated_at": time.Now().UTC(), "environment": s.Cfg.Env}
	providers, _ := s.Store.ListProviders(ctx, "", false)
	statuses := make([]provStatus, len(providers))
	var wg sync.WaitGroup
	for i, pr := range providers {
		statuses[i] = provStatus{Provider: pr}
		if !pr.Enabled {
			continue
		}
		wg.Add(1)
		go func(i int, pr model.Provider) {
			defer wg.Done()
			res, err := s.RP.Resolvers.For(ctx, pr.Profile)
			if err != nil {
				statuses[i].Error = err.Error()
				return
			}
			chain, err := res.Resolve(ctx, pr.EntityID, oidcfed.EntityTypeOP)
			if err != nil {
				statuses[i].Error = err.Error()
				return
			}
			statuses[i].Trusted, statuses[i].ChainExp = true, chain.Exp
			for _, tm := range chain.TrustMarks {
				statuses[i].TrustMarks = append(statuses[i].TrustMarks, tm.Type)
			}
		}(i, pr)
	}
	wg.Wait()
	out["providers"] = statuses
	recs, _ := s.Store.ListKeys(ctx, "")
	keyViews := []*model.KeyInfo{}
	for _, rec := range recs {
		if rec.Status != model.KeyRetired {
			keyViews = append(keyViews, keys.Describe(rec))
		}
	}
	out["keys"] = keyViews
	profiles := []map[string]any{}
	for _, p := range []model.Profile{model.ProfileSPID, model.ProfileCIE} {
		cfg, err := s.Store.GetProfile(ctx, p)
		if err != nil {
			continue
		}
		rpStatus := map[string]any{"profile": p, "enabled": cfg.Enabled, "entity_id": cfg.EntityID, "environment": cfg.Environment, "warnings": s.profileWarnings(ctx, cfg)}
		// Self-check: our own entity configuration must chain to an anchor.
		if res, err := s.RP.Resolvers.For(ctx, p); err == nil && len(res.Anchors) > 0 {
			if chain, err := res.Resolve(ctx, cfg.EntityID, oidcfed.EntityTypeRP); err != nil {
				rpStatus["self_trust"] = map[string]any{"trusted": false, "error": err.Error()}
			} else {
				rpStatus["self_trust"] = map[string]any{"trusted": true, "exp": chain.Exp, "trust_marks": chain.TrustMarks, "trust_mark_errors": chain.TrustMarkErrors}
			}
		}
		profiles = append(profiles, rpStatus)
	}
	out["profiles"] = profiles
	stats, _ := s.Store.Stats(ctx, time.Now().Add(-24*time.Hour))
	out["auth_last_24h"] = stats
	failures, _ := s.Store.RecentFailures(ctx, 25)
	if failures == nil {
		failures = []map[string]any{}
	}
	out["recent_failures"] = failures
	writeJSON(w, http.StatusOK, out)
}

// --------------------------------------------------------------- internal

func (s *Server) registerInternal(mux *http.ServeMux) {
	mux.HandleFunc("GET /internal/auth-results", s.internalAuth(s.findResults))
	mux.HandleFunc("GET /internal/auth-results/{id}", s.internalAuth(s.getResult))
	mux.HandleFunc("POST /internal/auth-results/{id}/bind", s.internalAuth(s.bindResult))
}

func (s *Server) findResults(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	subjects := q["subject"]
	if len(subjects) == 0 || len(subjects) > 50 {
		storeErr(w, errors.New("1..50 subject parameters required"))
		return
	}
	since, err1 := time.Parse(time.RFC3339, q.Get("since"))
	until, err2 := time.Parse(time.RFC3339, q.Get("until"))
	if err1 != nil || err2 != nil || until.Sub(since) > time.Hour || until.Before(since) {
		storeErr(w, errors.New("since/until must be RFC3339 and span at most one hour"))
		return
	}
	res, err := s.Store.FindResults(r.Context(), subjects, since, until)
	if err != nil {
		storeErr(w, err)
		return
	}
	if res == nil {
		res = []*store.AuthResult{}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) getResult(w http.ResponseWriter, r *http.Request) {
	res, err := s.Store.GetResult(r.Context(), r.PathValue("id"))
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "attributes": s.attributes(res)})
}

func (s *Server) bindResult(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IdentityID string `json:"identity_id"`
		SessionID  string `json:"session_id"`
	}
	if err := decode(r, &body); err != nil {
		storeErr(w, err)
		return
	}
	if _, err := uuid.Parse(body.IdentityID); err != nil {
		storeErr(w, errors.New("identity_id must be a UUID"))
		return
	}
	if _, err := uuid.Parse(body.SessionID); err != nil {
		storeErr(w, errors.New("session_id must be a UUID"))
		return
	}
	if err := s.Store.BindResult(r.Context(), r.PathValue("id"), body.IdentityID, body.SessionID); err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"bound": true})
}
