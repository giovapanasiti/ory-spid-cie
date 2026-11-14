package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/enpam/iam/federation-broker/internal/fedjose"
	"github.com/enpam/iam/federation-broker/internal/model"
	"github.com/enpam/iam/federation-broker/internal/oidcfed"
	"github.com/enpam/iam/federation-broker/internal/rp"
	"github.com/enpam/iam/federation-broker/internal/store"
)

const reqCookie = "fedbroker_req"

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ------------------------------------------------------------- federation

func (s *Server) entityConfiguration(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.profile(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	raw, _, err := s.RP.EntityConfiguration(r.Context(), cfg)
	if err != nil {
		s.Log.Error("entity configuration", "err", err)
		http.Error(w, "entity configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", oidcfed.ContentTypeEntityStmt)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write([]byte(raw))
}

// resolveEndpoint implements federation_resolve_endpoint (accepts both the
// "trust_anchor" parameter of OpenID Federation Final and the legacy "anchor").
func (s *Server) resolveEndpoint(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.profile(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	sub := q.Get("sub")
	anchor := q.Get("trust_anchor")
	if anchor == "" {
		anchor = q.Get("anchor")
	}
	entityType := q.Get("entity_type")
	if entityType == "" {
		entityType = oidcfed.EntityTypeOP
	}
	if sub == "" || anchor == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "sub and trust_anchor are required")
		return
	}
	res, err := s.RP.Resolvers.For(r.Context(), cfg.Profile)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "resolver unavailable")
		return
	}
	known := false
	for _, a := range res.Anchors {
		if a.EntityID == anchor {
			known = true
		}
	}
	if !known {
		oauthError(w, http.StatusNotFound, "invalid_trust_anchor", "unknown trust anchor")
		return
	}
	chain, err := res.Resolve(r.Context(), sub, entityType)
	if err != nil || chain.Anchor != anchor {
		oauthError(w, http.StatusNotFound, "invalid_trust_chain", "trust chain could not be established")
		return
	}
	signer, err := s.Keys.Signing(r.Context(), cfg.Profile, model.PurposeFederation)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "no signing key")
		return
	}
	now := time.Now().UTC()
	payload := map[string]any{
		"iss": cfg.EntityID, "sub": sub, "iat": now.Unix(), "exp": chain.Exp.Unix(),
		"metadata": chain.Metadata, "trust_chain": chain.Raw,
	}
	var tms []map[string]string
	for _, ref := range chain.Leaf().TrustMarks {
		for _, v := range chain.TrustMarks {
			if v.Type == ref.Type() {
				tms = append(tms, map[string]string{"id": v.Type, "trust_mark_type": v.Type, "trust_mark": ref.TrustMark})
			}
		}
	}
	if len(tms) > 0 {
		payload["trust_marks"] = tms
	}
	jwt, err := fedjose.Sign(payload, signer, fedjose.TypResolveResponse)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "signing failed")
		return
	}
	w.Header().Set("Content-Type", oidcfed.ContentTypeResolveResp)
	w.Write([]byte(jwt))
}

// ----------------------------------------------------------------- facade

func (s *Server) facadeIssuer(p model.Profile) string {
	return s.Cfg.InternalURL + "/oidc/" + string(p)
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	p, err := model.ParseProfile(r.PathValue("profile"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	iss := s.facadeIssuer(p)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                s.Cfg.PublicURL + "/oidc/" + string(p) + "/authorize",
		"token_endpoint":                        iss + "/token",
		"userinfo_endpoint":                     iss + "/userinfo",
		"jwks_uri":                              iss + "/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "given_name", "family_name", "email", "acr", "amr", "auth_time", "loa", "fed_result_id"},
		"acr_values_supported":                  []string{model.LoALow, model.LoASubstantial, model.LoAHigh},
	})
}

func (s *Server) facadeJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := s.Keys.PublicJWKS(r.Context(), model.ProfileFacade, model.PurposeFacadeSig)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, set)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// requestedLoA picks the strictest recognised value among acr_values.
func requestedLoA(cfg *model.RPProfile, acrValues string) string {
	best := ""
	for _, v := range strings.Fields(acrValues) {
		l := v
		if model.LoARank(l) < 0 {
			l = cfg.LoAForACR(v)
		}
		if model.LoARank(l) > model.LoARank(best) {
			best = l
		}
	}
	return best
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cfg, err := s.profile(r)
	if err != nil {
		s.userError(w, r, http.StatusNotFound, rp.FailConfig)
		return
	}
	// Validate client and redirect URI before any redirect (no open redirect).
	if !tokenEqual(q.Get("client_id"), s.Cfg.FacadeClientID) || !slices.Contains(s.Cfg.FacadeRedirectURIs, q.Get("redirect_uri")) {
		s.userError(w, r, http.StatusBadRequest, rp.FailConfig)
		return
	}
	redirectURI, state := q.Get("redirect_uri"), q.Get("state")
	switch {
	case state == "" || len(state) > 1024:
		redirectWithError(w, r, redirectURI, state, "invalid_request", "state required")
		return
	case q.Get("response_type") != "code":
		redirectWithError(w, r, redirectURI, state, "unsupported_response_type", "")
		return
	case !slices.Contains(strings.Fields(q.Get("scope")), "openid"):
		redirectWithError(w, r, redirectURI, state, "invalid_scope", "openid scope required")
		return
	case q.Get("code_challenge") != "" && q.Get("code_challenge_method") != "S256":
		redirectWithError(w, r, redirectURI, state, "invalid_request", "only S256 PKCE is supported")
		return
	case len(q.Get("nonce")) > 1024:
		redirectWithError(w, r, redirectURI, state, "invalid_request", "nonce too long")
		return
	case !cfg.Enabled:
		redirectWithError(w, r, redirectURI, state, "temporarily_unavailable", "profile_disabled")
		return
	}
	loa := requestedLoA(cfg, q.Get("acr_values"))
	if loa == "" {
		loa = cfg.DefaultLoA
	}
	if _, ok := cfg.ACRForLoA(loa); !ok {
		redirectWithError(w, r, redirectURI, state, "access_denied", rp.FailInsufficientLoA)
		return
	}
	req := &store.AuthRequest{
		Profile: cfg.Profile, ClientID: q.Get("client_id"), RedirectURI: redirectURI, ClientState: state,
		ClientNonce: q.Get("nonce"), ClientCodeChallenge: q.Get("code_challenge"), RequestedLoA: loa,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := s.Store.CreateAuthRequest(r.Context(), req); err != nil {
		s.Log.Error("create auth request", "err", err)
		redirectWithError(w, r, redirectURI, state, "server_error", "")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: reqCookie, Value: req.ID, Path: "/", HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	providers, err := s.Store.ListProviders(r.Context(), cfg.Profile, true)
	if err != nil || len(providers) == 0 {
		redirectWithError(w, r, redirectURI, state, "temporarily_unavailable", "no_provider")
		return
	}
	if len(providers) == 1 && cfg.Profile == model.ProfileCIE {
		s.startUpstream(w, r, cfg, req, providers[0].EntityID)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "select.html", map[string]any{
		"Profile": cfg.Profile, "RequestID": req.ID, "Providers": providers, "LoA": loa,
	})
}

func (s *Server) selectProvider(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.profile(r)
	if err != nil {
		s.userError(w, r, http.StatusNotFound, rp.FailConfig)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.userError(w, r, http.StatusBadRequest, rp.FailExpired)
		return
	}
	reqID := r.PostForm.Get("request_id")
	c, err := r.Cookie(reqCookie)
	if err != nil || !tokenEqual(c.Value, reqID) {
		s.userError(w, r, http.StatusBadRequest, rp.FailExpired)
		return
	}
	req, err := s.Store.GetPendingAuthRequest(r.Context(), reqID)
	if err != nil || req.Profile != cfg.Profile {
		s.userError(w, r, http.StatusBadRequest, rp.FailExpired)
		return
	}
	if r.PostForm.Get("action") == "cancel" {
		_ = s.Store.FailAuthRequest(r.Context(), req.ID, rp.FailCancelled)
		s.Audit.Emit(r.Context(), "federation.authentication", "failure", "", map[string]any{"profile": cfg.Profile, "reason": rp.FailCancelled})
		redirectWithError(w, r, req.RedirectURI, req.ClientState, "access_denied", rp.FailCancelled)
		return
	}
	providers, err := s.Store.ListProviders(r.Context(), cfg.Profile, true)
	if err != nil {
		s.userError(w, r, http.StatusInternalServerError, rp.FailConfig)
		return
	}
	chosen := r.PostForm.Get("provider")
	for _, p := range providers {
		if p.ID == chosen {
			s.startUpstream(w, r, cfg, req, p.EntityID)
			return
		}
	}
	s.userError(w, r, http.StatusBadRequest, rp.FailConfig)
}

func (s *Server) startUpstream(w http.ResponseWriter, r *http.Request, cfg *model.RPProfile, req *store.AuthRequest, opEntityID string) {
	target, err := s.RP.StartAuth(r.Context(), cfg, req, opEntityID)
	if err != nil {
		reason := rp.FailConfig
		var f *rp.Failure
		if errors.As(err, &f) {
			reason = f.Code
		}
		s.Log.Warn("start upstream authentication failed", "err", err, "op", opEntityID)
		_ = s.Store.FailAuthRequest(r.Context(), req.ID, reason)
		mAuth.WithLabelValues(string(cfg.Profile), reason).Inc()
		s.Audit.Emit(r.Context(), "federation.trust", "failure", "", map[string]any{"profile": cfg.Profile, "op_entity_id": opEntityID, "reason": reason})
		redirectWithError(w, r, req.RedirectURI, req.ClientState, "access_denied", reason)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	browserReq := ""
	if c, err := r.Cookie(reqCookie); err == nil {
		browserReq = c.Value
	}
	http.SetCookie(w, &http.Cookie{Name: reqCookie, Value: "", Path: "/", HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	out, err := s.RP.HandleCallback(r.Context(), s.profileByName(r.Context()), r.URL.Query(), browserReq)
	if err != nil {
		var f *rp.Failure
		if !errors.As(err, &f) {
			f = &rp.Failure{Code: rp.FailInvalidResponse, Detail: err.Error()}
		}
		s.Log.Warn("federated authentication failed", "reason", f.Code, "detail", f.Detail)
		profile := r.PathValue("profile")
		ctx := map[string]any{"profile": profile, "reason": f.Code}
		evType := "federation.authentication"
		if f.Code == rp.FailUntrusted {
			evType = "federation.trust"
		}
		if f.Request != nil {
			ctx["op_entity_id"] = f.Request.OPEntityID
			_ = s.Store.FailAuthRequest(r.Context(), f.Request.ID, f.Code)
		}
		mAuth.WithLabelValues(profile, f.Code).Inc()
		s.Audit.Emit(r.Context(), evType, "failure", "", ctx)
		if f.Request != nil && f.Code != rp.FailReplay {
			redirectWithError(w, r, f.Request.RedirectURI, f.Request.ClientState, "access_denied", f.Code)
			return
		}
		s.userError(w, r, http.StatusBadRequest, f.Code)
		return
	}
	attrs, _ := json.Marshal(out.Attributes)
	code := randomToken()
	res := &store.AuthResult{
		RequestID: out.Request.ID, Profile: string(out.Request.Profile), OPEntityID: out.OP.EntityID, OPIssuer: out.OP.Issuer,
		ExternalSub: out.ExternalSub, SubjectHash: rp.SubjectHash(out.OP.Issuer, out.ExternalSub), ACR: out.ACR, LoA: out.LoA,
		AuthTime: out.AuthTime, CodeHash: hashToken(code), CodeExpiresAt: time.Now().Add(60 * time.Second),
	}
	res.ID = newUUID()
	sealed, err := s.Keys.Sealer.Seal(attrs, []byte("attrs:"+res.ID))
	if err != nil {
		s.userError(w, r, http.StatusInternalServerError, rp.FailConfig)
		return
	}
	res.AttributesEnc = sealed
	if err := s.Store.InsertAuthResult(r.Context(), res); err != nil {
		s.Log.Error("store auth result", "err", err)
		s.userError(w, r, http.StatusInternalServerError, rp.FailConfig)
		return
	}
	mAuth.WithLabelValues(string(out.Request.Profile), "success").Inc()
	s.Audit.Emit(r.Context(), "federation.authentication", "success", "", map[string]any{
		"profile": out.Request.Profile, "op_entity_id": out.OP.EntityID, "acr": out.ACR, "loa": out.LoA,
		"result_id": res.ID, "subject_hash": res.SubjectHash, "attribute_warnings": out.Warnings,
	})
	u, _ := url.Parse(out.Request.RedirectURI)
	qq := u.Query()
	qq.Set("code", code)
	qq.Set("state", out.Request.ClientState)
	qq.Set("iss", s.facadeIssuer(out.Request.Profile))
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) clientAuth(r *http.Request) (string, bool) {
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if tokenEqual(id, s.Cfg.FacadeClientID) && tokenEqual(secret, s.Cfg.FacadeClientSecret) {
		return id, true
	}
	return "", false
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	p, err := model.ParseProfile(r.PathValue("profile"))
	if err != nil {
		oauthError(w, http.StatusNotFound, "invalid_request", "unknown profile")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	clientID, ok := s.clientAuth(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="federation-broker"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}
	accessToken := randomToken()
	res, err := s.Store.RedeemCode(r.Context(), hashToken(r.PostForm.Get("code")), hashToken(accessToken))
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.Audit.Emit(r.Context(), "federation.code_replay", "failure", clientID, map[string]any{"profile": p})
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	if res.Profile != string(p) || res.ClientID != clientID || res.RedirectURI != r.PostForm.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	if res.CodeChallenge != "" && rp.PKCEChallenge(r.PostForm.Get("code_verifier")) != res.CodeChallenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	attrs := s.attributes(res)
	signer, err := s.Keys.Signing(r.Context(), model.ProfileFacade, model.PurposeFacadeSig)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": s.facadeIssuer(p), "sub": res.SubjectHash, "aud": clientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"auth_time": res.AuthTime.Unix(), "acr": res.ACR, "amr": []string{string(p)}, "loa": res.LoA, "fed_result_id": res.ID,
	}
	if res.ClientNonce != "" {
		claims["nonce"] = res.ClientNonce
	}
	if at, err := rp.AtHash(accessToken, string(signer.Alg)); err == nil {
		claims["at_hash"] = at
	}
	for _, k := range []string{"given_name", "family_name", "email"} {
		if v, ok := attrs[k]; ok {
			claims[k] = v
		}
	}
	idToken, err := fedjose.Sign(claims, signer, "JWT")
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 300, "id_token": idToken, "scope": "openid"})
}

func (s *Server) attributes(res *store.AuthResult) map[string]any {
	out := map[string]any{}
	if len(res.AttributesEnc) == 0 {
		return out
	}
	pt, err := s.Keys.Sealer.Open(res.AttributesEnc, []byte("attrs:"+res.ID))
	if err != nil {
		s.Log.Error("unseal attributes", "err", err)
		return out
	}
	_ = json.Unmarshal(pt, &out)
	return out
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	tok := bearer(r)
	if tok == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	res, err := s.Store.ResultByAccessToken(r.Context(), hashToken(tok), 5*time.Minute)
	if err != nil || res.Profile != r.PathValue("profile") {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	attrs := s.attributes(res)
	out := map[string]any{"sub": res.SubjectHash, "acr": res.ACR, "loa": res.LoA}
	for _, k := range []string{"given_name", "family_name", "email"} {
		if v, ok := attrs[k]; ok {
			out[k] = v
		}
	}
	writeJSON(w, http.StatusOK, out)
}
