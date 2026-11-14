package rp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/enpam/iam/federation-broker/internal/fedjose"
	"github.com/enpam/iam/federation-broker/internal/keys"
	"github.com/enpam/iam/federation-broker/internal/model"
	"github.com/enpam/iam/federation-broker/internal/oidcfed"
	"github.com/enpam/iam/federation-broker/internal/safehttp"
	"github.com/enpam/iam/federation-broker/internal/seal"
	"github.com/enpam/iam/federation-broker/internal/store"
)

// Service is the federation Relying Party.
type Service struct {
	Store     *store.Store
	Keys      *keys.Manager
	Resolvers *Resolvers
	HTTP      *safehttp.Client
	Sealer    *seal.Sealer
	Now       func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func secondsDur(n int) time.Duration { return time.Duration(n) * time.Second }

// Failure is a classified, user-safe authentication failure.
type Failure struct {
	Code    string // stable reason code shown to users / audit
	Detail  string // internal detail (logs only, never shown to users)
	Request *store.AuthRequest
}

func (f *Failure) Error() string { return f.Code + ": " + f.Detail }

// Failure codes.
const (
	FailCancelled        = "cancelled"
	FailUntrusted        = "federation_untrusted"
	FailOPUnavailable    = "provider_unavailable"
	FailInvalidResponse  = "invalid_response"
	FailInsufficientLoA  = "insufficient_assurance"
	FailMissingAttribute = "missing_attributes"
	FailReplay           = "replay_detected"
	FailExpired          = "flow_expired"
	FailConfig           = "configuration_error"
)

func fail(code string, req *store.AuthRequest, format string, a ...any) *Failure {
	return &Failure{Code: code, Detail: fmt.Sprintf(format, a...), Request: req}
}

// ------------------------------------------------------ entity configuration

// EntityConfiguration builds and signs the RP Entity Configuration.
func (s *Service) EntityConfiguration(ctx context.Context, cfg *model.RPProfile) (string, *oidcfed.EntityStatement, error) {
	fedKeys, err := s.Keys.PublicJWKS(ctx, cfg.Profile, model.PurposeFederation)
	if err != nil {
		return "", nil, err
	}
	coreKeys, err := s.Keys.PublicJWKS(ctx, cfg.Profile, model.PurposeCoreSig, model.PurposeCoreEnc)
	if err != nil {
		return "", nil, err
	}
	signer, err := s.Keys.Signing(ctx, cfg.Profile, model.PurposeFederation)
	if err != nil {
		return "", nil, err
	}
	now := s.now().UTC()
	fe := map[string]any{
		"organization_name":           cfg.OrganizationName,
		"homepage_uri":                cfg.HomepageURI,
		"policy_uri":                  cfg.PolicyURI,
		"contacts":                    cfg.Contacts,
		"federation_resolve_endpoint": strings.TrimRight(cfg.EntityID, "/") + "/resolve",
	}
	if cfg.LogoURI != "" {
		fe["logo_uri"] = cfg.LogoURI
	}
	rpMeta := map[string]any{
		"client_id":                       cfg.EntityID,
		"client_registration_types":       []string{"automatic"},
		"application_type":                "web",
		"client_name":                     cfg.ClientName,
		"contacts":                        cfg.Contacts,
		"redirect_uris":                   cfg.RedirectURIs,
		"response_types":                  []string{"code"},
		"grant_types":                     []string{"authorization_code", "refresh_token"},
		"jwks":                            coreKeys,
		"id_token_signed_response_alg":    cfg.SigningAlg,
		"userinfo_signed_response_alg":    cfg.SigningAlg,
		"userinfo_encrypted_response_alg": cfg.UserinfoEncAlg,
		"userinfo_encrypted_response_enc": cfg.UserinfoEncEnc,
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": cfg.SigningAlg,
		"request_object_signing_alg":      cfg.SigningAlg,
	}
	es := &oidcfed.EntityStatement{
		Iss: cfg.EntityID, Sub: cfg.EntityID,
		Iat: now.Unix(), Exp: now.Add(secondsDur(cfg.EntityConfigTTL)).Unix(),
		JWKS:           fedKeys,
		AuthorityHints: cfg.AuthorityHints,
		Metadata:       map[string]map[string]any{oidcfed.EntityTypeFederation: fe, oidcfed.EntityTypeRP: rpMeta},
	}
	for _, tm := range cfg.TrustMarks {
		es.TrustMarks = append(es.TrustMarks, oidcfed.TrustMarkRef{ID: tm.ID, TrustMark: tm.TrustMark})
	}
	raw, err := es.Sign(signer)
	if err != nil {
		return "", nil, err
	}
	es.Raw = raw
	return raw, es, nil
}

// ------------------------------------------------------------- authorization

var alnum = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

// randomAlnum returns n uniformly random alphanumeric characters (state and
// nonce must be >= 32 alphanumerics per SPID/CIE).
func randomAlnum(n int) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alnum)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		out[i] = alnum[v.Int64()]
	}
	return string(out)
}

// PKCEChallenge computes the S256 challenge for a verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// StartAuth prepares the upstream authorization request and returns the
// browser redirect URL.
func (s *Service) StartAuth(ctx context.Context, cfg *model.RPProfile, req *store.AuthRequest, opEntityID string) (string, error) {
	op, err := s.ResolveOP(ctx, cfg.Profile, cfg, opEntityID)
	if err != nil {
		code := FailUntrusted
		if errors.Is(err, safehttp.ErrBlocked) {
			code = FailConfig
		}
		return "", fail(code, req, "resolve OP %s: %v", opEntityID, err)
	}
	loa := req.RequestedLoA
	if model.LoARank(loa) < 1 {
		loa = cfg.DefaultLoA
	}
	acr, ok := cfg.ACRForLoA(loa)
	if !ok {
		return "", fail(FailInsufficientLoA, req, "no ACR mapped for %s", loa)
	}
	if len(op.ACRValuesSupported) > 0 && !slices.Contains(op.ACRValuesSupported, acr) {
		return "", fail(FailInsufficientLoA, req, "OP does not support %s", acr)
	}
	signer, err := s.Keys.Signing(ctx, cfg.Profile, model.PurposeCoreSig)
	if err != nil {
		return "", fail(FailConfig, req, "%v", err)
	}
	req.OPEntityID = opEntityID
	req.RPState = randomAlnum(48)
	req.RPNonce = randomAlnum(48)
	req.CodeVerifier = randomAlnum(64)
	req.RequestedACR = acr
	if err := s.Store.MarkRedirected(ctx, req); err != nil {
		return "", fail(FailExpired, req, "auth request no longer pending")
	}
	scope := scopeString(cfg.Scopes)
	now := s.now().UTC()
	ro := map[string]any{
		"iss":                   cfg.EntityID,
		"sub":                   cfg.EntityID,
		"aud":                   []string{op.Issuer},
		"iat":                   now.Unix(),
		"exp":                   now.Add(2 * time.Minute).Unix(),
		"jti":                   uuid.NewString(),
		"client_id":             cfg.EntityID,
		"response_type":         "code",
		"scope":                 scope,
		"redirect_uri":          cfg.RedirectURIs[0],
		"state":                 req.RPState,
		"nonce":                 req.RPNonce,
		"code_challenge":        PKCEChallenge(req.CodeVerifier),
		"code_challenge_method": "S256",
		"prompt":                "consent login",
		"acr_values":            acr,
	}
	if cfg.UILocales != "" {
		ro["ui_locales"] = cfg.UILocales
	}
	if len(cfg.RequestedClaims) > 0 {
		var claims any
		if err := json.Unmarshal(cfg.RequestedClaims, &claims); err == nil {
			ro["claims"] = claims
		}
	}
	jwt, err := fedjose.Sign(ro, signer, "")
	if err != nil {
		return "", fail(FailConfig, req, "sign request object: %v", err)
	}
	u, err := url.Parse(op.AuthorizationEndpoint)
	if err != nil {
		return "", fail(FailConfig, req, "authorization endpoint: %v", err)
	}
	q := u.Query()
	q.Set("client_id", cfg.EntityID)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("code_challenge", ro["code_challenge"].(string))
	q.Set("code_challenge_method", "S256")
	q.Set("request", jwt)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func scopeString(scopes []string) string {
	out := []string{"openid"}
	for _, s := range scopes {
		if s != "" && s != "openid" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// --------------------------------------------------------------- callback

// Outcome is a successfully validated upstream authentication.
type Outcome struct {
	Request     *store.AuthRequest
	OP          *OPMetadata
	ExternalSub string
	ACR         string
	LoA         string
	AuthTime    time.Time
	Attributes  map[string]any
	Warnings    []string
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// IDTokenClaims are the ID token claims validated by the RP.
type IDTokenClaims struct {
	Iss      string          `json:"iss"`
	Sub      string          `json:"sub"`
	Aud      json.RawMessage `json:"aud"`
	Azp      string          `json:"azp"`
	Exp      int64           `json:"exp"`
	Iat      int64           `json:"iat"`
	Nbf      int64           `json:"nbf"`
	AuthTime int64           `json:"auth_time"`
	Nonce    string          `json:"nonce"`
	ACR      string          `json:"acr"`
	AtHash   string          `json:"at_hash"`
	JTI      string          `json:"jti"`
}

func audiences(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

// HandleCallback validates the OP redirect and the subsequent token and
// UserInfo responses. Every check fails closed.
func (s *Service) HandleCallback(ctx context.Context, cfgFor func(model.Profile) (*model.RPProfile, error), q url.Values, browserReqID string) (*Outcome, error) {
	state := q.Get("state")
	if state == "" {
		return nil, fail(FailInvalidResponse, nil, "missing state")
	}
	req, err := s.Store.ConsumeByRPState(ctx, state)
	if err != nil {
		// Unknown, expired or already used state: possible replay / CSRF.
		return nil, fail(FailReplay, nil, "state not pending: %v", err)
	}
	if browserReqID == "" || browserReqID != req.ID {
		return nil, fail(FailReplay, req, "callback not bound to this browser")
	}
	cfg, err := cfgFor(req.Profile)
	if err != nil {
		return nil, fail(FailConfig, req, "profile: %v", err)
	}
	if e := q.Get("error"); e != "" {
		if e == "access_denied" {
			return nil, fail(FailCancelled, req, "OP returned access_denied")
		}
		return nil, fail(FailOPUnavailable, req, "OP error %q", e)
	}
	op, err := s.ResolveOP(ctx, req.Profile, cfg, req.OPEntityID)
	if err != nil {
		return nil, fail(FailUntrusted, req, "re-resolve OP: %v", err)
	}
	// RFC 9207 mix-up protection; mandatory for CIE.
	if iss := q.Get("iss"); iss != "" {
		if iss != op.Issuer {
			return nil, fail(FailInvalidResponse, req, "iss parameter mismatch")
		}
	} else if req.Profile == model.ProfileCIE {
		return nil, fail(FailInvalidResponse, req, "CIE response without iss parameter")
	}
	code := q.Get("code")
	if code == "" {
		return nil, fail(FailInvalidResponse, req, "missing code")
	}
	tok, err := s.exchangeCode(ctx, cfg, op, req, code)
	if err != nil {
		return nil, err
	}
	claims, err := s.validateIDToken(ctx, cfg, op, req, tok)
	if err != nil {
		return nil, err
	}
	attrs, err := s.fetchUserInfo(ctx, cfg, op, req, tok.AccessToken, claims.Sub)
	if err != nil {
		return nil, err
	}
	// Upstream tokens are not kept: revoke immediately (SPID logout rules
	// require revocation at session end; the broker holds no upstream session).
	go s.revoke(context.WithoutCancel(ctx), cfg, op, tok.AccessToken)

	norm, warnings := NormalizeAttributes(attrs)
	var missing []string
	for _, a := range cfg.RequiredAttributes {
		if _, ok := norm[LocalName(a)]; !ok {
			missing = append(missing, LocalName(a))
		}
	}
	if len(missing) > 0 {
		return nil, fail(FailMissingAttribute, req, "missing %s", strings.Join(missing, ","))
	}
	loa := cfg.LoAForACR(claims.ACR)
	authTime := time.Unix(claims.Iat, 0)
	if claims.AuthTime > 0 {
		authTime = time.Unix(claims.AuthTime, 0)
	}
	return &Outcome{Request: req, OP: op, ExternalSub: claims.Sub, ACR: claims.ACR, LoA: loa, AuthTime: authTime.UTC(), Attributes: norm, Warnings: warnings}, nil
}

func (s *Service) clientAssertion(ctx context.Context, cfg *model.RPProfile, aud string) (string, error) {
	signer, err := s.Keys.Signing(ctx, cfg.Profile, model.PurposeCoreSig)
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	return fedjose.Sign(map[string]any{
		"iss": cfg.EntityID, "sub": cfg.EntityID, "aud": aud,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": uuid.NewString(),
	}, signer, "")
}

func (s *Service) exchangeCode(ctx context.Context, cfg *model.RPProfile, op *OPMetadata, req *store.AuthRequest, code string) (*tokenResponse, error) {
	assertion, err := s.clientAssertion(ctx, cfg, op.TokenEndpoint)
	if err != nil {
		return nil, fail(FailConfig, req, "client assertion: %v", err)
	}
	form := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {cfg.RedirectURIs[0]},
		"client_id":             {cfg.EntityID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"code_verifier":         {req.CodeVerifier},
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, op.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fail(FailConfig, req, "%v", err)
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hreq.Header.Set("Accept", "application/json")
	resp, body, err := s.HTTP.Do(hreq)
	if err != nil {
		return nil, fail(FailOPUnavailable, req, "token endpoint: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fail(FailInvalidResponse, req, "token endpoint status %d", resp.StatusCode)
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fail(FailInvalidResponse, req, "token response: %v", err)
	}
	if tok.AccessToken == "" || tok.IDToken == "" || !strings.EqualFold(tok.TokenType, "bearer") {
		return nil, fail(FailInvalidResponse, req, "token response missing access_token/id_token or not Bearer")
	}
	return &tok, nil
}

func hashForAlg(alg string) (func() hash.Hash, bool) {
	switch {
	case strings.HasSuffix(alg, "256"):
		return sha256.New, true
	case strings.HasSuffix(alg, "384"):
		return sha512.New384, true
	case strings.HasSuffix(alg, "512"):
		return sha512.New, true
	}
	return nil, false
}

// AtHash computes the at_hash for an access token and JWS alg.
func AtHash(accessToken, alg string) (string, error) {
	h, ok := hashForAlg(alg)
	if !ok {
		return "", errors.New("unsupported alg for at_hash")
	}
	d := h()
	d.Write([]byte(accessToken))
	sum := d.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

func (s *Service) validateIDToken(ctx context.Context, cfg *model.RPProfile, op *OPMetadata, req *store.AuthRequest, tok *tokenResponse) (*IDTokenClaims, error) {
	if strings.Count(tok.IDToken, ".") == 4 {
		// Encrypted ID token (CIE optional): decrypt, then verify the nested JWS.
		keysDec, err := s.Keys.Decryption(ctx, cfg.Profile)
		if err != nil {
			return nil, fail(FailConfig, req, "%v", err)
		}
		pt, _, err := fedjose.Decrypt(tok.IDToken, keysDec, fedjose.DecryptOptions{})
		if err != nil {
			return nil, fail(FailInvalidResponse, req, "id_token decrypt: %v", err)
		}
		tok.IDToken = strings.TrimSpace(string(pt))
	}
	v, err := fedjose.Verify(tok.IDToken, op.JWKS, fedjose.VerifyOptions{AllowedAlgs: op.IDTokenAlgs})
	if err != nil {
		return nil, fail(FailInvalidResponse, req, "id_token: %v", err)
	}
	if t := typOf(v.Header); t != "" && !fedjose.TypMatches(t, "JWT") {
		return nil, fail(FailInvalidResponse, req, "id_token typ %q not accepted", t)
	}
	var c IDTokenClaims
	if err := json.Unmarshal(v.Payload, &c); err != nil {
		return nil, fail(FailInvalidResponse, req, "id_token claims: %v", err)
	}
	now := s.now()
	skew := secondsDur(cfg.ClockSkewSeconds)
	switch {
	case c.Iss != op.Issuer:
		return nil, fail(FailInvalidResponse, req, "id_token issuer mismatch")
	case c.Sub == "":
		return nil, fail(FailInvalidResponse, req, "id_token without sub")
	case !slices.Contains(audiences(c.Aud), cfg.EntityID):
		return nil, fail(FailInvalidResponse, req, "id_token audience mismatch")
	case len(audiences(c.Aud)) > 1 && c.Azp != cfg.EntityID:
		return nil, fail(FailInvalidResponse, req, "id_token azp mismatch")
	case c.Exp == 0 || !time.Unix(c.Exp, 0).After(now.Add(-skew)):
		return nil, fail(FailInvalidResponse, req, "id_token expired")
	case c.Iat == 0 || time.Unix(c.Iat, 0).After(now.Add(skew)):
		return nil, fail(FailInvalidResponse, req, "id_token iat invalid")
	case now.Sub(time.Unix(c.Iat, 0)) > secondsDur(cfg.MaxIDTokenAgeSecond):
		return nil, fail(FailInvalidResponse, req, "id_token too old")
	case c.Nbf != 0 && time.Unix(c.Nbf, 0).After(now.Add(skew)):
		return nil, fail(FailInvalidResponse, req, "id_token not yet valid")
	case c.Nonce == "" || c.Nonce != req.RPNonce:
		return nil, fail(FailInvalidResponse, req, "id_token nonce mismatch")
	case c.AtHash == "":
		return nil, fail(FailInvalidResponse, req, "id_token without at_hash")
	}
	want, err := AtHash(tok.AccessToken, v.Header.Algorithm)
	if err != nil || want != c.AtHash {
		return nil, fail(FailInvalidResponse, req, "at_hash mismatch")
	}
	gotLoA := cfg.LoAForACR(c.ACR)
	if gotLoA == "" {
		return nil, fail(FailInsufficientLoA, req, "unknown acr %q", c.ACR)
	}
	reqLoA := cfg.LoAForACR(req.RequestedACR)
	if model.LoARank(gotLoA) < model.LoARank(reqLoA) {
		return nil, fail(FailInsufficientLoA, req, "acr %s below requested %s", c.ACR, req.RequestedACR)
	}
	if c.JTI != "" {
		if err := s.Store.ClaimJTI(ctx, c.Iss, c.JTI, time.Unix(c.Exp, 0).Add(skew)); err != nil {
			return nil, fail(FailReplay, req, "id_token jti replay")
		}
	} else {
		return nil, fail(FailInvalidResponse, req, "id_token without jti")
	}
	return &c, nil
}

func typOf(h jose.Header) string {
	if v, ok := h.ExtraHeaders[jose.HeaderType].(string); ok {
		return v
	}
	return ""
}

func (s *Service) fetchUserInfo(ctx context.Context, cfg *model.RPProfile, op *OPMetadata, req *store.AuthRequest, accessToken, sub string) (map[string]any, error) {
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, op.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fail(FailConfig, req, "%v", err)
	}
	hreq.Header.Set("Authorization", "Bearer "+accessToken)
	hreq.Header.Set("Accept", "application/jwt, application/jose")
	resp, body, err := s.HTTP.Do(hreq)
	if err != nil {
		return nil, fail(FailOPUnavailable, req, "userinfo: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fail(FailInvalidResponse, req, "userinfo status %d", resp.StatusCode)
	}
	raw := strings.TrimSpace(string(body))
	if strings.Count(raw, ".") != 4 {
		// SPID/CIE: UserInfo is always signed then encrypted.
		return nil, fail(FailInvalidResponse, req, "userinfo response is not encrypted")
	}
	decKeys, err := s.Keys.Decryption(ctx, cfg.Profile)
	if err != nil {
		return nil, fail(FailConfig, req, "%v", err)
	}
	pt, _, err := fedjose.Decrypt(raw, decKeys, fedjose.DecryptOptions{
		KeyAlgs:     []jose.KeyAlgorithm{jose.RSA_OAEP, jose.RSA_OAEP_256, jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A256KW},
		ContentAlgs: []jose.ContentEncryption{jose.A128CBC_HS256, jose.A256CBC_HS512},
	})
	if err != nil {
		return nil, fail(FailInvalidResponse, req, "userinfo decrypt: %v", err)
	}
	v, err := fedjose.Verify(strings.TrimSpace(string(pt)), op.JWKS, fedjose.VerifyOptions{AllowedAlgs: AllowedSigAlgs})
	if err != nil {
		return nil, fail(FailInvalidResponse, req, "userinfo signature: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(v.Payload, &claims); err != nil {
		return nil, fail(FailInvalidResponse, req, "userinfo claims: %v", err)
	}
	if iss, _ := claims["iss"].(string); iss != op.Issuer {
		return nil, fail(FailInvalidResponse, req, "userinfo issuer mismatch")
	}
	audRaw, _ := json.Marshal(claims["aud"])
	if !slices.Contains(audiences(audRaw), cfg.EntityID) {
		return nil, fail(FailInvalidResponse, req, "userinfo audience mismatch")
	}
	if s2, _ := claims["sub"].(string); s2 != sub {
		return nil, fail(FailInvalidResponse, req, "userinfo sub differs from id_token sub")
	}
	if exp, ok := claims["exp"].(float64); ok && !time.Unix(int64(exp), 0).After(s.now().Add(-secondsDur(cfg.ClockSkewSeconds))) {
		return nil, fail(FailInvalidResponse, req, "userinfo expired")
	}
	return claims, nil
}

func (s *Service) revoke(ctx context.Context, cfg *model.RPProfile, op *OPMetadata, token string) {
	if op.RevocationEndpoint == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	assertion, err := s.clientAssertion(ctx, cfg, op.RevocationEndpoint)
	if err != nil {
		return
	}
	form := url.Values{
		"token": {token}, "token_type_hint": {"access_token"}, "client_id": {cfg.EntityID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion},
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, op.RevocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, _, _ = s.HTTP.Do(hreq)
}

// ----------------------------------------------------------- normalisation

var (
	reCF     = regexp.MustCompile(`^[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]$`)
	reCFTemp = regexp.MustCompile(`^[0-9]{11}$`)
	reDate   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// LocalName strips the eID attribute namespace from a claim name.
func LocalName(claim string) string {
	claim = strings.TrimPrefix(claim, model.AttrPrefix)
	return strings.TrimPrefix(claim, model.AttrLegacyPrefix)
}

// NormalizeAttributes maps UserInfo claims to the canonical attribute set.
// Protocol claims are dropped; malformed values are dropped with a warning.
func NormalizeAttributes(claims map[string]any) (map[string]any, []string) {
	out := map[string]any{}
	var warnings []string
	skip := map[string]bool{"iss": true, "aud": true, "sub": true, "iat": true, "exp": true, "nbf": true, "jti": true, "azp": true}
	for k, v := range claims {
		if skip[k] {
			continue
		}
		name := LocalName(k)
		switch name {
		case "fiscal_number":
			s, _ := v.(string)
			s = strings.ToUpper(strings.TrimSpace(s))
			s = strings.TrimPrefix(s, "TINIT-")
			if reCF.MatchString(s) || reCFTemp.MatchString(s) {
				out[name] = s
			} else {
				warnings = append(warnings, "fiscal_number malformed")
			}
		case "email":
			s, _ := v.(string)
			s = strings.ToLower(strings.TrimSpace(s))
			if strings.Count(s, "@") == 1 && len(s) <= 254 {
				out[name] = s
			} else {
				warnings = append(warnings, "email malformed")
			}
		case "birthdate", "eid_exp_date":
			s, _ := v.(string)
			if reDate.MatchString(s) {
				out[name] = s
			} else {
				warnings = append(warnings, name+" malformed")
			}
		case "given_name", "family_name", "place_of_birth", "gender", "phone_number", "spid_code",
			"company_name", "registered_office", "company_fiscal_number", "vat_number", "e_delivery_service",
			"landline_number":
			if s, ok := v.(string); ok && len(s) <= 512 {
				out[name] = strings.TrimSpace(s)
			}
		case "email_verified", "phone_number_verified":
			if b, ok := v.(bool); ok {
				out[name] = b
			}
		case "address", "document_details":
			out[name] = v
		}
	}
	return out, warnings
}

// SubjectHash derives the stable facade subject for (issuer, sub).
func SubjectHash(issuer, sub string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + sub))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ensure crypto import used for hash registration side-effects
var _ = crypto.SHA256
