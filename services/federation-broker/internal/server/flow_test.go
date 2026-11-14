package server

// End-to-end protocol tests: broker (RP + facade) <-> local test federation
// (Trust Anchor + OPs) over real HTTP with real signatures, encryption and
// trust-chain validation. Requires PostgreSQL: set TEST_DATABASE_URL
// (e.g. postgres://test:test@localhost:55432/postgres?sslmode=disable).
// These are SPID/CIE *protocol integration* tests against a simulator; they
// are not official conformance tests.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"github.com/enpam/iam/federation-broker/internal/audit"
	"github.com/enpam/iam/federation-broker/internal/fedjose"
	"github.com/enpam/iam/federation-broker/internal/keys"
	"github.com/enpam/iam/federation-broker/internal/model"
	"github.com/enpam/iam/federation-broker/internal/oidcfed"
	"github.com/enpam/iam/federation-broker/internal/rp"
	"github.com/enpam/iam/federation-broker/internal/safehttp"
	"github.com/enpam/iam/federation-broker/internal/seal"
	"github.com/enpam/iam/federation-broker/internal/sim"
	"github.com/enpam/iam/federation-broker/internal/store"
)

const kratosCB = "http://kratos.test/self-service/methods/oidc/callback/spid"

type testEnv struct {
	broker, simBase string
	srv             *Server
	sim             *sim.Sim
	st              *store.Store
	providers       map[string]string // sim path -> provider id
}

type simFetcher struct{ c *safehttp.Client }

func (f simFetcher) Get(ctx context.Context, url, accept string) ([]byte, string, error) {
	return f.c.Get(ctx, url, accept)
}

func testDB(t *testing.T) string {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "broker_test_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	u, _ := url.Parse(dsn)
	u.Path = "/" + name
	return u.String()
}

func listen(t *testing.T) (net.Listener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln, "http://" + ln.Addr().String()
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	dsn := testDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bl, broker := listen(t)
	sl, simBase := listen(t)
	httpc := safehttp.New(safehttp.Policy{AllowHTTP: true, AllowPrivateNetworks: true, Timeout: 5 * time.Second})
	s, err := sim.New(sim.Config{InternalBase: simBase, PublicBase: simBase, RPEntities: []string{broker + "/rp/spid", broker + "/rp/cie"},
		RPTrustMarkID: "https://registry.spid.gov.it/openid_relying_party/public/", Fetcher: simFetcher{httpc}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.DB.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	sealer, _ := seal.New("t1:" + base64.StdEncoding.EncodeToString(k))
	km := &keys.Manager{Store: st, Sealer: sealer}
	for _, p := range []model.Profile{model.ProfileSPID, model.ProfileCIE} {
		for _, purpose := range []string{model.PurposeFederation, model.PurposeCoreSig, model.PurposeCoreEnc} {
			if err := km.EnsureActive(ctx, p, purpose, fedjose.KeyRSA2048); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := km.EnsureActive(ctx, model.ProfileFacade, model.PurposeFacadeSig, fedjose.KeyRSA2048); err != nil {
		t.Fatal(err)
	}
	e := &testEnv{broker: broker, simBase: simBase, sim: s, st: st, providers: map[string]string{}}
	for _, p := range []model.Profile{model.ProfileSPID, model.ProfileCIE} {
		entity := broker + "/rp/" + string(p)
		cfg := model.DefaultProfile(p, entity, entity+"/callback")
		cfg.Enabled = true
		cfg.AuthorityHints = []string{s.TA.ID}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := st.PutProfile(ctx, &cfg, "test"); err != nil {
			t.Fatal(err)
		}
		if err := st.UpsertTrustAnchor(ctx, &model.TrustAnchor{Profile: p, EntityID: s.TA.ID, JWKS: s.TAJWKS(), Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	for path, prof := range map[string]model.Profile{"spid-test": "spid", "spid-test-2": "spid", "rogue": "spid", "tampered": "spid", "cie-test": "cie"} {
		pr := &model.Provider{Profile: prof, EntityID: simBase + "/op/" + path, DisplayName: path, Enabled: true}
		if err := st.UpsertProvider(ctx, pr); err != nil {
			t.Fatal(err)
		}
		e.providers[path] = pr.ID
	}
	cfg := &Config{Env: "development", PublicURL: broker, InternalURL: broker, FacadeClientID: "kratos",
		FacadeClientSecret: strings.Repeat("s", 40), FacadeRedirectURIs: []string{kratosCB, strings.Replace(kratosCB, "spid", "cie", 1)}, CookieSecure: false, RateLimitRPS: 1000, RateLimitBurst: 1000}
	svc := &rp.Service{Store: st, Keys: km, HTTP: httpc, Sealer: sealer, Resolvers: &rp.Resolvers{Store: st, HTTP: httpc}}
	srv, err := New(cfg, st, km, svc, audit.New("", "", log), log)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	bs := &http.Server{Handler: srv.PublicHandler()}
	ss := &http.Server{Handler: s.Handler()}
	go bs.Serve(bl) //nolint:errcheck
	go ss.Serve(sl) //nolint:errcheck
	t.Cleanup(func() { bs.Close(); ss.Close() })
	return e
}

// fixTrustMarks replaces placeholder trust marks once the simulator is up.
func (e *testEnv) fixTrustMarks(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, p := range []model.Profile{model.ProfileSPID, model.ProfileCIE} {
		cfg, err := e.st.GetProfile(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Get(e.simBase + "/ta/dev/trust-mark?sub=" + url.QueryEscape(cfg.EntityID))
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&raw)
		resp.Body.Close()
		cfg.TrustMarks = []model.TrustMarkRef{{ID: raw["id"], TrustMark: raw["trust_mark"]}}
		if err := e.st.PutProfile(ctx, cfg, "test"); err != nil {
			t.Fatal(err)
		}
	}
}

type browser struct {
	c *http.Client
}

func newBrowser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{c: &http.Client{Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) get(t *testing.T, u string) (*http.Response, string) {
	t.Helper()
	resp, err := b.c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func (b *browser) post(t *testing.T, u string, form url.Values) (*http.Response, string) {
	t.Helper()
	resp, err := b.c.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

var (
	reReqID = regexp.MustCompile(`name="request_id" value="([^"]+)"`)
	reQuery = regexp.MustCompile(`name="query" value="([^"]+)"`)
)

type flowOpts struct {
	profile  string
	op       string
	acrValue string
	user     string
	acr      string
	scenario string
	cancel   bool
}

type flowResult struct {
	errCode    string // error_description returned to Kratos
	code       string
	callback   string
	verifier   string
	stoppedAt  string
	statusCode int
	body       string
}

func (e *testEnv) run(t *testing.T, b *browser, o flowOpts) flowResult {
	t.Helper()
	if o.profile == "" {
		o.profile = "spid"
	}
	if o.user == "" {
		o.user = "u1"
	}
	if o.acr == "" {
		o.acr = model.ACRSpidL2
	}
	if o.scenario == "" {
		o.scenario = "success"
	}
	verifier := strings.Repeat("v", 50)
	q := url.Values{"client_id": {"kratos"}, "redirect_uri": {strings.Replace(kratosCB, "spid", o.profile, 1)}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"kratos-state"}, "nonce": {"kratos-nonce"},
		"code_challenge": {rp.PKCEChallenge(verifier)}, "code_challenge_method": {"S256"}}
	if o.acrValue != "" {
		q.Set("acr_values", o.acrValue)
	}
	resp, body := b.get(t, e.broker+"/oidc/"+o.profile+"/authorize?"+q.Encode())
	var opURL string
	switch resp.StatusCode {
	case 200:
		m := reReqID.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("no request id in chooser: %s", body)
		}
		resp, body = b.post(t, e.broker+"/oidc/"+o.profile+"/select", url.Values{"request_id": {m[1]}, "provider": {e.providers[o.op]}})
		if resp.StatusCode != 302 {
			return flowResult{stoppedAt: "select", statusCode: resp.StatusCode, body: body}
		}
		opURL = resp.Header.Get("Location")
	case 302:
		opURL = resp.Header.Get("Location")
	default:
		return flowResult{stoppedAt: "authorize", statusCode: resp.StatusCode, body: body}
	}
	if strings.HasPrefix(opURL, kratosCB[:20]) {
		return parseKratos(t, opURL, verifier)
	}
	resp, body = b.get(t, opURL)
	if resp.StatusCode != 200 {
		return flowResult{stoppedAt: "op-authorize", statusCode: resp.StatusCode, body: body}
	}
	m := reQuery.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no query in OP login page")
	}
	action := "login"
	if o.cancel {
		action = "cancel"
	}
	path := strings.TrimPrefix(opURL, e.simBase+"/op/")
	path = path[:strings.Index(path, "/")]
	resp, _ = b.post(t, e.simBase+"/op/"+path+"/login", url.Values{"query": {html.UnescapeString(m[1])}, "user": {o.user}, "acr": {o.acr}, "scenario": {o.scenario}, "action": {action}})
	if resp.StatusCode != 302 {
		t.Fatalf("OP login status %d", resp.StatusCode)
	}
	cb := resp.Header.Get("Location")
	resp, body = b.get(t, cb)
	if resp.StatusCode != 302 {
		return flowResult{stoppedAt: "callback", statusCode: resp.StatusCode, body: body, callback: cb}
	}
	r := parseKratos(t, resp.Header.Get("Location"), verifier)
	r.callback = cb
	return r
}

func parseKratos(t *testing.T, loc, verifier string) flowResult {
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("state") != "kratos-state" {
		t.Fatalf("state not echoed: %s", loc)
	}
	if e := q.Get("error"); e != "" {
		return flowResult{errCode: q.Get("error_description")}
	}
	return flowResult{code: q.Get("code"), verifier: verifier}
}

func (e *testEnv) redeem(t *testing.T, profile, code, verifier string) (map[string]any, int) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {strings.Replace(kratosCB, "spid", profile, 1)}, "code_verifier": {verifier}}
	req, _ := http.NewRequest("POST", e.broker+"/oidc/"+profile+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("kratos", strings.Repeat("s", 40))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, resp.StatusCode
}

func (e *testEnv) verifyFacadeToken(t *testing.T, tok string) map[string]any {
	t.Helper()
	resp, err := http.Get(e.broker + "/oidc/spid/jwks")
	if err != nil {
		t.Fatal(err)
	}
	var set jose.JSONWebKeySet
	_ = json.NewDecoder(resp.Body).Decode(&set)
	resp.Body.Close()
	v, err := fedjose.Verify(tok, set, fedjose.VerifyOptions{AllowedAlgs: []jose.SignatureAlgorithm{jose.RS256}})
	if err != nil {
		t.Fatalf("facade id_token: %v", err)
	}
	var c map[string]any
	_ = json.Unmarshal(v.Payload, &c)
	return c
}

func TestFederationFlows(t *testing.T) {
	e := setup(t)
	e.fixTrustMarks(t)

	t.Run("entity configuration is signed and self-consistent", func(t *testing.T) {
		resp, err := http.Get(e.broker + "/rp/spid/.well-known/openid-federation")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.Header.Get("Content-Type") != oidcfed.ContentTypeEntityStmt {
			t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
		}
		var peek oidcfed.EntityStatement
		_ = fedjose.UnverifiedClaims(string(body), &peek)
		es, err := oidcfed.ParseAndVerify(string(body), peek.JWKS, rp.AllowedSigAlgs, time.Now(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		rpMeta := es.Metadata[oidcfed.EntityTypeRP]
		if rpMeta["token_endpoint_auth_method"] != "private_key_jwt" || es.Iss != es.Sub || len(es.TrustMarks) != 1 {
			t.Fatalf("unexpected EC: %+v", es)
		}
	})

	t.Run("SPID success + facade token + code replay", func(t *testing.T) {
		b := newBrowser()
		r := e.run(t, b, flowOpts{op: "spid-test"})
		if r.code == "" {
			t.Fatalf("expected code, got %+v", r)
		}
		tok, status := e.redeem(t, "spid", r.code, r.verifier)
		if status != 200 {
			t.Fatalf("token status %d %v", status, tok)
		}
		c := e.verifyFacadeToken(t, tok["id_token"].(string))
		if c["loa"] != model.LoASubstantial || c["acr"] != model.ACRSpidL2 || c["given_name"] != "Ada" || c["nonce"] != "kratos-nonce" {
			t.Fatalf("unexpected claims %v", c)
		}
		if _, ok := c["fiscal_number"]; ok {
			t.Fatal("fiscal number must not be sent to Kratos")
		}
		// Code replay.
		if _, status := e.redeem(t, "spid", r.code, r.verifier); status != 400 {
			t.Fatalf("code replay accepted: %d", status)
		}
		// Callback replay (same browser): state already consumed.
		resp, _ := b.get(t, r.callback)
		if resp.StatusCode != 400 {
			t.Fatalf("callback replay status %d", resp.StatusCode)
		}
		// Attributes available to identity-service through the internal API.
		res, err := e.st.FindResults(context.Background(), []string{c["sub"].(string)}, time.Now().Add(-time.Minute), time.Now().Add(time.Minute))
		if err != nil || len(res) != 1 {
			t.Fatalf("results: %v %d", err, len(res))
		}
		attrs := e.srv.attributes(res[0])
		if attrs["fiscal_number"] != "TSTDAA85T50H501R" {
			t.Fatalf("fiscal number normalisation: %v", attrs["fiscal_number"])
		}
	})

	t.Run("CIE success with iss parameter", func(t *testing.T) {
		r := e.run(t, newBrowser(), flowOpts{profile: "cie", op: "cie-test", acr: model.ACRSpidL3, acrValue: model.LoAHigh})
		if r.code == "" {
			t.Fatalf("expected code, got %+v", r)
		}
		tok, status := e.redeem(t, "cie", r.code, r.verifier)
		if status != 200 {
			t.Fatalf("token %d", status)
		}
		if c := e.verifyFacadeToken(t, tok["id_token"].(string)); c["loa"] != model.LoAHigh {
			t.Fatalf("loa %v", c["loa"])
		}
	})

	t.Run("PKCE mismatch at facade", func(t *testing.T) {
		r := e.run(t, newBrowser(), flowOpts{op: "spid-test"})
		if _, status := e.redeem(t, "spid", r.code, "wrong-verifier"); status != 400 {
			t.Fatalf("PKCE bypass: %d", status)
		}
	})

	failures := []struct {
		name string
		o    flowOpts
		want string
	}{
		{"cancel", flowOpts{op: "spid-test", cancel: true}, rp.FailCancelled},
		{"missing attributes", flowOpts{op: "spid-test", scenario: "missing_attributes"}, rp.FailMissingAttribute},
		{"insufficient acr", flowOpts{op: "spid-test", scenario: "wrong_acr"}, rp.FailInsufficientLoA},
		{"step-up high but L2 delivered", flowOpts{op: "spid-test", acrValue: model.LoAHigh, acr: model.ACRSpidL2}, rp.FailInsufficientLoA},
		{"expired id token", flowOpts{op: "spid-test", scenario: "expired_id_token"}, rp.FailInvalidResponse},
		{"bad signature", flowOpts{op: "spid-test", scenario: "bad_signature"}, rp.FailInvalidResponse},
		{"alg confusion", flowOpts{op: "spid-test", scenario: "alg_confusion"}, rp.FailInvalidResponse},
		{"wrong issuer", flowOpts{op: "spid-test", scenario: "wrong_issuer"}, rp.FailInvalidResponse},
		{"wrong audience", flowOpts{op: "spid-test", scenario: "wrong_audience"}, rp.FailInvalidResponse},
		{"wrong nonce", flowOpts{op: "spid-test", scenario: "wrong_nonce"}, rp.FailInvalidResponse},
		{"id token jti replay", flowOpts{op: "spid-test", scenario: "replay_jti"}, rp.FailReplay},
		{"unencrypted userinfo", flowOpts{op: "spid-test", scenario: "plain_userinfo"}, rp.FailInvalidResponse},
		{"mix-up iss param", flowOpts{op: "spid-test", scenario: "wrong_iss_param"}, rp.FailInvalidResponse},
		{"untrusted issuer", flowOpts{op: "rogue"}, rp.FailUntrusted},
		{"tampered metadata", flowOpts{op: "tampered"}, rp.FailUntrusted},
	}
	for _, f := range failures {
		t.Run("rejects "+f.name, func(t *testing.T) {
			r := e.run(t, newBrowser(), f.o)
			if r.code != "" {
				t.Fatalf("authentication unexpectedly succeeded")
			}
			got := r.errCode
			if got == "" && r.stoppedAt == "callback" && strings.Contains(r.body, f.want) {
				got = f.want
			}
			if got != f.want {
				t.Fatalf("want %s, got %+v", f.want, r)
			}
		})
	}

	t.Run("callback from another browser is rejected", func(t *testing.T) {
		b1 := newBrowser()
		// Run until OP redirect, then deliver callback in a different browser.
		verifier := strings.Repeat("v", 50)
		q := url.Values{"client_id": {"kratos"}, "redirect_uri": {kratosCB}, "response_type": {"code"}, "scope": {"openid"}, "state": {"kratos-state"},
			"code_challenge": {rp.PKCEChallenge(verifier)}, "code_challenge_method": {"S256"}}
		_, body := b1.get(t, e.broker+"/oidc/spid/authorize?"+q.Encode())
		mm := reReqID.FindStringSubmatch(body)
		if mm == nil {
			t.Fatalf("no chooser: %s", body)
		}
		id := mm[1]
		resp, _ := b1.post(t, e.broker+"/oidc/spid/select", url.Values{"request_id": {id}, "provider": {e.providers["spid-test"]}})
		_, body = b1.get(t, resp.Header.Get("Location"))
		m := reQuery.FindStringSubmatch(body)
		resp, _ = b1.post(t, e.simBase+"/op/spid-test/login", url.Values{"query": {html.UnescapeString(m[1])}, "user": {"u1"}, "acr": {model.ACRSpidL2}, "scenario": {"success"}, "action": {"login"}})
		resp2, body2 := newBrowser().get(t, resp.Header.Get("Location"))
		if resp2.StatusCode == 302 && strings.Contains(resp2.Header.Get("Location"), "code=") {
			t.Fatal("login CSRF: callback accepted without browser binding")
		}
		_ = body2
	})

	t.Run("authorize refuses unregistered redirect_uri (no open redirect)", func(t *testing.T) {
		q := url.Values{"client_id": {"kratos"}, "redirect_uri": {"https://evil.example/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s"}}
		resp, _ := newBrowser().get(t, e.broker+"/oidc/spid/authorize?"+q.Encode())
		if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
			t.Fatalf("open redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("token endpoint requires client authentication", func(t *testing.T) {
		resp, err := http.PostForm(e.broker+"/oidc/spid/token", url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "client_id": {"kratos"}, "client_secret": {"wrong"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("concurrent bind of one result to two sessions", func(t *testing.T) {
		r := e.run(t, newBrowser(), flowOpts{op: "spid-test-2"})
		tok, _ := e.redeem(t, "spid", r.code, r.verifier)
		c := e.verifyFacadeToken(t, tok["id_token"].(string))
		id := c["fed_result_id"].(string)
		var wg sync.WaitGroup
		errs := make([]error, 8)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = e.st.BindResult(context.Background(), id, "00000000-0000-4000-8000-000000000001", fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1))
			}(i)
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("expected exactly one successful bind, got %d", ok)
		}
	})
}
