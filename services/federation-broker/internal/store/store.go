// Package store persists federation configuration and authentication state
// in PostgreSQL.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/enpam/iam/federation-broker/internal/model"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned on uniqueness / state conflicts.
var ErrConflict = errors.New("conflict")

// Store wraps a pgx pool.
type Store struct{ DB *pgxpool.Pool }

// Open connects to PostgreSQL.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Store{DB: pool}, nil
}

// Migrate applies embedded migrations idempotently (advisory-locked).
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(727001)`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(727001)`) //nolint:errcheck
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	for _, n := range names {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, n).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + n)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, n); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// ---------------------------------------------------------------- profiles

// GetProfile loads a profile configuration.
func (s *Store) GetProfile(ctx context.Context, p model.Profile) (*model.RPProfile, error) {
	var raw []byte
	err := s.DB.QueryRow(ctx, `SELECT config FROM fed_profiles WHERE profile=$1`, string(p)).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var out model.RPProfile
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutProfile stores a validated profile.
func (s *Store) PutProfile(ctx context.Context, cfg *model.RPProfile, actor string) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO fed_profiles(profile, config, updated_at, updated_by) VALUES($1,$2,now(),$3)
		ON CONFLICT (profile) DO UPDATE SET config=EXCLUDED.config, updated_at=now(), updated_by=EXCLUDED.updated_by`,
		string(cfg.Profile), raw, actor)
	return err
}

// InsertProfileIfAbsent seeds a profile without overwriting.
func (s *Store) InsertProfileIfAbsent(ctx context.Context, cfg *model.RPProfile) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO fed_profiles(profile, config) VALUES($1,$2) ON CONFLICT DO NOTHING`, string(cfg.Profile), raw)
	return err
}

// --------------------------------------------------------------- providers

// ListProviders lists providers for a profile ("" = all).
func (s *Store) ListProviders(ctx context.Context, p model.Profile, onlyEnabled bool) ([]model.Provider, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, profile, entity_id, display_name, logo_uri, enabled, sort_order, created_at
		FROM fed_providers WHERE ($1='' OR profile=$1) AND (NOT $2 OR enabled) ORDER BY profile, sort_order, display_name`, string(p), onlyEnabled)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Provider{}
	for rows.Next() {
		var pr model.Provider
		var id uuid.UUID
		var prof string
		if err := rows.Scan(&id, &prof, &pr.EntityID, &pr.DisplayName, &pr.LogoURI, &pr.Enabled, &pr.SortOrder, &pr.CreatedAt); err != nil {
			return nil, err
		}
		pr.ID, pr.Profile = id.String(), model.Profile(prof)
		out = append(out, pr)
	}
	return out, rows.Err()
}

// UpsertProvider creates or updates a provider.
func (s *Store) UpsertProvider(ctx context.Context, pr *model.Provider) error {
	if pr.ID == "" {
		pr.ID = uuid.NewString()
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO fed_providers(id, profile, entity_id, display_name, logo_uri, enabled, sort_order)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO UPDATE SET entity_id=EXCLUDED.entity_id, display_name=EXCLUDED.display_name,
		logo_uri=EXCLUDED.logo_uri, enabled=EXCLUDED.enabled, sort_order=EXCLUDED.sort_order`,
		pr.ID, string(pr.Profile), pr.EntityID, pr.DisplayName, pr.LogoURI, pr.Enabled, pr.SortOrder)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeleteProvider removes a provider.
func (s *Store) DeleteProvider(ctx context.Context, id string) error {
	ct, err := s.DB.Exec(ctx, `DELETE FROM fed_providers WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ------------------------------------------------------------ trust anchors

// ListTrustAnchors lists trust anchors for a profile ("" = all).
func (s *Store) ListTrustAnchors(ctx context.Context, p model.Profile, onlyEnabled bool) ([]model.TrustAnchor, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, profile, entity_id, jwks, description, enabled, created_at FROM fed_trust_anchors
		WHERE ($1='' OR profile=$1) AND (NOT $2 OR enabled) ORDER BY profile, entity_id`, string(p), onlyEnabled)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.TrustAnchor{}
	for rows.Next() {
		var ta model.TrustAnchor
		var id uuid.UUID
		var prof string
		var raw []byte
		if err := rows.Scan(&id, &prof, &ta.EntityID, &raw, &ta.Description, &ta.Enabled, &ta.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &ta.JWKS); err != nil {
			return nil, err
		}
		ta.ID, ta.Profile = id.String(), model.Profile(prof)
		out = append(out, ta)
	}
	return out, rows.Err()
}

// UpsertTrustAnchor creates or updates a trust anchor.
func (s *Store) UpsertTrustAnchor(ctx context.Context, ta *model.TrustAnchor) error {
	if ta.ID == "" {
		ta.ID = uuid.NewString()
	}
	raw, err := json.Marshal(ta.JWKS)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO fed_trust_anchors(id, profile, entity_id, jwks, description, enabled)
		VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT (id) DO UPDATE SET entity_id=EXCLUDED.entity_id, jwks=EXCLUDED.jwks,
		description=EXCLUDED.description, enabled=EXCLUDED.enabled`,
		ta.ID, string(ta.Profile), ta.EntityID, raw, ta.Description, ta.Enabled)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeleteTrustAnchor removes a trust anchor.
func (s *Store) DeleteTrustAnchor(ctx context.Context, id string) error {
	ct, err := s.DB.Exec(ctx, `DELETE FROM fed_trust_anchors WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --------------------------------------------------------------------- keys

// KeyRecord is a stored key including its sealed private part.
type KeyRecord struct {
	model.KeyInfo
	PrivateSealed []byte
}

const keyCols = `id, profile, purpose, kid, alg, key_type, status, private_key_enc, public_jwk, cert_pem, created_at, activated_at, retired_at`

func scanKey(row pgx.Row) (*KeyRecord, error) {
	var k KeyRecord
	var id uuid.UUID
	var prof string
	if err := row.Scan(&id, &prof, &k.Purpose, &k.Kid, &k.Alg, &k.KeyType, &k.Status, &k.PrivateSealed, &k.PublicJWK, &k.CertPEM, &k.CreatedAt, &k.ActivatedAt, &k.RetiredAt); err != nil {
		return nil, err
	}
	k.ID, k.Profile = id.String(), model.Profile(prof)
	return &k, nil
}

// InsertKey stores a new key.
func (s *Store) InsertKey(ctx context.Context, k *KeyRecord) error {
	if k.ID == "" {
		k.ID = uuid.NewString()
	}
	var activated *time.Time
	if k.Status == model.KeyActive {
		now := time.Now().UTC()
		activated = &now
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO fed_keys(id, profile, purpose, kid, alg, key_type, status, private_key_enc, public_jwk, cert_pem, activated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		k.ID, string(k.Profile), k.Purpose, k.Kid, k.Alg, k.KeyType, k.Status, k.PrivateSealed, []byte(k.PublicJWK), k.CertPEM, activated)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// ListKeys returns keys, optionally filtered by profile.
func (s *Store) ListKeys(ctx context.Context, p model.Profile) ([]*KeyRecord, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+keyCols+` FROM fed_keys WHERE ($1='' OR profile=$1) ORDER BY profile, purpose, created_at DESC`, string(p))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*KeyRecord
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// GetKey loads a key by id.
func (s *Store) GetKey(ctx context.Context, id string) (*KeyRecord, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	k, err := scanKey(s.DB.QueryRow(ctx, `SELECT `+keyCols+` FROM fed_keys WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return k, err
}

// ActivateKey makes a key active; the previously active key of the same
// profile/purpose becomes deprecated (still published) in the same transaction.
func (s *Store) ActivateKey(ctx context.Context, id string) (*KeyRecord, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	k, err := scanKey(tx.QueryRow(ctx, `SELECT `+keyCols+` FROM fed_keys WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if k.Status == model.KeyRetired {
		return nil, fmt.Errorf("%w: retired keys cannot be re-activated", ErrConflict)
	}
	if _, err := tx.Exec(ctx, `UPDATE fed_keys SET status='deprecated' WHERE profile=$1 AND purpose=$2 AND status='active' AND id<>$3`, string(k.Profile), k.Purpose, id); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE fed_keys SET status='active', activated_at=now() WHERE id=$1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetKey(ctx, id)
}

// RetireKey stops publishing a key. Active keys cannot be retired directly.
func (s *Store) RetireKey(ctx context.Context, id string) error {
	ct, err := s.DB.Exec(ctx, `UPDATE fed_keys SET status='retired', retired_at=now() WHERE id=$1 AND status IN ('next','deprecated')`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("%w: only next or deprecated keys can be retired", ErrConflict)
	}
	return nil
}

// DeleteKey removes a retired key permanently.
func (s *Store) DeleteKey(ctx context.Context, id string) error {
	ct, err := s.DB.Exec(ctx, `DELETE FROM fed_keys WHERE id=$1 AND status='retired'`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("%w: only retired keys can be deleted", ErrConflict)
	}
	return nil
}

// SetKeyCertificate stores the PEM certificate chain and updated public JWK.
func (s *Store) SetKeyCertificate(ctx context.Context, id, pem string, jwk []byte) error {
	ct, err := s.DB.Exec(ctx, `UPDATE fed_keys SET cert_pem=$2, public_jwk=$3 WHERE id=$1`, id, pem, jwk)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ------------------------------------------------------------ auth requests

// AuthRequest tracks one brokered authentication.
type AuthRequest struct {
	ID                  string
	Profile             model.Profile
	ClientID            string
	RedirectURI         string
	ClientState         string
	ClientNonce         string
	ClientCodeChallenge string
	RequestedLoA        string
	OPEntityID          string
	RPState             string
	RPNonce             string
	CodeVerifier        string
	RequestedACR        string
	Status              string
	ExpiresAt           time.Time
}

// CreateAuthRequest inserts a new request.
func (s *Store) CreateAuthRequest(ctx context.Context, r *AuthRequest) error {
	r.ID = uuid.NewString()
	_, err := s.DB.Exec(ctx, `INSERT INTO auth_requests(id, profile, client_id, redirect_uri, client_state, client_nonce, client_code_challenge, requested_loa, expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, r.ID, string(r.Profile), r.ClientID, r.RedirectURI, r.ClientState, r.ClientNonce, r.ClientCodeChallenge, r.RequestedLoA, r.ExpiresAt)
	return err
}

const arCols = `id, profile, client_id, redirect_uri, client_state, client_nonce, client_code_challenge, requested_loa,
	COALESCE(op_entity_id,''), COALESCE(rp_state,''), COALESCE(rp_nonce,''), COALESCE(code_verifier,''), COALESCE(requested_acr,''), status, expires_at`

func scanAR(row pgx.Row) (*AuthRequest, error) {
	var r AuthRequest
	var id uuid.UUID
	var prof string
	err := row.Scan(&id, &prof, &r.ClientID, &r.RedirectURI, &r.ClientState, &r.ClientNonce, &r.ClientCodeChallenge, &r.RequestedLoA,
		&r.OPEntityID, &r.RPState, &r.RPNonce, &r.CodeVerifier, &r.RequestedACR, &r.Status, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.ID, r.Profile = id.String(), model.Profile(prof)
	return &r, nil
}

// GetPendingAuthRequest returns a request in "created" state that has not expired.
func (s *Store) GetPendingAuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	return scanAR(s.DB.QueryRow(ctx, `SELECT `+arCols+` FROM auth_requests WHERE id=$1 AND status='created' AND expires_at > now()`, id))
}

// GetAuthRequest returns a request regardless of state.
func (s *Store) GetAuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	return scanAR(s.DB.QueryRow(ctx, `SELECT `+arCols+` FROM auth_requests WHERE id=$1`, id))
}

// MarkRedirected stores upstream parameters; only one transition is allowed.
func (s *Store) MarkRedirected(ctx context.Context, r *AuthRequest) error {
	ct, err := s.DB.Exec(ctx, `UPDATE auth_requests SET op_entity_id=$2, rp_state=$3, rp_nonce=$4, code_verifier=$5, requested_acr=$6, status='redirected'
		WHERE id=$1 AND status='created' AND expires_at > now()`, r.ID, r.OPEntityID, r.RPState, r.RPNonce, r.CodeVerifier, r.RequestedACR)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// ConsumeByRPState atomically moves a redirected request to "completed"
// and returns it. A second call with the same state fails (replay).
func (s *Store) ConsumeByRPState(ctx context.Context, state string) (*AuthRequest, error) {
	return scanAR(s.DB.QueryRow(ctx, `UPDATE auth_requests SET status='completed'
		WHERE rp_state=$1 AND status='redirected' AND expires_at > now() RETURNING `+arCols, state))
}

// FailAuthRequest records a failure reason (no PII).
func (s *Store) FailAuthRequest(ctx context.Context, id, reason string) error {
	_, err := s.DB.Exec(ctx, `UPDATE auth_requests SET status='failed', failure_reason=$2 WHERE id=$1`, id, reason)
	return err
}

// ------------------------------------------------------------ auth results

// AuthResult is a validated upstream authentication.
type AuthResult struct {
	ID              string     `json:"id"`
	RequestID       string     `json:"request_id"`
	Profile         string     `json:"profile"`
	OPEntityID      string     `json:"op_entity_id"`
	OPIssuer        string     `json:"op_issuer"`
	ExternalSub     string     `json:"external_sub"`
	SubjectHash     string     `json:"subject_hash"`
	ACR             string     `json:"acr"`
	LoA             string     `json:"loa"`
	AuthTime        time.Time  `json:"auth_time"`
	AttributesEnc   []byte     `json:"-"`
	CodeHash        string     `json:"-"`
	CodeExpiresAt   time.Time  `json:"-"`
	TokenIssuedAt   *time.Time `json:"token_issued_at,omitempty"`
	BoundIdentityID *string    `json:"bound_identity_id,omitempty"`
	BoundSessionID  *string    `json:"bound_session_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ClientNonce     string     `json:"-"`
	ClientID        string     `json:"-"`
	RedirectURI     string     `json:"-"`
	CodeChallenge   string     `json:"-"`
}

// InsertAuthResult stores a result.
func (s *Store) InsertAuthResult(ctx context.Context, r *AuthResult) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO auth_results(id, request_id, profile, op_entity_id, op_issuer, external_sub, subject_hash, acr, loa, auth_time, attributes_enc, code_hash, code_expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		r.ID, r.RequestID, r.Profile, r.OPEntityID, r.OPIssuer, r.ExternalSub, r.SubjectHash, r.ACR, r.LoA, r.AuthTime, r.AttributesEnc, r.CodeHash, r.CodeExpiresAt)
	return err
}

const resCols = `r.id, r.request_id, r.profile, r.op_entity_id, r.op_issuer, r.external_sub, r.subject_hash, r.acr, r.loa, r.auth_time,
	r.attributes_enc, r.code_hash, r.code_expires_at, r.token_issued_at, r.bound_identity_id::text, r.bound_session_id::text, r.created_at,
	q.client_nonce, q.client_id, q.redirect_uri, q.client_code_challenge`

func scanResult(row pgx.Row) (*AuthResult, error) {
	var r AuthResult
	var id, rid uuid.UUID
	err := row.Scan(&id, &rid, &r.Profile, &r.OPEntityID, &r.OPIssuer, &r.ExternalSub, &r.SubjectHash, &r.ACR, &r.LoA, &r.AuthTime,
		&r.AttributesEnc, &r.CodeHash, &r.CodeExpiresAt, &r.TokenIssuedAt, &r.BoundIdentityID, &r.BoundSessionID, &r.CreatedAt,
		&r.ClientNonce, &r.ClientID, &r.RedirectURI, &r.CodeChallenge)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.ID, r.RequestID = id.String(), rid.String()
	return &r, nil
}

// RedeemCode atomically marks a code as used and returns the result. A reused
// code returns ErrConflict (and callers must treat the grant as compromised).
func (s *Store) RedeemCode(ctx context.Context, codeHash, accessTokenHash string) (*AuthResult, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var id uuid.UUID
	var used *time.Time
	var exp time.Time
	err = tx.QueryRow(ctx, `SELECT id, code_used_at, code_expires_at FROM auth_results WHERE code_hash=$1 FOR UPDATE`, codeHash).Scan(&id, &used, &exp)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if used != nil {
		// Code replay: invalidate the issued access token (RFC 6749 §4.1.2).
		_, _ = tx.Exec(ctx, `UPDATE auth_results SET access_token_hash=NULL WHERE id=$1`, id)
		_ = tx.Commit(ctx)
		return nil, ErrConflict
	}
	if time.Now().After(exp) {
		return nil, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE auth_results SET code_used_at=now(), token_issued_at=now(), access_token_hash=$2 WHERE id=$1`, id, accessTokenHash); err != nil {
		return nil, err
	}
	r, err := scanResult(tx.QueryRow(ctx, `SELECT `+resCols+` FROM auth_results r JOIN auth_requests q ON q.id=r.request_id WHERE r.id=$1`, id))
	if err != nil {
		return nil, err
	}
	return r, tx.Commit(ctx)
}

// ResultByAccessToken returns the result for a facade access token.
func (s *Store) ResultByAccessToken(ctx context.Context, hash string, maxAge time.Duration) (*AuthResult, error) {
	return scanResult(s.DB.QueryRow(ctx, `SELECT `+resCols+` FROM auth_results r JOIN auth_requests q ON q.id=r.request_id
		WHERE r.access_token_hash=$1 AND r.token_issued_at > now() - $2::interval`, hash, fmt.Sprintf("%d seconds", int(maxAge.Seconds()))))
}

// GetResult loads a result by id.
func (s *Store) GetResult(ctx context.Context, id string) (*AuthResult, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	return scanResult(s.DB.QueryRow(ctx, `SELECT `+resCols+` FROM auth_results r JOIN auth_requests q ON q.id=r.request_id WHERE r.id=$1`, id))
}

// FindResults lists results for a facade subject whose token was issued in [since, until].
func (s *Store) FindResults(ctx context.Context, subjectHashes []string, since, until time.Time) ([]*AuthResult, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+resCols+` FROM auth_results r JOIN auth_requests q ON q.id=r.request_id
		WHERE r.subject_hash = ANY($1) AND r.token_issued_at BETWEEN $2 AND $3 ORDER BY r.token_issued_at DESC LIMIT 20`, subjectHashes, since, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuthResult
	for rows.Next() {
		r, err := scanResult(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// BindResult binds a result to a Kratos identity and session exactly once.
func (s *Store) BindResult(ctx context.Context, id, identityID, sessionID string) error {
	ct, err := s.DB.Exec(ctx, `UPDATE auth_results SET bound_identity_id=$2, bound_session_id=$3, bound_at=COALESCE(bound_at, now())
		WHERE id=$1 AND (bound_identity_id IS NULL OR bound_identity_id=$2) AND (bound_session_id IS NULL OR bound_session_id=$3)`, id, identityID, sessionID)
	if isUnique(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// PurgeAttributes removes sealed PII from results older than maxAge.
func (s *Store) PurgeAttributes(ctx context.Context, maxAge time.Duration) (int64, error) {
	ct, err := s.DB.Exec(ctx, `UPDATE auth_results SET attributes_enc=NULL WHERE attributes_enc IS NOT NULL AND created_at < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int(maxAge.Seconds())))
	return ct.RowsAffected(), err
}

// PurgeExpired removes old requests (cascading to results) and stale jti rows.
func (s *Store) PurgeExpired(ctx context.Context, retention time.Duration) error {
	if _, err := s.DB.Exec(ctx, `DELETE FROM auth_requests WHERE expires_at < now() - $1::interval`, fmt.Sprintf("%d seconds", int(retention.Seconds()))); err != nil {
		return err
	}
	_, err := s.DB.Exec(ctx, `DELETE FROM seen_jti WHERE expires_at < now()`)
	return err
}

// ClaimJTI records a token identifier; returns ErrConflict on replay.
func (s *Store) ClaimJTI(ctx context.Context, issuer, jti string, exp time.Time) error {
	if strings.TrimSpace(jti) == "" {
		return errors.New("empty jti")
	}
	ct, err := s.DB.Exec(ctx, `INSERT INTO seen_jti(issuer, jti, expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, issuer, jti, exp)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// Stats returns counters for the admin dashboard.
func (s *Store) Stats(ctx context.Context, since time.Time) (map[string]int64, error) {
	out := map[string]int64{}
	rows, err := s.DB.Query(ctx, `SELECT profile || ':' || status, count(*) FROM auth_requests WHERE created_at > $1 GROUP BY 1`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// RecentFailures returns recent failed requests (reason codes only).
func (s *Store) RecentFailures(ctx context.Context, limit int) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `SELECT id::text, profile, COALESCE(op_entity_id,''), COALESCE(failure_reason,''), created_at FROM auth_requests
		WHERE status='failed' ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, prof, op, reason string
		var at time.Time
		if err := rows.Scan(&id, &prof, &op, &reason, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "profile": prof, "op_entity_id": op, "reason": reason, "created_at": at})
	}
	return out, rows.Err()
}
