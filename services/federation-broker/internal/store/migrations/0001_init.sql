-- Federation broker schema. All timestamps are UTC.
CREATE TABLE IF NOT EXISTS fed_profiles (
    profile     TEXT PRIMARY KEY CHECK (profile IN ('spid', 'cie')),
    config      JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS fed_providers (
    id           UUID PRIMARY KEY,
    profile      TEXT NOT NULL CHECK (profile IN ('spid', 'cie')),
    entity_id    TEXT NOT NULL,
    display_name TEXT NOT NULL,
    logo_uri     TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT true,
    sort_order   INT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (profile, entity_id)
);

CREATE TABLE IF NOT EXISTS fed_trust_anchors (
    id          UUID PRIMARY KEY,
    profile     TEXT NOT NULL CHECK (profile IN ('spid', 'cie')),
    entity_id   TEXT NOT NULL,
    jwks        JSONB NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (profile, entity_id)
);

-- Private keys are stored encrypted (AES-256-GCM, envelope key from env).
CREATE TABLE IF NOT EXISTS fed_keys (
    id              UUID PRIMARY KEY,
    profile         TEXT NOT NULL CHECK (profile IN ('spid', 'cie', 'facade')),
    purpose         TEXT NOT NULL CHECK (purpose IN ('federation', 'core-sig', 'core-enc', 'facade-sig')),
    kid             TEXT NOT NULL UNIQUE,
    alg             TEXT NOT NULL,
    key_type        TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('next', 'active', 'deprecated', 'retired')),
    private_key_enc BYTEA NOT NULL,
    public_jwk      JSONB NOT NULL,
    cert_pem        TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at    TIMESTAMPTZ,
    retired_at      TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS fed_keys_one_active
    ON fed_keys (profile, purpose) WHERE status = 'active';

-- One row per authentication attempt started by Kratos.
CREATE TABLE IF NOT EXISTS auth_requests (
    id                     UUID PRIMARY KEY,
    profile                TEXT NOT NULL,
    client_id              TEXT NOT NULL,
    redirect_uri           TEXT NOT NULL,
    client_state           TEXT NOT NULL,
    client_nonce           TEXT NOT NULL DEFAULT '',
    client_code_challenge  TEXT NOT NULL DEFAULT '',
    requested_loa          TEXT NOT NULL DEFAULT '',
    op_entity_id           TEXT,
    rp_state               TEXT UNIQUE,
    rp_nonce               TEXT,
    code_verifier          TEXT,
    requested_acr          TEXT,
    status                 TEXT NOT NULL DEFAULT 'created'
                           CHECK (status IN ('created', 'redirected', 'completed', 'failed')),
    failure_reason         TEXT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at             TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_requests_expires ON auth_requests (expires_at);

-- Validated authentication results. PII is encrypted and purged after use.
CREATE TABLE IF NOT EXISTS auth_results (
    id                UUID PRIMARY KEY,
    request_id        UUID NOT NULL REFERENCES auth_requests (id) ON DELETE CASCADE,
    profile           TEXT NOT NULL,
    op_entity_id      TEXT NOT NULL,
    op_issuer         TEXT NOT NULL,
    external_sub      TEXT NOT NULL,
    subject_hash      TEXT NOT NULL,
    acr               TEXT NOT NULL,
    loa               TEXT NOT NULL,
    auth_time         TIMESTAMPTZ NOT NULL,
    attributes_enc    BYTEA,
    code_hash         TEXT NOT NULL UNIQUE,
    code_expires_at   TIMESTAMPTZ NOT NULL,
    code_used_at      TIMESTAMPTZ,
    access_token_hash TEXT UNIQUE,
    token_issued_at   TIMESTAMPTZ,
    bound_identity_id UUID,
    bound_session_id  UUID UNIQUE,
    bound_at          TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auth_results_subject ON auth_results (subject_hash, token_issued_at DESC);

-- Replay protection for upstream ID token jti values.
CREATE TABLE IF NOT EXISTS seen_jti (
    issuer     TEXT NOT NULL,
    jti        TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (issuer, jti)
);

CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());
