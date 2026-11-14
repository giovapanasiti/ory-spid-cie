-- Canonical federated identity links. One external identity (issuer + subject)
-- maps to at most one internal (Kratos) identity: enforced by UNIQUE.
CREATE TABLE identity_links (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id           UUID NOT NULL,
    provider              TEXT NOT NULL CHECK (provider IN ('spid', 'cie')),
    issuer                TEXT NOT NULL,
    external_subject      TEXT NOT NULL,
    external_subject_hash TEXT NOT NULL,
    state                 TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'unlinked')),
    linked_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    unlinked_at           TIMESTAMPTZ,
    last_auth_at          TIMESTAMPTZ,
    last_loa              TEXT,
    last_acr              TEXT,
    UNIQUE (provider, issuer, external_subject)
);
CREATE INDEX identity_links_identity ON identity_links (identity_id);
CREATE INDEX identity_links_hash ON identity_links (external_subject_hash);

-- Verified attributes with provenance. Values are sealed (AES-256-GCM, app-level);
-- lookup_hash is an HMAC allowing exact-match administrative search.
CREATE TABLE verified_attributes (
    identity_id  UUID NOT NULL,
    name         TEXT NOT NULL,
    value_sealed TEXT NOT NULL,
    lookup_hash  TEXT,
    provider     TEXT NOT NULL,
    issuer       TEXT NOT NULL,
    loa          TEXT NOT NULL,
    verified_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (identity_id, name)
);
CREATE INDEX verified_attributes_lookup ON verified_attributes (name, lookup_hash);

-- Assurance computed for a Kratos session (bound to one broker result at most).
CREATE TABLE session_assurance (
    session_id      UUID PRIMARY KEY,
    identity_id     UUID NOT NULL,
    method_time     TIMESTAMPTZ,
    loa             TEXT NOT NULL,
    acr             TEXT NOT NULL,
    amr             TEXT[] NOT NULL,
    provider        TEXT,
    federated_acr   TEXT,
    auth_time       TIMESTAMPTZ,
    result_id       UUID UNIQUE,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX session_assurance_identity ON session_assurance (identity_id);

CREATE TABLE admin_roles (
    identity_id UUID NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('viewer', 'support', 'client-admin', 'federation-admin', 'security-auditor', 'superadmin')),
    granted_by  TEXT NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (identity_id, role)
);
