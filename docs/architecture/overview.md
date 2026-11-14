# Architecture overview

## Components and trust boundaries

```mermaid
flowchart LR
  subgraph Browser
    U[User agent]
  end
  subgraph Public["Public zone (ingress / published ports)"]
    LC[login-consent :3000]
    KP[Kratos public :4433]
    HP[Hydra public :4444]
    BP[Broker public :8090<br/>RP endpoints + OIDC facade]
    PO[identity-portal :3200]
    AC[admin-console :3100]
    DW[demo-web :5555]
  end
  subgraph Internal["Internal zone (never exposed)"]
    KA[Kratos admin :4434]
    HA[Hydra admin :4445]
    BA[Broker admin/internal :8091]
    IS[identity-service :4000]
    AS[audit-service :4100]
    API[demo-api :5600]
    PG[(PostgreSQL<br/>kratos, hydra, federation,<br/>identity, audit)]
  end
  subgraph Federation["SPID / CIE federation (external)"]
    TA[Trust Anchor]
    OP[SPID IdPs / CIE OP]
  end
  U --> LC & KP & HP & BP & PO & AC & DW
  LC --> KA & HA & IS
  AC --> HA & KA & BA & IS & AS
  PO --> KP & KA & IS
  IS --> KA & BA
  KP -- generic OIDC --> BP
  BP -- trust chain, token, userinfo --> TA & OP
  DW --> HP & API
  API -- JWKS / introspection --> HP & HA
  KA & HA & BA & IS & AS --> PG
```

Trust boundaries:

1. **Browser ↔ public endpoints**: TLS (production), HttpOnly/SameSite cookies, CSRF tokens + Origin checks on every state-changing form, strict CSP.
2. **Kratos ↔ broker facade**: confidential OIDC client (`client_secret_basic`, PKCE forced), exact redirect URIs. The broker returns only a pairwise subject, name and email.
3. **Broker ↔ SPID/CIE**: OpenID Federation trust chains rooted in **pinned** trust-anchor keys; all responses cryptographically validated; SSRF-hardened egress.
4. **Internal APIs** (Kratos admin, Hydra admin, broker admin/internal, identity-service, audit-service): never published; bearer service tokens; network policies in Kubernetes.
5. **Data at rest**: Ory secrets encrypt their data; broker keys/PII and identity-service attributes are sealed with AES-256-GCM using keys from the environment/secrets manager.

## Authentication flow (OIDC application with SPID)

```mermaid
sequenceDiagram
  autonumber
  participant App as Application (demo-web)
  participant H as Hydra
  participant LC as login-consent
  participant K as Kratos
  participant B as federation-broker
  participant OP as SPID IdP
  participant IS as identity-service
  App->>H: /oauth2/auth (PKCE, state, nonce, acr_values?)
  H->>LC: /login?login_challenge
  LC->>K: whoami (cookie)
  LC-->>K: no/insufficient session → /self-service/login/browser?return_to=/login?challenge
  K->>U: login UI (login-consent /auth/login) — "Accedi con SPID"
  U->>K: POST provider=spid [upstream_parameters.acr_values]
  K->>B: /oidc/spid/authorize (facade, PKCE)
  B->>U: IdP chooser
  B->>B: resolve OP trust chain (pinned TA), check acr support
  B->>OP: authorization request with signed request object, PKCE S256
  OP->>B: /rp/spid/callback?code&state&iss
  B->>OP: token request (private_key_jwt)
  B->>B: validate ID token (sig, iss, aud, nonce, at_hash, acr, jti)
  B->>OP: UserInfo → decrypt JWE, verify JWS, normalise attributes
  B->>OP: revoke upstream access token
  B->>K: code → facade ID token (pairwise sub, acr, loa)
  K->>K: create/refresh session (oidc credential "spid:<sub>")
  K->>LC: return_to /login?login_challenge
  LC->>IS: resolve assurance(session)
  IS->>B: find & bind auth result (once), fetch sealed attributes
  IS->>IS: upsert identity link + verified attributes (provenance)
  LC->>H: accept login (subject = Kratos UUID, acr = LoA, amr, context)
  H->>LC: /consent → claims per scope (fiscal_number only with scope)
  H->>App: code → tokens (JWT access token with ext.loa/auth_time)
```

## Canonical identity model

| Concept | Where |
|---|---|
| Internal identity (canonical subject) | Kratos identity UUID (`sub` in Hydra tokens) |
| Self-asserted traits (email, name) | Kratos traits |
| External provider / issuer / subject | `identity-service.identity_links` (`provider`, `issuer`, `external_subject`), Kratos oidc credential (`provider:pairwise-hash`) |
| Authentication method / time / assurance | `identity-service.session_assurance` (per Kratos session), Hydra `acr`/`amr`, token `ext` |
| Verified attributes + provenance + verification time | `identity-service.verified_attributes` (sealed values, provider, issuer, LoA, `verified_at`) |
| Linking state | `identity_links.state` (`active` / `unlinked`), audit events |

## Services

| Service | Responsibility | Data |
|---|---|---|
| Kratos | identities, credentials (password, passkey, oidc), sessions, recovery, verification, settings/linking | `kratos` DB |
| Hydra | OAuth2/OIDC: auth code + PKCE, refresh rotation, client credentials, revocation, introspection, JWKS, logout | `hydra` DB |
| federation-broker | SPID/CIE RP (OpenID Federation), OIDC facade for Kratos, federation admin API | `federation` DB |
| login-consent | Hydra login/consent/logout; Kratos self-service UI; assurance policy | stateless |
| identity-service | assurance binding, identity links, verified attributes, admin roles | `identity` DB |
| audit-service | append-only audit events, retention | `audit` DB |
| identity-portal | end-user account page (profile, verified data, methods, sessions) | stateless |
| admin-console | RBAC admin UI (users, sessions, clients, **federation keys/certificates/metadata**, audit) | stateless (sealed cookie) |
| demo-web / demo-api | example RP and resource server | in-memory |

See `decisions.md` for ADRs and `federation-compatibility.md` for the protocol matrix.
