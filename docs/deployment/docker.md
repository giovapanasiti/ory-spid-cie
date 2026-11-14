# Local deployment with Docker Compose

The Compose stack (`infrastructure/docker/docker-compose.yml`, project name `iam`) runs the whole
platform on one machine for **development and automated tests only**. It uses the **LOCAL test
federation** (`fedsim`): a simulated SPID/CIE Trust Anchor and OPs with synthetic users. Logging in
through it says nothing about conformance with the real SPID/CIE federations.

## 1. Prerequisites

| Tool | Version | Used by |
|---|---|---|
| Docker Engine + Compose v2 | Engine ≥ 25 (healthchecks use `start_interval`), Compose ≥ 2.20; checked by `scripts/setup.sh` | everything |
| GNU Make, Bash | — | `Makefile`, scripts |
| OpenSSL | — | `scripts/setup.sh` secret generation |
| Node.js | `^22.13.0 \|\| >=24` (`package.json` `engines`) | tests, lint, `make build-local` only (not `make dev`) |
| Go | 1.26 (`services/federation-broker/go.mod`) | Go tests, lint, `make build-local` only (not `make dev`) |
| `jq` (optional) | — | examples in the docs |

Free host ports (all bound to `127.0.0.1`): 3100, 3200, 4433, 4444, 4455, 5580, 5600, 8025, 8070, 8090;
plus 55432 for `make test-db`.

## 2. Quick start

```bash
make dev
```

`make dev` = `setup` → `build` → `up` → `seed`:

1. **setup** (`scripts/setup.sh`): creates `.env` from `.env.example`, replacing every `__GENERATE_*__`
   placeholder with a random value (kept if `.env` already exists; `--force` regenerates), writes
   `infrastructure/docker/dev-secrets/{kratos,hydra}.secrets.yml` (Ory secrets, SMTP to Mailpit, Kratos
   OIDC providers `spid`/`cie` pointing at the broker facade), then `npm ci` and `go mod download`.
2. **build**: TypeScript build, Go build, image `iam/node:dev` (`Dockerfile.node`, one image for all
   TypeScript apps), images `iam/federation-broker:dev` and `iam/fedsim:dev` (`Dockerfile.broker`).
3. **up**: `docker compose up -d --wait`.
4. **seed** (`scripts/seed-dev.mjs`, idempotent): Hydra clients `admin-console`, `demo-web`,
   `demo-public`, `demo-m2m`; Kratos user `DEV_ADMIN_EMAIL` with password `DEV_ADMIN_PASSWORD` and role
   `superadmin`; pins the **fedsim** Trust Anchor without out-of-band verification (local only), installs
   fedsim-issued trust marks and enables both profiles.

| URL | What |
|---|---|
| http://localhost:5580 | demo application (demo-web) |
| http://localhost:4455 | login UI (login-consent) |
| http://localhost:3200 | account portal (identity-portal) |
| http://localhost:3100 | admin console — user `DEV_ADMIN_EMAIL`, password `DEV_ADMIN_PASSWORD` from `.env` |
| http://localhost:8070 | LOCAL test federation (fedsim) |
| http://localhost:8025 | Mailpit (verification / recovery emails) |
| http://localhost:5600 | demo API |
| http://localhost:4433, :4444, http://broker.localhost:8090 | Kratos public, Hydra public, broker public |
| http://trust-anchor.localhost:8000, http://cie-provider.localhost:8002 | REFERENCE TEST federation, only after `make reference-up` ([`../federation/reference-federation.md`](../federation/reference-federation.md)) |

Try it: open the demo app → *Accedi* → *Accedi con SPID* → choose "SPID Test IdP (locale)" → pick a
synthetic user and the scenario *Successo* in fedsim. Other fedsim scenarios inject failures
(missing attributes, low ACR, bad signature, …).

## 3. Make targets

| Target | Description |
|---|---|
| `make help` | list targets |
| `make setup` | preflight checks (Docker daemon, Engine ≥ 25, Compose ≥ 2.20, free ports), generate `.env` + Ory overlay files |
| `make deps` | install host npm and Go dependencies (tests, lint) |
| `make build` | build the container images (TypeScript and Go compile inside Docker) |
| `make build-local` | compile TypeScript and Go on the host (developer check) |
| `make up` | start the stack without rebuilding |
| `make dev` | setup + build + up + seed |
| `make migrate` | start Postgres and apply all migrations (Kratos, Hydra, broker, identity, audit) |
| `make seed` | seed clients, dev admin, local federation trust |
| `make down` | stop (keeps volumes) |
| `make clean` | stop and **delete volumes** (all local data) |
| `make logs` / `make ps` | follow logs / status |
| `make test` | Go tests (with a throw-away Postgres on :55432) + TypeScript unit tests |
| `make test-go` / `make test-ts` | each half of `make test` |
| `make test-e2e` | Playwright tests against the running stack (run `make dev` first) |
| `make test-security` | Go protocol-attack tests, TS security tests, live smoke tests (if stack running), govulncheck, npm audit |
| `make coverage` | coverage reports in `coverage/` |
| `make lint` / `make fmt` / `make typecheck` | ESLint/Prettier/gofmt/go vet / format / tsc |
| `make helm-lint` / `make k8s-validate` | `scripts/k8s-validate.sh` |

Note: `make test-ts` does not set `TEST_DATABASE_URL`, so the database-backed identity-service tests
(`services/identity-service/src/service.test.ts`) are skipped. Run them with
`make test-db && TEST_DATABASE_URL=postgres://test:test@localhost:55432/postgres?sslmode=disable npm test`.

## 4. Services and ports

| Service | Image | Container port | Host | Depends on |
|---|---|---|---|---|
| postgres | `postgres:17-alpine` | 5432 | — | — |
| mailpit | `axllent/mailpit:latest` | 8025 (UI), 1025 (SMTP) | 8025 | — |
| kratos-migrate / kratos | `oryd/kratos:v26.2.0` | 4433 public, 4434 admin | 4433 | migrate, broker healthy |
| hydra-migrate / hydra | `oryd/hydra:v26.2.0` | 4444 public, 4445 admin | 4444 | migrate |
| federation-broker | `iam/federation-broker:dev` | 8090 public, 8091 admin | 8090 | postgres |
| fedsim (TEST ONLY) | `iam/fedsim:dev` | 8070 | 8070 | — |
| identity-service | `iam/node:dev` | 4000 | — | postgres |
| audit-service | `iam/node:dev` | 4100 | — | postgres |
| login-consent | `iam/node:dev` | 3000 | **4455** | kratos, hydra, identity-service |
| identity-portal | `iam/node:dev` | 3200 | 3200 | kratos, identity-service |
| admin-console | `iam/node:dev` | 3100 | 3100 | hydra, identity-service |
| demo-api | `iam/node:dev` | 5600 | 5600 | hydra |
| demo-web | `iam/node:dev` | 5555 | **5580** | hydra |
| seed (profile `seed`) | `node:22-alpine` | — | — | run by `make seed` |

Admin ports 4434, 4445, 8091 and the internal services (4000, 4100) are **not published**
(checked by `scripts/security-smoke.sh`). Containers run read-only with `no-new-privileges` and all
capabilities dropped (except Ory, Postgres, Mailpit, fedsim which use their image defaults). Ory runs with
`--dev` (http allowed) — never reuse this configuration outside local development.

## 5. Environment variables

### 5.1 `.env` (generated from `.env.example`)

| Variable | Used by | Purpose | Default / generation |
|---|---|---|---|
| `POSTGRES_PASSWORD` | postgres | superuser password (init only) | random 24 chars |
| `KRATOS_DB_PASSWORD` | postgres init, Kratos DSN | role `kratos`, db `kratos` | random |
| `HYDRA_DB_PASSWORD` | postgres init, Hydra DSN | role `hydra`, db `hydra` | random |
| `BROKER_DB_PASSWORD` | postgres init, broker | role `broker`, db `federation` | random |
| `IDENTITY_DB_PASSWORD` | postgres init, identity-service | role `identity`, db `identity` | random |
| `AUDIT_DB_PASSWORD` | postgres init, audit-service | role `audit`, db `audit` | random |
| `KRATOS_SECRETS_COOKIE` | Kratos overlay `secrets.cookie` | session/CSRF cookie signing | hex 64 |
| `KRATOS_SECRETS_CIPHER` | Kratos overlay `secrets.cipher` | encryption of stored OIDC tokens (exactly 32 chars) | hex 32 |
| `HYDRA_SECRETS_SYSTEM` | Hydra overlay `secrets.system` | encryption at rest | hex 64 |
| `HYDRA_SECRETS_COOKIE` | Hydra overlay `secrets.cookie` | cookie signing | hex 64 |
| `BROKER_SEAL_KEYS` | broker | seals private keys and pending PII (`kid:base64`) | `k<yyyymm>:<32 random bytes>` |
| `BROKER_ADMIN_TOKEN` | broker, admin-console, seed | admin API bearer token | hex 64 |
| `BROKER_INTERNAL_TOKEN` | broker, identity-service | internal API bearer token | hex 64 |
| `BROKER_FACADE_CLIENT_SECRET` | broker, Kratos overlay | Kratos → broker facade client secret | hex 64 |
| `IDENTITY_SERVICE_TOKEN` | identity-service (`INTERNAL_API_TOKEN`), login-consent, portal, admin-console, seed | internal API token | hex 64 |
| `IDENTITY_FIELD_SEAL_KEYS` | identity-service (`FIELD_SEAL_KEYS`) | seals verified attributes | seal key |
| `IDENTITY_LOOKUP_HMAC_KEY` | identity-service (`LOOKUP_HMAC_KEY`) | HMAC for exact-match search | hex 64 |
| `AUDIT_INGEST_TOKEN` | audit-service; producers as `AUDIT_TOKEN` | `POST /events` | hex 64 |
| `AUDIT_READ_TOKEN` | audit-service, admin-console | `GET /events` | hex 64 |
| `AUDIT_RETENTION_DAYS` | audit-service | retention (30–3650) | `365` |
| `LOGIN_COOKIE_SEAL_KEYS` | login-consent (`COOKIE_SEAL_KEYS`) | seals the re-auth marker cookie | seal key |
| `LOGIN_CSRF_SECRET` | login-consent (`CSRF_SECRET`) | CSRF HMAC | hex 64 |
| `ADMIN_OIDC_CLIENT_SECRET` | admin-console, seed | Hydra client `admin-console` | hex 64 |
| `ADMIN_COOKIE_SEAL_KEYS` | admin-console (`COOKIE_SEAL_KEYS`) | seals admin session cookie | seal key |
| `ADMIN_CSRF_SECRET` | admin-console (`CSRF_SECRET`) | CSRF HMAC | hex 64 |
| `ADMIN_BOOTSTRAP_EMAILS` | admin-console | first verified login with this email becomes superadmin if none exists | `admin@iam.local` |
| `ADMIN_REQUIRED_LOA` | admin-console | minimum LoA for admin login | empty (production: e.g. `urn:iam:loa:substantial`) |
| `PORTAL_CSRF_SECRET` | identity-portal (`CSRF_SECRET`) | CSRF HMAC | hex 64 |
| `DEMO_OIDC_CLIENT_SECRET` | demo-web (`OIDC_CLIENT_SECRET`), seed | Hydra client `demo-web` | hex 64 |
| `DEMO_M2M_CLIENT_SECRET` | seed, e2e tests | Hydra client `demo-m2m` | hex 64 |
| `DEMO_CSRF_SECRET` | demo-web (`CSRF_SECRET`) | CSRF HMAC | hex 64 |
| `DEV_ADMIN_EMAIL` | seed, `make dev` output | dev administrator | `admin@iam.local` |
| `DEV_ADMIN_PASSWORD` | seed | dev administrator password | random |

### 5.2 Common to TypeScript services

| Variable | Purpose | Default | Compose value |
|---|---|---|---|
| `LOG_LEVEL` | pino log level | `info` | `info` |
| `SECURE_COOKIES` | `Secure` flag on cookies | `true` | `false` (http) |
| `AUDIT_URL` | audit ingest URL (unset = log only) | — | `http://audit-service:4100/events` |
| `AUDIT_TOKEN` | audit ingest token | — | `AUDIT_INGEST_TOKEN` |
| `PORT` | listen port | per service | per service |

### 5.3 federation-broker (`services/federation-broker/internal/server/config.go`)

| Variable | Purpose | Default | Compose value |
|---|---|---|---|
| `BROKER_ENV` | `development` or `production` (production refuses insecure settings, requires https public URL and secure cookies) | `production` | `development` |
| `BROKER_LISTEN` / `BROKER_ADMIN_LISTEN` | listeners | `:8090` / `:8091` | defaults |
| `BROKER_PUBLIC_URL` | browser-facing base URL (**required**) | — | `http://broker.localhost:8090` (`*.localhost` resolves to loopback in browsers; network alias in compose) |
| `BROKER_INTERNAL_URL` | base URL used by Kratos (facade issuer) | = public URL | `http://federation-broker:8090` |
| `BROKER_DATABASE_URL` | PostgreSQL DSN (**required**) | — | `postgres://broker:…@postgres:5432/federation` |
| `BROKER_SEAL_KEYS` | seal keys (**required**) | — | from `.env` |
| `BROKER_ADMIN_TOKEN` / `BROKER_INTERNAL_TOKEN` | API tokens (**required**, ≥ 32 chars) | — | from `.env` |
| `BROKER_FACADE_CLIENT_ID` | facade client ID | `kratos` | `kratos` |
| `BROKER_FACADE_CLIENT_SECRET` | facade client secret (**required**, ≥ 32) | — | from `.env` |
| `BROKER_FACADE_REDIRECT_URIS` | allowed Kratos callback URLs, comma-separated (**required**) | — | Kratos `…/self-service/methods/oidc/callback[/spid|/cie]` |
| `BROKER_ALLOW_INSECURE_HTTP` | allow http federation URLs (dev only) | `false` | `true` |
| `BROKER_ALLOW_PRIVATE_NETWORKS` | allow private-IP federation targets (dev only) | `false` | `true` |
| `BROKER_OUTBOUND_HOST_ALLOWLIST` | allowed host suffixes for outbound federation requests | empty (no host restriction) | unset |
| `BROKER_COOKIE_SECURE` | `Secure` cookies + HSTS | `true` | `false` |
| `BROKER_BOOTSTRAP_FILE` | JSON applied on first start only | — | `/etc/config/federation/bootstrap.local.json` |
| `BROKER_AUTOGENERATE_KEYS` | create missing active keys (RSA-2048) at start | `true` | default |
| `BROKER_ATTRIBUTE_TTL_SECONDS` | purge sealed attributes after | `900` | default |
| `BROKER_RETENTION_DAYS` | delete expired auth requests/results after | `30` | default |
| `BROKER_RATE_LIMIT_RPS` / `_BURST` | per-IP limiter on auth routes (0 = off) | `20` / `40` | default |
| `AUDIT_URL` / `AUDIT_TOKEN` | audit shipping | — | audit-service |

### 5.4 fedsim (TEST ONLY, `cmd/fedsim/main.go`)

| Variable | Purpose | Default | Compose value |
|---|---|---|---|
| `FEDSIM_I_UNDERSTAND_THIS_IS_TEST_ONLY` | must be `true` or it refuses to start | — | `true` |
| `FEDSIM_LISTEN` | listen address | `:8070` | default |
| `FEDSIM_INTERNAL_URL` / `FEDSIM_PUBLIC_URL` | entity IDs / browser URLs | — | `http://fedsim:8070` / `http://localhost:8070` |
| `FEDSIM_RP_ENTITIES` | RP entities accepted as TA subordinates | — | broker `/rp/spid`, `/rp/cie` |
| `FEDSIM_RP_TRUST_MARK_ID` | trust mark type issued to RPs | `https://registry.spid.gov.it/openid_relying_party/public/` | default |
| `FEDSIM_KEY_FILE` | persists simulator keys | — | `/data/fedsim-keys.json` (volume `fedsim`) |

### 5.5 identity-service, audit-service

| Service | Variable | Purpose | Default |
|---|---|---|---|
| identity-service | `PORT` | listen port | `4000` |
| | `DATABASE_URL` | identity DB | required |
| | `INTERNAL_API_TOKEN` | inbound bearer token (≥ 32) | required |
| | `KRATOS_PUBLIC_URL`, `KRATOS_ADMIN_URL` | Kratos | required |
| | `BROKER_ADMIN_URL`, `BROKER_INTERNAL_TOKEN` | broker internal API (admin listener) | required |
| | `FIELD_SEAL_KEYS`, `LOOKUP_HMAC_KEY` | sealing / HMAC | required |
| audit-service | `PORT` | listen port | `4100` |
| | `DATABASE_URL` | audit DB | required |
| | `AUDIT_INGEST_TOKEN`, `AUDIT_READ_TOKEN` | tokens (≥ 32) | required |
| | `AUDIT_RETENTION_DAYS` | retention, purge hourly | `365` |

### 5.6 login-consent, identity-portal, admin-console

| Service | Variable | Purpose | Default |
|---|---|---|---|
| login-consent | `PORT` | listen | `3000` |
| | `PUBLIC_URL` | own public URL (Origin checks, return URLs) | required |
| | `KRATOS_PUBLIC_URL`, `KRATOS_BROWSER_URL`, `KRATOS_ADMIN_URL` | Kratos server-side, browser, admin | required |
| | `HYDRA_ADMIN_URL` | Hydra admin | required |
| | `IDENTITY_SERVICE_URL`, `IDENTITY_SERVICE_TOKEN` | identity-service | required |
| | `COOKIE_SEAL_KEYS`, `CSRF_SECRET` | cookie sealing, CSRF | required |
| | `REMEMBER_LOGIN_SECONDS` | Hydra remember login (0–86400) | `3600` |
| | `REMEMBER_CONSENT_SECONDS` | Hydra remember consent | `2592000` |
| | `ALLOWED_ORIGINS` | extra allowed Origins (csv) | empty |
| identity-portal | `PORT` | listen | `3200` |
| | `PUBLIC_URL`, `LOGIN_UI_URL` | own URL, login UI URL | required |
| | `KRATOS_PUBLIC_URL`, `KRATOS_BROWSER_URL`, `KRATOS_ADMIN_URL` | Kratos | required |
| | `IDENTITY_SERVICE_URL`, `IDENTITY_SERVICE_TOKEN`, `CSRF_SECRET` | | required |
| admin-console | `PORT` | listen | `3100` |
| | `PUBLIC_URL` | own URL (redirect URI `<PUBLIC_URL>/callback`) | required |
| | `OIDC_ISSUER`, `OIDC_INTERNAL_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Hydra as OP (public issuer, internal base) | required |
| | `ADMIN_REQUIRED_LOA`, `ADMIN_BOOTSTRAP_EMAILS` | see §5.1 | empty |
| | `KRATOS_PUBLIC_URL`, `KRATOS_ADMIN_URL`, `HYDRA_ADMIN_URL` | Ory | required |
| | `IDENTITY_SERVICE_URL`, `IDENTITY_SERVICE_TOKEN` | identity-service | required |
| | `BROKER_ADMIN_URL`, `BROKER_ADMIN_TOKEN` | broker admin API | required |
| | `AUDIT_READ_URL`, `AUDIT_READ_TOKEN` | audit queries | optional |
| | `COOKIE_SEAL_KEYS`, `CSRF_SECRET` | | required |
| | `SESSION_TTL_SECONDS` | admin session (300–43200) | `28800` |

### 5.7 Demo apps and seed

| Service | Variable | Purpose | Default / compose |
|---|---|---|---|
| demo-api | `PORT` | listen | `5600` |
| | `OAUTH2_ISSUER` | expected `iss` | compose `http://localhost:4444/` |
| | `OAUTH2_JWKS_URL` | Hydra JWKS (internal) | compose `http://hydra:4444/.well-known/jwks.json` |
| | `OAUTH2_AUDIENCE` | expected audience | `demo-api` |
| | `HYDRA_ADMIN_URL` | introspection | optional |
| | `ALWAYS_INTROSPECT` | introspect every token | `false` (compose `true`) |
| demo-web | `PORT` | listen | `5555` |
| | `PUBLIC_URL`, `OIDC_ISSUER`, `OIDC_INTERNAL_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | OIDC client | required |
| | `API_URL`, `API_AUDIENCE` | demo API | `API_AUDIENCE=demo-api` |
| | `CSRF_SECRET` | CSRF | required |
| | `ALLOW_INSECURE_HTTP` | let openid-client use http | `false` (compose `true`) |
| seed | `HYDRA_ADMIN_URL`, `KRATOS_ADMIN_URL`, `BROKER_ADMIN_URL`, `BROKER_ADMIN_TOKEN`, `IDENTITY_SERVICE_URL`, `IDENTITY_SERVICE_TOKEN`, `FEDSIM_URL`, `ADMIN_OIDC_CLIENT_SECRET`, `DEMO_OIDC_CLIENT_SECRET`, `DEMO_M2M_CLIENT_SECRET`, `DEV_ADMIN_EMAIL`, `DEV_ADMIN_PASSWORD` | targets and secrets for seeding | from compose/.env |

### 5.8 Ory components

Kratos and Hydra receive `DSN` as environment variable and their secrets through the overlay files in
`infrastructure/docker/dev-secrets/` (generated, git-ignored, mode 600). Base configuration:
`config/kratos/kratos.yml`, `config/kratos/identity.schema.json`, `config/kratos/federated.jsonnet`,
`config/hydra/hydra.yml`.

## 6. Local federation bootstrap

`config/federation/bootstrap.local.json` is applied by the broker **on first start only** (existing rows
are never overwritten — the database is the source of truth). It defines both profiles (disabled until
seeding), the fedsim OPs (`spid-test`, `spid-test-2`, `cie-test` enabled; `rogue`, `tampered` disabled
for negative tests) and no trust anchors. Editing the file later has no effect unless you `make clean`;
use the admin console instead.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `bind: address already in use` | another process uses a port from §1: `lsof -iTCP:<port> -sTCP:LISTEN`; stop it (ports are fixed in the compose file) |
| `up --wait` times out | `make ps`, then `make logs`; first start pulls images and runs migrations |
| Code changes not visible | `make build && make up` (the stack runs prebuilt images) |
| Postgres auth errors after `scripts/setup.sh --force` | passwords are applied only when the volume is created: `make clean && make dev` (deletes data) |
| Broker logs `unseal key` errors | `BROKER_SEAL_KEYS` changed while the volume kept old keys: restore the old value or `make clean` |
| SPID/CIE login fails with `federation_untrusted` after `docker volume rm iam_fedsim` | fedsim regenerated its TA keys: `make seed` re-pins them |
| Kratos error `invalid_client` after a federated login | dev-secrets and `.env` out of sync: `make setup && make up` |
| Admin console "Accesso negato" | user has no role; the seeded admin is `DEV_ADMIN_EMAIL`; roles via another superadmin |
| Odd login behaviour across apps | all apps share cookies on `localhost`; use a private window or clear cookies |
| Emails (verification/recovery) | read them in Mailpit http://localhost:8025 |
| `make test-e2e` fails immediately | stack not running or not seeded: `make dev` |
