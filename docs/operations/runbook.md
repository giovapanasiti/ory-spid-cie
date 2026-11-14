# Operations runbook

Day-to-day operation of the platform. Commands are given for the **local Docker Compose stack**
([`../deployment/docker.md`](../deployment/docker.md)); Kubernetes equivalents are noted where they
differ ([`../deployment/kubernetes.md`](../deployment/kubernetes.md)). API calls use the helpers defined in
[`api-examples.md`](api-examples.md) §0 (`icurl` runs curl inside the compose network).

> Production operations (changes to configuration, keys, trust anchors, clients, secrets, deployments)
> follow ENPAM **Change Management** and the **Procedura di Sviluppo Sicuro**. Security events follow the
> ENPAM **Incident Management** procedure. This runbook does not replace them, and none of its steps
> authorises a production change by itself.

## 1. Start, stop, status

| Action | Command |
|---|---|
| First start / full rebuild + seed | `make dev` |
| Start without rebuilding | `make up` |
| Re-run seeding (idempotent) | `make seed` |
| Apply migrations only | `make migrate` |
| Status | `make ps` |
| Follow logs | `make logs` (or `docker compose --env-file .env -f infrastructure/docker/docker-compose.yml logs -f <service>`) |
| Stop (keep data) | `make down` |
| Stop and **delete all data** | `make clean` |

Start order is enforced by compose `depends_on` health conditions: postgres → migrations → broker →
Kratos; Hydra; identity-service/audit-service → login-consent, portal, admin console, demo apps.

Kubernetes: `kubectl -n iam get pods`, `kubectl -n iam logs deploy/<release>-<component>`,
`kubectl -n iam rollout restart deploy/<…>`.

## 2. Health endpoints

| Component | Liveness | Readiness | Port (container) | Published locally |
|---|---|---|---|---|
| federation-broker public | `GET /healthz` | `GET /readyz` (DB ping, 503 when down) | 8090 | `localhost:8090` |
| federation-broker admin | `GET /healthz` | — | 8091 | no |
| Kratos | — | `GET /admin/health/ready` (admin) | 4434 | no |
| Hydra | — | `GET /health/ready` (admin) | 4445 | no |
| identity-service | `GET /healthz` | `GET /readyz` (DB) | 4000 | no |
| audit-service | `GET /healthz` | — | 4100 | no |
| login-consent, identity-portal, admin-console, demo-web, demo-api | `GET /healthz` | — | 3000 / 3200 / 3100 / 5555 / 5600 | 4455 / 3200 / 3100 / 5580 / 5600 |
| fedsim (local only) | `GET /healthz` | — | 8070 | `localhost:8070` |

```bash
for u in http://localhost:8090/readyz http://localhost:4455/healthz http://localhost:3100/healthz \
         http://localhost:3200/healthz http://localhost:5580/healthz http://localhost:5600/healthz; do
  printf '%-36s %s\n' "$u" "$(curl -s -o /dev/null -w '%{http_code}' "$u")"; done
icurl http://kratos:4434/admin/health/ready; icurl http://hydra:4445/health/ready; icurl http://identity-service:4000/readyz
```

## 3. Logs and correlation

- All services log JSON to stdout. `authorization`, `cookie` and `set-cookie` headers are redacted
  (`packages/shared/src/log.ts`); Ory runs with `leak_sensitive_values: false`.
- The broker reads/sets `X-Correlation-Id` (generated when absent) and logs it on every request;
  the Fastify services use `x-correlation-id` as request ID. Error pages show it as
  "Riferimento / reference" — ask users for it.
- Find a failed login: take the reference from the error page, then
  ```bash
  make logs | grep '<reference>'          # or the log platform in Kubernetes
  icurl -H "Authorization: Bearer $AUDIT_READ_TOKEN" "http://audit-service:4100/events?correlation_id=<reference>" | jq
  ```
- Broker failure details (`detail`) are only in logs (`"federated authentication failed"`,
  `"start upstream authentication failed"`), never in user pages or audit context.

## 4. Metrics

Exposed only by the broker on the admin port: `GET http://federation-broker:8091/metrics`
(Kubernetes: scrape annotations or ServiceMonitor, `metrics.*` in Helm values).

| Metric | Labels | Use |
|---|---|---|
| `broker_federated_auth_total` | `profile`, `outcome` (`success` or failure code) | login success rate, spikes of `provider_unavailable`, `federation_untrusted`, `insufficient_assurance` |
| `broker_http_requests_total` | `listener`, `route`, `code` | traffic, 429/5xx rates |
| `broker_http_duration_seconds` | `listener`, `route` | latency |

Plus Go runtime/process metrics from the Prometheus client. The TypeScript services and Ory components
are not scraped by this repository's configuration; no alert rules are provided (to be defined).
Suggested alerts: federated failure ratio, `broker_http_requests_total{code="429"}`, readiness failures,
certificate/chain expiry from `/admin/status`.

## 5. Common incidents

### 5.0 Never change an RP entity ID casually

SPID and CIE OPs issue pairwise subjects per RP. A new entity ID (for example a new host name) gives
every user a new external subject: existing `identity_links` no longer match, returning users appear
as new federated identities and Kratos starts its account-linking flow when the email already exists.
Treat the production entity IDs as permanent; a change needs a migration plan, user communication and
a Change Management record. (Observed locally on 2026-11-14 when the entity IDs moved to
`broker.localhost`.)

### 5.1 An identity provider is unavailable

Symptoms: users see "Il gestore dell'identità non è disponibile"; `outcome="provider_unavailable"`
grows; **Federazione SPID/CIE → Panoramica** shows the OP untrusted or errors.

1. Check *Diagnostica* for the OP (cache bypass) and broker logs for `token endpoint:` / `userinfo:`
   errors (timeouts, TLS, DNS).
2. Check egress: outbound host allow-list (`BROKER_OUTBOUND_HOST_ALLOWLIST`), NetworkPolicy
   `brokerInternetEgress`, proxies.
3. If the OP is down, optionally disable it in **Identity Provider** so users pick another IdP (change
   record; re-enable when resolved). For CIE with a single provider there is no alternative.
4. Communicate per service procedures. Do not relax TLS or outbound restrictions.

### 5.2 Trust chain failure

Symptoms: `federation_untrusted`; `federation.trust` audit events; *Panoramica* "non valida".

1. *Diagnostica* → resolve the OP with *Ignora cache*; read the error:
   - `trust anchor configuration not signed by pinned keys` → the TA rotated keys or the pinned JWKS is
     wrong → follow [`key-rotation.md`](key-rotation.md#5-trust-anchor-key-changes) (out-of-band
     verification required).
   - `expired` / `issued in the future` → check clocks (NTP) of broker hosts; check statement expiry.
   - `no valid path to a trust anchor` / `has no authority_hints` → OP not (or no longer) registered.
   - `outbound request blocked by policy` → allow-list/egress configuration.
2. Resolve our own RP (`openid_relying_party`) — `self_trust` in *Panoramica* — to detect problems with
   our registration or federation key.
3. *Svuota tutte le cache di trust* after fixing configuration.
4. Unexpected trust changes (unknown keys, tampered statements) are security events: stop and apply
   Incident Management.

### 5.3 Key or certificate expiry

- *Chiavi e certificati* shows certificate validity; `GET /admin/status` lists non-retired keys with
  `certificate.not_after`. Profile warnings report missing active keys.
- Rotate before expiry following [`key-rotation.md`](key-rotation.md). Federation keys require
  coordination with the federation operator.
- The broker does not alert by itself; monitor `/admin/status` externally.

### 5.4 Database unavailable

- Broker `/readyz` → 503; Kratos/Hydra readiness fails; identity-service `/readyz` → 503; logins fail
  closed (no assurance can be bound → login rejected or LoA `none`).
- Check PostgreSQL health, connection limits (`max_conns=20` for Ory DSNs, pool 10 for Node services),
  credentials. After recovery services reconnect; restart pods that remain unready.
- Data loss → [`disaster-recovery.md`](disaster-recovery.md).

### 5.5 Kratos cannot use the broker facade

Symptoms: Kratos errors after returning from SPID/CIE, `invalid_client` at `/oidc/{profile}/token`.
Check that `client_secret` in `kratos.secrets.yml` equals `BROKER_FACADE_CLIENT_SECRET`, and that
Kratos' callback URLs are listed in `BROKER_FACADE_REDIRECT_URIS`.

### 5.6 Broker fails to start or cannot use its keys

Configuration errors are printed at start-up (`internal/server/config.go`), e.g. missing variables,
tokens shorter than 32 characters, `https` required in production. If the broker starts but logs
`unseal key …` errors (Entity Configuration returns 503, logins fail with `configuration_error`),
`BROKER_SEAL_KEYS` no longer contains the key that sealed the stored private keys — restore the previous
value ([`key-rotation.md`](key-rotation.md#3-seal-keys)).

### 5.7 Audit service unavailable

Events are still written to service logs (`"audit"` lines); delivery retries are limited (broker: queue
of 1024, dropped when full; TS services: 3 attempts) and lost events are logged as
`audit event delivery failed` / `audit queue full`. Recover the service, then reconcile from logs if needed.

## 6. Audit queries

Admin console **Audit** (role with `audit.read`: `security-auditor`, `superadmin`) with quick filters:
login failures, federation, admin, keys. API: [`api-examples.md`](api-examples.md) §10. SQL (audit DB,
read-only access recommended):

```sql
-- federated failures by reason, last 24 h
SELECT context->>'profile' AS profile, context->>'reason' AS reason, count(*)
  FROM audit_events WHERE type LIKE 'federation.%' AND outcome='failure' AND ts > now() - interval '24 hours'
 GROUP BY 1,2 ORDER BY 3 DESC;
-- administrative changes to federation configuration and keys
SELECT ts, actor, type, context FROM audit_events
 WHERE type LIKE 'admin.federation.%' OR type LIKE 'key.%' ORDER BY ts DESC LIMIT 100;
-- account-linking conflicts
SELECT ts, actor, context FROM audit_events WHERE type = 'account.link_conflict' ORDER BY ts DESC;
```

Local SQL shell: `docker compose --env-file .env -f infrastructure/docker/docker-compose.yml exec postgres psql -U postgres -d audit`.
Event catalogue: [`../security/threat-model.md`](../security/threat-model.md#6-audit-events-relevant-to-security-monitoring).

## 7. Revoking sessions and tokens

| Scope | How |
|---|---|
| One Kratos session of a user | admin console **Utenti → <user> → Sessioni → Revoca** (`sessions.revoke`) |
| Everything for a user (Kratos sessions, Hydra login + consent sessions, issued tokens) | **Revoca tutte le sessioni e i token** |
| User's own other sessions | identity portal **Disconnetti** / **Disconnetti tutte le altre sessioni** |
| A single token | `POST /oauth2/revoke` with the client's credentials ([`api-examples.md`](api-examples.md) §4) |
| All tokens of a client | delete the client (admin console) or rotate its secret; note JWT access tokens remain valid until `exp` (15 min) for APIs that do not introspect |

Resource servers that must honour revocation immediately must enable introspection
(`alwaysIntrospect`), as demo-api does.

## 8. Registering a new application in Hydra

1. Agree with the application owner: client type (confidential web, public SPA/mobile with PKCE,
   machine-to-machine), exact redirect URIs (https in production, no wildcards), post-logout URIs,
   scopes, API audiences, minimum LoA, allowed federated providers, whether consent may be skipped
   (first-party only).
2. Admin console → **Client OAuth2 → Registra nuova applicazione** (`client-admin` or `superadmin`):
   name, type, redirect URIs (one per line), post-logout URIs, scopes, audiences, *LoA minimo
   richiesto*, *Applicazione di prima parte (salta consenso)*. Wildcards and non-local `http` URIs are
   rejected.
3. Copy the **client secret shown once** directly into the secrets manager. It is never displayed again.
4. If needed, set `metadata.allowed_providers` or edit other fields with the Hydra admin API (the console
   only creates and deletes clients) — [`api-examples.md`](api-examples.md) §6,
   [`../security/assurance-levels.md`](../security/assurance-levels.md) §4.
5. New scopes must also be granted to the client (`scope`) and, to be advertised in discovery, added to
   `webfinger.oidc_discovery.supported_scope` in `config/hydra/hydra.yml`. Claims are released per scope
   by login-consent (`apps/login-consent/src/claims.ts`): `profile`, `email`, `fiscal_number`.
6. The application must use authorization code + PKCE, validate `state`, `nonce`, issuer and audience,
   send `audience=<api>` when it calls APIs, and handle RFC 9470 errors by re-authenticating with
   `acr_values` (example: `apps/demo-web/src/main.ts`).
7. Audit: `client.created` / `client.deleted`.

## 9. Connecting a new protected API with `@iam/auth-sdk`

`packages/auth-sdk` is a workspace package of this monorepo (not published to a registry). A new API in
the monorepo can depend on it directly.

```ts
// based on services/demo-api/src/main.ts and app.ts
import Fastify from "fastify";
import { createTokenValidator, requireAuth } from "@iam/auth-sdk";
import { LOA } from "@iam/shared";

const validator = createTokenValidator({
  issuer: process.env.OAUTH2_ISSUER!,          // e.g. https://oauth.example.it/  (must equal Hydra's issuer)
  jwksUrl: process.env.OAUTH2_JWKS_URL!,       // e.g. http://<hydra-public-svc>:4444/.well-known/jwks.json
  audience: "payments-api",                    // required; clients must request audience=payments-api
  hydraAdminUrl: process.env.HYDRA_ADMIN_URL,  // enables introspection (opaque tokens, revocation)
  alwaysIntrospect: true,                      // honour revocation immediately
});

const app = Fastify({ bodyLimit: 16 * 1024 });
app.get("/api/me", { preHandler: requireAuth(validator, { kind: "user", scopes: ["profile.read"] }) },
  async (req) => ({ sub: req.principal!.subject, loa: req.principal!.loa }));

// sensitive: recent (≤ 5 min) high-assurance authentication, SPID or CIE only
app.post("/api/payments", {
  preHandler: requireAuth(validator, { kind: "user", scopes: ["payments.write"], minLoA: LOA.HIGH,
                                       maxAuthAgeSeconds: 300, amrAnyOf: ["spid", "cie"] }) },
  async () => ({ ok: true }));

// machine-to-machine
app.get("/api/batch", { preHandler: requireAuth(validator, { kind: "machine", scopes: ["batch.read"] }) },
  async () => ({ ok: true }));
```

Checklist:

- [ ] Choose an audience name and add it to the `audience` list of every client allowed to call the API.
- [ ] Define scopes; grant them to clients; add them to Hydra discovery if they should be advertised.
- [ ] Reach Hydra JWKS and (if introspecting) the Hydra **admin** endpoint over the internal network
      only; add NetworkPolicy flows in Kubernetes.
- [ ] Authorise per resource in business logic — a valid token is not authorisation to every object.
- [ ] Return the SDK's `WWW-Authenticate` errors unchanged so clients can step up
      ([`../security/assurance-levels.md`](../security/assurance-levels.md) §7).
- [ ] Add tests like `services/demo-api/src/app.test.ts` (status codes for missing, invalid, wrong
      kind, insufficient LoA, stale authentication).

## 10. Routine checks

| Frequency | Check |
|---|---|
| Daily | *Panoramica*: providers trusted, recent failures; `broker_federated_auth_total` failure ratio |
| Weekly | audit review of `admin.*`, `key.*`, `client.*`, `account.link_conflict`; Security workflow results |
| Monthly | key and certificate expiry; trust-chain expiry; admin role assignments (`/internal/roles` or admin console) |
| Per release | `make test`, `make test-security`, `make test-e2e`, `scripts/k8s-validate.sh`; human review |
