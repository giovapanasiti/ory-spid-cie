# Progress

_Last updated: 2026-11-14._ Status legend: COMPLETE · PARTIAL · BLOCKED · NOT STARTED.
"COMPLETE" means implemented **and** verified by the tests listed; it never implies certification or conformance.

## Verification evidence (2026-11-14, local)

| Suite | Command | Result |
|---|---|---|
| Go unit + protocol integration (race) | `make test-go` | PASS — fedjose, oidcfed, safehttp, sim (trust chain), server (end-to-end federation flows, 15 rejection scenarios) |
| TS unit + DB integration | `make test-ts` | PASS — 29 tests (shared, auth-sdk, ui, login-consent policy/claims, demo-api, admin RBAC, identity-service linking/assurance incl. concurrent linking) |
| Lint / typecheck | `npm run lint`, `npm run build`, `gofmt`, `go vet` | PASS |
| Live security smoke | `scripts/security-smoke.sh` | 14/14 PASS |
| Browser e2e (Playwright, Chromium) | `make test-e2e` | 10/10 PASS |
| Go vulnerabilities | `govulncheck ./...` (go1.26.11) | No vulnerabilities found |
| npm production deps | `npm audit --omit=dev --audit-level=high` | 0 vulnerabilities |
| Helm | `scripts/k8s-validate.sh` (helm lint + kubeconform) | PASS (57/58 resources valid, ServiceMonitor CRD skipped) |
| Coverage (Go, cross-package) | `make coverage` | 55.5% total; rp/service.go 81.9%, oidcfed 75–83%, fedjose/jwt.go 78% ; server/admin.go 2.6% (exercised only by e2e) |

Untested / weakly tested security-relevant paths: broker admin API handlers (unit), key import of EC keys + ECDH-ES userinfo decryption, signed_jwks_uri OP metadata, trust marks issued by non-TA issuers, intermediate (multi-level) trust chains, Kratos settings-flow linking UI end-to-end, passkey ceremonies (need a WebAuthn virtual authenticator in Playwright), recovery/verification email flows.

## Phase status

| Phase | Status | Notes |
|---|---|---|
| 0 Research & architecture | COMPLETE | `docs/architecture/*` (research notes, compatibility matrix, ADRs, overview), threat model in `docs/security/` |
| 1 Core infrastructure | COMPLETE | monorepo, Postgres (one DB/role per service), Kratos/Hydra v26.2.0, migrations, compose, `.env` generation |
| 2 Authentication platform | COMPLETE | login-consent, Kratos UI, OAuth2/OIDC flows, demo app — e2e verified |
| 3 Federation foundation | COMPLETE (local) | trust chain, metadata policy, trust marks, keys, SSRF-safe fetch, simulator |
| 4 SPID | PARTIAL | protocol implemented and tested against LOCAL simulator; official conformance & onboarding BLOCKED (B1, B5) |
| 5 CIE | PARTIAL | as SPID; CIE-specific ACR values UNVERIFIED (B2, B9) |
| 6 Identity management | COMPLETE | links, verified attributes, portal, admin console (incl. federation keys/certificates/metadata UI), audit |
| 7 Security & testing | PARTIAL | suites above pass; independent security review NOT STARTED (B7) |
| 8 Deployment | PARTIAL | Helm chart + CI written and statically validated; no cluster run, workflows never executed on GitHub (B8, B10) |
| 9 Readiness assessment | COMPLETE | `docs/compliance/readiness-checklist.md` |

## Feature status (selected)

| Feature | Status |
|---|---|
| Password, registration, recovery (code), verification, settings | COMPLETE (registration/login e2e; recovery/verification not e2e-tested) |
| Passkeys (Kratos passkey method, CSP/CORS-compatible triggers) | PARTIAL — UI wired, no automated ceremony test |
| Hydra auth code + PKCE, refresh rotation, revocation, introspection, client credentials, logout | COMPLETE |
| SPID login (local federation) | COMPLETE (local) |
| CIE login + step-up to high (local federation) | COMPLETE (local) |
| Account linking (unique constraint, bind-once, conflicts audited) | COMPLETE (DB tests); Kratos link UI not e2e-tested |
| Admin console RBAC, CSRF, clients, sessions, audit view | COMPLETE |
| Federation admin UI: RP metadata, trust marks, keys (generate/import/rotate/retire), CSR, self-signed, CA cert upload, trust anchors (preview + pin), providers, EC preview, diagnostics | COMPLETE |
| Audit service (append-only, retention) | COMPLETE |
| OpenTelemetry tracing | NOT STARTED (Prometheus metrics on broker only; JSON logs everywhere) |
| SPID SAML | NOT STARTED (out of scope of OIDC profiles) |
| Trust mark status polling | NOT STARTED |

## Next task

1. Human review of the code and ADRs (ENPAM Procedura di Sviluppo Sicuro).
2. Start official onboarding (BLOCKERS B1–B4), then run official conformance tools (B5).
3. Add Playwright virtual-authenticator passkey test and Kratos link/unlink e2e test.
4. Add OpenTelemetry instrumentation; validate Helm chart on a staging cluster.
