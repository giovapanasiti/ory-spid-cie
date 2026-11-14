# Readiness checklist

Evidence-based status against the acceptance criteria of `prompt.md` §25. Date of assessment:
**2026-11-14**. Status values: **COMPLETE** (implemented and evidenced by tests or execution),
**PARTIAL** (implemented with gaps or without full test evidence), **BLOCKED** (depends on an external
party or a prior gate), **NOT STARTED**.

> This document does **not** certify anything. The platform is **not** certified, has **not** passed
> official SPID or CIE conformance tests, has **not** been onboarded into any federation, and no
> GDPR or other legal compliance is claimed. All results below come from the local development
> environment with the **LOCAL test federation** (`fedsim`), which is not conformance evidence.
> Every decision to proceed — review, approval, risk acceptance, release — belongs to the responsible
> people under the ENPAM Linee Guida AI, Procedura di Sviluppo Sicuro and Change Management.

## 1. Test evidence available

| Suite | Command | Result recorded (2026-11-14) | Scope |
|---|---|---|---|
| Go unit + protocol integration | `make test-go` | all pass | `fedjose` (sign/verify, alg none, HS256 confusion, missing kid, JWE, CSR), `oidcfed` policy, `sim` trust chains (valid, rogue, tampered, unknown, wrong pinned key, expired, alg allow-list), `server` end-to-end federation flows incl. 15 rejection scenarios, browser binding, open redirect, client auth, concurrent binding |
| TypeScript unit + identity-service DB integration | `make test-ts` | 30 pass (5 consecutive runs) | auth-sdk, demo-api, login-consent policy/claims, shared (XSS, CSRF, sealing, LoA, audit scrubbing), UI, RBAC matrix, 7 identity-service DB tests (`make test-ts` starts the test database) |
| Live security smoke | `scripts/security-smoke.sh` | 14/14 PASS | admin ports not exposed, headers/CSP, broker open redirect, token auth, forged state, EC format, Hydra redirect URI, demo API missing/alg-none token, admin POST without session |
| End-to-end (Playwright) | `make test-e2e` | 10/10 pass | see criteria 2–14 |
| End-to-end against the REFERENCE TEST federation | `make reference-up`, `make test-e2e-reference` | 2/2 pass | SPID and CIE logins through the official reference implementation demo OPs (`italia/spid-cie-oidc-django`), with two documented test-only adjustments of the reference containers ([`../federation/reference-federation.md`](../federation/reference-federation.md)). Interoperability evidence, not conformance |
| Helm | `scripts/k8s-validate.sh` | pass | lint, template, kubeconform (default + staging), guards |
| Dependency / vuln scanners | `make test-security` (govulncheck, npm audit), `security.yml` | results **not recorded** in this checklist | — |
| CI workflows | `.github/workflows/*.yml` | **never run on GitHub** | — |
| Official SPID/CIE conformance | — | **not run** | `demo.spid.gov.it` is SAML only; the AgID OIDC validator and CIE pre-production need a public URL and onboarding |

## 2. Acceptance criteria — technically complete for local development

| # | Criterion | Status | Evidence / notes |
|---|---|---|---|
| 1 | `make dev` starts the complete platform | COMPLETE | `Makefile`, `infrastructure/docker/docker-compose.yml`; stack used by the e2e and smoke runs |
| 2 | Kratos login works | COMPLETE | e2e "password registration, OIDC login via Hydra…"; "login page offers SPID, CIE, passkey and password". **Passkey login itself is not automated** (button presence only) |
| 3 | Hydra issues valid OAuth2/OIDC tokens | COMPLETE | e2e: code flow validated by `openid-client` in demo-web, refresh rotation, client credentials |
| 4 | Demo application authenticates through Hydra | COMPLETE | `apps/demo-web`; e2e password and SPID flows |
| 5 | Login/consent integrates Hydra and Kratos | COMPLETE | `apps/login-consent`; `policy.test.ts`; e2e flows incl. consent and logout |
| 6 | SPID authentication works against a local federation test environment | COMPLETE (local simulator and local reference implementation) | e2e "SPID login (substantial)…", "SPID cancellation…", "invalid ID token signature…"; Go `TestFederationFlows` |
| 7 | CIE authentication works against a local federation test environment | COMPLETE (local simulator and local reference implementation) | e2e "step-up: high assurance…" (CIE), "CIE with insufficient level is rejected"; Go "CIE success with iss parameter". CIE ACR values UNVERIFIED ([`../federation/cie.md`](../federation/cie.md)) |
| 8 | Federation trust validation is exercised by automated tests | COMPLETE | `internal/sim/chain_test.go`, `internal/oidcfed/policy_test.go`, flow tests "untrusted issuer", "tampered metadata" |
| 9 | User identities are created correctly | COMPLETE | e2e SPID test checks federated identity + verified attributes; Kratos schema; `federated.jsonnet` |
| 10 | Account linking is secure | PARTIAL | Unique constraint, conditional bind, fail-closed assurance and concurrency are implemented and covered by Go test "concurrent bind…" and the identity-service DB tests (concurrent linking, re-link after unlink). Kratos settings-link and duplicate-credential flows are **not covered by automated tests** (the duplicate-email flow was observed manually on 2026-11-14 after an entity ID change); unlink reconciliation is lazy ([`../security/account-linking.md`](../security/account-linking.md)) |
| 11 | Authentication assurance information is preserved | COMPLETE | `federated_acr`, `loa`, `amr`, `auth_time` in tokens; `session_assurance`; e2e step-up; `auth-sdk.test.ts` |
| 12 | Protected APIs validate tokens | COMPLETE | `packages/auth-sdk`, `services/demo-api/src/app.test.ts`, smoke tests, e2e |
| 13 | Logout and revocation work as designed | COMPLETE | e2e logout, refresh-token revocation by demo-web, client-credentials revocation + introspection; upstream access token revoked by the broker (no SPID/CIE single logout by design) |
| 14 | Administrative interfaces enforce authorization | COMPLETE | `rbac.ts` + `rbac.test.ts`; e2e "admin console rejects users without roles and cross-site POSTs", federation-admin test |
| 15 | Audit events are recorded | PARTIAL | Structured events in all services, append-only table, scrubbing unit-tested. No automated test asserts persisted events; delivery is best effort; Kratos-native login failures (e.g. wrong password) are not sent to audit-service |
| 16 | Security tests pass | COMPLETE (scope as listed in §1) | Go rejection suites, TS security tests, smoke 14/14. Scanner results not recorded; no penetration test |
| 17 | Kubernetes configurations validate | COMPLETE (static validation) | `scripts/k8s-validate.sh`; not installed on a cluster |
| 18 | Documentation explains installation and operation | COMPLETE (pending human review) | `README.md`, `docs/**` |

## 3. Production readiness gates (separate)

| # | Gate | Status | What is needed |
|---|---|---|---|
| 19 | Verified federation conformance | NOT STARTED | run official validators (`italia/spid-cie-oidc-django` onboarding validators; AgID tooling; operators' pre-production tests) against a public test deployment; record evidence |
| 20 | Official registration and onboarding (AgID, Ministero dell'Interno) | NOT STARTED — BLOCKED on external parties | [`../federation/onboarding.md`](../federation/onboarding.md) |
| 21 | Production trust configuration (TA keys pinned out-of-band, trust marks, production entity IDs) | BLOCKED by gate 20 | — |
| 22 | Security review | NOT STARTED | independent review/penetration test of the broker, login-consent, identity-service, deployment; review of [`../security/threat-model.md`](../security/threat-model.md) residual risks |
| 23 | Operational readiness | NOT STARTED | staging deployment, CI executed, monitoring/alerting, backup/restore drill, RPO/RTO approved, on-call runbooks validated |
| 24 | Approved production credentials and certificates | BLOCKED by gate 20 | production keys generated in the target environment, certificates from the required CA (if any), secrets in the secrets manager |
| 25 | Legal and organisational requirements | NOT STARTED | DPO assessment (legal basis, DPIA, retention, data-subject request procedures), branding rules, agreements with federation operators, ENPAM approvals |

## 4. Not implemented (by design or pending)

- SPID SAML 2.0 profile.
- Trust mark status / revocation polling.
- Refresh tokens from SPID/CIE OPs; SPID/CIE single logout (not defined by the profile docs inspected).
- Data-subject erasure tooling; admin unlink/merge functions; re-sealing tools for seal-key rotation.
- OpenTelemetry instrumentation of broker and TypeScript services; alert rules.
- Publishing `@iam/auth-sdk` outside the monorepo.

## 5. Unresolved risks

Summary of [`../security/threat-model.md`](../security/threat-model.md) §5 and other findings:

1. Custom federation broker without independent review or official conformance testing.
2. Broker admin API trusts actor/role headers from any holder of `BROKER_ADMIN_TOKEN`.
3. Broker rate limiter keys on the direct peer IP; behind an ingress it becomes a shared limit.
4. CIE-specific ACR values, production TA URLs, trust-mark IDs, certificate requirements UNVERIFIED.
5. Trust marks validated statically only.
6. Seal/HMAC keys in environment variables; no re-sealing; `IDENTITY_LOOKUP_HMAC_KEY` not rotatable.
7. Plain HTTP between in-cluster services (incl. Kratos → broker facade); Kratos acceptance of an HTTP
   issuer without `--dev` not verified.
8. Audit delivery best effort; Kratos-native failures not in the audit store.
9. Account-linking edge cases (lazy reconciliation; attributes kept after unlink); Kratos linking flows not covered by automated tests.
10. No erasure tooling; retention defaults not approved.
11. Helm chart never deployed; CI never executed; no restore drill.
12. Passkey authentication not covered by an automated test.
