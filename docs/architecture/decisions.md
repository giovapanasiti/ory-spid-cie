# Architecture Decision Records

All decisions are dated 2026-11-14 unless stated. Status: Accepted (subject to human review and Change Management).

## ADR-001 — SPID/CIE integration: standalone Go federation broker (option C)

**Context.** The prompt asks to choose between (A) extending Ory Polis, (B) a standalone adapter integrated with Polis, (C) a standalone SPID/CIE broker exposing an OIDC interface to Kratos. SPID/CIE OIDC (docs v1.2.1, Regolamento SPID OIDC Federation v2.0) require OpenID Federation 1.0 entity configurations, trust chains, metadata policy, trust marks, signed request objects, `private_key_jwt`, PKCE and signed+encrypted UserInfo.

**Evidence.** `ory/polis` (HEAD 2026-07-27) is a SAML/OIDC→OAuth2 bridge; its upstream OIDC client (`npm/src/controller/oauth/oidc-client.ts`, openid-client 6.8.4) uses discovery + client secret. Repository-wide search found no OpenID Federation, entity statement, trust chain, `private_key_jwt` or request-object support (see `research-notes.md` §10). Kratos v26.2.0 supports generic OIDC providers with `pkce`, `claims_source` and `upstream_parameters.acr_values` (`embedx/config.schema.json`, `spec/api.json`).

**Decision.** Option C. `services/federation-broker` (Go) is (1) the SPID and CIE Relying Party in the OpenID Federation and (2) a minimal OIDC Provider ("facade") consumed by Kratos as two generic providers (`spid`, `cie`). Polis is not deployed.

**Consequences.** Smallest security-sensitive custom code that can satisfy the profile; all cryptography delegated to go-jose v4 / Go stdlib. Kratos remains the identity/session authority; Hydra remains the OAuth2 authority. Custom code must be reviewed and conformance-tested before production (see readiness checklist). Revisit if Polis or Kratos gain native OpenID Federation support.

## ADR-002 — Language choices

Go for the broker (mature JOSE library, static binaries, distroless images). TypeScript (strict) + Fastify 5 for apps/services, as required. User-facing apps are **server-rendered** (no React/Next.js): this deviates from the suggested stack. Rationale: login, consent and admin pages handle security-sensitive flows; server rendering keeps tokens server-side, allows a strict CSP without inline scripts, and avoids a large client bundle/supply chain. A React front-end can be added later behind the same BFF routes.

## ADR-003 — Federated assurance binding

The broker stores each validated upstream authentication (`auth_results`) and returns to Kratos only a pairwise facade subject `sha256(op_issuer || sub)`. After Kratos creates the session, `identity-service` binds the broker result to the Kratos session **exactly once** (DB unique constraint on `bound_session_id`), selecting only results for the identity's own federated credential identifiers within a short time window of the Kratos `authentication_methods[].completed_at`. If no result can be bound, the session gets `urn:iam:loa:none` (fail closed). A normal Kratos session is never upgraded.

## ADR-004 — Internal assurance model

Internal LoA: `urn:iam:loa:none|low|substantial|high` (eIDAS-aligned labels). Each federation profile has its own explicit ACR→LoA map (default SPID: SpidL1→low, L2→substantial, L3→high; CIE uses the same ACR URIs per SPID/CIE docs v1.2.1 — CIE-specific ACR values UNVERIFIED). Local methods (password, passkey) get `none` because the identity is not proofed in that authentication; `identity_verified` signals prior verified attributes separately. The original federation ACR is preserved (`federated_acr`). Step-up is driven by `acr_values` / client `metadata.min_loa`, enforced in login-consent, consent, and resource servers (RFC 9470 errors).

## ADR-005 — Identity linking

`identity-service.identity_links` has `UNIQUE(provider, issuer, external_subject)`: one external identity maps to at most one account. Linking happens only through Kratos flows that require proof of control (Kratos settings "link" with privileged session / re-authentication, or Kratos duplicate-credential flow requiring login with the existing credential). Accounts are never merged on email or fiscal code. Conflicts are rejected and audited.

## ADR-006 — Data minimisation

Fiscal code and other verified attributes are not copied into Kratos traits; they are stored sealed (AES-256-GCM, app-level) in identity-service with provenance, with an HMAC lookup hash for exact-match admin search. Broker PII awaiting pick-up is sealed and purged after `BROKER_ATTRIBUTE_TTL_SECONDS` (default 15 min). The fiscal code is released to applications only with the dedicated `fiscal_number` scope and user consent.

## ADR-007 — Ory components

Kratos + Hydra only. Oathkeeper not used (API protection via `@iam/auth-sdk` in each resource server is sufficient and keeps assurance checks close to business logic). Keto not used (no relationship-based authorization requirement identified; admin RBAC is a small role table).

## ADR-008 — Federation configuration storage and UI

Federation configuration (RP profiles, providers, trust anchors, keys/certificates) is stored in the broker database and managed through the broker admin API and the admin console UI. A JSON bootstrap file seeds the first start only. Private keys are generated or imported inside the broker, sealed at rest and never exported. Trust anchor keys must be pinned after out-of-band verification (the UI shows RFC 7638 thumbprints and requires explicit confirmation).

## ADR-009 — Local test federation

A Go simulator (`cmd/fedsim`) provides a Trust Anchor and SPID/CIE OPs with fault injection, reusing the same protocol libraries so tests exercise real cryptography. It refuses to start without `FEDSIM_I_UNDERSTAND_THIS_IS_TEST_ONLY=true` and is excluded from production images/charts. It is **not** conformance evidence; official tools (`italia/spid-cie-oidc-django`, `AgID/spid-oidc-check-op`) and the federation operators' pre-production environments are required for that.
