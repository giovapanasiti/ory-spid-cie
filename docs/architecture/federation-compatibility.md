# Federation compatibility matrix

Sources and versions: see `research-notes.md` (SPID/CIE OIDC docs **v1.2.1**, Regolamento SPID OIDC Federation **v2.0 / Det. AgID 71/2025**, OpenID Federation 1.0 **Final 2026-02-17**, Ory Kratos/Hydra **v26.2.0**, Ory Polis HEAD **2026-07-27**).

Legend: **N** supported natively · **C** supported through configuration · **X** requires custom implementation · **U** unsupported · **?** not yet verified.
"Here" = this repository (`services/federation-broker`), with implementation location.

| Capability | Ory Polis | Ory Kratos | Ory Hydra | Here | Evidence / notes |
|---|---|---|---|---|---|
| Generic SAML 2.0 (IdP side) | N | U | U | U | Polis README. Not needed for SPID/CIE OIDC. |
| Generic OpenID Connect RP | N (client secret) | N (generic provider) | U (is an OP) | Facade consumed by Kratos | Kratos `selfServiceOIDCProvider` schema; Polis `oidc-client.ts` |
| SPID SAML profile (Avviso 29 etc.) | U (no SPID metadata/signing profile) | U | U | **U (not implemented)** | Out of scope; documented in readiness checklist. Keys support X.509 for future work. |
| SPID OIDC profile | U | U | U | X — `internal/rp` | request object, PKCE S256, private_key_jwt, signed+encrypted UserInfo, acr SpidL1-3 (docs `authorization_endpoint.rst`, `token_endpoint.rst`, `userinfo_endpoint.rst`) |
| CIE OIDC profile | U | U | U | X — `internal/rp` (+ mandatory `iss` response param) | docs v1.2.1; CIE-specific ACR URIs **?** |
| OpenID Federation 1.0 | U | U | U | X — `internal/oidcfed` | Final §§3–10 |
| Entity Statements (EC + subordinate) | U | U | U | X — `oidcfed/entity.go`, RP EC in `rp/service.go` | typ `entity-statement+jwt` enforced |
| Trust chain validation | U | U | U | X — `oidcfed/chain.go` (bottom-up, pinned TA keys, max depth, loop detection, constraints) | Final §10.2; tests `internal/sim/chain_test.go` |
| Trust Anchors | U | U | U | C (admin UI / API, pinned JWKS) | ADR-008 |
| Trust Marks | U | U | U | X — validation (`VerifyTrustMark`), RP publication (admin UI) | `id` and `trust_mark_type` both accepted; status endpoint not called (**?** dynamic revocation) |
| Metadata policies | U | U | U | X — `oidcfed/policy.go` (value, add, default, one_of, subset_of, superset_of, essential; crit) | tests `policy_test.go` |
| Dynamic client registration (automatic) | U | U | N (RFC 7591, not federation) | X — `client_registration_types=["automatic"]` + EC published | SPID/CIE use automatic registration via trust chain, not RFC 7591 |
| Signed authentication requests | U | U | U | X — request object signed with core-sig key | |
| PAR / JARM | U | U | N (Hydra as OP) | U (not required by profile, docs v1.2.1) | disallowed status **?** |
| Supported assurance levels | U | aal1/aal2 only | acr passthrough | X — ACR→LoA map per profile, step-up | ADR-004 |
| Attribute validation | U | jsonnet mapping | U | X — `rp.NormalizeAttributes` (CF format, email, dates) | |
| Cryptographic key rotation | U | U (Kratos secrets only) | N (own JWKS) | X — next/active/deprecated/retired lifecycle, admin UI | `docs/operations/key-rotation.md` |
| Federation revocation & trust updates | U | U | U | Partial — chain re-resolution with TTL ≤ chain exp, manual refresh, TA/provider disable | trust mark status endpoint polling NOT implemented |
| Resolve endpoint (`federation_resolve_endpoint`) | U | U | U | X — `/rp/{profile}/resolve` (`trust_anchor` and legacy `anchor`) | |
| Upstream token revocation (logout) | U | U | U | X — revoked right after UserInfo | broker keeps no upstream session |

## Decision

Polis cannot be used as SPID/CIE RP (no OpenID Federation, no `private_key_jwt`, no request objects). Option **C** selected — see ADR-001.

## Gaps requiring further work before production

1. Dynamic trust mark status checks (trust_mark_status endpoint) — currently static validation only.
2. Official conformance runs (spid-cie-oidc-django onboarding validators, AgID spid-oidc-check-op) — not executed.
3. CIE-specific ACR/claims differences — **?** to confirm with Ministero dell'Interno documentation during onboarding.
4. Refresh tokens / long sessions from the OPs — not used by design.
5. SPID SAML — not implemented.
