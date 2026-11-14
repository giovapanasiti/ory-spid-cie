# Decisions

Full ADRs: `docs/architecture/decisions.md`. Summary:

| # | Decision | Status |
|---|---|---|
| ADR-001 | SPID/CIE via standalone Go federation broker (option C); Ory Polis not used (no OpenID Federation / private_key_jwt) | Accepted |
| ADR-002 | Go for broker; TypeScript/Fastify for services; **server-rendered UIs instead of React/Next.js** (deviation, security rationale) | Accepted |
| ADR-003 | Broker result bound once to a Kratos session by identity-service (fail closed) | Accepted |
| ADR-004 | Internal LoA `urn:iam:loa:none|low|substantial|high`, per-profile ACR maps, step-up | Accepted |
| ADR-005 | `identity_links` UNIQUE(provider, issuer, external_subject); no merge on email/fiscal code | Accepted |
| ADR-006 | Verified attributes sealed in identity-service, not in Kratos traits; fiscal code only with `fiscal_number` scope | Accepted |
| ADR-007 | No Oathkeeper / Keto | Accepted |
| ADR-008 | Federation configuration in broker DB, managed via admin console UI; keys never exported; TA keys pinned after OOB verification | Accepted |
| ADR-009 | Local test federation simulator, test-only, not conformance evidence | Accepted |

Operational decisions made during implementation (2026-11-14):

- Host ports: login UI **4455** and demo **5580** (3000 and 5555 were occupied on the development host).
- `form-action` CSP directive omitted on pages whose form POSTs start OAuth2 redirect chains (browsers enforce it on every redirect hop); other CSP directives remain strict.
- `Referrer-Policy: same-origin` (not `no-referrer`) so browsers send a real `Origin` header used by CSRF checks.
- Kratos public CORS enabled only for the login UI origin, required to load `webauthn.js` with SRI for passkeys.
- Broker public URL and local entity IDs on `broker.localhost:8090` (resolves to loopback in browsers and to the broker through a compose network alias): reference OPs require the `redirect_uri` host inside the `client_id`.
- Optional REFERENCE TEST federation from the official `italia/spid-cie-oidc-django` image (pinned digest), with two test-only adjustments documented in `docs/federation/reference-federation.md` (UserInfo `iss`/`aud` patch in the test OP, valid synthetic fiscal codes in the demo fixture). The broker keeps enforcing the specification.
- `demo.spid.gov.it` not used: it is SAML 2.0 only.
- Go toolchain pinned to go1.26.11 (go1.26.0 had 37 reachable stdlib vulnerabilities per govulncheck).
