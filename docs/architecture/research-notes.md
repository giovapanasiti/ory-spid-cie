# Research notes — SPID/CIE OIDC Federation, Ory components

Research performed 2026-11-14 against the sources below. Items marked
**UNVERIFIED** could not be confirmed from a primary source and must be
re-checked during federation onboarding.

Sources inspected:

| Source | Version / revision |
|---|---|
| `italia/spid-cie-oidc-docs` (published as "versione-corrente") | tag **1.2.1**, commit `a65aa1a`, 2023-10-31 |
| `italia/spid-cie-oidc-django` (reference implementation) | HEAD 2026-11-09 |
| AgID SPID page — https://www.agid.gov.it/it/piattaforme/spid | fetched 2026-11-14 |
| Regolamento SPID OpenID Connect Federation 1.0 (Det. AgID 71/2025 attachment `spid-oidc-federation.pdf`) | v2.0, 2025-03-31 |
| OpenID Federation 1.0 — https://openid.net/specs/openid-federation-1_0.html | **Final**, 2026-02-17 |
| `ory/polis` | HEAD 2026-07-27 |
| `ory/kratos`, `ory/hydra` | v26.2.0 (`spec/api.json`, `embedx/config.schema.json`) |

## 1. Binding regulation

- Linee Guida OpenID Connect in SPID — AgID Determinazione 616/2021 (2021-12-02).
- Regolamento SPID OpenID Connect Federation 1.0 — DT DG n. 249 (2022-09-14), updated by
  **Determinazione 71/2025** (2025-04-29, Regolamento v2.0 of 2025-03-31: "Federation Entity
  Discovery", Trust Mark revocation, ES/EC and metadata updates).
- Avviso SPID n.41 (2022-05-06), Tabella Attributi v1.3 (2022-06-24).
- CIE: Manuale Operativo v3 (Jan 2024), onboarding via https://federazione.servizicie.interno.gov.it/.

### Naming drift between SPID/CIE docs v1.2.1 and OpenID Federation Final

| Item | SPID/CIE docs v1.2.1 | OpenID Federation Final | Our implementation |
|---|---|---|---|
| Resolve endpoint TA parameter | `anchor` | `trust_anchor` | accept both |
| Trust Mark type claim | `id` | `trust_mark_type` | accept both, emit `id` (+ `trust_mark_type`) |
| Trust mark status request | `id` + `sub` | `trust_mark` (JWT) | accept both |

## 2. RP Entity Configuration (`entity_configuration.rst`, `metadata_oidc_rp.rst`)

- Served at `/.well-known/openid-federation`, `Content-Type: application/entity-statement+jwt`,
  JWS header `typ: entity-statement+jwt` (reference impl rejects other typ — `entity/statements.py:77`).
- Required: `iss`=`sub`, `iat`, `exp`, `jwks` (federation keys, `kid` mandatory), `metadata`,
  `authority_hints`; `trust_marks` mandatory for every participant except the TA.
- OIDC core keys SHOULD differ from federation keys.
- `federation_entity`: `organization_name`, `homepage_uri`, `policy_uri`, `contacts` (PEC),
  `federation_resolve_endpoint`; `logo_uri` recommended (SVG).
- `openid_relying_party`: `redirect_uris`, `grant_types` [`authorization_code`,`refresh_token`],
  `jwks` (CIE mandatory; SPID `jwks` or `signed_jwks_uri`), `id_token_signed_response_alg`,
  `userinfo_signed_response_alg`, `userinfo_encrypted_response_alg`/`_enc`,
  `token_endpoint_auth_method=private_key_jwt`, `client_id` (HTTPS URL),
  `client_registration_types=["automatic"]`, `response_types=["code"]`.
- Algorithms (`cryptographic_algos.rst`): MUST RS256, RS512, RSA-OAEP, RSA-OAEP-256,
  A128CBC-HS256, A256CBC-HS512; RECOMMENDED ES256, ES512, PS256, PS512, ECDH-ES(+A128KW/A256KW, CIE);
  MUST NOT none, RSA1_5, HS256/384/512. RSA ≥ 2048 bits (4096 recommended).
- Maximum EC lifetime: **UNVERIFIED** (only rule: chain exp = min exp).

## 3. Authorization request (`authorization_endpoint.rst`)

- GET or POST; signed `request` JWT mandatory; `request_uri` not used.
- HTTP params: `scope` (must match JWT), `client_id`, `response_type`, `code_challenge`,
  `code_challenge_method`.
- Request Object claims: `client_id`, `code_challenge`, `code_challenge_method`, `nonce` (≥32
  alphanumerics), `state` (≥32 alphanumerics), `prompt` (`consent` or `consent login` only),
  `redirect_uri`, `response_type`, `scope`, `acr_values`, `claims`, `exp`, `iat`,
  `iss`=`client_id`, `aud`=OP `issuer`, `ui_locales`.
- `acr_values`: space separated from `https://www.spid.gov.it/SpidL1|SpidL2|SpidL3`; the OP metadata
  table lists these for **both SPID and CIE**. CIE-specific ACR URIs: **UNVERIFIED** (none found).
- PKCE S256 mandatory. Response: `code`, `state`; CIE also returns `iss` which the RP MUST validate.
- PAR / JARM: not required, not mentioned (disallowed status UNVERIFIED) → not implemented.
- SPID attributes requested only via `claims` and returned only from UserInfo.

## 4. Token request (`token_endpoint.rst`)

- `private_key_jwt`: `client_id`, `client_assertion`,
  `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
- Assertion: `iss`=`sub`=`client_id`, `aud`=token endpoint URL, `iat`, `exp`, `jti`.
- `authorization_code` + `code_verifier`; `refresh_token` only with `offline_access` + `prompt=consent`,
  max 30 days. CIE: rotation mandatory, refresh MUST NOT yield ID Token. SPID: refresh yields ID token
  limited to SpidL1.

## 5. ID Token / UserInfo

- ID token: `iss`, pairwise `sub`, `aud`=client_id, `acr` ≥ requested, `at_hash`, `iat`, `exp`,
  `nbf` (SPID, = iat), `jti`, `nonce`. CIE optional signed-then-encrypted ID token (`cty: JWT`).
- UserInfo: SPID GET only, Bearer; response **always signed-then-encrypted** (JWE `cty: JWT`, inner
  JWS); payload `sub` (= ID token sub), `iss`, `aud`, `iat`, `exp` + attributes. Content-Type
  `application/jwt` (text) or `application/jose` (example) → accept both.

## 6. Attributes (`attributi_utente.rst`, prefix `https://attributes.eid.gov.it`)

- SPID+CIE: `given_name`, `family_name`, `place_of_birth`, `birthdate`, `gender`,
  `$PREFIX/fiscal_number` (value `TINIT-<CF>`), `document_details`, `phone_number`, `email`,
  `$PREFIX/e_delivery_service`, `address`.
- SPID only: `$PREFIX/spid_code`, `company_name`, `registered_office`, `company_fiscal_number`,
  `vat_number`, `eid_exp_date`. CIE only: `phone_number_verified`, `email_verified`, `$PREFIX/landline_number`.
- Legacy namespace `https://attributes.spid.gov.it/` appears in an old example; accepted on input.

## 7. Federation endpoints

| Endpoint | Final | SPID/CIE docs | Response typ |
|---|---|---|---|
| Fetch | GET `sub` | `sub` | `entity-statement+jwt` |
| List | GET `entity_type`,`trust_marked`,`trust_mark_type`,`intermediate` | `entity_type` | JSON |
| Resolve | GET `sub`,`trust_anchor`,`entity_type` | `sub`,`anchor` | `resolve-response+jwt` |
| Trust mark status | POST `trust_mark` | POST `id`+`sub` → `{"active":true}` | JSON / `trust-mark-status-response+jwt` |

## 8. Trust chain / metadata policy / trust marks

- Validation (Final §10.2): claims present, iat past/exp future, EC self-signed, each statement
  signed by key in next statement's `jwks`, last issued by TA; then metadata policy (§6.1.4) and
  constraints (§6.2). Chain exp = min exp.
- SPID/CIE OP rule (`trust_negotiation.rst`): OP validates RP trust mark **before** walking
  authority hints; no valid RP trust mark → reject.
- Operators: value, add, default, one_of, subset_of, superset_of, essential (+ extensions via
  `metadata_policy_crit`).
- Trust mark claims: `iss`, `sub`, `id`, `iat`, `logo_uri`, `exp`, `ref`, `organization_type`,
  `id_code`, `email`, `organization_name`, `sa_profile`.
- Trust mark id format `https://<domain>/<role>/<public|private>/`; SPID domain differs between docs
  (`registry.agid.gov.it`) and Regolamento v2.0 (`registry.spid.gov.it`); CIE examples
  `registry.interno.gov.it`. Production TA URLs: **UNVERIFIED** — obtained during onboarding.

## 9. Revocation / logout

- RFC 7009 with private_key_jwt; OP always 200.
- SPID: on logout revoke access + refresh token. CIE: revoke access token, not refresh token.
- No RP-initiated / front-channel logout defined.

## 10. Ory Polis assessment

Polis (README + `npm/src/controller/oauth/oidc-client.ts`, openid-client 6.8.4 with client secret)
is a SAML/OIDC → OAuth2 bridge. Repo-wide search found **no** support for `openid-federation`,
entity statements, trust chains, `private_key_jwt`, signed request objects or SPID/CIE.
→ Polis cannot act as SPID/CIE OIDC Federation RP. See ADR-001.

## 11. Test tools

- `italia/spid-cie-oidc-django`: demo federation (TA :8000 with SPID OP, RP :8001, CIE OP :8002),
  Docker image `ghcr.io/italia/spid-cie-oidc-django`. Integrated as the optional REFERENCE TEST
  federation (`make reference-up`, `*.localhost` host names instead of `/etc/hosts` entries); see
  [`../federation/reference-federation.md`](../federation/reference-federation.md). Demo credentials:
  isolated use only. Checked 2026-11-14 (image of 2026-11-09): its UserInfo JWT omits `iss`/`aud`
  required by `userinfo_endpoint.rst`; the demo user's fiscal number is malformed (15 characters).
- `demo.spid.gov.it` (AgID): SAML 2.0 only (IdP metadata `/metadata.xml`, SP registration through the
  SPID SAML Validator); no OpenID Federation endpoints on 2026-11-14. Not usable by this OIDC-only RP.
- `AgID/spid-oidc-check-op`: OP conformance tool (Node 14).
- CIE pre-production environment: via onboarding portal; URLs **UNVERIFIED**.
