# API examples

Copy-paste examples for the **local** stack started with `make dev`. Hostnames, ports and client IDs are
those created by `scripts/seed-dev.mjs`. In other environments replace the URLs and obtain secrets from
the secrets manager — never paste production secrets into shell history or tickets.

## 0. Shell setup

```bash
cd /path/to/ory-spid
set -a; source .env; set +a          # LOCAL ONLY: loads the generated development secrets

# Admin/internal APIs (Kratos :4434, Hydra :4445, broker :8091, identity-service :4000,
# audit-service :4100) are not published on the host. Run curl inside the compose network
# ("iam_default", from `name: iam` in docker-compose.yml) with a throwaway container.
# The curl image is not part of the stack: pin it according to your image policy.
icurl() { docker run --rm -i --network iam_default curlimages/curl:8.11.1 -sS "$@"; }
```

Public endpoints used below: Hydra `http://localhost:4444`, demo-api `http://localhost:5600`,
broker `http://localhost:8090`.

## 1. OIDC discovery and JWKS

```bash
curl -s http://localhost:4444/.well-known/openid-configuration | jq '{issuer, authorization_endpoint, token_endpoint, scopes_supported}'
curl -s http://localhost:4444/.well-known/jwks.json | jq '.keys[] | {kid, alg, use}'
```

## 2. Authorization code + PKCE (public client `demo-public`)

`demo-public` is a public client (`token_endpoint_auth_method: none`) with redirect URI
`http://localhost:5580/public-callback`. demo-web does not implement that path, so after login the browser
shows a 404 — copy the `code` from the address bar.

```bash
VERIFIER=$(openssl rand -base64 64 | tr -d '=+/\n' | cut -c1-64)
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16); NONCE=$(openssl rand -hex 16)

echo "http://localhost:4444/oauth2/auth?response_type=code&client_id=demo-public\
&redirect_uri=http%3A%2F%2Flocalhost%3A5580%2Fpublic-callback\
&scope=openid%20offline_access%20profile%20profile.read&audience=demo-api\
&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256"
# Optional: append &acr_values=urn%3Aiam%3Aloa%3Ahigh to require SPID/CIE level high (step-up).
```

Open the printed URL, sign in, consent, then exchange the code:

```bash
CODE='<code from the address bar>'
curl -s http://localhost:4444/oauth2/token \
  -d grant_type=authorization_code -d client_id=demo-public \
  -d redirect_uri=http://localhost:5580/public-callback \
  -d code="$CODE" -d code_verifier="$VERIFIER" | tee /tmp/tokens.json | jq 'del(.access_token,.refresh_token,.id_token) + {has_refresh: (.refresh_token != null)}'
AT=$(jq -r .access_token /tmp/tokens.json); RT=$(jq -r .refresh_token /tmp/tokens.json)
```

Verify `state` and the ID token `nonce` in a real client (libraries such as `openid-client` do this; see
`apps/demo-web/src/main.ts`). Delete `/tmp/tokens.json` when done.

Refresh (rotation — the old refresh token becomes invalid):

```bash
curl -s http://localhost:4444/oauth2/token -d grant_type=refresh_token -d client_id=demo-public -d refresh_token="$RT" | jq 'keys'
```

## 3. Calling the protected demo API

```bash
curl -s http://localhost:5600/api/public | jq
curl -s -H "Authorization: Bearer $AT" http://localhost:5600/api/profile | jq
curl -si -H "Authorization: Bearer $AT" http://localhost:5600/api/sensitive | sed -n '1p;/^www-authenticate/Ip'
# 401 + WWW-Authenticate: Bearer error="insufficient_user_authentication", ..., acr_values="urn:iam:loa:high"
# unless the token comes from a SPID/CIE level-high login within the last 300 s.
```

## 4. Client credentials (machine-to-machine, `demo-m2m`)

```bash
M2M=$(curl -s -u "demo-m2m:$DEMO_M2M_CLIENT_SECRET" http://localhost:4444/oauth2/token \
  -d grant_type=client_credentials -d scope=reports.read -d audience=demo-api | jq -r .access_token)
curl -s  -H "Authorization: Bearer $M2M" http://localhost:5600/api/reports | jq     # 200
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $M2M" http://localhost:5600/api/profile   # 403 (machine token)

# Revoke, then the API (ALWAYS_INTROSPECT=true) rejects it
curl -s -u "demo-m2m:$DEMO_M2M_CLIENT_SECRET" http://localhost:4444/oauth2/revoke -d token="$M2M"
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $M2M" http://localhost:5600/api/reports  # 401
```

## 5. Token introspection (internal network only)

Hydra's introspection endpoint is on the admin port and must never be exposed publicly.

```bash
icurl -X POST http://hydra:4445/admin/oauth2/introspect -d token="$AT" | jq '{active, sub, client_id, scope, aud, exp, ext}'
```

## 6. Registering an OAuth2 client (Hydra admin API)

Prefer the admin console (**Client OAuth2 → Registra nuova applicazione**): it validates redirect URIs
and shows the secret once. API equivalent (Hydra generates the secret when none is supplied; it is
returned only in this response):

```bash
icurl -X POST http://hydra:4445/admin/clients -H 'content-type: application/json' --data-binary @- <<'JSON' | jq '{client_id, client_secret}'
{
  "client_name": "Example App",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid offline_access profile email",
  "audience": ["demo-api"],
  "redirect_uris": ["http://localhost:7000/callback"],
  "post_logout_redirect_uris": ["http://localhost:7000/"],
  "token_endpoint_auth_method": "client_secret_basic",
  "skip_consent": false,
  "metadata": {"min_loa": "urn:iam:loa:substantial", "allowed_providers": ["spid", "cie"]}
}
JSON
icurl http://hydra:4445/admin/clients/<client_id> | jq 'del(.client_secret)'
```

## 7. RP-initiated logout

```bash
ID_TOKEN=$(jq -r .id_token /tmp/tokens.json)
echo "http://localhost:4444/oauth2/sessions/logout?id_token_hint=$ID_TOKEN&post_logout_redirect_uri=<registered post-logout URI>"
```

`demo-public` has no post-logout redirect URI registered; `demo-web` uses `http://localhost:5580/`.
login-consent asks for confirmation, accepts the Hydra logout and ends the Kratos session.

## 8. Broker federation endpoints (public)

```bash
# RP entity configuration (compact JWS) — decode the payload
curl -s http://localhost:8090/rp/spid/.well-known/openid-federation | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{iss, exp, authority_hints, metadata: (.metadata | keys)}'

# Resolve an OP through our resolve endpoint (trust anchor = LOCAL fedsim)
curl -s 'http://localhost:8090/rp/spid/resolve?sub=http://fedsim:8070/op/spid-test&trust_anchor=http://fedsim:8070/ta' | cut -c1-80; echo

# Facade discovery used by Kratos
curl -s http://localhost:8090/oidc/spid/.well-known/openid-configuration | jq '{issuer, authorization_endpoint, token_endpoint}'
```

(`base64 -d` may need padding on some platforms; any JWT decoder works.)

## 9. Broker admin API (internal network, `X-Actor` headers)

Every call needs the service token **and** the actor identity/roles; these are trusted by the broker,
so use a real, traceable actor ID (it is written to the audit log).

```bash
B='http://federation-broker:8091'
H=(-H "Authorization: Bearer $BROKER_ADMIN_TOKEN" -H "X-Actor: ops:mario.rossi" -H "X-Actor-Roles: federation-admin" -H 'content-type: application/json')

icurl "${H[@]}" $B/admin/status | jq '{environment, providers: [.providers[] | {profile, display_name, enabled, trusted, error}], auth_last_24h}'
icurl "${H[@]}" $B/admin/profiles/spid | jq '.warnings, .config.entity_id, .config.acr_map'
icurl "${H[@]}" $B/admin/keys?profile=spid | jq '.[] | {id, purpose, kid, status, cert_expires: .certificate.not_after}'

# Trust chain diagnostics (bypass cache)
icurl "${H[@]}" -X POST $B/admin/trust/resolve -d '{"profile":"spid","entity_id":"http://fedsim:8070/op/spid-test","entity_type":"openid_provider","no_cache":true}' | jq '{trusted, error, exp: .chain.exp, path: .chain.path}'

# Preview a Trust Anchor (nothing stored) — compare thumbprints out of band
icurl "${H[@]}" -X POST $B/admin/trust-anchors/preview -d '{"entity_id":"http://fedsim:8070/ta"}' | jq '{entity_id, thumbprints, warning}'

# Add a provider
icurl "${H[@]}" -X POST $B/admin/providers -d '{"profile":"spid","entity_id":"https://idp.example.it","display_name":"Example IdP","logo_uri":"","enabled":false,"sort_order":10}' | jq

# Generate a next key for rotation
icurl "${H[@]}" -X POST $B/admin/keys/generate -d '{"profile":"spid","purpose":"core-sig","key_type":"RSA-3072","alg":"","status":"next"}' | jq '{id, kid, status}'

# Update a profile: GET .config, edit, PUT back (unknown fields are rejected)
icurl "${H[@]}" $B/admin/profiles/spid | jq '.config | .ui_locales = "it"' > /tmp/spid-profile.json
icurl "${H[@]}" -X PUT $B/admin/profiles/spid --data-binary @- < /tmp/spid-profile.json | jq '.warnings'
```

Key types accepted by `generate`: see `GET /admin/meta` (`key_types`). The full endpoint list is in
[`../federation/spid.md`](../federation/spid.md#13-broker-admin-api).

## 10. Audit queries (audit-service)

```bash
icurl -H "Authorization: Bearer $AUDIT_READ_TOKEN" 'http://audit-service:4100/events?type=federation.&outcome=failure&limit=20' | jq '.[] | {timestamp, type, service, context}'
icurl -H "Authorization: Bearer $AUDIT_READ_TOKEN" 'http://audit-service:4100/events?correlation_id=<id from error page>' | jq
```

Parameters: `type` (prefix match), `actor`, `outcome` (`success`/`failure`), `service`,
`correlation_id`, `since`, `until` (ISO 8601 with offset), `limit` (1–500, default 100).

## 11. Broker metrics

```bash
icurl http://federation-broker:8091/metrics | grep -E '^broker_(federated_auth_total|http_requests_total)' | head
```
