#!/usr/bin/env bash
# Live security smoke tests against the running local stack (non-destructive).
set -uo pipefail
fail=0
pass() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
reachable() { curl -s -m 2 -o /dev/null "$1"; }

for u in http://localhost:4434/admin/identities http://localhost:4445/admin/clients http://localhost:8091/admin/status; do
  if reachable "$u"; then bad "admin API exposed on host: $u"; else pass "admin API not exposed on host: $u"; fi
done

h=$(curl -s -D - -o /dev/null "http://localhost:4455/auth/error?id=x" | tr -d '\r')
grep -qi "^content-security-policy:.*frame-ancestors 'none'" <<<"$h" && pass "login UI CSP with frame-ancestors 'none'" || bad "login UI CSP"
grep -qi '^x-content-type-options: nosniff' <<<"$h" && pass "login UI nosniff" || bad "login UI nosniff"
grep -qi '^x-frame-options: DENY' <<<"$h" && pass "login UI X-Frame-Options" || bad "login UI X-Frame-Options"

c=$(code 'http://localhost:8090/oidc/spid/authorize?client_id=kratos&redirect_uri=https://evil.example/cb&response_type=code&scope=openid&state=x')
[ "$c" = 400 ] && pass "broker refuses unregistered redirect_uri (no open redirect)" || bad "broker open redirect ($c)"
c=$(code -d grant_type=authorization_code -d code=x http://localhost:8090/oidc/spid/token)
[ "$c" = 401 ] && pass "broker token endpoint requires client auth" || bad "broker token auth ($c)"
c=$(code 'http://localhost:8090/rp/spid/callback?state=forged&code=x')
[ "$c" = 400 ] && pass "broker callback rejects forged state" || bad "broker forged state ($c)"
ec=$(curl -s http://localhost:8090/rp/spid/.well-known/openid-federation)
[[ "$ec" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] && pass "RP entity configuration is a compact JWS" || bad "RP entity configuration"

loc=$(curl -s -o /dev/null -w '%{redirect_url}' 'http://localhost:4444/oauth2/auth?client_id=demo-web&response_type=code&scope=openid&state=abcdefghij&redirect_uri=http://localhost:5580/evil')
[[ "$loc" != http://localhost:5580/evil* ]] && pass "hydra rejects unregistered redirect_uri" || bad "hydra redirect_uri"

c=$(code http://localhost:5600/api/profile)
[ "$c" = 401 ] && pass "demo API rejects missing token" || bad "demo API missing token ($c)"
c=$(code -H 'authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.' http://localhost:5600/api/profile)
[ "$c" = 401 ] && pass "demo API rejects alg=none token" || bad "demo API alg none ($c)"
c=$(code -X POST -d csrf=x http://localhost:3100/federation/keys/generate)
[ "$c" = 401 ] && pass "admin console POST without session rejected" || bad "admin POST ($c)"
exit $fail
