#!/usr/bin/env bash
# Generates .env (random development secrets) and Ory secret overlay files.
# Idempotent: existing .env is kept unless --force is given.
set -euo pipefail
cd "$(dirname "$0")/.."
FORCE=${1:-}
need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }
need openssl; need docker

if [[ -f .env && "$FORCE" != "--force" ]]; then
  echo ".env already exists (use scripts/setup.sh --force to regenerate)"
else
  tmp=$(mktemp)
  while IFS= read -r line; do
    while [[ "$line" == *__GENERATE_* ]]; do
      case "$line" in
        *__GENERATE_PASSWORD__*) v=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24); line=${line/__GENERATE_PASSWORD__/$v} ;;
        *__GENERATE_HEX32__*)    v=$(openssl rand -hex 32); line=${line/__GENERATE_HEX32__/$v} ;;
        *__GENERATE_HEX16__*)    v=$(openssl rand -hex 16); line=${line/__GENERATE_HEX16__/$v} ;;
        *__GENERATE_SEALKEY__*)  v="k$(date +%Y%m):$(openssl rand -base64 32)"; line=${line/__GENERATE_SEALKEY__/$v} ;;
        *) break ;;  # e.g. documentation comments mentioning the placeholder syntax
      esac
    done
    printf '%s\n' "$line" >> "$tmp"
  done < .env.example
  # strip inline comments from assignments so docker compose reads clean values
  sed -E 's/^([A-Z0-9_]+=[^ #]*)[[:space:]]+#.*$/\1/' "$tmp" > .env
  rm -f "$tmp"; chmod 600 .env
  echo "generated .env with random development secrets"
fi

set -a; source .env; set +a
dir=infrastructure/docker/dev-secrets
mkdir -p "$dir"; chmod 700 "$dir"
cat > "$dir/kratos.secrets.yml" <<YAML
secrets:
  cookie: ["$KRATOS_SECRETS_COOKIE"]
  cipher: ["$KRATOS_SECRETS_CIPHER"]
courier:
  smtp:
    connection_uri: smtp://mailpit:1025/?disable_starttls=true
selfservice:
  methods:
    oidc:
      config:
        providers:
          - id: spid
            provider: generic
            label: SPID
            client_id: kratos
            client_secret: "$BROKER_FACADE_CLIENT_SECRET"
            issuer_url: http://federation-broker:8090/oidc/spid
            mapper_url: file:///etc/config/kratos/federated.jsonnet
            scope: [openid]
            claims_source: id_token
            pkce: force
          - id: cie
            provider: generic
            label: CIE
            client_id: kratos
            client_secret: "$BROKER_FACADE_CLIENT_SECRET"
            issuer_url: http://federation-broker:8090/oidc/cie
            mapper_url: file:///etc/config/kratos/federated.jsonnet
            scope: [openid]
            claims_source: id_token
            pkce: force
YAML
cat > "$dir/hydra.secrets.yml" <<YAML
secrets:
  system: ["$HYDRA_SECRETS_SYSTEM"]
  cookie: ["$HYDRA_SECRETS_COOKIE"]
YAML
chmod 600 "$dir"/*.yml
echo "wrote $dir/{kratos,hydra}.secrets.yml"
