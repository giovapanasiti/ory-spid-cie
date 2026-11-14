#!/usr/bin/env bash
# Generates .env (random development secrets) and Ory secret overlay files.
# Idempotent: existing .env is kept unless --force is given.
set -euo pipefail
cd "$(dirname "$0")/.."
FORCE=${1:-}
need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }
need openssl; need docker

# ---- preflight: fail early with a clear message instead of an obscure compose error
if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed but the daemon is not reachable: start Docker Desktop / the docker service" >&2
  exit 1
fi
if ! compose_version=$(docker compose version --short 2>/dev/null); then
  echo "Docker Compose v2 is required ('docker compose', not the old 'docker-compose')" >&2
  exit 1
fi
case "$compose_version" in
  v1.*|1.*|v2.[0-9].*|2.[0-9].*|v2.1[0-9].*|2.1[0-9].*)
    echo "Docker Compose $compose_version is too old: 2.20 or newer is required" >&2
    exit 1 ;;
esac
# Healthchecks use start_interval: Docker Engine 25+ (API 1.44+).
api=$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || echo 0.0)
if (( ${api%%.*} < 1 || (${api%%.*} == 1 && 10#${api#*.} < 44) )); then
  echo "Docker Engine API $api is too old: Docker Engine 25 or newer is required (healthcheck start_interval)" >&2
  exit 1
fi
# Published ports (all on 127.0.0.1). Skip the check when this stack is already running.
if [[ -z "$(docker compose -f infrastructure/docker/docker-compose.yml ps -q 2>/dev/null)" ]]; then
  busy=()
  for p in 3100 3200 4433 4444 4455 5580 5600 8025 8070 8090; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then busy+=("$p"); fi
  done
  if ((${#busy[@]})); then
    echo "These host ports are already in use: ${busy[*]}" >&2
    echo "Stop the programs using them (e.g. 'lsof -nP -iTCP:<port> -sTCP:LISTEN') and run make dev again." >&2
    exit 1
  fi
fi

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
