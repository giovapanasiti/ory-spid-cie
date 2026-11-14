# iam-platform Helm chart

Production-oriented chart for the IAM platform: Ory Kratos and Hydra (v26.2.0),
the SPID/CIE federation broker (Go) and the TypeScript apps/services
(login-consent, identity-portal, admin-console, identity-service,
audit-service, plus the optional demo-web/demo-api).

Installing or upgrading in any shared environment follows the ENPAM Change
Management and Secure Development procedures. The chart does not approve or
deploy anything by itself; images are not published by this repository unless
the manual release workflow is explicitly run with `publish=true`.

## What it deploys

| Component | Image | Ports | Exposed by Ingress |
|---|---|---|---|
| kratos | `images.kratos` | 4433 public, 4434 admin | 4433 only (`hosts.kratos`) |
| kratos-courier | `images.kratos` | none | no |
| hydra | `images.hydra` | 4444 public, 4445 admin | 4444 only (`hosts.hydra`) |
| federation-broker | `images.broker` | 8090 public, 8091 admin/internal/metrics | 8090 only (`hosts.broker`) |
| login-consent | `images.node` | 3000 | yes (`hosts.login`) |
| identity-portal | `images.node` | 3200 | yes (`hosts.portal`) |
| admin-console | `images.node` | 3100 | yes, separate Ingress (`hosts.admin`) |
| identity-service | `images.node` | 4000 | no |
| audit-service | `images.node` | 4100 | no |
| demo-web / demo-api | `images.node` | 5555 / 5600 | demo-web only, when `demo.enabled` |
| fedsim (TEST ONLY) | `images.fedsim` | 8070 | only with `testFederation.enabled` + acknowledgement flag |

Admin ports have their own `*-admin` Services and are never routed by an
Ingress (`scripts/k8s-validate.sh` checks this).

Migrations run as `pre-install,pre-upgrade` hook Jobs: Kratos and Hydra
(`migrate sql up -e --yes`), the broker (`-migrate`), identity-service and
audit-service (`node <path>/dist/main.js --migrate`). Failed Jobs are kept for
inspection; successful ones are deleted.

## Prerequisites

1. **PostgreSQL** (external, see `postgresql` in `values.yaml`): one database
   and one role per service, TLS (`sslmode=verify-full`), backups/PITR.
   Set `postgresql.networkPeers` to the DB CIDR.
2. **Secrets**, created out-of-band before installing (External Secrets,
   Sealed Secrets, Vault ...). Required keys are listed in `values.yaml`
   (`secrets`). Split them per component with `<component>.existingSecret` to
   limit blast radius.
3. **Ory overlay files** stored as keys of the Secret(s):

   `kratos.secrets.yml` (the issuer URLs are printed by `helm install` NOTES):

   ```yaml
   secrets:
     cookie: ["<HEX32>"]          # rotate by prepending a new value
     cipher: ["<exactly 32 chars>"]
   courier:
     smtp:
       connection_uri: smtps://<user>:<password>@smtp.example.it:465/
   selfservice:
     methods:
       oidc:
         config:
           providers:
             - id: spid
               provider: generic
               label: SPID
               client_id: kratos
               client_secret: "<BROKER_FACADE_CLIENT_SECRET>"
               issuer_url: http://<release-fullname>-federation-broker:8090/oidc/spid
               mapper_url: file:///etc/config/kratos/federated.jsonnet
               scope: [openid]
               claims_source: id_token
               pkce: force
             - id: cie
               # same as spid with id/label "cie" and issuer_url .../oidc/cie
   ```

   `hydra.secrets.yml`:

   ```yaml
   secrets:
     system: ["<HEX32>"]
     cookie: ["<HEX32>"]
   ```
4. An ingress controller (default selectors assume ingress-nginx in namespace
   `ingress-nginx`) and TLS certificates (cert-manager or pre-created Secrets).
5. A CNI that enforces NetworkPolicy. Adjust `networkPolicy.dns`,
   `networkPolicy.ingressController`, `networkPolicy.monitoring` to your cluster.
6. Hydra OAuth2 clients (`admin-console`, `demo-web`, ...) and the federation
   trust configuration are not created by the chart; register them through the
   admin APIs under change management (see `scripts/seed-dev.mjs` for the
   shape used locally).

## Install

```bash
helm upgrade --install iam infrastructure/helm/iam-platform -n iam \
  -f my-values.yaml            # hosts, images (digests), secrets, DB CIDR
# staging example:
helm upgrade --install iam infrastructure/helm/iam-platform -n iam-staging \
  -f infrastructure/helm/iam-platform/values-staging.yaml
```

## Validate locally

```bash
scripts/k8s-validate.sh        # helm lint + template (default, staging) + kubeconform
```

Uses local `helm`/`kubeconform` when present, otherwise the
`alpine/helm` and `ghcr.io/yannh/kubeconform` Docker images. It also checks that
`files/identity.schema.json` and `files/federated.jsonnet` match
`config/kratos/` (they are copies, because Helm cannot read files outside the
chart directory).

## Security defaults

- Pods: `runAsNonRoot`, fixed UIDs (node 10001, kratos 10000, hydra/broker
  65532), `seccompProfile: RuntimeDefault`; containers: read-only root FS,
  no privilege escalation, all capabilities dropped; `/tmp` is an emptyDir.
- ServiceAccounts with `automountServiceAccountToken: false`; no RBAC.
- NetworkPolicies: default deny for every pod of the release, then one policy
  per component generated from a single flow table in
  `templates/networkpolicy.yaml` (ingress controller to public ports only;
  service-to-service flows mirror the env wiring; PostgreSQL, DNS; broker HTTPS
  egress to public IPs only; SMTP for the courier).
- No `--dev` flag on Ory: HTTPS issuer/base URLs, secure cookies.
- Broker runs with `BROKER_ENV=production` (refuses http public URL,
  insecure cookies, private networks).
- RollingUpdate with `maxUnavailable: 0`, PodDisruptionBudgets
  (`maxUnavailable: 1`), optional HPA, soft topology spread.

## Observability

- Broker metrics: `/metrics` on the internal admin port 8091. Scrape
  annotations are on by default (`metrics.podAnnotations`); a ServiceMonitor is
  available (`metrics.serviceMonitor.enabled`, needs Prometheus Operator CRDs).
- `observability.otel.endpoint` sets `TRACING_*` for Ory and
  `OTEL_EXPORTER_OTLP_ENDPOINT` for the other workloads (placeholder: the
  TypeScript services and the broker are not instrumented yet).

## Known limitations / to verify before production

- Not deployed on a real cluster yet: only `helm lint`, `helm template` and
  kubeconform schema validation have been run.
- Kratos talks to the broker OIDC facade over in-cluster HTTP
  (`BROKER_INTERNAL_URL`), as in docker compose. Confirm that Kratos without
  `--dev` accepts a plain-HTTP `issuer_url`; otherwise terminate TLS for the
  internal Service or use a service mesh with mTLS.
- Hydra runs `serve all` behind a TLS-terminating Ingress. Review whether
  `serve.tls.allow_termination_from` is needed for your Ory version/ingress.
- `demo.web.allowInsecureInternalHttp` is needed because demo-web reaches
  Hydra over in-cluster HTTP; admin-console does the same without such a flag.
  Verify the OIDC client behaviour end to end in staging.
- The courier runs as a single standalone replica (Recreate strategy). Running
  `--watch-courier` in several API replicas was not evaluated.
- `testFederation` (fedsim) is for isolated test clusters only and also requires
  the broker in development mode, which the chart does not configure for you.
