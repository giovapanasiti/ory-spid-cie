# Implementation plan

Status legend: COMPLETE · PARTIAL · BLOCKED · NOT STARTED. See `PROGRESS.md` for evidence.

## Architecture (decided — ADR-001..ADR-008 in `docs/architecture/decisions.md`)

```
Application ─► Hydra (OAuth2/OIDC) ─► login-consent ─► Kratos ─► federation-broker (OIDC facade)
                                                                   └► SPID / CIE OPs (OIDC Federation RP)
```

| Component | Tech | Path |
|---|---|---|
| Identity & sessions | Ory Kratos v26.2.0 | `config/kratos` |
| OAuth2 / OIDC | Ory Hydra v26.2.0 | `config/hydra` |
| SPID/CIE federation RP + OIDC facade for Kratos | Go 1.26, go-jose v4, pgx v5 | `services/federation-broker` |
| Local test federation (TA + OPs) | Go (shares protocol code) | `services/federation-broker/cmd/fedsim` |
| Login / consent + Kratos self-service UI | TypeScript, Fastify 5 | `apps/login-consent` |
| Account portal | TypeScript, Fastify 5 | `apps/identity-portal` |
| Admin console (incl. SPID/CIE certificates, keys, metadata UI) | TypeScript, Fastify 5 | `apps/admin-console` |
| Demo RP + protected API | TypeScript, openid-client, jose | `apps/demo-web`, `services/demo-api` |
| Identity links, verified attributes, assurance, admin roles | TypeScript, Fastify, PostgreSQL | `services/identity-service` |
| Audit events | TypeScript, Fastify, PostgreSQL | `services/audit-service` |
| Shared libs | TypeScript | `packages/*` |
| Infra | Docker Compose, Helm, GitHub Actions | `infrastructure/`, `.github/workflows` |

Ory Polis: **not used** (no OIDC Federation / private_key_jwt support, see research notes §10).
Ory Oathkeeper / Keto: **not used** (no demonstrated need; API protection via `@iam/auth-sdk`).

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | Research, compatibility matrix, ADRs, threat model | see PROGRESS.md |
| 1 | Monorepo, Postgres, Kratos, Hydra, migrations, networking, env | see PROGRESS.md |
| 2 | Login/consent, Kratos UI, OAuth2 flows, demo app | see PROGRESS.md |
| 3 | Federation foundation (trust chain, keys, metadata, simulator) | see PROGRESS.md |
| 4 | SPID profile | see PROGRESS.md |
| 5 | CIE profile | see PROGRESS.md |
| 6 | Identity normalisation, linking, portal, admin console, audit | see PROGRESS.md |
| 7 | Security & tests | see PROGRESS.md |
| 8 | Kubernetes, CI/CD, monitoring, ops docs | see PROGRESS.md |
| 9 | Readiness assessment | see `docs/compliance/readiness-checklist.md` |
