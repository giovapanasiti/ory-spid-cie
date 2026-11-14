# IAM platform — developer entry points. Run `make help`.
SHELL := /bin/bash
COMPOSE := docker compose --env-file .env -f infrastructure/docker/docker-compose.yml
GO_DIR := services/federation-broker
TEST_PG := iam-test-pg
TEST_DB_URL := postgres://test:test@localhost:55432/postgres?sslmode=disable

NODE_DEPS := node_modules/.package-lock.json

.PHONY: help setup deps dev up build build-local migrate seed reference-up reference-down down clean logs ps test test-db test-go test-ts test-e2e test-e2e-reference test-security lint fmt typecheck coverage helm-lint k8s-validate

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-15s\033[0m %s\n",$$1,$$2}'

setup: ## Check prerequisites, generate .env and dev secrets (only Docker, Bash and OpenSSL needed)
	@scripts/setup.sh

# Host toolchains (Node >= 22.13, Go 1.26) are needed only for tests, lint and local builds,
# never for `make dev`: the container images compile everything inside Docker.
$(NODE_DEPS): package-lock.json
	@command -v npm >/dev/null || { echo "Node.js >= 22.13 is required for this target (not for make dev)" >&2; exit 1; }
	npm ci --no-audit --no-fund

deps: $(NODE_DEPS) ## Install host dependencies for tests and lint (Node >= 22.13, Go 1.26)
	@command -v go >/dev/null || { echo "Go 1.26 is required for this target (not for make dev)" >&2; exit 1; }
	cd $(GO_DIR) && go mod download

build: ## Build the container images (everything compiles inside Docker)
	docker build -f infrastructure/docker/Dockerfile.node -t iam/node:dev .
	$(COMPOSE) build federation-broker fedsim

build-local: deps ## Compile TypeScript and Go on the host (developer check, not needed by make dev)
	npm run build
	cd $(GO_DIR) && go build ./...

up: ## Start the stack (without rebuilding)
	$(COMPOSE) up -d --wait

dev: setup build up seed ## Build and start the complete local platform, then seed it
	@echo; echo "Platform ready:"; \
	echo "  Demo app        http://localhost:5580"; \
	echo "  Login UI        http://localhost:4455"; \
	echo "  Account portal  http://localhost:3200"; \
	echo "  Admin console   http://localhost:3100  (user $$(grep ^DEV_ADMIN_EMAIL .env | cut -d= -f2), password: DEV_ADMIN_PASSWORD in .env)"; \
	echo "  Test federation http://localhost:8070  (LOCAL simulator)"; \
	echo "  Mailpit         http://localhost:8025"

migrate: ## Apply all database migrations (Ory + services)
	$(COMPOSE) up -d --wait postgres
	$(COMPOSE) run --rm kratos-migrate
	$(COMPOSE) run --rm hydra-migrate
	$(COMPOSE) run --rm --no-deps federation-broker -migrate
	$(COMPOSE) run --rm --no-deps identity-service node services/identity-service/dist/main.js --migrate
	$(COMPOSE) run --rm --no-deps audit-service node services/audit-service/dist/main.js --migrate

seed: ## Seed OAuth2 clients, dev admin and LOCAL test federation trust
	$(COMPOSE) --profile seed run --rm seed

reference-up: ## Start the REFERENCE TEST federation (italia/spid-cie-oidc-django) and connect the broker to it
	$(COMPOSE) --profile reference up -d --wait ref-ta ref-cie-op
	$(COMPOSE) --profile reference exec -T -e PYTHONPATH=/work/pylib -w /work/federation_authority ref-ta python3 manage.py shell < infrastructure/reference-federation/register_rp.py
	$(COMPOSE) --profile reference run --rm seed-reference

reference-down: ## Stop the REFERENCE TEST federation containers (broker configuration is kept)
	$(COMPOSE) --profile reference stop ref-ta ref-cie-op
	$(COMPOSE) --profile reference rm -f ref-ta ref-cie-op

down: ## Stop the stack (keeps volumes)
	$(COMPOSE) down

clean: ## Stop the stack and delete volumes (DESTROYS local data)
	$(COMPOSE) down -v

logs: ## Follow logs
	$(COMPOSE) logs -f --tail=100

ps: ## Show service status
	$(COMPOSE) ps

test-db:
	@docker inspect $(TEST_PG) >/dev/null 2>&1 || docker run -d --name $(TEST_PG) -p 55432:5432 -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test postgres:17-alpine >/dev/null
	@for i in $$(seq 1 30); do docker exec $(TEST_PG) pg_isready -U test >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1

test-go: test-db ## Go unit + protocol integration tests (federation)
	cd $(GO_DIR) && TEST_DATABASE_URL="$(TEST_DB_URL)" go test -race -count=1 ./...

test-ts: test-db $(NODE_DEPS) ## TypeScript unit + DB integration tests
	TEST_DATABASE_URL="$(TEST_DB_URL)" npm test

test: test-go test-ts ## All unit and integration tests (no running stack required)

coverage: test-db $(NODE_DEPS) ## Coverage reports (coverage/)
	mkdir -p coverage
	cd $(GO_DIR) && TEST_DATABASE_URL="$(TEST_DB_URL)" go test -count=1 -coverpkg=./internal/... -coverprofile=../../coverage/go.out ./... && go tool cover -func=../../coverage/go.out | tail -1
	TEST_DATABASE_URL="$(TEST_DB_URL)" npm run test:coverage

test-e2e: $(NODE_DEPS) ## End-to-end browser tests against the running stack (run `make dev` first)
	cd tests/e2e && npx playwright install chromium && npx playwright test

test-e2e-reference: $(NODE_DEPS) ## End-to-end tests against the REFERENCE TEST federation (run `make dev` and `make reference-up` first)
	cd tests/e2e && npx playwright install chromium && npx playwright test -c reference.config.ts

test-security: test-db $(NODE_DEPS) ## Security suites: protocol attacks, token validation, CSRF, headers, dependency scans
	cd $(GO_DIR) && TEST_DATABASE_URL="$(TEST_DB_URL)" go test -count=1 -run 'TestFederationFlows|TestTrustChain|TestRejects|TestRequires' ./...
	node --import tsx --test --test-reporter=spec packages/auth-sdk/src/*.test.ts services/demo-api/src/*.test.ts packages/shared/src/*.test.ts
	@if curl -sf -o /dev/null http://localhost:4455/healthz; then scripts/security-smoke.sh; else echo "stack not running: skipped live security smoke tests"; fi
	cd $(GO_DIR) && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	npm audit --omit=dev --audit-level=high

lint: $(NODE_DEPS) ## Lint and format checks (TS + Go)
	npm run lint
	cd $(GO_DIR) && test -z "$$(gofmt -l .)" && go vet ./...

fmt: $(NODE_DEPS) ## Format code
	npm run format
	cd $(GO_DIR) && gofmt -w .

typecheck: $(NODE_DEPS) ## TypeScript type check
	npm run build

helm-lint: ## Lint and render the Helm chart
	scripts/k8s-validate.sh

k8s-validate: ## Validate rendered Kubernetes manifests
	scripts/k8s-validate.sh
