# IAM platform — developer entry points. Run `make help`.
SHELL := /bin/bash
COMPOSE := docker compose --env-file .env -f infrastructure/docker/docker-compose.yml
GO_DIR := services/federation-broker
TEST_PG := iam-test-pg
TEST_DB_URL := postgres://test:test@localhost:55432/postgres?sslmode=disable

.PHONY: help setup dev up build migrate seed down clean logs ps test test-db test-go test-ts test-e2e test-security lint fmt typecheck coverage helm-lint k8s-validate

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-15s\033[0m %s\n",$$1,$$2}'

setup: ## Install dependencies, generate .env and dev secrets
	@scripts/setup.sh
	npm ci --no-audit --no-fund
	cd $(GO_DIR) && go mod download

build: ## Build TypeScript, Go binaries and container images
	npm run build
	cd $(GO_DIR) && go build ./...
	docker build -f infrastructure/docker/Dockerfile.node -t iam/node:dev .
	$(COMPOSE) build federation-broker fedsim

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

test-ts: test-db ## TypeScript unit + DB integration tests
	TEST_DATABASE_URL="$(TEST_DB_URL)" npm test

test: test-go test-ts ## All unit and integration tests (no running stack required)

coverage: test-db ## Coverage reports (coverage/)
	mkdir -p coverage
	cd $(GO_DIR) && TEST_DATABASE_URL="$(TEST_DB_URL)" go test -count=1 -coverpkg=./internal/... -coverprofile=../../coverage/go.out ./... && go tool cover -func=../../coverage/go.out | tail -1
	TEST_DATABASE_URL="$(TEST_DB_URL)" npm run test:coverage

test-e2e: ## End-to-end browser tests against the running stack (run `make dev` first)
	cd tests/e2e && npx playwright install chromium && npx playwright test

test-security: test-db ## Security suites: protocol attacks, token validation, CSRF, headers, dependency scans
	cd $(GO_DIR) && TEST_DATABASE_URL="$(TEST_DB_URL)" go test -count=1 -run 'TestFederationFlows|TestTrustChain|TestRejects|TestRequires' ./...
	node --import tsx --test --test-reporter=spec packages/auth-sdk/src/*.test.ts services/demo-api/src/*.test.ts packages/shared/src/*.test.ts
	@if curl -sf -o /dev/null http://localhost:4455/healthz; then scripts/security-smoke.sh; else echo "stack not running: skipped live security smoke tests"; fi
	cd $(GO_DIR) && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	npm audit --omit=dev --audit-level=high

lint: ## Lint and format checks (TS + Go)
	npm run lint
	cd $(GO_DIR) && test -z "$$(gofmt -l .)" && go vet ./...

fmt: ## Format code
	npm run format
	cd $(GO_DIR) && gofmt -w .

typecheck: ## TypeScript type check
	npm run build

helm-lint: ## Lint and render the Helm chart
	scripts/k8s-validate.sh

k8s-validate: ## Validate rendered Kubernetes manifests
	scripts/k8s-validate.sh
