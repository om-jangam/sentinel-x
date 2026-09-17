.PHONY: help keys up down migrate seed api web test lint typecheck openapi check

BACKEND := cd backend &&
FRONTEND := cd frontend &&

help:  ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

keys:  ## Generate the RS256 JWT signing key into ./.secrets
	$(BACKEND) uv run sentinelx generate-keys --out ../.secrets

up:  ## Start the lite stack (Postgres, Redis, OpenSearch, API, indexer, web) on http://localhost:8080
	docker compose up --build -d

down:  ## Stop the stack
	docker compose down

migrate:  ## Apply database migrations (local dev)
	$(BACKEND) uv run sentinelx migrate

seed:  ## Bootstrap org, roles and the first admin (local dev)
	$(BACKEND) uv run sentinelx seed --admin-email $${SENTINELX_BOOTSTRAP_ADMIN_EMAIL:-admin@example.com}

api:  ## Run the API with reload
	$(BACKEND) uv run uvicorn app.main:create_app --factory --reload

web:  ## Run the console dev server (proxies /api to :8000)
	$(FRONTEND) npm run dev

test:  ## Backend + frontend tests
	$(BACKEND) uv run pytest --cov
	$(FRONTEND) npm test

lint:  ## Linters and architecture contracts
	$(BACKEND) uv run ruff check . && uv run ruff format --check . && uv run lint-imports
	$(FRONTEND) npm run lint && npm run format:check

typecheck:  ## mypy --strict and tsc
	$(BACKEND) uv run mypy app
	$(FRONTEND) npm run typecheck

openapi:  ## Regenerate the OpenAPI contract and the typed TS client
	$(BACKEND) uv run sentinelx export-openapi --out openapi.json
	$(FRONTEND) npm run gen:api

check: lint typecheck test  ## Everything CI runs locally
