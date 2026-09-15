# Sentinel-X backend

Python 3.12 · FastAPI · SQLAlchemy 2.0 async · Pydantic v2 — a modular monolith
(see [`docs/03`](../docs/03-system-architecture.md) and [`docs/09`](../docs/09-folder-structure.md)).

```bash
uv sync                                   # install (creates .venv)
uv run sentinelx generate-keys            # dev RS256 signing key → ../.secrets/
uv run sentinelx migrate                  # alembic upgrade head
uv run sentinelx seed --admin-email admin@example.com
uv run uvicorn app.main:app --reload
uv run pytest                             # tests (SQLite by default; set SENTINELX_TEST_DATABASE_URL for Postgres)
uv run ruff check . && uv run mypy app && uv run lint-imports
```

Module docs live in [`docs/modules/`](../docs/modules/).
