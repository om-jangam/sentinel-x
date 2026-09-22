# syntax=docker/dockerfile:1.7
# Multi-stage, non-root, no build tooling in the runtime image (docs/08 §A.5).

FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /src

COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project --extra otel

COPY app ./app
# --reinstall-package: uv caches the project's built wheel by version in the cache mount, so without it an
# image rebuilt from changed code at the same version would silently ship the previous build.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --extra otel --reinstall-package sentinel-x

FROM python:3.12-slim AS runtime
RUN groupadd --system --gid 10001 sentinelx \
 && useradd --system --uid 10001 --gid sentinelx --no-create-home sentinelx
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /srv
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
