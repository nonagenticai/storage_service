# -----------------------------
# Stage 0: Base (shared)
# -----------------------------
ARG BASE_REGISTRY=docker.io
FROM ${BASE_REGISTRY}/library/python:3.14-slim AS base

ENV UV_SYSTEM_PYTHON=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:$PATH"

WORKDIR /app

# Multi-arch compatible uv binary (pinned for ARM64 compatibility)
COPY --from=ghcr.io/astral-sh/uv:0.10.10 /uv /uvx /usr/local/bin/


# -----------------------------
# Stage 1: Builder
# -----------------------------
FROM base AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Prime cache with metadata + lock. uv.lock is REQUIRED (no glob): a missing
# lock must fail the build, and the image never re-resolves. An in-image
# `uv lock` / unlocked install is how pyjwt 2.15.1 shipped while the lock said
# 2.14.0 and broke auth estate-wide (gitops#4248, license-authz#63).
COPY README.md pyproject.toml uv.lock ./

# Install dependencies only, exactly as locked (the project itself is run from
# /app/src via PYTHONPATH and is never installed into the venv).
RUN uv sync --frozen --no-dev --no-install-project

# Build-time guard: fail the build if any installed version != uv.lock
# (pyjwt asserted explicitly). Same script as media-discovery#64 /
# license-authz#63. `--no-install-project` on the check because this image
# never installs the project; uv 0.5.14 had no `uv sync --check`, hence the bump to 0.10.10.
COPY scripts/assert_lock_versions.py /tmp/assert_lock_versions.py
RUN uv export --frozen --no-dev --no-emit-project --no-hashes -o /tmp/lock-pins.txt && \
    /app/.venv/bin/python /tmp/assert_lock_versions.py uv.lock /tmp/lock-pins.txt && \
    uv sync --frozen --no-dev --no-install-project --check

# App source after deps for better cache reuse
COPY src/ /app/src/


# -----------------------------
# Stage 2: Production
# -----------------------------
FROM base AS production

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH=/app/src \
    PORT=8391

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user, created before the ownership-bearing COPYs below so
# --chown can resolve it. Only the /app dir inode itself needs a manual
# chown (it was created root:root by WORKDIR in the base stage); every
# path underneath gets its ownership set at copy-time instead of via a
# separate recursive RUN, which used to rewrite every inode under /app
# on every build.
RUN useradd -m -u 1000 appuser && chown appuser:appuser /app

COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv
COPY --from=builder --chown=appuser:appuser /app/pyproject.toml /app/pyproject.toml
COPY --from=builder --chown=appuser:appuser /app/README.md /app/README.md
COPY --from=builder --chown=appuser:appuser /app/uv.lock /app/uv.lock
COPY --chown=appuser:appuser src/ /app/src/

USER appuser

EXPOSE 8391

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health/live || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8391"]
