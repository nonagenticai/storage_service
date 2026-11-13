# Storage Service

[![CI](https://github.com/nonagenticai/storage_service/actions/workflows/ci.yml/badge.svg)](https://github.com/nonagenticai/storage_service/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nonagenticai/storage_service)](https://github.com/nonagenticai/storage_service/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Centralized FastAPI proxy for MinIO object storage with optional ClamAV virus scanning. Port 8391.

| | |
|---|---|
| **Stack** | Python 3.14 · FastAPI · Pydantic · MinIO SDK |
| **Database** | None (stateless proxy) |
| **Licence** | Apache-2.0 |

This is a source release. `docker compose up` brings up a local MinIO and the proxy; the
licence-introspection auth method is optional and needs no licence service on loopback or an
RFC 1918 network.

## What Storage Service Does

When any service in the cluster needs to store or retrieve a file, it sends an HTTP request to this service rather than connecting to MinIO directly. Storage Service is the sole holder of MinIO credentials in the entire platform. This design means that if credentials rotate or the storage backend changes, only one service needs updating rather than every consumer. Requests arrive as standard multipart uploads or simple GETs with a bucket name and object key, authenticated via license token or trusted-network bypass.

On upload, the service first validates that the target bucket is in the allowed list (or already exists in MinIO), then checks the file against the configured size limit of 500 MB. If ClamAV virus scanning is enabled, the file is streamed to the ClamAV daemon over a network socket with automatic retry on connection failure. Infected files are rejected with a 400 response before they ever reach MinIO. Scanning fails CLOSED: if the daemon is unreachable, the retries are exhausted, or the reply carries no verdict, the upload is refused with **503** and nothing is written — an unscanned file is never stored, and no response ever reports `virus_scanned: true` without a real verdict. Clean files are written to MinIO via the S3-compatible API, and the response includes the etag, content type, and scan result. Downloads are served as streaming responses with proper Content-Disposition headers, and metadata queries return size, last-modified time, and custom metadata without transferring the file body.

The service also manages the bucket lifecycle. It auto-creates a configurable set of allowed buckets on startup (kag-ingestion, kag-processed, kag-quarantine, artifacts by default) and exposes CRUD endpoints for dynamic bucket management. A protected-buckets list prevents accidental deletion of critical buckets through the API. Bucket names are validated against S3 naming rules including consecutive-hyphen and reserved-prefix checks.

Storage Service is stateless -- it holds no data of its own and can be restarted or scaled without migration. The MinIO client and ClamAV scanner are initialized as singletons on first use. Health checks report per-component status (MinIO healthy, ClamAV healthy/degraded/unavailable) so Kubernetes probes can distinguish between a fully healthy service and one whose upload path is refusing writes because ClamAV is down.

## Features

- **Credential isolation** — sole holder of MinIO access and secret keys so no other service in the cluster needs storage credentials, reducing the blast radius of a credential leak
- **ClamAV virus scanning** — scans uploaded files for malware before writing to MinIO, with automatic retry on ClamAV connection failure and a **fail-closed** refusal (HTTP 503) when the scanner never returns a verdict, so an unscanned file is never stored
- **Bucket lifecycle management** — auto-creates allowed buckets on startup and exposes create/delete endpoints with S3-compatible name validation so consumers do not need to manage bucket provisioning
- **Protected bucket enforcement** — prevents deletion of critical buckets (kag-ingestion, kag-processed, kag-quarantine, artifacts) through the API so accidental cleanup commands cannot destroy production data
- **Streaming downloads** — returns files as streaming responses with Content-Disposition headers so large files do not need to be buffered entirely in memory
- **Upload size limits** — enforces a configurable maximum upload size (default 500 MB) before writing to MinIO so storage quotas are respected at the proxy layer
- **Component-level health checks** — reports MinIO and ClamAV health independently with latency measurements so Kubernetes probes can detect partial failures and operators can pinpoint which backend is down
- **License token caching** — caches introspection results for 5 minutes (1000 entries max) so repeated requests from the same tenant do not hit the license service on every call
- **Trusted network bypass** — allows unauthenticated access from RFC 1918 and loopback addresses so internal cluster services can call storage without carrying tokens. Such a caller is **always** the configured `DEFAULT_TENANT_ID`: a caller-supplied `X-Tenant-Id` that is not a `Bearer` license token is ignored and logged, because an unauthenticated caller must not be able to name its own tenant.

> ⚠️ **Storage is not tenant-authorized.** Authentication is enforced; per-object *authorization* is not. No route compares an object key against the caller's tenant, so any caller admitted by the trusted-network path (the default `TRUSTED_CIDRS` covers the whole `10.0.0.0/8` pod and service CIDR) can read, list and delete every object in every allowed bucket. Closing this needs per-caller license tokens for the six in-cluster callers plus a tenant-scoped key layout; it cannot be fixed inside this service alone. See `ARCHITECTURE.md`.

## Authentication

Auth enabled by default (`ENABLE_AUTH=true`). Can be disabled for development.

When enabled, requests to `/api/*` are authenticated in priority order:

| Priority | Method | Details |
|----------|--------|---------|
| 1 | Licence token | `X-Tenant-Id: Bearer <token>` validated by POSTing the token to `LICENSE_INTROSPECT_URL` (empty by default: then only method 2 applies) |
| 2 | Trusted network | RFC 1918 + loopback IPs allowed with optional plain `X-Tenant-Id` header (defaults to `DEFAULT_TENANT_ID`) |

Public endpoints (no auth): `/`, `/docs`, `/redoc`, `/openapi.json`, `/health/*`, `/metrics`, `/favicon.ico`.

## Quick Start

```bash
cp .env.example .env
docker compose up -d
curl http://localhost:8391/health
docker compose down -v
```

## API Endpoints

### Files `/api/files`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/upload` | Upload file (multipart: bucket, object_key, file) |
| GET | `/{bucket}/{key}` | Download file as streaming response |
| GET | `/{bucket}/{key}/exists` | Check if file exists |
| GET | `/{bucket}/{key}/metadata` | Get file metadata (size, etag, content type) |
| DELETE | `/{bucket}/{key}` | Delete file |
| GET | `/{bucket}` | List files with prefix, recursive, max_keys filters |

### Buckets `/api/buckets`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List all buckets |
| POST | `/` | Create bucket (S3-compatible name validation) |
| GET | `/{name}` | Get bucket info |
| DELETE | `/{name}` | Delete bucket (protected buckets blocked, force option) |

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service info and endpoint listing |
| GET | `/health` | Full health check (MinIO + ClamAV status with latency) |
| GET | `/health/live` | Liveness probe |
| GET | `/health/ready` | Readiness probe (checks MinIO connectivity) |

## Configuration

All configuration via environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8391` | Listen port |
| `SERVICE_NAME` | `storage-service` | Service identifier |
| `VERSION` | `1.0.0` | Service version |
| `ENVIRONMENT` | `production` | Environment name |
| `LOG_LEVEL` | `INFO` | Log level |
| `ENABLE_AUTH` | `true` | Enable license token auth middleware |
| `DEFAULT_TENANT_ID` | `0195f48b-d000-7000-8000-000000000001` | Tenant ID for trusted network requests |
| `CORS_ALLOW_ORIGINS` | `http://localhost:8921,...` | Comma-separated CORS origins |
| `MINIO_ENDPOINT` | *(required)* | MinIO S3 endpoint, e.g. `localhost:9000` |
| `MINIO_ACCESS_KEY` | *(required)* | MinIO access key (secret, via .env) |
| `MINIO_SECRET_KEY` | *(required)* | MinIO secret key (secret, via .env) |
| `MINIO_SECURE` | `false` | Use TLS for MinIO connections |
| `ALLOWED_BUCKETS` | `artifacts` | Auto-created buckets (comma-separated) |
| `PROTECTED_BUCKETS` | `artifacts` | Undeletable buckets (comma-separated) |
| `ENABLE_VIRUS_SCANNING` | `true` | Enable ClamAV scanning on upload |
| `CLAMAV_HOST` | `clamav` | ClamAV daemon hostname |
| `CLAMAV_PORT` | `3310` | ClamAV daemon port |
| `CLAMAV_TIMEOUT` | `30.0` | ClamAV scan timeout in seconds |
| `MAX_UPLOAD_SIZE_MB` | `500` | Max file upload size in MB |

## Architecture

```
                         ┌──────────────────────────┐
  Other services ──────► │  Storage Service (8391)   │
  (license token or      │  FastAPI proxy            │
   trusted network)      │                           │
                         │  ┌─────────┐  ┌────────┐ │
                         │  │  MinIO  │  │ ClamAV │ │
                         │  │  client │  │ client │ │
                         │  └────┬────┘  └───┬────┘ │
                         └───────┼───────────┼──────┘
                                 │           │
                          minio:9000            clamav:3310
```

```
src/
├── main.py                        # FastAPI app, CORS, auth middleware, router registration
├── config.py                      # Pydantic settings (env vars, bucket lists, size limits)
├── auth/
│   ├── middleware.py               # License token introspection + trusted network bypass
│   └── models.py                   # User type definition (dict alias)
├── routes/
│   ├── files.py                    # /api/files endpoints (upload, download, delete, list, metadata)
│   ├── buckets.py                  # /api/buckets endpoints (CRUD with protection)
│   ├── health.py                   # /health endpoints (full, live, ready)
│   └── responses.py                # Shared OpenAPI response schemas (401, 404)
├── services/
│   ├── minio_client.py             # MinIO wrapper singleton (all S3 operations)
│   └── virus_scanner.py            # ClamAV wrapper singleton (scan with retry)
├── models/
│   └── schemas.py                  # Pydantic request/response DTOs (15 schemas)
└── custom_types/
    └── constraint_types.py         # SafeString annotated types for input validation
```

## Testing

```bash
uv run pytest tests/ -v --cov=src          # All tests with coverage
uv run pytest tests/integration/ -v -m integration  # Integration tests (requires live MinIO)
uv run ruff check src/ tests/              # Lint
uv run ruff format --check src/ tests/     # Format check
```

Coverage threshold: 80% (enforced in pyproject.toml).

Unit tests: 9 test files covering auth middleware, config, files, buckets, health, MinIO client, virus scanner, and schemas. Integration tests require a running MinIO instance. Contract tests (Schemathesis) are present but disabled in CI.

## CI

`.github/workflows/ci.yml` runs on GitHub-hosted runners only:
`gitleaks` → `private-refs` → `ruff` + `pytest` (tests use an in-memory MinIO double, so no object
store is needed) → a Docker build. It is deliberately self-contained and does **not** deploy: this
repository is a source release, and a public repo must never hold a credential that can push an
image into a private registry.

## Docker

```bash
docker build -t storage-service .
docker run -p 8391:8391 -e MINIO_ACCESS_KEY=key -e MINIO_SECRET_KEY=secret -e MINIO_ENDPOINT=localhost:9000 storage-service
```

For a full local stack (proxy + MinIO on 9000/9001, default credentials `minioadmin/minioadmin`),
use `docker compose up -d`.

## Dependencies

- **MinIO** — S3-compatible object storage backend
- **ClamAV** — virus scanning daemon. Optional via `ENABLE_VIRUS_SCANNING`, but when enabled it is a **hard dependency of the upload path**: uploads return 503 while it is unreachable. Reads, lists and deletes are unaffected.
- **A licence service** — optional; only when `LICENSE_INTROSPECT_URL` is set and a real token must be validated
- **FastAPI** — web framework
- **Uvicorn** — ASGI server
- **Pydantic** — settings and schema validation
- **minio** — MinIO Python SDK
- **clamd** — ClamAV client library
- **cachetools** — TTL cache for licence introspection results
- **httpx** — async HTTP client for licence introspection

## Usage from Other Services

```python
import httpx

STORAGE_URL = "http://storage-api:8391"

# Upload
with open("file.pdf", "rb") as f:
    resp = httpx.post(
        f"{STORAGE_URL}/api/files/upload",
        files={"file": f},
        data={"bucket": "artifacts", "object_key": "docs/file.pdf"},
        headers={"X-Tenant-Id": "0195f48b-d000-7000-8000-000000000001"},
    )

# Download
resp = httpx.get(
    f"{STORAGE_URL}/api/files/artifacts/docs/file.pdf",
    headers={"X-Tenant-Id": "0195f48b-d000-7000-8000-000000000001"},
)
```

## Known Issues

- ~~**CI build failing**~~ — **resolved / stale.** This described a self-hosted runner losing communication with the server during the Docker image build. The last workflow run on `main` **succeeded (2026-08-26)**. CI runs on ARC self-hosted runner pods scheduled onto nodes labelled `node-role/ci-runner=true` — read the label, never a hardcoded node name.
- **Schemathesis contract tests disabled** — contract testing step in CI is commented out ("TEMPORARILY DISABLED - schemathesis blocking deploys"). Contract test hooks and fixtures exist in `tests/contract/` but are not exercised in CI.
- **Node.js 20 deprecation warnings** — GitHub Actions annotations warn that actions/checkout@v4, actions/upload-artifact@v4, and astral-sh/setup-uv@v5 run on Node.js 20 which is deprecated. Forced migration to Node.js 24 coming June 2026.

## Security

Report vulnerabilities privately through the repository's Security tab — see
[`SECURITY.md`](SECURITY.md). Do not open a public issue for a security problem.

## Contributing

Issues and pull requests are welcome. See
[`CONTRIBUTING.md`](https://github.com/nonagenticai/.github/blob/main/CONTRIBUTING.md) for the
organisation-wide rules; setup, test and lint commands are in this README. Commits carry DCO
sign-off.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
