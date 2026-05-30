# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

PicoShogun is pre-1.0. Only the latest release receives security fixes.

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Instead, open a private vulnerability report on GitHub:
https://github.com/KirkForge/PicoShogun/security/advisories/new

Include:
- PicoShogun version (`picoshogun --version` or check `config/version.py`)
- Python version and OS
- Deployment method (Docker, bare metal, systemd)
- Description of the vulnerability
- Steps to reproduce
- Potential impact

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix or mitigation**: depends on severity

### Disclosure Policy

- **Coordinated disclosure**: we ask for 90 days before public disclosure
- **Credit**: researchers receive credit in the changelog and advisory unless they request anonymity
- **Advisories**: published as GitHub Security Advisories and in CHANGELOG.md

## Security Model

### Startup Validation

PicoShogun refuses to boot in production with insecure defaults. The `assert_secure()` check enforces:

- **No default secret key** — `PICOSHOGUN_SECRET_KEY` must be set; the default `change-me-in-production` is rejected in production
- **No wildcard CORS** — `PICOSHOGUN_CORS_ORIGINS` must list explicit origins in production
- **No wildcard allowed hosts** — `PICOSHOGUN_ALLOWED_HOSTS` must be explicit in production
- **No debug mode** — `PICOSHOGUN_DEBUG=false` in production

Override with `PICOSHOGUN_SKIP_SECURE_ASSERT=1` (only for CI/testing).

### Authentication

- **JWT** (PyJWT) for session tokens with configurable expiration
- **API keys** with rotation, expiration, and automatic cleanup
- **RBAC** — 18 permissions across viewer/operator/admin roles via `require_permission()` dependency

### Plugin Trust Boundary

The `plugins/` directory is a trust boundary equivalent to giving someone a shell on the server. Plugin code runs in-process with full access to the runtime, database, and network.

For production, set `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1` to enforce Ed25519 manifest signatures. The signed content includes the module's SHA-256 checksum, so swapping a `.py` file after signing invalidates the signature.

### Tenant Isolation

Multi-tenant access is enforced at the API layer. Cross-tenant requests return 403. See `TenantDataIsolation` integration tests for coverage.

### TLS Termination

PicoShogun does not terminate TLS. Run behind a reverse proxy (nginx, Caddy, cloud load balancer) that handles TLS.

## Known Limitations

- **SQLite write locks**: Under high concurrent write load, p99 latency increases due to WAL lock contention. The Postgres pool (`PICOSHOGUN_DATABASE_BACKEND=postgres`) addresses this for production deployments.
- **Plugin sandbox**: Plugins run in-process with no isolation. Only load plugins you trust.
- **Rate limiting**: Per-IP and per-org rate limiting uses in-memory state. State is lost on restart (unless Redis persistence is configured separately).
