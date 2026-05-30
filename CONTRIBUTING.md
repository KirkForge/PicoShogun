# Contributing to PicoShogun

Thanks for your interest in PicoShogun! This guide covers how to contribute effectively.

## Quick Start

```bash
git clone https://github.com/KirkForge/PicoShogun.git
cd PicoShogun
bash scripts/setup.sh          # Create venv, install deps
source .venv/bin/activate
python -m pytest tests/ -v     # 168 tests
```

## Development

### Running Tests

```bash
python -m pytest tests/ -v                  # All tests (168)
python -m pytest tests/test_api.py -v       # API unit tests (54)
python -m pytest tests/test_integration.py  # Integration tests (114)
python -m pytest -x                         # Stop on first failure
```

### Linting & Type Checking

```bash
ruff check .                      # Lint
ruff format --check .             # Format check
mypy api config database middleware services --ignore-missing-imports --no-strict-optional
```

### Pre-push CI

Run these before pushing:

```bash
ruff check . && ruff format --check . && mypy api/ config/ database/ middleware/ services/ && python -m pytest tests/ -v
```

## Architecture

```
api/
  server.py          # FastAPI app, lifespan, middleware stack (248 lines)
  deps.py            # Shared dependencies (auth, DB, permissions)
  models.py          # Pydantic request/response models
  routers/           # 12 router modules (health, auth, orgs, projects, etc.)
config/
  settings.py        # Dataclass config from PICOSHOGUN_* env vars
  version.py         # Single-source version
database/
  manager.py         # Thread-safe SQLite WAL + migrations
  pools.py           # SQLitePool + PostgresPool abstraction
middleware/           # 12-layer stack (security headers → audit)
services/            # Business logic (auth, rbac, plugin_manager, etc.)
plugins/             # Runtime-loaded plugins (Ed25519 signed manifests)
front/               # SPA dashboard (index.html)
```

## Pull Request Guidelines

- **One concern per PR** — keep changes focused
- **Tests required** — new features and bug fixes must include tests
- **ruff + mypy clean** — no lint or type errors
- **No hardcoded paths** — use `PICOSHOGUN_*` env vars or `Path(__file__)` relative resolution
- **Security-first** — PicoShogun enforces `assert_secure()` at startup; do not weaken defaults

## Adding a Plugin

1. Create a directory under `plugins/` with `plugin.json` and a Python module
2. The `entry_point` in `plugin.json` must match the Python filename (no dots, no path separators)
3. Implement `PluginInterface` from `services/plugin_manager.py`
4. For production, sign the manifest: `python scripts/sign_manifest.py sign plugins/your_plugin/plugin.json`
5. Set `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1` in production

## Adding a Middleware

Middleware is added in `api/server.py` — last added = outermost. Follow the existing pattern:

```python
app.add_middleware(YourMiddleware, param=value)
```

## License

By contributing, you agree that your contributions will be licensed under the [Business Source License 1.1](LICENSE), converting to Apache-2.0 after the change date.
