# PicoShogun — Current Status

**Updated:** 2026-05-30

## Recent Changes (v2.16.0)

- **Rename**: Shogun → PicoShogun across all user-facing surfaces
- **Env vars**: `PICOSHOGUN_*` is now primary. `SHOGUN_*` still works as backward compat.
- **CLI**: `picoshogun` is primary entrypoint. `shogun` still works as alias.
- **Docker**: Image name is now `picoshogun`
- **Co-authorship**: Removed `55N10E` from pyproject.toml (sole author: Henrik Kirk)
- **Docs**: Rewritten with honest pre-1.0 beta status, no inflated "enterprise" or "98/100" claims
- **Architecture docs**: `Iron Dome` → `PicoDome` references updated

## CI Status

- GitHub Actions billing exhausted — CI is currently failing due to billing, not code issues
- Resets in a few days
- Local tests pass: `python -m pytest tests/ -v`

## Known Issues

- Rate limit persistence default is OFF (`persist=True` needed for production)
- CORS wildcard blocking not yet enforced
- Discord notifier plugin logs but doesn't actually send messages
- No load testing benchmarks exist
