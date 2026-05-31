**See also**: [REPORULES.md](../REPORULES.md) — multi-machine sync, git identity, PAT handling, and new-repo bootstrap.

# AGENTS.md — PicoShogun

## What PicoShogun IS
- Command centre and firewall for the Pico Security Series (PicoSentry, PicoDome, PicoShogun, PicoWatch)
- FastAPI REST API + SQLite backend with 12-layer security middleware
- Orchestrator for running Pico series tools and extracting intelligence
- Monitoring dashboard (SPA) with auth, rate limiting, and alerting

## What PicoShogun is NOT
- Not "enterprise-grade" — it's pre-1.0 beta
- Not a standalone firewall product — it orchestrates PicoDome and PicoSentry
- Not SOC2 compliant — no audit has been done
- Not production-hardened for multi-tenant SaaS — org system exists but is minimally tested

## ⚠️ Mandatory Rules — Read Before Editing

- **Never commit**: `node_modules/`, `.venv/`, `venv/`, `__pycache__/`, `*.pyc`, `dist/`, `build/`, `.next/`, `coverage/`, `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `.tox/`, `.DS_Store`, `*.log`, `.env`, `*.pem`, `*.key`
- **Always pull before work, push after work**
- **Git identity**: `Henrik Kirk <285947470+KirkForge@users.noreply.github.com>`
- **Commit format**: `type(scope): message` — feat, fix, docs, refactor, test, chore, wip
- **Pre-push CI**: `ci-cleandev` hooks block pushes on failure. Fix, don't bypass.
- **No AI co-authors**: Do not add `Co-authored-by: GLM-5.1` or similar. Henrik Kirk is the sole author.
- **No inflated claims**: If something is scaffold or stub, say so. Don't call it "enterprise" or "battle-tested" unless it actually is.

## Python Project Rules

- Use `python3 -m pytest` not bare `pytest`
- Use `ruff check .` for linting
- Use `mypy .` for type checking
- Never create venv in project root — use `.venv/`
- Never `pip install` without venv active

## Before Editing

1. `git pull`
2. Check `.gitignore` — don't stage ignored files
3. Check this file for project-specific rules

## Before Committing

1. `git status --short` — review staged files
2. No secrets, no generated files, no cache directories
3. `git diff --cached` — verify actual content
4. Let pre-push CI pass before pushing

## Writing Rules

- **Honest docs only** — no "9/10 readiness" scores on scaffolded features
- **Version labels**: This is pre-1.0 beta. Say so.
- **Threat models**: Document anything that takes untrusted input
- **No dead code** implying capabilities the product doesn't have
- **Product names**: PicoShogun, PicoSentry, PicoDome, PicoWatch — not Shogun, IronDome
- **Env vars**: `PICOSHOGUN_*` is primary. `SHOGUN_*` is backward compat, supported but deprecated.

---

## 🔒 Secure-Defaults Checklist (Definition of Done)

> **The rule:** The secure state is the DEFAULT. Opening it up is an EXPLICIT, LOGGED, opt-in — never the fallback.

### Network binding
- [ ] Servers bind `127.0.0.1` by default. Non-loopback requires explicit flag/env AND auth enabled.
- [ ] Non-loopback bind logs a startup WARNING naming the exposure.
- [ ] CORS / allowed-hosts default to an explicit allowlist, never `["*"]`.

### Secrets
- [ ] No secret has a usable default value. Missing secret in production → refuse to boot (`exit 1`).
- [ ] Empty-string / placeholder secrets are never a valid signing key, even in dev. Generate random per-process secret if none supplied (+ warning).
- [ ] No secret value is written into generated artifacts (systemd units, configmaps, scripts).
- [ ] Secrets come from env or a secret manager — never a committed file. `*token*.json`, `credentials*.json` etc. are gitignored.

### Comparisons (constant-time)
- [ ] Every secret / token / signature / hash comparison uses constant-time compare (`hmac.compare_digest` / `crypto.timingSafeEqual`), never `==` / `!==`.
- [ ] `grep -rEn '(sig|hmac|token|secret|hash|key)\b.*(==|!=|!==)' src/` returns nothing that compares a secret.

### Allowlists / deny-by-default
- [ ] An empty allowlist means DENY, never ALLOW-ALL.
- [ ] Filesystem paths from tool/API input are confined to a configured root by default; arbitrary paths require explicit opt-in.
- [ ] Command execution uses argv arrays, never `shell=True` / string interpolation. Raw-shell paths gated behind `ALLOW_UNSAFE_*=1`, default off.

### Multi-tenant isolation
- [ ] Every shared store (sessions, cache, files, memory, routing) is keyed by `tenant_id`, not a global namespace.
- [ ] List/enumerate endpoints scope results to the calling tenant.
- [ ] Identity (owner/role/tenant) is derived from the authenticated session/token, never from the request body.
- [ ] At least one test asserts tenant A cannot read/modify tenant B's data.

### Authorization (not just authentication)
- [ ] Every protected endpoint calls BOTH authn (who are you) AND authz (are you allowed).
- [ ] New endpoints are deny-by-default — added to the authz table, not left to fall through.

### Sandbox / untrusted execution
- [ ] Child processes get an explicit env allowlist, not `{...process.env}` inheritance.
- [ ] For untrusted/model-generated code, real isolation (container/microVM/namespaces + rlimits + no-new-privs) is the DEFAULT path; bare-host "constrained" is opt-in with a warning.
- [ ] Isolation claims in README match what the code enforces. No "kernel-enforced"/"enterprise-grade" unless it is.

### Claims vs reality
- [ ] README maturity label matches code reality.
- [ ] Threat model is documented for anything that takes untrusted input.
- [ ] No dead code that implies a capability the product doesn't have.
