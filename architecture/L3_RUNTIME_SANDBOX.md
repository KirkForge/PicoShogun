# L3 Runtime Sandbox — Architecture Plan

## Problem

L1 (perimeter/DDoS) and L2 (supply chain static analysis) catch known patterns before code runs. But **runtime attacks** — crypto miners, data exfiltration, DNS tunneling, process spawning, filesystem abuse — only manifest during execution. Traditional sandboxing (Docker, VMs) is heavy, slow, and doesn't integrate into a CI/CD security gate. Nobody does **deterministic, lightweight, local-first runtime behavioral analysis** with a security decision engine.

## Product

**Shogun Runtime Sandbox** — a lightweight process sandbox that monitors runtime behavior against a policy engine, producing deterministic verdicts (ALLOW / DENY / AUDIT) per operation. Runs locally, no cloud, no LLM.

### Core Principles
1. **Deterministic** — same behavior trace, same verdict. Policy-driven, not heuristic.
2. **Local-first** — no cloud calls, no telemetry. Runs on the build machine or CI runner.
3. **Zero-trust** — every syscall, network call, and filesystem operation is intercepted and evaluated.
4. **Lightweight** — seccomp-bpf + ptrace on Linux, seatbelt on macOS. No VM overhead.
5. **Fast** — sandbox spinup <2s, overhead <15% on typical workloads.

## Scope

### In Scope (L3 Sandbox)
- **Process sandboxing** — seccomp-bpf filter generation from policy
- **Syscall interception** — allow/deny/audit per syscall class (network, filesystem, process, signal)
- **Network policy** — block outbound connections except whitelisted hosts/ports
- **Filesystem policy** — read-only mounts, write allowlists, path restrictions
- **Resource limits** — CPU time, memory, wall-clock timeout, max processes
- **Behavioral logging** — structured JSON trace of all intercepted operations
- **Policy DSL** — YAML/JSON policy files that define what a "safe" run looks like
- **CLI tool** — `shogun sandbox run --policy policy.yml -- ./test_runner.sh`
- **REST API endpoint** — `POST /api/v1/sandboxes` — submit code + policy, get verdict
- **Integration** — feeds verdicts back to Shogun AlertHub (webhook on DENY/AUDIT)
- **SARIF + JSON output** — same format as L2, extended with runtime findings

### Out of Scope (Future Layers)
- L4: Behavioral analysis (timing side-channels, honeypots)
- L5: LLM prompt injection guardrails
- Container-level orchestration (Kubernetes policies, Istio) — we sandbox processes, not clusters
- Remote sandboxing (we don't send code to a cloud service)

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│                    CLI / API                       │
│  shogun sandbox run --policy policy.yml ./test    │
│  POST /api/v1/sandboxes                            │
└──────────────────────┬───────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────┐
│                 SandboxEngine                      │
│  Loads policy, creates sandbox, monitors process  │
│  Produces SandboxResult with verdict              │
└──────────────────────┬───────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────┐
│              Policy Engine                         │
│  Evaluates each intercepted operation against      │
│  the loaded policy rules. Returns verdict.         │
└──┬──────────┬──────────┬──────────────────────────┘
   │          │          │
   ▼          ▼          ▼
┌────────┐┌────────┐┌──────────────┐
│Syscall ││Network ││Filesystem    │
│Policy  ││Policy  ││Policy        │
└────────┘└────────┘└──────────────┘
                       │
┌──────────────────────▼───────────────────────────┐
│            Platform Backend                        │
│  Linux: seccomp-bpf + ptrace                      │
│  macOS: seatbelt (sandbox-exec)                   │
│  Fallback: subprocess + resource limits           │
└──────────────────────────────────────────────────┘
```

## Data Model

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict
from datetime import datetime

class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    AUDIT = "AUDIT"  # Suspicious but not blocked — log and alert

class OperationClass(str, Enum):
    SYSCALL = "SYSCALL"
    NETWORK = "NETWORK"
    FILESYSTEM = "FILESYSTEM"
    PROCESS = "PROCESS"
    SIGNAL = "SIGNAL"
    RESOURCE = "RESOURCE"

@dataclass(frozen=True)
class SandboxEvent:
    """A single intercepted operation during sandboxed execution."""
    timestamp: str           # ISO 8601
    pid: int
    operation_class: OperationClass
    operation: str           # e.g. "connect", "open", "execve", "kill"
    args: List[str]          # syscall arguments or resolved paths
    verdict: Verdict
    rule_id: str             # e.g. "L3-NET-001"
    detail: str              # Human-readable explanation

@dataclass(frozen=True)
class SandboxPolicy:
    """A loaded policy that governs sandbox behavior."""
    name: str
    version: str
    default_verdict: Verdict = Verdict.DENY  # deny-by-default
    rules: List[Dict] = field(default_factory=list)
    network: Dict = field(default_factory=dict)  # allowlisted hosts/ports
    filesystem: Dict = field(default_factory=dict)  # read-only, write allowlists
    resources: Dict = field(default_factory=dict)  # cpu, memory, time limits

@dataclass
class SandboxResult:
    """Complete result of a sandboxed execution."""
    sandbox_id: str = ""
    timestamp: str = ""
    target: str = ""                # command that was sandboxed
    policy_name: str = ""
    policy_version: str = ""
    exit_code: Optional[int] = None
    exit_reason: str = ""           # "normal", "killed", "timeout", "policy_violation"
    verdict: Verdict = Verdict.ALLOW  # Overall verdict
    events: List[SandboxEvent] = field(default_factory=list)
    duration_ms: int = 0
    peak_memory_mb: float = 0.0
    cpu_time_ms: int = 0

    def to_dict(self) -> Dict:
        return {
            "sandbox_id": self.sandbox_id,
            "timestamp": self.timestamp,
            "target": self.target,
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "exit_code": self.exit_code,
            "exit_reason": self.exit_reason,
            "verdict": self.verdict.value,
            "events": [e.__dict__ if hasattr(e, '__dict__') else dict(e) for e in self.events],
            "duration_ms": self.duration_ms,
            "peak_memory_mb": self.peak_memory_mb,
            "cpu_time_ms": self.cpu_time_ms,
        }
```

## Policy DSL

Policies are YAML files that define what a "safe" run looks like:

```yaml
# policies/default.yml — deny-by-default
name: default
version: "1.0"
default_verdict: DENY

network:
  allow_outbound:
    - host: "registry.npmjs.org"
      ports: [443]
    - host: "github.com"
      ports: [443, 22]
  deny_all_other: true

filesystem:
  read_only_mounts:
    - "/usr"
    - "/lib"
  write_allowlist:
    - "./node_modules/.cache"
    - "/tmp/shogun-sandbox-*"
  deny_paths:
    - "/etc/shadow"
    - "/root/.ssh"
    - "/etc/passwd"  # read-only, no writes

process:
  allow_spawn: false          # no child processes
  allow_signals_to_parent: false
  max_processes: 1

resources:
  cpu_time_seconds: 60
  memory_mb: 512
  wall_time_seconds: 120
  max_open_files: 64
```

## Policy Rule Catalog

| ID | Class | Name | What It Catches |
|----|-------|------|-----------------|
| L3-SYS-001 | SYSCALL | ForbiddenSyscall | Blocked syscalls (execve, fork, clone outside policy) |
| L3-NET-001 | NETWORK | OutboundBlocked | Network connection to non-allowlisted host:port |
| L3-NET-002 | NETWORK | DNSExfiltration | Suspicious DNS query patterns (long subdomains, high frequency) |
| L3-FS-001 | FILESYSTEM | WriteDenied | Write to path not in allowlist |
| L3-FS-002 | FILESYSTEM | ReadDenied | Read from denied path (shadow, ssh keys) |
| L3-PROC-001 | PROCESS | SpawnDenied | Child process spawn when allow_spawn=false |
| L3-PROC-002 | PROCESS | SignalAbuse | Signal sent to non-child process |
| L3-RES-001 | RESOURCE | CpuLimitExceeded | Process exceeded CPU time limit |
| L3-RES-002 | RESOURCE | MemoryLimitExceeded | Process exceeded memory limit |
| L3-RES-003 | RESOURCE | WallTimeExceeded | Process exceeded wall-clock timeout |

## Platform Backends

### Linux (Primary)
- **seccomp-bpf**: Generate BPF filter from policy → restrict syscalls at kernel level
- **ptrace**: Intercept syscalls for AUDIT verdicts and detailed logging
- **cgroups v2**: Enforce resource limits (memory, CPU, PIDs)
- **namespaces**: Network namespace isolation (optional, for strict network policy)

### macOS (Secondary)
- **seatbelt** (`sandbox-exec`): Apple's built-in sandboxing
- Parse our YAML policy → generate seatbelt profile
- Resource limits via `setrlimit`

### Fallback (Any OS)
- **subprocess** with `resource` module limits
- No syscall interception — relies on exit code + resource monitoring
- Verdict is less granular (ALLOW/DENY based on exit code only)

## File Structure

```
iron_dome/
├── L1_perimeter/
│   └── ddos_shield.py              # existing
├── L2_validation/
│   ├── engine.py                    # existing
│   ├── models.py                    # existing
│   ├── rules/                       # existing (6 detectors)
│   ├── formatters/                   # existing (JSON, SARIF, table)
│   └── cli.py                       # existing
├── L3_execution/
│   ├── __init__.py
│   ├── engine.py                    # SandboxEngine — orchestrator
│   ├── models.py                    # SandboxEvent, SandboxPolicy, SandboxResult
│   ├── policy.py                    # Policy loader (YAML → SandboxPolicy)
│   ├── policies/
│   │   ├── default.yml              # Deny-by-default policy
│   │   ├── npm_ci.yml               # Permissive for npm install
│   │   └── test_runner.yml          # Tight policy for test execution
│   ├── backends/
│   │   ├── __init__.py
│   │   ├── linux_seccomp.py         # seccomp-bpf + ptrace backend
│   │   ├── macos_seatbelt.py        # sandbox-exec backend
│   │   └── fallback_subprocess.py   # subprocess + resource limits fallback
│   ├── interceptors/
│   │   ├── __init__.py
│   │   ├── syscall.py               # L3-SYS-001
│   │   ├── network.py               # L3-NET-001, L3-NET-002
│   │   ├── filesystem.py            # L3-FS-001, L3-FS-002
│   │   ├── process.py               # L3-PROC-001, L3-PROC-002
│   │   └── resource.py              # L3-RES-001, L3-RES-002, L3-RES-003
│   ├── formatters/
│   │   ├── __init__.py
│   │   ├── json_fmt.py              # JSON output
│   │   ├── sarif.py                 # SARIF for GitHub/GitLab
│   │   └── table.py                 # Human-readable table
│   └── cli.py                       # shogun-sandbox CLI entry point
├── L4_behavioral/                   # future
└── L5_prompt_shield/               # future
```

## Integration Points

1. **API**: `POST /api/v1/sandboxes` — accepts command + policy, returns SandboxResult
2. **CLI**: `python -m iron_dome.L3_execution.cli run --policy default.yml -- ./command`
3. **CI/CD**: Exit code 0=ALLOW, 1=DENY, 2=AUDIT (needs review), 3=error
4. **L2 Integration**: L2 findings can auto-generate L3 policies (e.g., "package X has post-install script → sandbox it")
5. **Webhook**: DENY/AUDIT verdicts → AlertHub → Discord/Slack/Email
6. **SARIF**: Same format as L2, extended with `sandboxEvents` property

## L2 → L3 Pipeline

L2 and L3 are designed to chain:

```
L2 Scan (static) → Findings → Generate L3 Policy → L3 Sandbox (runtime) → Verdict
```

Example:
- L2 finds `malicious-pkg@1.0.0` has post-install script (L2-POST-001)
- Auto-generate policy: "sandbox `npm install` with network deny + filesystem write-only to node_modules/.cache"
- L3 runs install in sandbox → catches the post-install phoning home (L3-NET-001)
- Verdict: DENY → AlertHub notification

## Success Metrics
- Sandbox spinup <2 seconds
- Runtime overhead <15% on typical npm install
- Zero false DENY verdicts on clean npm install of top-100 packages
- Catch all known post-install + runtime attacks from 2024-2026
- Policy YAML parse + validate <50ms
- Works on Ubuntu 22.04+, macOS 13+ (Linux primary, macOS best-effort)