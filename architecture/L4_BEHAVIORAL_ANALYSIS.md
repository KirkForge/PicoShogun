# L4 Behavioral Analysis — Architecture Plan

## Problem

L1 (perimeter/DDoS) stops flood attacks. L2 (supply chain scanner) catches malicious packages before install. L3 (runtime sandbox) intercepts policy-violating syscalls, network calls, and filesystem access during execution. But **behavioral attacks** — timing side-channels, covert exfiltration through allowed channels, honeypot-triggering payloads, sleep-evading malware, and low-and-slow data leakage — slip through all three layers because they operate within policy boundaries. They don't violate any single rule, but their **pattern of behavior** over time is anomalous.

Nobody does **deterministic, local, zero-trust behavioral analysis** that chains off L2 and L3 outputs.

## Product

**PicoShogun Behavioral Analysis Engine** — a deterministic behavioral profiler that observes process execution traces over time, builds behavioral baselines, and detects deviations that indicate compromise. No LLMs. No probabilistic guessing. Same trace, same verdict. Runs locally.

### Core Principles
1. **Deterministic** — same behavioral trace, same verdict. Policy-driven thresholds, not ML black boxes.
2. **Local-first** — no cloud calls, no telemetry. Runs on the build machine or CI runner.
3. **Zero-trust** — normal behavior must be explicitly defined; everything else is anomalous.
4. **Composable** — each detector is a standalone rule. Add new rules without touching core.
5. **Trace-chained** — feeds from L2 findings and L3 sandbox events. No standalone operation.
6. **Fast** — behavioral profile generation <5s for typical npm install trace. Baseline diff <1s.

## Scope

### In Scope (L4 Behavioral)
- **Behavioral profiling** — build execution profiles from L3 sandbox event traces
- **Timing anomaly detection** — detect timing side-channels (sleep evasion, steganographic timing)
- **Covert channel detection** — spot data exfiltration through allowed channels (DNS, HTTPS headers, error messages)
- **Baseline diffing** — compare current run's behavioral profile against known-good baseline
- **Honeypot triggering** — detect processes that probe for fake secrets, canary tokens, or decoy files
- **Entropy analysis** — flag data with abnormally high entropy leaving the process (exfiltration signal)
- **Behavioral rules engine** — deterministic rule evaluation against behavioral profiles
- **CLI tool** — `shogun behavioral analyze --baseline baseline.json --trace trace.json`
- **REST API endpoint** — `POST /api/v1/behavioral` — submit L3 trace, get behavioral verdict
- **Integration** — feeds verdicts to AlertHub, chains from L2→L3→L4 pipeline
- **SARIF + JSON output** — same format as L2/L3, extended with behavioral findings

### Out of Scope (Future Layers)
- L5: LLM prompt injection guardrails
- Real-time process monitoring (we analyze traces, not live processes)
- ML-based anomaly detection (we use deterministic rules, not neural nets)
- Container orchestration policies (Kubernetes, Istio)

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                       CLI / API                            │
│  shogun behavioral analyze --baseline b.json --trace t.json│
│  POST /api/v1/behavioral                                  │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│                  BehavioralEngine                          │
│  Loads baseline + trace, runs detectors, produces         │
│  BehavioralResult with verdict and findings               │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│                BehavioralProfiler                          │
│  Converts L3 SandboxEvent trace into BehavioralProfile    │
│  Extracts: timing, entropy, call frequency, sequence      │
│  patterns, resource usage curves                          │
└────────┬──────────┬──────────┬──────────┬───────────────┘
         │          │          │          │
         ▼          ▼          ▼          ▼
┌────────────┐┌──────────┐┌──────────┐┌──────────────┐
│  Timing    ││  Covert  ││ Entropy  ││  Honeypot    │
│  Analyzer  ││  Channel ││ Analyzer ││  Detector    │
│            ││  Detector││          ││              │
└────────────┘└──────────┘└──────────┘└──────────────┘
         │          │          │          │
         ▼          ▼          ▼          ▼
┌──────────────────────────────────────────────────────────┐
│                  BaselineDiffer                           │
│  Diff current profile against known-good baseline         │
│  Produces: added calls, removed calls, timing shifts,    │
│  entropy deltas, new network destinations                 │
└──────────────────────────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│                 Rule Evaluation                           │
│  Each rule evaluates behavioral diff → Finding or pass   │
│  Rules are deterministic: threshold-based, never fuzzy    │
└──────────────────────────────────────────────────────────┘
```

## Data Model

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# --- Reuse from L3 ---
from pico_dome.L3_execution.models import Verdict, Severity

class BehavioralVerdict(str, Enum):
    NORMAL = "NORMAL"         # Within baseline tolerance
    SUSPICIOUS = "SUSPICIOUS" # Deviates from baseline, needs review
    MALICIOUS = "MALICIOUS"   # Clear behavioral attack pattern
    UNKNOWN = "UNKNOWN"       # No baseline available, cannot judge

class TimingPattern(str, Enum):
    STEADY = "STEADY"                # Regular, predictable intervals
    BURSTY = "BURSTY"                # Clusters of rapid calls
    SLEEP_EVASION = "SLEEP_EVASION"  # Delayed execution to avoid detection
    STOCHASTIC = "STOCHASTIC"        # Randomized timing (anti-pattern)

class ExfilChannel(str, Enum):
    DNS = "DNS"              # Data encoded in DNS queries
    HTTPS_HEADER = "HTTPS_HEADER"  # Data in HTTP headers
    HTTPS_BODY = "HTTPS_BODY"       # Data in request bodies
    ERROR_MESSAGE = "ERROR_MESSAGE" # Data in stderr/error output
    EXIT_CODE = "EXIT_CODE"         # Data encoded in exit codes
    TIMING = "TIMING"               # Data encoded in timing patterns

@dataclass(frozen=True)
class TimingEntry:
    """A single timing measurement from the trace."""
    timestamp: str        # ISO 8601
    operation: str        # e.g. "connect", "open", "write"
    duration_ms: float    # How long this operation took
    interval_ms: float    # Time since previous operation of same type

@dataclass(frozen=True)
class EntropyMeasurement:
    """Entropy measurement for data flowing through a channel."""
    timestamp: str
    channel: str          # "stdout", "stderr", "network_out", "file_write"
    entropy_bits: float   # Shannon entropy in bits (0-8 for byte data)
    sample_size: int      # Bytes sampled
    is_anomalous: bool    # True if entropy > threshold (default: 7.0 bits)

@dataclass(frozen=True)
class CallFrequency:
    """Frequency count of a syscall/operation type in the trace."""
    operation: str
    count: int
    first_seen_ms: float  # ms from trace start
    last_seen_ms: float
    avg_interval_ms: float
    stddev_interval_ms: float

@dataclass(frozen=True)
class NetworkSummary:
    """Summary of network activity in the trace."""
    total_connections: int
    unique_hosts: int
    unique_ports: int
    dns_queries: int
    unique_dns_domains: int
    bytes_sent: int
    bytes_received: int
    hosts: List[str] = field(default_factory=list)
    dns_domains: List[str] = field(default_factory=list)

@dataclass
class BehavioralProfile:
    """Complete behavioral profile extracted from an L3 trace."""
    profile_id: str = ""
    timestamp: str = ""
    source_trace_id: str = ""     # Links to L3 SandboxResult.run_id
    command: List[str] = field(default_factory=list)
    duration_ms: int = 0
    # Timing
    timing_pattern: TimingPattern = TimingPattern.STEADY
    timing_entries: List[TimingEntry] = field(default_factory=list)
    # Call frequencies
    call_frequencies: List[CallFrequency] = field(default_factory=list)
    # Network summary
    network: NetworkSummary = field(default_factory=NetworkSummary)
    # Entropy measurements
    entropy: List[EntropyMeasurement] = field(default_factory=list)
    # Resource usage curve (sampled every 100ms)
    cpu_curve: List[float] = field(default_factory=list)      # % CPU at each sample
    memory_curve: List[float] = field(default_factory=list)   # MB at each sample
    # Sequence patterns (ordered lists of operation types)
    top_sequences: List[Tuple[str, int]] = field(default_factory=list)  # (pattern, count)
    # Honeypot interactions
    honeypot_touches: List[str] = field(default_factory=list)  # Paths of decoy files accessed
    # Unique identifier for baseline comparison
    baseline_key: str = ""  # e.g. "npm-install-express" or "pytest-projectx"

    def to_dict(self) -> Dict:
        return {
            "profile_id": self.profile_id,
            "timestamp": self.timestamp,
            "source_trace_id": self.source_trace_id,
            "command": self.command,
            "duration_ms": self.duration_ms,
            "timing_pattern": self.timing_pattern.value,
            "call_frequencies": [
                {"operation": cf.operation, "count": cf.count,
                 "avg_interval_ms": cf.avg_interval_ms,
                 "stddev_interval_ms": cf.stddev_interval_ms}
                for cf in self.call_frequencies
            ],
            "network": self.network.__dict__,
            "entropy": [
                {"channel": e.channel, "entropy_bits": e.entropy_bits,
                 "sample_size": e.sample_size, "is_anomalous": e.is_anomalous}
                for e in self.entropy
            ],
            "cpu_curve_samples": len(self.cpu_curve),
            "memory_curve_samples": len(self.memory_curve),
            "honeypot_touches": self.honeypot_touches,
            "baseline_key": self.baseline_key,
        }

@dataclass(frozen=True)
class BehavioralFinding:
    """A single finding from behavioral analysis."""
    rule_id: str
    severity: Severity
    confidence: Confidence  # Reuse L2's Confidence enum
    category: str           # "timing", "covert_channel", "entropy", "honeypot", "baseline_drift"
    message: str
    evidence: str
    remediation: str
    baseline_key: str = ""
    deviation_pct: float = 0.0  # How far from baseline (0-100)

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "baseline_key": self.baseline_key,
            "deviation_pct": self.deviation_pct,
        }

@dataclass
class BehavioralResult:
    """Complete result of behavioral analysis."""
    analysis_id: str = ""
    timestamp: str = ""
    source_trace_id: str = ""     # L3 SandboxResult.run_id
    baseline_key: str = ""
    verdict: BehavioralVerdict = BehavioralVerdict.UNKNOWN
    findings: List[BehavioralFinding] = field(default_factory=list)
    profile: Optional[BehavioralProfile] = None
    baseline_diff: Optional[Dict] = None  # Diff against baseline profile
    duration_ms: int = 0

    def to_dict(self) -> Dict:
        return {
            "analysis_id": self.analysis_id,
            "timestamp": self.timestamp,
            "source_trace_id": self.source_trace_id,
            "baseline_key": self.baseline_key,
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
            "profile": self.profile.to_dict() if self.profile else None,
            "baseline_diff": self.baseline_diff,
            "duration_ms": self.duration_ms,
        }
```

## Behavioral Rule Catalog

| ID | Category | Name | What It Catches |
|----|----------|------|-----------------|
| L4-TIME-001 | timing | SleepEvasion | Process sleeps then performs suspicious actions (anti-sandbox) |
| L4-TIME-002 | timing | TimingSideChannel | Data encoded in inter-operation timing intervals |
| L4-TIME-003 | timing | BurstAnomaly | Sudden burst of operations deviating from baseline pattern |
| L4-EXFIL-001 | covert_channel | DNSExfiltration | Data encoded in DNS query subdomains (already flagged at L3, L4 quantifies) |
| L4-EXFIL-002 | covert_channel | HTTPSHeaderExfil | Data encoded in outbound HTTPS headers (User-Agent, Cookie, Referer) |
| L4-EXFIL-003 | covert_channel | ErrorChannelExfil | Data leaked through stderr, error messages, or exit codes |
| L4-ENTROPY-001 | entropy | HighEntropyEgress | Data with entropy >7.0 bits/byte written to network or file (exfiltration signal) |
| L4-ENTROPY-002 | entropy | EntropySpike | Sudden increase in output entropy compared to baseline (encryption/compression start) |
| L4-HONEY-001 | honeypot | CanaryFileTouch | Process accessed a planted canary file (decoy secrets, fake .env, fake credentials) |
| L4-HONEY-002 | honeypot | CanaryDNSLookup | Process resolved a canary domain (decoy DNS entry that should never be queried) |
| L4-HONEY-003 | honeypot | CanaryTokenHit | Process used a canary token value (fake API key, fake credential that triggers on use) |
| L4-BASE-001 | baseline | CallFrequencyDrift | Significant change in syscall/operation frequency vs baseline (>30% deviation) |
| L4-BASE-002 | baseline | NetworkProfileDrift | New network destinations or changed connection patterns vs baseline |
| L4-BASE-003 | baseline | ResourceCurveDrift | CPU/memory usage curve shape changed significantly vs baseline (DTW distance) |

## Behavioral Profiler

The `BehavioralProfiler` converts an L3 `SandboxResult` (list of `SandboxEvent`) into a `BehavioralProfile`:

```python
class BehavioralProfiler:
    """
    Converts L3 sandbox event trace into a behavioral profile.
    
    Extracts:
    - Timing patterns (interval analysis between operations)
    - Call frequency (histogram of operation types)
    - Network summary (hosts, ports, DNS, bytes)
    - Entropy measurements (Shannon entropy on egress data)
    - Resource curves (CPU/memory sampled over time)
    - Sequence patterns (most common operation sequences)
    - Honeypot touches (access to planted decoy files)
    """
    
    def profile(self, result: SandboxResult, 
                honeypot_paths: List[str] = None) -> BehavioralProfile:
        """Convert L3 SandboxResult → BehavioralProfile."""
        ...
    
    def _analyze_timing(self, events: List[SandboxEvent]) -> TimingPattern:
        """Classify timing pattern: STEADY, BURSTY, SLEEP_EVASION, STOCHASTIC."""
        ...
    
    def _compute_call_frequencies(self, events: List[SandboxEvent]) -> List[CallFrequency]:
        """Count operations, compute intervals and stddev."""
        ...
    
    def _summarize_network(self, events: List[SandboxEvent]) -> NetworkSummary:
        """Extract network activity summary from events."""
        ...
    
    def _measure_entropy(self, events: List[SandboxEvent]) -> List[EntropyMeasurement]:
        """Compute Shannon entropy on data written to network/files/stdout."""
        ...
    
    def _extract_sequences(self, events: List[SandboxEvent], 
                           window: int = 3) -> List[Tuple[str, int]]:
        """Find most common n-grams of operation sequences."""
        ...
    
    def _check_honeypots(self, events: List[SandboxEvent],
                         honeypot_paths: List[str]) -> List[str]:
        """Check if any events touched planted canary files."""
        ...
```

## Baseline Differ

The `BaselineDiffer` compares a current profile against a known-good baseline:

```python
@dataclass
class BaselineDiff:
    """Difference between current profile and baseline."""
    baseline_key: str
    # Added/removed operations
    added_operations: List[str]
    removed_operations: List[str]
    # Frequency changes (operation, baseline_count, current_count, deviation_pct)
    frequency_drifts: List[Dict]
    # Timing changes
    timing_pattern_changed: bool
    timing_drift_pct: float
    # Network changes
    new_hosts: List[str]
    removed_hosts: List[str]
    new_dns_domains: List[str]
    # Entropy changes
    entropy_spikes: List[Dict]  # Channels where entropy jumped
    # Resource curve similarity (DTW distance, 0=identical, >1=very different)
    curve_similarity: float
    # Overall deviation score (0-100)
    deviation_score: float
```

### DTW (Dynamic Time Warping) for Resource Curves

Resource curves (CPU, memory over time) are compared using DTW distance:
- DTW distance 0.0 → identical curves
- DTW distance <0.3 → normal variation
- DTW distance >0.7 → significant behavioral drift
- DTW distance >1.0 → fundamentally different execution pattern

This is **not** ML — DTW is a deterministic, well-known algorithm for time-series comparison.

## Honeypot System

L4 includes a **canary planting** system that works with L3:

1. **Before L3 sandbox run**: Plant decoy files in the sandbox filesystem
   - `~/.aws/credentials` (fake AWS keys)
   - `~/.env` (fake API tokens)
   - `~/.ssh/id_rsa` (fake SSH key)
   - `~/.gitconfig` (fake git token)
   - `/etc/canary.conf` (canary marker file)

2. **During L3 run**: Monitor for any process accessing these files (L3-FS-002 events)

3. **After L3 run**: L4 checks which canary files were touched → `L4-HONEY-001`

4. **Canary DNS**: Plant `canary.picoshogun.internal` in `/etc/resolv.conf` → L3-NET events → `L4-HONEY-002`

5. **Canary tokens**: Inject fake credentials into environment → L4-HONEY-003

### Honeypot Configuration

```yaml
# honeypots/default.yml
name: default_canaries
version: "1.0"

canary_files:
  - path: "/home/user/.aws/credentials"
    content: |
      [default]
      aws_access_key_id = AKIAIOSFODNN7CANARY
      aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCANARY
    rule: L4-HONEY-001

  - path: "/home/user/.env"
    content: |
      API_KEY=sk-canary-shogun-token-00000000
      DATABASE_URL=postgres://canary:canary@canary.picoshogun.internal:5432/fake
    rule: L4-HONEY-001

  - path: "/home/user/.ssh/id_rsa"
    content: |
      -----BEGIN RSA PRIVATE KEY-----
      CANARY-KEY-DO-NOT-USE-THIS-IS-A-TRAP
      -----END RSA PRIVATE KEY-----
    rule: L4-HONEY-001

canary_dns:
  - domain: "canary.picoshogun.internal"
    should_resolve: false
    rule: L4-HONEY-002

canary_env_vars:
  - key: "AWS_SECRET_ACCESS_KEY"
    value: "canary-token-shogun-00000000"
    rule: L4-HONEY-003
  - key: "GITHUB_TOKEN"
    value: "ghp_canary_shogun_000000000000000000"
    rule: L4-HONEY-003
```

## Entropy Analysis

Shannon entropy is computed on data egress channels:

```python
import math
from collections import Counter

def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (0-8)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

# Thresholds:
# <4.0 bits — likely text/structured data (normal)
# 4.0-7.0 bits — mixed content (watch)
# >7.0 bits — likely compressed/encrypted (exfiltration signal)
# >7.9 bits — almost certainly encrypted or random data
```

## L2 → L3 → L4 Pipeline

The three layers chain:

```
L2 Scan (static)
  → Findings (post-install scripts, obfuscation, typosquatting)
  → Auto-generate L3 policy (sandbox the suspicious package)
  → L3 Sandbox (runtime)
  → SandboxResult (events, verdict)
  → L4 Behavioral Analysis
  → BehavioralResult (behavioral verdict, findings)
  → AlertHub (if SUSPICIOUS or MALICIOUS)
```

### Pipeline Integration Code

```python
from pico_dome.L2_validation.engine import ScanEngine
from pico_dome.L3_execution.engine import sandbox_run
from pico_dome.L3_execution.policy_generator import generate_from_findings
from pico_dome.L4_behavioral.engine import BehavioralEngine
from pico_dome.L4_behavioral.profiler import BehavioralProfiler
from pico_dome.L4_behavioral.baseline import BaselineStore

def full_pipeline(target_path: str, command: List[str]) -> dict:
    """L2 → L3 → L4 full analysis pipeline."""
    
    # Step 1: L2 static scan
    l2_engine = ScanEngine()
    l2_result = l2_engine.scan(target_path)
    
    # Step 2: Generate L3 policy from L2 findings
    if l2_result.findings:
        policy = generate_from_findings(l2_result.findings)
    else:
        policy = load_default_policy()
    
    # Step 3: L3 sandbox run
    l3_result = sandbox_run(command, policy=policy)
    
    # Step 4: L4 behavioral analysis
    l4_engine = BehavioralEngine()
    l4_result = l4_engine.analyze(l3_result)
    
    return {
        "l2_scan_id": l2_result.scan_id,
        "l3_run_id": l3_result.run_id,
        "l4_analysis_id": l4_result.analysis_id,
        "l2_findings": len(l2_result.findings),
        "l3_verdict": l3_result.overall_verdict.value,
        "l4_verdict": l4_result.verdict.value,
        "l4_findings": len(l4_result.findings),
    }
```

## File Structure

```
pico_dome/
├── L1_perimeter/
│   └── ddos_shield.py              # existing
├── L2_validation/
│   ├── engine.py                    # existing
│   ├── models.py                    # existing
│   ├── rules/                       # existing (6 detectors)
│   ├── formatters/                   # existing
│   └── cli.py                       # existing
├── L3_execution/
│   ├── engine.py                    # existing
│   ├── models.py                    # existing
│   ├── backends/                     # existing (3 backends)
│   ├── policies/                     # existing
│   ├── formatters/                   # existing
│   └── cli.py                       # existing
├── L4_behavioral/
│   ├── __init__.py
│   ├── engine.py                    # BehavioralEngine — orchestrator
│   ├── models.py                    # BehavioralProfile, BehavioralResult, BehavioralFinding, etc.
│   ├── profiler.py                  # Converts L3 SandboxResult → BehavioralProfile
│   ├── baseline.py                  # BaselineStore — load/save/compare baselines
│   ├── differ.py                   # BaselineDiffer — compute diff between profiles
│   ├── entropy.py                   # Shannon entropy computation
│   ├── dtw.py                       # Dynamic Time Warping for curve comparison
│   ├── honeypot.py                  # Canary file/DNS/env planting + detection
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── timing.py                # L4-TIME-001, L4-TIME-002, L4-TIME-003
│   │   ├── covert_channel.py        # L4-EXFIL-001, L4-EXFIL-002, L4-EXFIL-003
│   │   ├── entropy_rules.py         # L4-ENTROPY-001, L4-ENTROPY-002
│   │   ├── honeypot_rules.py        # L4-HONEY-001, L4-HONEY-002, L4-HONEY-003
│   │   └── baseline_rules.py        # L4-BASE-001, L4-BASE-002, L4-BASE-003
│   ├── baselines/
│   │   ├── default/                 # Shipped baseline profiles
│   │   │   ├── npm-install.json     # Baseline for `npm install`
│   │   │   ├── pip-install.json     # Baseline for `pip install`
│   │   │   ├── pytest.json          # Baseline for `pytest`
│   │   │   └── make-build.json      # Baseline for `make`
│   │   └── custom/                  # User-generated baselines
│   ├── honeypots/
│   │   ├── default.yml              # Default canary configuration
│   │   ├── strict.yml               # Strict canary set (more decoys)
│   │   └── minimal.yml              # Minimal canary set (CI-friendly)
│   ├── formatters/
│   │   ├── __init__.py
│   │   ├── json_fmt.py              # JSON output
│   │   ├── sarif.py                 # SARIF for GitHub/GitLab
│   │   └── table.py                 # Human-readable table
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_profiler.py
│   │   ├── test_differ.py
│   │   ├── test_entropy.py
│   │   ├── test_dtw.py
│   │   ├── test_honeypot.py
│   │   ├── test_rules.py
│   │   └── test_pipeline.py         # Full L2→L3→L4 pipeline test
│   └── cli.py                       # shogun-behavioral CLI entry point
└── L5_prompt_shield/               # future
```

## CLI Interface

```bash
# Analyze an L3 trace against a baseline
shogun behavioral analyze \
  --trace /tmp/shogun-l3-trace.json \
  --baseline baselines/npm-install.json \
  --output json

# Build a baseline from multiple L3 traces
shogun behavioral baseline build \
  --name "npm-install-express" \
  --traces traces/*.json \
  --output baselines/custom/npm-install-express.json

# Plant honeypots before an L3 sandbox run
shogun behavioral honeypot plant \
  --config honeypots/default.yml \
  --target /tmp/picoshogun-sandbox-root/

# Full pipeline: L2 scan → L3 sandbox → L4 behavioral
shogun pipeline run \
  --target ./project \
  --command "npm install && npm test" \
  --baseline baselines/npm-install.json \
  --output sarif
```

## REST API

```
POST /api/v1/behavioral/analyze
  Body: { "trace": <SandboxResult JSON>, "baseline_key": "npm-install" }
  Response: BehavioralResult JSON

POST /api/v1/behavioral/baseline
  Body: { "name": "npm-install-express", "traces": [<SandboxResult JSON>, ...] }
  Response: { "baseline_id": "...", "profile_count": 5 }

GET /api/v1/behavioral/baselines
  Response: { "baselines": [...] }

POST /api/v1/behavioral/honeypot/plant
  Body: { "config": "default", "target_path": "/tmp/sandbox" }
  Response: { "planted_files": [...], "planted_dns": [...], "planted_env_vars": [...] }

POST /api/v1/pipeline
  Body: { "target_path": "./project", "command": ["npm", "install"], "baseline_key": "npm-install" }
  Response: { "l2_scan_id": "...", "l3_run_id": "...", "l4_analysis_id": "...", "verdicts": {...} }
```

## Integration Points

1. **L3 Integration**: L4 consumes `SandboxResult` (L3 output) as input. No L3 changes needed.
2. **L2 Integration**: L2 findings auto-generate L3 policies. L4 baselines can be scoped per L2 finding type.
3. **API**: `POST /api/v1/behavioral/analyze` — submit trace + baseline key, get verdict
4. **CLI**: `python -m pico_dome.L4_behavioral.cli analyze --trace t.json --baseline b.json`
5. **CI/CD**: Exit code 0=NORMAL, 1=SUSPICIOUS, 2=MALICIOUS, 3=UNKNOWN (no baseline), 4=error
6. **Webhook**: SUSPICIOUS/MALICIOUS verdicts → AlertHub → Discord/Slack/Email
7. **SARIF**: Same format as L2/L3, extended with `behavioralFindings` property

## Baseline Management

Baselines are JSON files containing a `BehavioralProfile` averaged over multiple known-good runs:

```json
{
  "baseline_key": "npm-install-express",
  "version": "1.0",
  "sample_count": 10,
  "created": "2026-05-14T00:00:00Z",
  "profile": {
    "timing_pattern": "STEADY",
    "call_frequencies": [
      {"operation": "open", "avg_count": 245, "stddev": 12, "avg_interval_ms": 4.2},
      {"operation": "write", "avg_count": 180, "stddev": 15, "avg_interval_ms": 5.8},
      {"operation": "connect", "avg_count": 8, "stddev": 2, "avg_interval_ms": 120.0}
    ],
    "network": {
      "avg_total_connections": 8,
      "avg_unique_hosts": 3,
      "avg_dns_queries": 12,
      "expected_hosts": ["registry.npmjs.org", "cdn.npmjs.org"]
    },
    "entropy": {
      "stdout_max_bits": 5.2,
      "stderr_max_bits": 4.8,
      "network_out_max_bits": 6.1
    },
    "resource_curves": {
      "cpu_avg": [0.0, 5.2, 12.8, 45.3, 78.1, 62.0, 30.5, 10.2, 2.1, 0.0],
      "memory_avg": [0.0, 12.0, 28.5, 45.2, 52.1, 48.0, 30.2, 15.5, 5.0, 2.0]
    },
    "honeypot_touches": []
  },
  "thresholds": {
    "frequency_drift_pct": 30,
    "timing_drift_pct": 50,
    "entropy_threshold_bits": 7.0,
    "dtw_distance_max": 0.7,
    "new_hosts_max": 0
  }
}
```

## Success Metrics
- Profile generation from L3 trace <5s for 10,000 event trace
- Baseline diff <1s
- Zero false MALICIOUS verdicts on clean npm install of top-100 packages
- Catch all known behavioral attacks from 2024-2026 (DNS exfiltration, timing channels, canary triggers)
- Entropy detection accuracy >95% for encrypted exfiltration
- DTW curve comparison accuracy >90% for behavioral drift detection
- Honeypot canary trigger rate >99% for processes that access decoy files
- Works on Ubuntu 22.04+ (Linux primary), macOS 13+ (best-effort)
- Full L2→L3→L4 pipeline <60s for typical npm install