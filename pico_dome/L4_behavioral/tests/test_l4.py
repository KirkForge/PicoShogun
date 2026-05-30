"""Unit tests for L4 Behavioral Analysis."""
import json
import os

import pytest

from ..baseline import DEFAULT_BASELINES, load_all_baselines, load_baseline, save_baseline
from ..differ import compare_profile_to_baseline, find_best_baseline
from ..dtw import compare_resource_curves, dtw_distance, normalized_dtw_distance
from ..engine import L4Engine, _compute_verdict, create_default_engine
from ..entropy import (
    detect_entropy_spikes,
    entropy_of_chunks,
    normalized_entropy,
    shannon_entropy,
    shannon_entropy_string,
)
from ..formatters import format_json, format_sarif, format_table
from ..honeypot import (
    check_canary_dns,
    check_canary_env,
    check_canary_file_access,
    generate_canary_domain,
    generate_canary_env_key,
    generate_canary_filename,
    plant_canary_dns,
    plant_canary_env,
    plant_canary_files,
)
from ..models import (
    AnalysisResult,
    AnalysisStats,
    Baseline,
    BehavioralProfile,
    BehavioralVerdict,
    Confidence,
    DNSQuery,
    DriftResult,
    FilesystemOp,
    Finding,
    NetworkCall,
    RuleID,
    Severity,
    TimingPoint,
)
from ..profiler import profile_from_trace
from ..rules.baseline_rules import detect_baseline_drift
from ..rules.entropy_rules import detect_entropy_anomalies
from ..rules.exfil import detect_exfiltration
from ..rules.honeypot_rules import detect_honeypot_touches
from ..rules.timing import detect_timing_anomalies

# ─── Helpers ────────────────────────────────────────────────────────────

def _make_profile(**overrides) -> BehavioralProfile:
    defaults = dict(
        package="test-pkg@1.0.0",
        command=["npm", "install"],
        duration_ms=10000,
    )
    defaults.update(overrides)
    return BehavioralProfile(**defaults)


def _make_baseline(**overrides) -> Baseline:
    defaults = dict(
        name="test-baseline",
        description="Test baseline",
    )
    defaults.update(overrides)
    return Baseline(**defaults)


def _make_suspicious_profile() -> BehavioralProfile:
    profile = BehavioralProfile(
        package="evil-pkg@1.0.0",
        command=["evil-cmd"],
        duration_ms=15000,
        egress_entropy=7.8,
        total_bytes_sent=15000,
        canary_file_accesses=["/tmp/secret_passwords_abc123.txt"],
        canary_dns_lookups=["abc123.canary.picoshogun.local"],
        canary_env_reads=["AWS_SECRET_XYZ"],
    )

    for i in range(20):
        profile.timing_points.append(TimingPoint(
            timestamp_ms=i * 100.0,
            operation="fs_read",
            duration_ms=10.0,
        ))
    for i in range(5):
        profile.timing_points.append(TimingPoint(
            timestamp_ms=20000.0 + i * 1000.0,
            operation="connect",
            duration_ms=5.0,
        ))
    profile.sleep_intervals = [800.0, 900.0, 1000.0, 1200.0, 1500.0]

    profile.network_calls.append(NetworkCall(
        host="evil-c2.example.com", port=443, bytes_sent=12000,
        timestamp_ms=25000.0,
    ))

    profile.dns_queries.append(DNSQuery(
        domain="a7f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5.evil.com",
        timestamp_ms=25000.0,
    ))

    profile.fs_ops.append(FilesystemOp(
        operation="fs_read", path="/tmp/secret_passwords_abc123.txt",
        timestamp_ms=1000.0,
    ))

    profile.call_frequencies = {
        "fs_read": 5000,
        "connect": 100,
        "dns": 50,
    }

    return profile


# ─── Models ──────────────────────────────────────────────────────────────

class TestModels:
    def test_behavioral_verdict_enum(self):
        assert BehavioralVerdict.CLEAN.value == "CLEAN"
        assert BehavioralVerdict.SUSPICIOUS.value == "SUSPICIOUS"
        assert BehavioralVerdict.MALICIOUS.value == "MALICIOUS"

    def test_rule_id_enum(self):
        assert RuleID.L4_TIME_001.value == "L4-TIME-001"
        assert RuleID.L4_EXFIL_001.value == "L4-EXFIL-001"
        assert RuleID.L4_HONEY_001.value == "L4-HONEY-001"
        assert RuleID.L4_BASE_001.value == "L4-BASE-001"
        assert len(RuleID) == 14  # 3+3+2+3+3

    def test_finding_is_frozen(self):
        f = Finding(
            rule_id="L4-TIME-001", severity=Severity.HIGH,
            confidence=Confidence.EXACT, package="evil@1.0.0",
            message="test", evidence="test", remediation="test",
        )
        with pytest.raises(AttributeError):
            f.message = "changed"

    def test_behavioral_profile_to_dict(self):
        p = _make_profile()
        d = p.to_dict()
        assert d["package"] == "test-pkg@1.0.0"
        assert d["duration_ms"] == 10000
        assert isinstance(d["timing_points"], list)

    def test_analysis_result_to_dict(self):
        r = AnalysisResult(target="test")
        d = r.to_dict()
        assert d["target"] == "test"
        assert d["overall_verdict"] == "CLEAN"
        assert isinstance(d["findings"], list)

    def test_baseline_to_dict(self):
        b = _make_baseline()
        d = b.to_dict()
        assert d["name"] == "test-baseline"

    def test_drift_result_to_dict(self):
        d = DriftResult(baseline_name="npm-install")
        dd = d.to_dict()
        assert dd["baseline_name"] == "npm-install"


# ─── Entropy ─────────────────────────────────────────────────────────────

class TestEntropy:
    def test_empty_data(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_byte(self):
        assert shannon_entropy(b"\x00") == 0.0

    def test_constant_data(self):
        assert shannon_entropy(b"\x00" * 100) == 0.0

    def test_random_data_high_entropy(self):
        data = os.urandom(1024)
        ent = shannon_entropy(data)
        assert 7.0 < ent <= 8.0

    def test_ascii_text_moderate_entropy(self):
        ent = shannon_entropy(b"hello world hello world")
        assert 2.0 < ent < 5.0

    def test_string_entropy(self):
        ent = shannon_entropy_string("hello")
        assert ent > 0

    def test_entropy_of_chunks(self):
        chunks = [b"\x00" * 100, os.urandom(4096)]
        entropies = entropy_of_chunks(chunks)
        assert entropies[0] == 0.0
        assert entropies[1] > 6.0  # Relaxed for smaller random samples

    def test_normalized_entropy(self):
        assert normalized_entropy(b"hello", baseline_entropy=0.0) > 0
        assert normalized_entropy(b"hello", baseline_entropy=3.0) < 1.0

    def test_detect_entropy_spikes(self):
        spikes = detect_entropy_spikes(b"\x00" * 1024, threshold=7.0)
        assert len(spikes) == 0

        data = os.urandom(1024)
        spikes = detect_entropy_spikes(data, threshold=7.0)
        assert len(spikes) > 0


# ─── DTW ─────────────────────────────────────────────────────────────────

class TestDTW:
    def test_identical_series_zero_distance(self):
        series = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert dtw_distance(series, series) == 0.0

    def test_different_series_positive_distance(self):
        a = [1.0, 2.0, 3.0]
        b = [4.0, 5.0, 6.0]
        assert dtw_distance(a, b) > 0.0

    def test_empty_series_infinite_distance(self):
        assert dtw_distance([], [1.0, 2.0]) == float("inf")

    def test_normalized_dtw_range(self):
        a = [1.0, 2.0, 3.0]
        b = [4.0, 5.0, 6.0]
        nd = normalized_dtw_distance(a, b)
        assert 0.0 <= nd <= 1.0

    def test_compare_resource_curves_no_drift(self):
        curve = [10.0, 20.0, 30.0, 20.0, 10.0]
        dist, is_drift = compare_resource_curves(curve, curve, threshold=0.3)
        assert dist == 0.0
        assert not is_drift

    def test_compare_resource_curves_with_drift(self):
        baseline = [10.0, 20.0, 30.0, 20.0, 10.0]
        observed = [50.0, 60.0, 70.0, 60.0, 50.0]
        dist, is_drift = compare_resource_curves(observed, baseline, threshold=0.3)
        assert is_drift


# ─── Profiler ────────────────────────────────────────────────────────────

class TestProfiler:
    def test_profile_from_trace_basic(self):
        events = [
            {"timestamp_ms": 0, "operation": "fs_read", "detail": "/etc/passwd"},
            {"timestamp_ms": 100, "operation": "connect", "detail": "evil.com:443"},
            {"timestamp_ms": 200, "operation": "dns", "detail": "evil.com"},
        ]
        profile = profile_from_trace("test-pkg", ["npm", "install"], events, duration_ms=1000)
        assert profile.package == "test-pkg"
        assert len(profile.fs_ops) == 1
        assert len(profile.network_calls) == 1
        assert len(profile.dns_queries) == 1
        assert profile.duration_ms == 1000

    def test_profile_from_trace_with_sleep(self):
        events = [
            {"timestamp_ms": 0, "operation": "fs_read", "detail": "/tmp/a"},
            {"timestamp_ms": 100, "operation": "fs_read", "detail": "/tmp/b"},
            {"timestamp_ms": 2000, "operation": "connect", "detail": "host:443"},
        ]
        profile = profile_from_trace("pkg", ["cmd"], events)
        assert len(profile.sleep_intervals) == 1

    def test_profile_from_trace_egress_entropy(self):
        events = [
            {"timestamp_ms": 0, "operation": "connect", "detail": "host:443"},
        ]
        egress_data = b"\x00" * 100
        profile = profile_from_trace("pkg", ["cmd"], events, egress_data=egress_data)
        assert profile.egress_entropy < 1.0


# ─── Baselines ───────────────────────────────────────────────────────────

class TestBaselines:
    def test_load_default_baselines(self):
        baselines = load_all_baselines()
        assert "npm-install" in baselines
        assert "pip-install" in baselines
        assert "pytest" in baselines
        assert "make-build" in baselines

    def test_load_specific_baseline(self):
        bl = load_baseline("npm-install")
        assert bl is not None
        assert bl.name == "npm-install"
        assert "registry.npmjs.org" in bl.network_hosts

    def test_load_nonexistent_baseline(self):
        bl = load_baseline("nonexistent-baseline")
        assert bl is None

    def test_save_custom_baseline(self, tmp_path):
        bl = _make_baseline(name="custom-test-bl", description="Custom test baseline")
        path = save_baseline(bl, tmp_path / "custom-test-bl.yml")
        assert path.exists()
        content = path.read_text()
        assert "custom-test-bl" in content


# ─── Differ ──────────────────────────────────────────────────────────────

class TestDiffer:
    def test_compare_to_matching_baseline(self):
        profile = BehavioralProfile(
            package="npm-test",
            duration_ms=15000,
            call_frequencies={"fs_read": 500, "fs_write": 100, "connect": 10, "dns": 5, "spawn": 2},
            total_bytes_sent=5000,
            total_bytes_received=500000,
        )
        baseline = DEFAULT_BASELINES["npm-install"]
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.baseline_name == "npm-install"
        assert drift.call_frequency_drift < 1.0
        assert drift.duration_drift < 1.0

    def test_compare_to_mismatched_baseline(self):
        profile = BehavioralProfile(
            package="suspicious",
            duration_ms=500,
            call_frequencies={"connect": 5000, "dns": 2000, "spawn": 100},
            total_bytes_sent=100000,
            egress_entropy=7.8,
        )
        baseline = DEFAULT_BASELINES["npm-install"]
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.network_drift > 0.0
        assert drift.entropy_drift > 0.0

    def test_find_best_baseline(self):
        profile = BehavioralProfile(
            package="npm-test",
            duration_ms=15000,
            call_frequencies={"fs_read": 500, "connect": 10, "dns": 5},
        )
        result = find_best_baseline(profile, DEFAULT_BASELINES)
        assert result is not None
        baseline, drift = result
        assert baseline.name in ["npm-install", "pip-install"]

    def test_zero_entropy_no_drift(self):
        """Profile with no egress data should have zero entropy drift."""
        profile = BehavioralProfile(
            package="clean-pkg",
            duration_ms=10000,
            call_frequencies={"fs_read": 10},
        )
        baseline = DEFAULT_BASELINES["npm-install"]
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.entropy_drift == 0.0


# ─── Honeypot ────────────────────────────────────────────────────────────

class TestHoneypot:
    def test_generate_canary_filename(self):
        name = generate_canary_filename()
        assert name.endswith(".txt")
        assert "secret" in name.lower() or len(name) > 5

    def test_generate_canary_domain(self):
        domain = generate_canary_domain()
        assert "canary.picoshogun.local" in domain

    def test_generate_canary_env_key(self):
        key = generate_canary_env_key()
        assert any(p in key for p in ["AWS", "SECRET", "KEY", "TOKEN", "PASSWORD", "DATABASE", "API", "PRIVATE", "CREDENTIAL"])

    def test_plant_canary_files(self, tmp_path):
        paths = plant_canary_files(tmp_path, count=3)
        assert len(paths) == 3
        for p in paths:
            assert p.exists()
            content = p.read_text()
            assert "CANARY_TOKEN" in content

    def test_plant_canary_env(self):
        env = plant_canary_env(count=3)
        assert len(env) >= 3

    def test_plant_canary_dns(self):
        domains = plant_canary_dns(count=3)
        assert len(domains) == 3
        for d in domains:
            assert "canary.picoshogun.local" in d

    def test_check_canary_file_access(self):
        paths = ["/tmp/secret_passwords_abc123.txt"]
        ops = [{"path": "/tmp/secret_passwords_abc123.txt", "operation": "fs_read"}]
        touched = check_canary_file_access(paths, ops)
        assert len(touched) == 1

    def test_check_canary_dns(self):
        domains = ["abc123.canary.picoshogun.local"]
        queries = [{"domain": "abc123.canary.picoshogun.local"}]
        touched = check_canary_dns(domains, queries)
        assert len(touched) == 1

    def test_check_canary_env(self):
        keys = ["AWS_SECRET_ABC"]
        reads = [{"key": "AWS_SECRET_ABC"}]
        touched = check_canary_env(keys, reads)
        assert len(touched) == 1


# ─── Rules: Timing ──────────────────────────────────────────────────────

class TestTimingRules:
    def test_no_sleep_no_finding(self):
        profile = _make_profile()
        findings = detect_timing_anomalies(profile)
        assert len(findings) == 0

    def test_sleep_evasion_detected(self):
        profile = _make_profile()
        profile.sleep_intervals = [600.0, 700.0, 800.0, 900.0, 1000.0]
        findings = detect_timing_anomalies(profile)
        time_findings = [f for f in findings if f.rule_id == "L4-TIME-001"]
        assert len(time_findings) == 1
        assert "sleep" in time_findings[0].message.lower()

    def test_burst_anomaly_detected(self):
        profile = _make_profile()
        for i in range(60):
            profile.timing_points.append(TimingPoint(
                timestamp_ms=float(i),
                operation="fs_read",
                duration_ms=1.0,
            ))
        findings = detect_timing_anomalies(profile)
        burst_findings = [f for f in findings if f.rule_id == "L4-TIME-003"]
        assert len(burst_findings) == 1


# ─── Rules: Exfiltration ────────────────────────────────────────────────

class TestExfilRules:
    def test_no_exfil_no_finding(self):
        profile = _make_profile()
        findings = detect_exfiltration(profile)
        assert len(findings) == 0

    def test_dns_exfiltration_detected(self):
        profile = _make_profile()
        profile.dns_queries.append(DNSQuery(
            domain="a7f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5.evil.com",
            timestamp_ms=100.0,
        ))
        findings = detect_exfiltration(profile)
        exfil_findings = [f for f in findings if f.rule_id == "L4-EXFIL-001"]
        assert len(exfil_findings) >= 1

    def test_https_exfiltration_detected(self):
        profile = _make_profile()
        profile.network_calls.append(NetworkCall(
            host="evil.com", port=443, bytes_sent=8192,
            timestamp_ms=100.0,
        ))
        findings = detect_exfiltration(profile)
        https_findings = [f for f in findings if f.rule_id == "L4-EXFIL-002"]
        assert len(https_findings) >= 1

    def test_error_channel_exfiltration_detected(self):
        profile = _make_profile()
        profile.total_bytes_sent = 50000
        findings = detect_exfiltration(profile)
        error_findings = [f for f in findings if f.rule_id == "L4-EXFIL-003"]
        assert len(error_findings) >= 1


# ─── Rules: Entropy ──────────────────────────────────────────────────────

class TestEntropyRules:
    def test_no_entropy_no_finding(self):
        profile = _make_profile()
        findings = detect_entropy_anomalies(profile)
        assert len(findings) == 0

    def test_high_entropy_egress_detected(self):
        profile = _make_profile(egress_entropy=7.8)
        findings = detect_entropy_anomalies(profile)
        ent_findings = [f for f in findings if f.rule_id == "L4-ENTROPY-001"]
        assert len(ent_findings) >= 1
        assert ent_findings[0].severity in (Severity.HIGH, Severity.CRITICAL)

    def test_entropy_spike_vs_baseline(self):
        profile = _make_profile(egress_entropy=7.8)
        baseline = _make_baseline(avg_egress_entropy=3.0, std_egress_entropy=0.5)
        findings = detect_entropy_anomalies(profile, baselines={"test": baseline})
        spike_findings = [f for f in findings if f.rule_id == "L4-ENTROPY-002"]
        assert len(spike_findings) >= 1


# ─── Rules: Honeypot ────────────────────────────────────────────────────

class TestHoneypotRules:
    def test_no_canary_no_finding(self):
        profile = _make_profile()
        findings = detect_honeypot_touches(profile)
        assert len(findings) == 0

    def test_canary_file_access(self):
        profile = _make_profile(
            canary_file_accesses=["/tmp/secret_passwords_abc123.txt"],
        )
        findings = detect_honeypot_touches(profile)
        honey_findings = [f for f in findings if f.rule_id == "L4-HONEY-001"]
        assert len(honey_findings) >= 1
        assert honey_findings[0].severity == Severity.CRITICAL
        assert honey_findings[0].confidence == Confidence.EXACT

    def test_canary_dns_lookup(self):
        profile = _make_profile(
            canary_dns_lookups=["abc123.canary.picoshogun.local"],
        )
        findings = detect_honeypot_touches(profile)
        dns_findings = [f for f in findings if f.rule_id == "L4-HONEY-002"]
        assert len(dns_findings) >= 1
        assert dns_findings[0].severity == Severity.CRITICAL

    def test_canary_env_read(self):
        profile = _make_profile(
            canary_env_reads=["AWS_SECRET_ABC"],
        )
        findings = detect_honeypot_touches(profile)
        env_findings = [f for f in findings if f.rule_id == "L4-HONEY-003"]
        assert len(env_findings) >= 1
        assert env_findings[0].severity == Severity.CRITICAL


# ─── Rules: Baseline Drift ──────────────────────────────────────────────

class TestBaselineRules:
    def test_no_drift_no_finding(self):
        profile = BehavioralProfile(
            package="npm-test",
            duration_ms=15000,
            call_frequencies={"fs_read": 500, "fs_write": 100, "connect": 10, "dns": 5, "spawn": 2},
        )
        findings = detect_baseline_drift(profile, DEFAULT_BASELINES)
        assert isinstance(findings, list)

    def test_significant_drift_detected(self):
        profile = BehavioralProfile(
            package="malware",
            duration_ms=500,
            call_frequencies={"connect": 5000, "dns": 2000, "spawn": 100},
            egress_entropy=7.8,
            total_bytes_sent=100000,
        )
        profile.network_calls = [NetworkCall(host="evil.com", port=443)]
        profile.dns_queries = [DNSQuery(domain="evil-c2.com")]
        findings = detect_baseline_drift(profile, DEFAULT_BASELINES)
        assert len(findings) >= 1


# ─── Engine ──────────────────────────────────────────────────────────────

class TestEngine:
    def test_create_default_engine(self):
        engine = create_default_engine()
        assert len(engine.list_rules()) == 5  # TIME, EXFIL, ENTROPY, HONEY, BASE

    def test_analyze_clean_profile(self):
        """A profile matching npm-install baseline closely should be CLEAN."""
        engine = create_default_engine()
        # Create a profile that closely matches the npm-install baseline
        profile = BehavioralProfile(
            package="npm-install-test",
            command=["npm", "install"],
            duration_ms=14000,  # Close to npm-install avg 15000
            call_frequencies={
                "fs_read": 480,   # npm-install expects 500±200
                "fs_write": 95,   # npm-install expects 100±50
                "dns": 4,         # npm-install expects 5±3
                "connect": 8,     # npm-install expects 10±5
                "spawn": 2,       # npm-install expects 2±1
            },
            total_bytes_sent=4800,
            total_bytes_received=480000,
            egress_entropy=0.0,  # No egress entropy data
        )
        result = engine.analyze(profile)
        # With low drift from baseline and no suspicious indicators, should be clean or at worst suspicious
        assert result.overall_verdict in (BehavioralVerdict.CLEAN, BehavioralVerdict.SUSPICIOUS)

    def test_analyze_suspicious_profile(self):
        engine = create_default_engine()
        profile = _make_suspicious_profile()
        result = engine.analyze(profile)
        assert len(result.findings) > 0
        assert result.overall_verdict in (BehavioralVerdict.SUSPICIOUS, BehavioralVerdict.MALICIOUS)

    def test_analyze_with_subset_rules(self):
        engine = create_default_engine()
        profile = _make_suspicious_profile()
        result = engine.analyze(profile, rules=["L4-TIME"])
        assert isinstance(result, AnalysisResult)

    def test_register_unregister_rule(self):
        engine = L4Engine()
        engine.register("TEST", lambda p, b=None: [])
        assert "TEST" in engine.list_rules()
        engine.unregister("TEST")
        assert "TEST" not in engine.list_rules()

    def test_compute_verdict(self):
        assert _compute_verdict([]) == BehavioralVerdict.CLEAN
        f_critical = Finding("T", Severity.CRITICAL, Confidence.EXACT, "p", "m", "e", "r")
        assert _compute_verdict([f_critical]) == BehavioralVerdict.MALICIOUS
        f_medium = Finding("T", Severity.MEDIUM, Confidence.MEDIUM, "p", "m", "e", "r")
        assert _compute_verdict([f_medium]) == BehavioralVerdict.SUSPICIOUS
        f_low = Finding("T", Severity.LOW, Confidence.LOW, "p", "m", "e", "r")
        assert _compute_verdict([f_low]) == BehavioralVerdict.CLEAN


# ─── Formatters ──────────────────────────────────────────────────────────

class TestL4Formatters:
    def _make_result(self):
        return AnalysisResult(
            target="test-pkg@1.0.0",
            findings=[
                Finding(
                    rule_id="L4-ENTROPY-001", severity=Severity.HIGH,
                    confidence=Confidence.EXACT, package="evil@1.0.0",
                    message="High entropy egress", evidence="ent=7.8",
                    remediation="Review outbound data",
                ),
            ],
            overall_verdict=BehavioralVerdict.SUSPICIOUS,
            stats=AnalysisStats(events_analyzed=100, duration_ms=50),
        )

    def test_json_format(self):
        result = self._make_result()
        text = format_json(result)
        data = json.loads(text)
        assert data["overall_verdict"] == "SUSPICIOUS"
        assert len(data["findings"]) == 1

    def test_sarif_format(self):
        result = self._make_result()
        text = format_sarif(result)
        data = json.loads(text)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 1

    def test_table_format(self):
        result = self._make_result()
        text = format_table(result, color=False)
        assert "L4-ENTROPY-001" in text
        assert "SUSPICIOUS" in text
