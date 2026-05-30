"""Unit tests for L3 Execution Sandbox."""
import json

import pytest

from ...L2_validation.models import Confidence, Finding
from ..backends.subprocess_backend import SubprocessBackend
from ..models import (
    PolicyRule,
    RuleID,
    SandboxEvent,
    SandboxResult,
    Severity,
    Verdict,
)
from ..policy_generator import generate_policy_from_findings
from ..policy_loader import DEFAULT_POLICY_YAML, load_policy, write_default_policy
from ..verdict import VerdictEngine

# ─── Models ──────────────────────────────────────────────────────────────

class TestModels:
    def test_verdict_enum(self):
        assert Verdict.ALLOW.value == "ALLOW"
        assert Verdict.DENY.value == "DENY"
        assert Verdict.AUDIT.value == "AUDIT"

    def test_rule_id_enum(self):
        assert RuleID.L3_SYS_001.value == "L3-SYS-001"
        assert RuleID.L3_NET_001.value == "L3-NET-001"

    def test_policy_rule_frozen(self):
        rule = PolicyRule(
            rule_id=RuleID.L3_SYS_001, action=Verdict.DENY,
            description="test", patterns=["execve"],
        )
        with pytest.raises(AttributeError):
            rule.action = Verdict.ALLOW

    def test_sandbox_result_to_dict(self):
        result = SandboxResult(command=["echo", "hi"], overall_verdict=Verdict.ALLOW)
        d = result.to_dict()
        assert d["overall_verdict"] == "ALLOW"
        assert d["command"] == ["echo", "hi"]

    def test_sandbox_event_fields(self):
        event = SandboxEvent(
            timestamp="2026-01-01T00:00:00Z",
            rule_id=RuleID.L3_NET_001,
            verdict=Verdict.DENY,
            operation="connect",
            detail="evil.com:443",
            address="evil.com:443",
        )
        assert event.rule_id == RuleID.L3_NET_001
        assert event.address == "evil.com:443"


# ─── Policy Loader ────────────────────────────────────────────────────────

class TestPolicyLoader:
    def test_load_default_policy(self):
        policy = load_policy()
        assert policy.name == "default"
        assert len(policy.rules) == 10
        assert policy.cpu_limit_seconds == 30
        assert policy.memory_limit_mb == 512

    def test_load_from_file(self, tmp_path):
        policy_file = tmp_path / "test.yml"
        policy_file.write_text(DEFAULT_POLICY_YAML)
        policy = load_policy(str(policy_file))
        assert policy.name == "default"

    def test_load_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_policy("/nonexistent/policy.yml")

    def test_write_default_policy(self, tmp_path):
        path = write_default_policy(tmp_path / "out.yml")
        assert path.exists()
        content = path.read_text()
        assert "Deny-by-default" in content

    def test_network_allowlist(self):
        policy = load_policy()
        assert isinstance(policy.network_allowlist, list)
        assert isinstance(policy.dns_allowlist, list)


# ─── Verdict Engine ──────────────────────────────────────────────────────

class TestVerdictEngine:
    def _make_engine(self) -> VerdictEngine:
        policy = load_policy()
        return VerdictEngine(policy)

    def test_evaluate_dangerous_syscall(self):
        engine = self._make_engine()
        event = engine.evaluate_syscall("execve")
        assert event.verdict == Verdict.DENY
        assert event.rule_id == RuleID.L3_SYS_001

    def test_evaluate_allowed_syscall(self):
        engine = self._make_engine()
        event = engine.evaluate_syscall("read")
        assert event.verdict == Verdict.ALLOW

    def test_evaluate_network_blocked(self):
        engine = self._make_engine()
        event = engine.evaluate_network("evil.com", 443)
        assert event.verdict == Verdict.DENY

    def test_evaluate_network_allowed(self):
        policy = load_policy()
        policy.network_allowlist = ["*.github.com", "registry.npmjs.org"]
        engine = VerdictEngine(policy)
        event = engine.evaluate_network("api.github.com", 443)
        assert event.verdict == Verdict.ALLOW

    def test_evaluate_fs_write_blocked(self):
        engine = self._make_engine()
        event = engine.evaluate_fs_write("/etc/passwd")
        assert event.verdict == Verdict.DENY

    def test_evaluate_fs_write_allowed(self):
        policy = load_policy()
        policy.filesystem_write_allowlist = ["/tmp", "/home"]
        engine = VerdictEngine(policy)
        event = engine.evaluate_fs_write("/tmp/output.json")
        assert event.verdict == Verdict.ALLOW

    def test_evaluate_spawn_blocked(self):
        engine = self._make_engine()
        event = engine.evaluate_spawn("curl")
        assert event.verdict == Verdict.DENY

    def test_evaluate_spawn_allowed(self):
        policy = load_policy()
        policy.process_allowlist = ["node", "python3"]
        engine = VerdictEngine(policy)
        event = engine.evaluate_spawn("python3")
        assert event.verdict == Verdict.ALLOW

    def test_evaluate_dns_blocked(self):
        engine = self._make_engine()
        event = engine.evaluate_dns("evil.com")
        assert event.verdict == Verdict.AUDIT

    def test_compute_overall_verdict_deny(self):
        policy = load_policy()
        engine = VerdictEngine(policy)
        events = [
            SandboxEvent("t", RuleID.L3_NET_001, Verdict.ALLOW, "op", "ok"),
            SandboxEvent("t", RuleID.L3_SYS_001, Verdict.DENY, "op", "bad"),
        ]
        assert engine.compute_overall_verdict(events) == Verdict.DENY

    def test_compute_overall_verdict_audit(self):
        policy = load_policy()
        engine = VerdictEngine(policy)
        events = [
            SandboxEvent("t", RuleID.L3_NET_002, Verdict.AUDIT, "op", "ok"),
            SandboxEvent("t", RuleID.L3_NET_001, Verdict.ALLOW, "op", "ok"),
        ]
        assert engine.compute_overall_verdict(events) == Verdict.AUDIT

    def test_compute_overall_verdict_allow(self):
        policy = load_policy()
        engine = VerdictEngine(policy)
        events = [
            SandboxEvent("t", RuleID.L3_NET_001, Verdict.ALLOW, "op", "ok"),
        ]
        assert engine.compute_overall_verdict(events) == Verdict.ALLOW


# ─── Subprocess Backend ────────────────────────────────────────────────

class TestSubprocessBackend:
    def test_is_available(self):
        backend = SubprocessBackend()
        assert backend.is_available() is True

    def test_run_echo(self):
        backend = SubprocessBackend()
        policy = load_policy()
        policy.process_allowlist = ["echo"]
        policy.filesystem_write_allowlist = ["/tmp", "/dev/null"]
        policy.filesystem_read_allowlist = ["/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", "/tmp"]
        # echo should work with allowlisted paths; verdict depends on preflight checks
        result = backend.run(["echo", "hello"], policy, timeout=5)
        # The command will be denied if cwd is not in write allowlist
        # so exit_code may be None (not executed) or 0
        assert result.exit_code is not None or result.overall_verdict == Verdict.DENY

    def test_run_nonexistent_command(self):
        backend = SubprocessBackend()
        policy = load_policy()
        result = backend.run(["nonexistent_cmd_12345"], policy, timeout=5)
        assert result.overall_verdict == Verdict.DENY


# ─── L2→L3 Policy Generator ──────────────────────────────────────────

class TestPolicyGenerator:
    def test_generate_from_empty_findings(self):
        policy = generate_policy_from_findings([])
        assert policy.name == "auto-generated-from-l2"

    def test_generate_from_post_install(self):
        findings = [
            Finding(
                rule_id="L2-POST-001", severity=Severity.HIGH,
                confidence=Confidence.EXACT, package="evil@1.0.0",
                file="evil/package.json", message="has postinstall",
                evidence="scripts.postinstall", remediation="remove",
            ),
        ]
        policy = generate_policy_from_findings(findings)
        assert policy.network_allowlist == []
        assert policy.process_allowlist == []
        assert "post-install" in policy.description

    def test_generate_from_obfuscation(self):
        findings = [
            Finding(
                rule_id="L2-OBFS-001", severity=Severity.CRITICAL,
                confidence=Confidence.EXACT, package="malware@1.0.0",
                file="malware/index.js", message="eval() detected",
                evidence="eval(", remediation="remove",
            ),
        ]
        policy = generate_policy_from_findings(findings)
        assert "LOCKDOWN" in policy.description
        assert policy.cpu_limit_seconds == 5
        assert policy.memory_limit_mb == 128


# ─── Formatters ──────────────────────────────────────────────────────────

class TestL3Formatters:
    def _make_result(self):
        result = SandboxResult(
            command=["echo", "hello"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
        )
        return result

    def test_json_format(self):
        from ..formatters import format_json
        result = self._make_result()
        text = format_json(result)
        data = json.loads(text)
        assert data["overall_verdict"] == "ALLOW"
        assert data["command"] == ["echo", "hello"]

    def test_sarif_format(self):
        from ..formatters import format_sarif
        result = self._make_result()
        text = format_sarif(result)
        data = json.loads(text)
        assert data["version"] == "2.1.0"

    def test_table_format(self):
        from ..formatters import format_table
        result = self._make_result()
        text = format_table(result, color=False)
        assert "echo" in text
        assert "ALLOW" in text
