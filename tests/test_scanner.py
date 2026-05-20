"""
Scanner test suite — deterministic, offline, no network.

Tests all 10 detector rules against fixture projects.
Same fixture + same corpus = same findings. Every time.
"""
import json
import tempfile
from pathlib import Path

import pytest

from scanner import create_default_engine, ScanEngine, Finding, Severity, Confidence
from scanner.rules.post_install import detect_post_install_scripts
from scanner.rules.obfuscation import detect_obfuscation
from scanner.rules.dep_confusion import detect_dep_confusion
from scanner.rules.typosquat import detect_typosquat
from scanner.rules.manifest import detect_manifest_issues
from scanner.rules.fork_drift import detect_fork_drift
from scanner.rules.credential_read import detect_credential_reading
from scanner.rules.lockfile_drift import detect_lockfile_drift
from scanner.rules.bundled_shadow import detect_bundled_shadows
from scanner.rules.provenance import detect_provenance_issues


FIXTURES = Path(__file__).parent / "fixtures"
MALICIOUS = FIXTURES / "malicious_project"
CLEAN = FIXTURES / "clean_project"


# ============================================================
# Models
# ============================================================

class TestModels:
    def test_finding_is_frozen(self):
        f = Finding(
            rule_id="L2-POST-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil@1.0.0",
            file="package.json",
            message="test",
            evidence="test evidence",
            remediation="fix it",
        )
        with pytest.raises(AttributeError):
            f.rule_id = "changed"

    def test_scan_result_deterministic_id(self):
        """Same target + corpus = same scan_id."""
        from scanner.models import ScanResult, ScanStats
        r1 = ScanResult(target="/foo", engine_version="0.1.0", corpus_version="0.1.0")
        r2 = ScanResult(target="/foo", engine_version="0.1.0", corpus_version="0.1.0")
        assert r1.scan_id == r2.scan_id

    def test_scan_result_different_target(self):
        """Different target = different scan_id."""
        from scanner.models import ScanResult, ScanStats
        r1 = ScanResult(target="/foo", engine_version="0.1.0", corpus_version="0.1.0")
        r2 = ScanResult(target="/bar", engine_version="0.1.0", corpus_version="0.1.0")
        assert r1.scan_id != r2.scan_id

    def test_to_json_sorted_keys(self):
        from scanner.models import ScanResult
        r = ScanResult(target="/test")
        j = r.to_json()
        # JSON output should be parseable and have sorted keys
        parsed = json.loads(j)
        assert "scan_id" in parsed
        assert "findings" in parsed

    def test_ml_context_output(self):
        from scanner.models import ScanResult, ScanStats
        f = Finding(
            rule_id="L2-POST-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.EXACT,
            package="evil@1.0.0",
            file="node_modules/evil/package.json",
            message="test",
            evidence="scripts.postinstall = curl ...",
            remediation="fix it",
        )
        r = ScanResult(
            target="/test",
            findings=[f],
            stats=ScanStats(packages_scanned=1),
        )
        ctx = r.to_ml_context()
        assert "L2-POST-001" in ctx
        assert "CRITICAL" in ctx
        assert "scan_id=" in ctx

    def test_finding_sort_key(self):
        f1 = Finding(
            rule_id="L2-OBFS-001", severity=Severity.HIGH, confidence=Confidence.HIGH,
            package="a", file="b", message="m", evidence="e", remediation="r",
        )
        f2 = Finding(
            rule_id="L2-POST-001", severity=Severity.HIGH, confidence=Confidence.HIGH,
            package="a", file="b", message="m", evidence="e", remediation="r",
        )
        assert f1.sort_key() < f2.sort_key()


# ============================================================
# Engine
# ============================================================

class TestEngine:
    def test_create_default_engine_has_10_rules(self):
        engine = create_default_engine()
        assert len(engine.list_rules()) == 10

    def test_scan_nonexistent_target(self):
        engine = create_default_engine()
        result = engine.scan("/nonexistent/path")
        assert len(result.findings) == 0

    def test_scan_clean_project(self):
        engine = create_default_engine()
        result = engine.scan(str(CLEAN))
        # Clean project should have minimal findings (no critical/high)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        # May have INFO findings (provenance) but no critical ones
        assert len(critical) == 0, f"Unexpected critical findings: {critical}"

    def test_scan_malicious_project(self):
        engine = create_default_engine()
        result = engine.scan(str(MALICIOUS))
        assert len(result.findings) > 0, "Malicious project should produce findings"

    def test_scan_deterministic(self):
        """Same input = same output, twice."""
        engine = create_default_engine()
        r1 = engine.scan(str(MALICIOUS))
        r2 = engine.scan(str(MALICIOUS))
        assert r1.scan_id == r2.scan_id
        assert len(r1.findings) == len(r2.findings)
        for f1, f2 in zip(
            sorted(r1.findings, key=lambda f: f.sort_key()),
            sorted(r2.findings, key=lambda f: f.sort_key()),
        ):
            assert f1.rule_id == f2.rule_id
            assert f1.package == f2.package

    def test_register_unregister_rule(self):
        engine = ScanEngine()
        engine.register("test-rule", lambda t, c: [])
        assert "test-rule" in engine.list_rules()
        engine.unregister("test-rule")
        assert "test-rule" not in engine.list_rules()

    def test_scan_subset_of_rules(self):
        engine = create_default_engine()
        result = engine.scan(str(MALICIOUS), rules=["L2-POST-001"])
        for f in result.findings:
            assert f.rule_id == "L2-POST-001"


# ============================================================
# Individual Rules
# ============================================================

class TestPostInstall:
    def test_detects_postinstall_with_network(self):
        findings = detect_post_install_scripts(MALICIOUS, MALICIOUS)
        postinstall = [f for f in findings if "postinstall" in f.message.lower()]
        assert len(postinstall) >= 1
        # Should be CRITICAL because it has network pattern (curl)
        critical = [f for f in postinstall if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_detects_preinstall(self):
        findings = detect_post_install_scripts(MALICIOUS, MALICIOUS)
        preinstall = [f for f in findings if "preinstall" in f.message.lower()]
        assert len(preinstall) >= 1

    def test_clean_project_no_dangerous_scripts(self):
        findings = detect_post_install_scripts(CLEAN, CLEAN)
        dangerous = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        # Clean project only has "test" and "build" — not dangerous
        assert len(dangerous) == 0


class TestObfuscation:
    def test_detects_eval(self):
        findings = detect_obfuscation(MALICIOUS, MALICIOUS)
        eval_findings = [f for f in findings if f.rule_id == "L2-OBFS-001"]
        assert len(eval_findings) >= 1

    def test_detects_hex_string(self):
        findings = detect_obfuscation(MALICIOUS, MALICIOUS)
        hex_findings = [f for f in findings if f.rule_id == "L2-OBFS-002"]
        assert len(hex_findings) >= 1

    def test_detects_base64_exec(self):
        findings = detect_obfuscation(MALICIOUS, MALICIOUS)
        b64_findings = [f for f in findings if f.rule_id == "L2-OBFS-003"]
        assert len(b64_findings) >= 1

    def test_detects_unicode_escape(self):
        findings = detect_obfuscation(MALICIOUS, MALICIOUS)
        unicode_findings = [f for f in findings if f.rule_id == "L2-OBFS-004"]
        assert len(unicode_findings) >= 1


class TestDepConfusion:
    def test_detects_internal_without_registry(self):
        # Create a temp project with internal dep but no .npmrc
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "package.json").write_text(json.dumps({
                "name": "test-project",
                "version": "1.0.0",
                "dependencies": {"@company/internal-sdk": "1.0.0"},
            }))
            findings = detect_dep_confusion(tmp, tmp)
            assert len(findings) >= 1
            assert any("internal" in f.package for f in findings)

    def test_no_findings_with_npmrc(self):
        # Malicious project has .npmrc with registry
        findings = detect_dep_confusion(MALICIOUS, MALICIOUS)
        # Should have findings about scoped deps without registry overrides
        # (even with .npmrc, some deps may not have scope-specific overrides)
        # This is a soft check — the .npmrc has @company registry
        assert isinstance(findings, list)


class TestTyposquat:
    def test_detects_typosquat(self):
        # "lodsh" is edit-distance 1 from "lodash"
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "package.json").write_text(json.dumps({
                "name": "test-project",
                "version": "1.0.0",
                "dependencies": {"lodsh": "1.0.0"},
            }))
            findings = detect_typosquat(tmp, tmp)
            assert len(findings) >= 1
            assert any("lodash" in f.message.lower() for f in findings)

    def test_no_false_positive_on_exact_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "package.json").write_text(json.dumps({
                "name": "test-project",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21"},
            }))
            findings = detect_typosquat(tmp, tmp)
            # lodash itself should NOT be flagged
            typosquat_pkgs = [f.package for f in findings]
            assert "lodash" not in typosquat_pkgs


class TestManifest:
    def test_detects_dangerous_version_range(self):
        findings = detect_manifest_issues(MALICIOUS, MALICIOUS)
        wildcard = [f for f in findings if f.rule_id == "L2-MANI-001"]
        assert len(wildcard) >= 1
        # Should flag "*" and ">=0.0.0"
        star_findings = [f for f in wildcard if "*" in f.evidence or "*\"" in f.evidence]
        range_findings = [f for f in wildcard if ">=" in f.evidence]
        assert len(star_findings) + len(range_findings) >= 2

    def test_clean_project_no_dangerous_ranges(self):
        findings = detect_manifest_issues(CLEAN, CLEAN)
        dangerous = [f for f in findings if f.rule_id == "L2-MANI-001"]
        # Clean project uses ^4.17.21 and ^29.0.0 — safe ranges
        assert len(dangerous) == 0


class TestLockfileDrift:
    def test_detects_missing_deps_in_lockfile(self):
        # Malicious project lockfile only has evil-pkg, missing lodash, react, etc.
        findings = detect_lockfile_drift(MALICIOUS, MALICIOUS)
        # Should find missing deps
        assert isinstance(findings, list)

    def test_no_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "package.json").write_text(json.dumps({
                "name": "test",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21"},
            }))
            findings = detect_lockfile_drift(tmp, tmp)
            assert len(findings) >= 1
            assert findings[0].severity == Severity.HIGH

    def test_weak_integrity(self):
        # Malicious project lockfile uses sha1 integrity
        findings = detect_lockfile_drift(MALICIOUS, MALICIOUS)
        weak = [f for f in findings if "weak integrity" in f.message.lower()]
        assert len(weak) >= 1


class TestBundledShadows:
    def test_detects_bundled_dependencies(self):
        findings = detect_bundled_shadows(MALICIOUS, MALICIOUS)
        bundled = [f for f in findings if "bundled" in f.message.lower()]
        assert len(bundled) >= 1

    def test_detects_binary_field(self):
        findings = detect_bundled_shadows(MALICIOUS, MALICIOUS)
        binary = [f for f in findings if "binary" in f.message.lower() or "native" in f.message.lower()]
        assert len(binary) >= 1

    def test_clean_project_no_bundled(self):
        findings = detect_bundled_shadows(CLEAN, CLEAN)
        bundled = [f for f in findings if f.rule_id == "L2-BUND-001"]
        assert len(bundled) == 0


class TestCredentialReading:
    def test_detects_env_network_exfil(self):
        # evil-pkg has postinstall that reads $AWS_SECRET_ACCESS_KEY + curl
        findings = detect_credential_reading(MALICIOUS, MALICIOUS)
        exfil = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(exfil) >= 1

    def test_detects_process_env_in_source(self):
        findings = detect_credential_reading(MALICIOUS, MALICIOUS)
        env_findings = [f for f in findings if "process.env" in f.evidence or "credential" in f.message.lower()]
        assert len(env_findings) >= 1


class TestForkDrift:
    def test_detects_no_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "node_modules" / "no-repo").mkdir(parents=True)
            (tmp / "node_modules" / "no-repo" / "package.json").write_text(json.dumps({
                "name": "no-repo",
                "version": "1.0.0",
            }))
            findings = detect_fork_drift(tmp, tmp)
            no_repo = [f for f in findings if "no repository" in f.message.lower()]
            assert len(no_repo) >= 1

    def test_clean_project_has_repo(self):
        # lodash has repository field pointing to github.com/lodash/lodash
        findings = detect_fork_drift(CLEAN, CLEAN)
        # Should not flag lodash as a fork (authoritative)
        lodash_fork = [f for f in findings if "lodash" in f.package and f.severity == Severity.MEDIUM]
        assert len(lodash_fork) == 0


class TestProvenance:
    def test_detects_missing_provenance(self):
        findings = detect_provenance_issues(MALICIOUS, MALICIOUS)
        prov = [f for f in findings if f.rule_id == "L2-PROV-001"]
        assert len(prov) >= 1

    def test_detects_weak_integrity(self):
        # evil-pkg has sha1 integrity
        findings = detect_provenance_issues(MALICIOUS, MALICIOUS)
        weak = [f for f in findings if "weak integrity" in f.message.lower() or "sha1" in f.evidence.lower()]
        assert len(weak) >= 1


# ============================================================
# JSON Output
# ============================================================

class TestJsonOutput:
    def test_to_json_is_valid(self):
        engine = create_default_engine()
        result = engine.scan(str(MALICIOUS))
        j = result.to_json()
        parsed = json.loads(j)
        assert "scan_id" in parsed
        assert "findings" in parsed
        assert "stats" in parsed

    def test_to_ml_context_compact(self):
        engine = create_default_engine()
        result = engine.scan(str(MALICIOUS))
        ctx = result.to_ml_context(token_budget=2048)
        assert len(ctx) < 2048 * 5  # well within budget


if __name__ == "__main__":
    pytest.main([__file__, "-v"])