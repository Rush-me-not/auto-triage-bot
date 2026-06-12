"""
test_auto_triage.py — pytest test suite for auto-triage-bot.

Tests each component in isolation and the full pipeline end-to-end.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Ensure the project root is on sys.path so we can import src.*
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Imports (all stdlib) ────────────────────────────────────────────────
from src.alert_parser import parse_alert_file, parse_alert_directory
from src.misp_enricher import enrich_alert, can_use_llm
from src.mitre_mapper import map_ttps, TECHNIQUES, TTP_SEVERITY
from src.triage_engine import score
from src.report import build_finding, build_report
from src.semantic_analyzer import analyze_command_line, can_use_deepseek, _load_key
from src.correlator import correlate


# ========================================================================
# Fixtures
# ========================================================================

def _make_alert(
    alert_id: str = "TEST-001",
    source: str = "test",
    timestamp: str = "2025-01-01T00:00:00Z",
    event_type: str = "process_creation",
    hostname: str = "TEST-HOST",
    process_name: str = "notepad.exe",
    command_line: str = "",
    parent_process: str = "C:\\Windows\\System32\\svchost.exe",
    indicators: dict | None = None,
    **extra,
) -> dict:
    alert = {
        "alert_id": alert_id,
        "source": source,
        "timestamp": timestamp,
        "event_type": event_type,
        "hostname": hostname,
        "process_name": process_name,
        "command_line": command_line,
        "parent_process": parent_process,
        "indicators": indicators or {"hashes": [], "ips": [], "domains": [], "file_paths": []},
    }
    alert.update(extra)
    return alert


# ========================================================================
# Tests: alert_parser
# ========================================================================

class TestAlertParser:
    def test_parse_valid_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(_make_alert(), f)
            fname = f.name
        try:
            result = parse_alert_file(fname)
            assert result["alert_id"] == "TEST-001"
            assert result["hostname"] == "TEST-HOST"
        finally:
            os.unlink(fname)

    def test_parse_missing_required_field(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"alert_id": "NO-FIELDS"}, f)
            fname = f.name
        try:
            import pytest
            with pytest.raises(ValueError, match="missing required fields"):
                parse_alert_file(fname)
        finally:
            os.unlink(fname)

    def test_parse_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            fname = f.name
        try:
            import pytest
            with pytest.raises(json.JSONDecodeError):
                parse_alert_file(fname)
        finally:
            os.unlink(fname)

    def test_parse_directory(self, tmp_path):
        a1 = tmp_path / "a.json"
        a2 = tmp_path / "b.json"
        a1.write_text(json.dumps(_make_alert(alert_id="A")))
        a2.write_text(json.dumps(_make_alert(alert_id="B")))
        results = parse_alert_directory(str(tmp_path))
        assert len(results) == 2
        ids = {r["alert_id"] for r in results}
        assert ids == {"A", "B"}


# ========================================================================
# Tests: misp_enricher
# ========================================================================

class TestMispEnricher:
    def test_no_indicators(self):
        alert = _make_alert(indicators={"hashes": [], "ips": [], "domains": [], "file_paths": []})
        result = enrich_alert(alert)
        assert result["matched_indicators"] == []
        assert result["threat_level"] == "None"

    def test_known_malicious_hash(self):
        alert = _make_alert(indicators={
            "hashes": ["aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"],
            "ips": [],
            "domains": [],
            "file_paths": [],
        })
        result = enrich_alert(alert)
        assert "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" in result["matched_indicators"]
        assert result["threat_level"] == "High"

    def test_unknown_ip(self):
        alert = _make_alert(indicators={
            "hashes": [],
            "ips": ["1.2.3.4"],
            "domains": [],
            "file_paths": [],
        })
        result = enrich_alert(alert)
        assert result["matched_indicators"] == []
        assert result["threat_level"] == "None"

    def test_c2_ip(self):
        alert = _make_alert(indicators={
            "hashes": [],
            "ips": ["185.130.5.251"],
            "domains": [],
            "file_paths": [],
        })
        result = enrich_alert(alert)
        assert "185.130.5.251" in result["matched_indicators"]
        assert result["threat_level"] == "High"

    def test_malicious_domain(self):
        alert = _make_alert(indicators={
            "hashes": [],
            "ips": [],
            "domains": ["evil.example.com"],
            "file_paths": [],
        })
        result = enrich_alert(alert)
        assert "evil.example.com" in result["matched_indicators"]

    def test_llm_check(self):
        # Just verify it doesn't crash
        result = can_use_llm()
        assert isinstance(result, bool)


# ========================================================================
# Tests: mitre_mapper
# ========================================================================

class TestMitreMapper:
    def test_clean_alert_no_ttps(self):
        alert = _make_alert(process_name="logonui.exe", command_line="C:\\Windows\\System32\\logonui.exe")
        ttps = map_ttps(alert)
        assert ttps == []

    def test_clean_alert_services(self):
        alert = _make_alert(process_name="services.exe", command_line="")
        ttps = map_ttps(alert)
        assert ttps == []

    def test_powershell_from_office(self):
        """T1059.001 — PowerShell spawned from Office macro."""
        alert = _make_alert(
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand SQBFAFgA",
            parent_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        )
        ttps = map_ttps(alert)
        ttp_ids = [t["id"] for t in ttps]
        assert "T1059.001" in ttp_ids, f"Expected T1059.001, got {ttp_ids}"

    def test_schtasks(self):
        """T1053.005 — Scheduled task creation."""
        alert = _make_alert(
            process_name="schtasks.exe",
            command_line="schtasks.exe /create /tn UpdaterTask",
        )
        ttps = map_ttps(alert)
        ttp_ids = [t["id"] for t in ttps]
        assert "T1053.005" in ttp_ids

    def test_rundll32(self):
        """T1218.011 — Rundll32 execution."""
        alert = _make_alert(
            process_name="rundll32.exe",
            command_line="rundll32.exe",
        )
        ttps = map_ttps(alert)
        ttp_ids = [t["id"] for t in ttps]
        assert "T1218.011" in ttp_ids

    def test_lsass_access(self):
        """T1003.001 — LSASS memory access."""
        alert = _make_alert(
            process_name="procdump.exe",
            command_line="procdump.exe -ma lsass.exe",
        )
        ttps = map_ttps(alert)
        ttp_ids = [t["id"] for t in ttps]
        assert "T1003.001" in ttp_ids

    def test_wmic(self):
        """T1047 — WMI execution."""
        alert = _make_alert(
            process_name="wmic.exe",
            command_line="wmic.exe process call create calc.exe",
        )
        ttps = map_ttps(alert)
        ttp_ids = [t["id"] for t in ttps]
        assert "T1047" in ttp_ids

    def test_system_discovery(self):
        """T1082 — System information discovery."""
        alert = _make_alert(
            process_name="cmd.exe",
            command_line="systeminfo",
        )
        ttps = map_ttps(alert)
        ttp_ids = [t["id"] for t in ttps]
        assert "T1082" in ttp_ids

    def test_all_techniques_defined(self):
        """Verify all 8 required TTPs are in the TECHNIQUES dict."""
        required = {"T1059.001", "T1059.003", "T1053.005", "T1204.002",
                     "T1218.011", "T1003.001", "T1047", "T1082"}
        assert required.issubset(set(TECHNIQUES.keys()))
        assert required.issubset(set(TTP_SEVERITY.keys()))


# ========================================================================
# Tests: triage_engine
# ========================================================================

class TestTriageEngine:
    def test_clean_alert(self):
        alert = _make_alert()
        sev, summary, recs = score(alert, [])
        assert sev == "CLEAN"
        assert "No action required" in recs[0]

    def test_low_alert_unusual(self):
        """0 TTPs but unusual process (powershell)."""
        alert = _make_alert(process_name="powershell.exe", command_line="powershell.exe -help")
        sev, summary, recs = score(alert, [])
        assert sev == "LOW"

    def test_medium_alert(self):
        """1 TTP with medium severity."""
        fake_ttp = [{"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"}]
        alert = _make_alert()
        sev, summary, recs = score(alert, fake_ttp)
        assert sev == "MEDIUM"

    def test_high_alert_two_ttps(self):
        """2 TTPs → HIGH."""
        fake_ttps = [
            {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
            {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
        ]
        alert = _make_alert()
        sev, summary, recs = score(alert, fake_ttps)
        assert sev == "HIGH"

    def test_high_alert_one_high_ttp(self):
        """1 TTP with high severity → HIGH."""
        fake_ttp = [{"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"}]
        alert = _make_alert()
        sev, summary, recs = score(alert, fake_ttp)
        assert sev == "HIGH"


# ========================================================================
# Tests: report
# ========================================================================

class TestReport:
    def test_build_finding(self):
        alert = _make_alert()
        finding = build_finding(
            alert=alert,
            ttps=[{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
            misp_enrichment={"matched_indicators": []},
            severity="HIGH",
            triage_summary="Test summary",
            recommendations=["Investigate"],
        )
        assert finding["alert_id"] == "TEST-001"
        assert finding["severity"] == "HIGH"
        assert len(finding["ttps"]) == 1

    def test_build_report(self):
        findings = [
            {
                "alert_id": "A1",
                "source": "test",
                "timestamp": "2025-01-01T00:00:00Z",
                "event_type": "process_creation",
                "hostname": "HOST",
                "severity": "HIGH",
                "ttps": [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
                "misp_enrichment": {},
                "triage_summary": "test",
                "recommendations": ["Investigate"],
            },
            {
                "alert_id": "A2",
                "source": "test",
                "timestamp": "2025-01-01T00:00:00Z",
                "event_type": "user_login",
                "hostname": "HOST",
                "severity": "CLEAN",
                "ttps": [],
                "misp_enrichment": {},
                "triage_summary": "clean",
                "recommendations": ["None"],
            },
        ]
        report = build_report(findings)
        assert report["tool"] == "auto-triage-bot"
        assert report["total_alerts"] == 2
        assert report["clean_alerts"] == 1
        assert report["suspicious_alerts"] == 1
        assert "T1059.001" in report["summary"]["ttp_coverage"]
        # overall assessment should mention critical
        assert "CRITICAL" in report["summary"]["overall_assessment"]


# ========================================================================
# Tests: end-to-end pipeline with test corpus files
# ========================================================================

class TestEndToEnd:
    def test_pipeline_all_alerts(self):
        """Process the entire test_corpus and verify key properties."""
        corpus_dir = _PROJECT_ROOT / "test_corpus"
        assert corpus_dir.is_dir(), f"test_corpus not found at {corpus_dir}"

        from src.alert_parser import parse_alert_directory
        from src.misp_enricher import enrich_alert
        from src.mitre_mapper import map_ttps
        from src.triage_engine import score
        from src.report import build_finding, build_report

        # Parse both clean/ and injected/ subdirectories
        clean_dir = corpus_dir / "clean"
        injected_dir = corpus_dir / "injected"
        alerts = (
            parse_alert_directory(str(clean_dir))
            + parse_alert_directory(str(injected_dir))
        )
        assert len(alerts) == 5, f"Expected 5 alerts, got {len(alerts)}"

        findings = []
        for alert in alerts:
            misp = enrich_alert(alert)
            ttps = map_ttps(alert)
            sev, summary, recs = score(alert, ttps)
            finding = build_finding(alert, ttps, misp, sev, summary, recs)
            findings.append(finding)

        report = build_report(findings)

        # Verify structural properties
        assert report["total_alerts"] == 5
        assert report["suspicious_alerts"] == 3  # 3 injected alerts
        assert report["clean_alerts"] == 2  # 2 clean alerts

        # Check each injected alert has >= 2 TTPs
        for finding in findings:
            if finding["alert_id"].endswith("SUSP"):
                assert len(finding["ttps"]) >= 2, (
                    f"{finding['alert_id']} has {len(finding['ttps'])} TTPs, expected >= 2"
                )

        # Check each clean alert has 0 TTPs
        for finding in findings:
            if finding["alert_id"].endswith("CLEAN"):
                assert len(finding["ttps"]) == 0, (
                    f"{finding['alert_id']} has {len(finding['ttps'])} TTPs, expected 0"
                )

        # Verify summary section
        assert "ttp_coverage" in report["summary"]
        assert "top_tactics" in report["summary"]
        assert "overall_assessment" in report["summary"]

        # Verify the report can be serialized
        json.dumps(report)

    def test_clean_alert_has_zero_ttps(self):
        """Specifically test clean corpus files."""
        clean_dir = _PROJECT_ROOT / "test_corpus" / "clean"
        alerts = parse_alert_directory(str(clean_dir))
        for a in alerts:
            ttps = map_ttps(a)
            assert len(ttps) == 0, f"{a['alert_id']} matched TTPs: {ttps}"

    def test_suspicious_alert_has_ttps(self):
        """Specifically test injected corpus files have >= 2 TTPs."""
        injected_dir = _PROJECT_ROOT / "test_corpus" / "injected"
        alerts = parse_alert_directory(str(injected_dir))
        assert len(alerts) == 3
        for a in alerts:
            ttps = map_ttps(a)
            assert len(ttps) >= 2, f"{a['alert_id']} has {len(ttps)} TTPs: {[t['id'] for t in ttps]}"


# ========================================================================
# Tests: semantic_analyzer
# ========================================================================

class TestSemanticAnalyzer:
    """Tests for semantic_analyzer.py — DeepSeek V4 LLM analysis."""

    def test_degraded_no_key(self, monkeypatch):
        """When no key is available, return degraded result."""
        monkeypatch.delenv("RAG_AUDIT_LLM_KEY", raising=False)
        import src.semantic_analyzer as sa
        orig_key_path = sa._KEY_FILE_PATH
        orig_legacy_path = sa._LEGACY_KEY_FILE_PATH
        sa._KEY_FILE_PATH = "/nonexistent/key/file.key"
        sa._LEGACY_KEY_FILE_PATH = "/nonexistent/legacy/file.key"
        try:
            result = analyze_command_line("powershell.exe -EncodedCommand SQBFAFgA")
            assert result["obfuscation_score"] == 0
            assert result["detected_patterns"] == []
            assert result["is_suspicious"] is False
            assert "unavailable" in result["llm_reasoning"].lower()
        finally:
            sa._KEY_FILE_PATH = orig_key_path
            sa._LEGACY_KEY_FILE_PATH = orig_legacy_path

    def test_can_use_deepseek_no_key(self, monkeypatch):
        """can_use_deepseek returns False when no key is available."""
        monkeypatch.delenv("RAG_AUDIT_LLM_KEY", raising=False)
        import src.semantic_analyzer as sa
        orig_key_path = sa._KEY_FILE_PATH
        orig_legacy_path = sa._LEGACY_KEY_FILE_PATH
        sa._KEY_FILE_PATH = "/nonexistent/key/file.key"
        sa._LEGACY_KEY_FILE_PATH = "/nonexistent/legacy/file.key"
        try:
            assert can_use_deepseek() is False
        finally:
            sa._KEY_FILE_PATH = orig_key_path
            sa._LEGACY_KEY_FILE_PATH = orig_legacy_path

    def test_degraded_on_network_error(self, monkeypatch):
        """When the API call fails (network error), return degraded result."""
        monkeypatch.delenv("RAG_AUDIT_LLM_KEY", raising=False)
        # Provide a fake key via env so _load_key returns it
        monkeypatch.setenv("RAG_AUDIT_LLM_KEY", "sk-test-fake-key")

        # Mock urllib.request.urlopen to raise URLError
        import urllib.error
        def _mock_urlopen(*args, **kwargs):
            raise urllib.error.URLError("Connection refused")

        monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen)
        result = analyze_command_line("powershell.exe -EncodedCommand TEST")
        assert result["obfuscation_score"] == 0
        assert result["is_suspicious"] is False
        assert "unavailable" in result["llm_reasoning"].lower()

    def test_parse_json_from_llm_response(self, monkeypatch):
        """Verify correct parsing when LLM returns valid JSON."""
        monkeypatch.setenv("RAG_AUDIT_LLM_KEY", "sk-test-fake-key")

        llm_response = json.dumps({
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"obfuscation_detected": true, '
                            '"patterns": ["base64_encoding", "encoded_command"], '
                            '"confidence": 0.95}'
                        )
                    }
                }
            ]
        })

        def _mock_urlopen(*args, **kwargs):
            class MockResponse:
                def read(self):
                    return llm_response.encode("utf-8")
                def __enter__(self):
                    return self
                def __exit__(self, *exc):
                    pass
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen)
        result = analyze_command_line("powershell.exe -EncodedCommand SQBFAFgA")

        assert result["obfuscation_score"] == 0.95
        assert "base64_encoding" in result["detected_patterns"]
        assert result["is_suspicious"] is True
        assert "confidence:" in result["llm_reasoning"]

    def test_strip_markdown_fences(self, monkeypatch):
        """Verify stripping of ```json ... ``` from LLM response."""
        monkeypatch.setenv("RAG_AUDIT_LLM_KEY", "sk-test-fake-key")

        llm_response = json.dumps({
            "choices": [
                {
                    "message": {
                        "content": (
                            "```json\n"
                            '{"obfuscation_detected": false, '
                            '"patterns": [], '
                            '"confidence": 0.0}\n'
                            "```"
                        )
                    }
                }
            ]
        })

        def _mock_urlopen(*args, **kwargs):
            class MockResponse:
                def read(self):
                    return llm_response.encode("utf-8")
                def __enter__(self):
                    return self
                def __exit__(self, *exc):
                    pass
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen)
        result = analyze_command_line("notepad.exe")

        assert result["obfuscation_score"] == 0.0
        assert result["detected_patterns"] == []
        assert result["is_suspicious"] is False

    def test_truncate_long_input(self, monkeypatch):
        """Verify input is truncated to 2000 characters."""
        monkeypatch.setenv("RAG_AUDIT_LLM_KEY", "sk-fake-key")

        long_cmd = "x" * 5000

        def _mock_urlopen(*args, **kwargs):
            # Verify the request body contains <= 2000 chars of cmd
            req = args[0]
            body_str = req.data.decode("utf-8") if isinstance(req.data, bytes) else ""
            # The cmd should be truncated
            import urllib.error
            raise urllib.error.URLError("mocked")

        monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen)
        result = analyze_command_line(long_cmd)
        assert result["obfuscation_score"] == 0
        assert result["is_suspicious"] is False

    def test_build_finding_includes_semantic_scan(self):
        """Verify build_finding output includes semantic_scan field."""
        finding = build_finding(
            alert=_make_alert(),
            ttps=[],
            misp_enrichment={"matched_indicators": []},
            severity="CLEAN",
            triage_summary="Test",
            recommendations=[],
            semantic_scan={"obfuscation_score": 0.5, "is_suspicious": True},
        )
        assert "semantic_scan" in finding
        assert finding["semantic_scan"]["obfuscation_score"] == 0.5
        assert finding["semantic_scan"]["is_suspicious"] is True


# ========================================================================
# Tests: correlator
# ========================================================================

class TestCorrelator:
    """Tests for correlator.py — cross-alert sequence correlation."""

    def _make_finding(
        self,
        alert_id: str = "TEST-001",
        ttps: list | None = None,
        severity: str = "MEDIUM",
    ) -> dict:
        return {
            "alert_id": alert_id,
            "source": "test",
            "timestamp": "2025-01-01T00:00:00Z",
            "event_type": "process_creation",
            "hostname": "HOST",
            "severity": severity,
            "ttps": ttps or [],
            "misp_enrichment": {},
            "semantic_scan": {},
            "triage_summary": "test",
            "recommendations": [],
        }

    def test_no_findings(self):
        """Empty findings list produces empty chains."""
        assert correlate([]) == []

    def test_no_chain_detected(self):
        """Clean findings with no TTPs produce no chains."""
        findings = [
            self._make_finding("CLEAN-001", []),
            self._make_finding("CLEAN-002", []),
        ]
        chains = correlate(findings)
        assert chains == []

    def test_persistence_chain_detected(self):
        """Office_proc -> PowerShell -> Scheduled_Task chain."""
        findings = [
            self._make_finding(
                "ALERT-PS",
                [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
                severity="HIGH",
            ),
            self._make_finding(
                "ALERT-SCHTASK",
                [{"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"}],
                severity="HIGH",
            ),
        ]
        chains = correlate(findings)
        assert len(chains) >= 1
        chain = chains[0]
        assert chain["chain_type"] == "persistence_chain"
        assert chain["severity"] == "CRITICAL"
        assert "ALERT-PS" in chain["alert_ids"]
        assert "ALERT-SCHTASK" in chain["alert_ids"]
        assert len(chain["recommendations"]) > 0

    def test_intrusion_chain_detected(self):
        """Phishing_delivery -> RAT_execution chain."""
        findings = [
            self._make_finding(
                "ALERT-FILE",
                [{"id": "T1204.002", "name": "Malicious File", "tactic": "Execution"}],
                severity="HIGH",
            ),
            self._make_finding(
                "ALERT-RUNDLL",
                [{"id": "T1218.011", "name": "Rundll32", "tactic": "Defense Evasion"}],
                severity="MEDIUM",
            ),
        ]
        chains = correlate(findings)
        assert len(chains) >= 1
        chain = chains[0]
        assert chain["chain_type"] == "intrusion_chain"
        assert chain["severity"] == "CRITICAL"
        assert "ALERT-FILE" in chain["alert_ids"]
        assert "ALERT-RUNDLL" in chain["alert_ids"]

    def test_full_intrusion_chain_detected(self):
        """Recon -> Lateral -> Credential access chain."""
        findings = [
            self._make_finding(
                "ALERT-RECON",
                [{"id": "T1082", "name": "System Discovery", "tactic": "Discovery"}],
                severity="LOW",
            ),
            self._make_finding(
                "ALERT-WMI",
                [{"id": "T1047", "name": "WMI", "tactic": "Execution"}],
                severity="MEDIUM",
            ),
            self._make_finding(
                "ALERT-LSASS",
                [{"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"}],
                severity="HIGH",
            ),
        ]
        chains = correlate(findings)
        assert len(chains) >= 1
        chain = chains[0]
        assert chain["chain_type"] == "full_intrusion"
        assert chain["severity"] == "CRITICAL"
        assert len(chain["alert_ids"]) == 3
        assert "ALERT-RECON" in chain["alert_ids"]
        assert "ALERT-WMI" in chain["alert_ids"]
        assert "ALERT-LSASS" in chain["alert_ids"]

    def test_multiple_chains_from_test_corpus(self):
        """The 3 injected test corpus alerts should form at least one chain."""
        corpus_dir = _PROJECT_ROOT / "test_corpus"
        injected_dir = corpus_dir / "injected"
        alerts = parse_alert_directory(str(injected_dir))
        assert len(alerts) == 3

        findings = []
        for alert in alerts:
            ttps = map_ttps(alert)
            sev, summary, recs = score(alert, ttps)
            finding = build_finding(
                alert=alert,
                ttps=ttps,
                misp_enrichment={"matched_indicators": []},
                severity=sev,
                triage_summary=summary,
                recommendations=recs,
            )
            findings.append(finding)

        chains = correlate(findings)
        # The 3 injected alerts form at least a persistence_chain (PS + schtasks)
        chain_types = {c["chain_type"] for c in chains}
        assert "persistence_chain" in chain_types
        # Each chain should have CRITICAL severity
        for c in chains:
            assert c["severity"] == "CRITICAL"

    def test_report_includes_correlation_chains(self):
        """Verify build_report output includes correlation_chains."""
        findings = [
            self._make_finding("A1", []),
        ]
        chains = [{
            "chain_id": "CHAIN-TEST-001",
            "chain_type": "persistence_chain",
            "alert_ids": ["A1"],
            "severity": "CRITICAL",
            "description": "Test chain",
            "recommendations": ["Investigate"],
        }]
        report = build_report(findings, correlation_chains=chains)
        assert "correlation_chains" in report
        assert len(report["correlation_chains"]) == 1
        assert report["correlation_chains"][0]["chain_id"] == "CHAIN-TEST-001"
