import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlator import compute_chain_confidence


class TestComputeChainConfidence:
    def test_high_confidence_chain(self):
        findings = [
            {
                "alert_id": "A1",
                "timestamp": "2025-01-01T00:00:00Z",
                "hostname": "HOST1",
                "ttps": [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
                "indicators": {"hashes": ["abc123"], "ips": ["1.2.3.4"], "domains": []},
                "severity": "HIGH",
            },
            {
                "alert_id": "A2",
                "timestamp": "2025-01-01T00:05:00Z",
                "hostname": "HOST1",
                "ttps": [{"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"}],
                "indicators": {"hashes": ["abc123"], "ips": [], "domains": ["evil.com"]},
                "severity": "HIGH",
            },
        ]
        chain_alert_ids = ["A1", "A2"]
        confidence = compute_chain_confidence(chain_alert_ids, findings)
        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.3  # overlapping IoC + high severity + close temporal

    def test_zero_confidence_no_ioc_overlap(self):
        findings = [
            {
                "alert_id": "A1",
                "timestamp": "2025-01-01T00:00:00Z",
                "hostname": "HOST1",
                "ttps": [{"id": "T1082", "name": "Discovery", "tactic": "Discovery"}],
                "indicators": {"hashes": ["hash_a"], "ips": ["1.1.1.1"], "domains": []},
                "severity": "LOW",
            },
            {
                "alert_id": "A2",
                "timestamp": "2025-06-01T00:00:00Z",
                "hostname": "HOST2",
                "ttps": [{"id": "T1047", "name": "WMI", "tactic": "Execution"}],
                "indicators": {"hashes": ["hash_b"], "ips": ["2.2.2.2"], "domains": []},
                "severity": "MEDIUM",
            },
        ]
        chain_alert_ids = ["A1", "A2"]
        confidence = compute_chain_confidence(chain_alert_ids, findings)
        assert confidence == 0.0  # no IoC overlap at all

    def test_temporal_decay(self):
        findings_close = [
            {
                "alert_id": "A1",
                "timestamp": "2025-01-01T00:00:00Z",
                "hostname": "HOST1",
                "ttps": [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
                "indicators": {"hashes": ["shared_hash"], "ips": ["1.2.3.4"], "domains": []},
                "severity": "HIGH",
            },
            {
                "alert_id": "A2",
                "timestamp": "2025-01-01T00:02:00Z",
                "hostname": "HOST1",
                "ttps": [{"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"}],
                "indicators": {"hashes": ["shared_hash"], "ips": [], "domains": []},
                "severity": "HIGH",
            },
        ]
        findings_far = [
            {
                "alert_id": "A1",
                "timestamp": "2025-01-01T00:00:00Z",
                "hostname": "HOST1",
                "ttps": [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
                "indicators": {"hashes": ["shared_hash"], "ips": ["1.2.3.4"], "domains": []},
                "severity": "HIGH",
            },
            {
                "alert_id": "A2",
                "timestamp": "2025-06-01T00:00:00Z",
                "hostname": "HOST1",
                "ttps": [{"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"}],
                "indicators": {"hashes": ["shared_hash"], "ips": [], "domains": []},
                "severity": "HIGH",
            },
        ]
        conf_close = compute_chain_confidence(["A1", "A2"], findings_close)
        conf_far = compute_chain_confidence(["A1", "A2"], findings_far)
        assert conf_close > conf_far


class TestCorrelatorWithConfidence:
    def _make_finding(self, alert_id, ttps, severity="HIGH",
                      timestamp="2025-01-01T00:00:00Z",
                      indicators=None):
        return {
            "alert_id": alert_id,
            "source": "test",
            "timestamp": timestamp,
            "event_type": "process_creation",
            "hostname": "HOST1",
            "severity": severity,
            "ttps": ttps,
            "misp_enrichment": {},
            "semantic_scan": {},
            "triage_summary": "test",
            "recommendations": [],
            "indicators": indicators or {"hashes": [], "ips": [], "domains": [], "file_paths": []},
        }

    def test_persistence_chain_has_confidence(self):
        from src.correlator import correlate
        findings = [
            self._make_finding(
                "ALERT-PS",
                [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
                indicators={"hashes": ["shared"], "ips": ["1.2.3.4"], "domains": []},
            ),
            self._make_finding(
                "ALERT-SCHTASK",
                [{"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"}],
                indicators={"hashes": ["shared"], "ips": [], "domains": []},
            ),
        ]
        chains = correlate(findings)
        assert len(chains) >= 1
        for chain in chains:
            assert "confidence" in chain
            assert 0.0 <= chain["confidence"] <= 1.0
