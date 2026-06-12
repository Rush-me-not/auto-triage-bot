import json
import os
import pickle
import tempfile
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.calibrated_scorer import CalibratedScorer

_SCORING_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "src", "scoring_config.json")


class TestCalibratedScorerInit:
    def test_init_without_calibrator_returns_none_model(self):
        scorer = CalibratedScorer(calibrator_path="/nonexistent/calibrator.pkl")
        assert scorer.is_calibrated is False

    def test_init_with_valid_calibrator_loads_model(self):
        from sklearn.isotonic import IsotonicRegression
        ir = IsotonicRegression()
        ir.fit([0.1, 0.3, 0.5, 0.7, 0.9], [0.0, 0.2, 0.5, 0.8, 1.0])
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(ir, f)
            path = f.name
        try:
            scorer = CalibratedScorer(calibrator_path=path)
            assert scorer.is_calibrated is True
        finally:
            os.unlink(path)


class TestCalibratedScorerScoring:
    def test_uncalibrated_falls_back_to_raw(self):
        scorer = CalibratedScorer(calibrator_path="/nonexistent/calibrator.pkl")
        assert scorer.is_calibrated is False
        with open(_SCORING_CONFIG_PATH) as f:
            config = json.load(f)
        alert = {
            "alert_id": "TEST-001",
            "event_type": "process_creation",
            "timestamp": "2025-06-11T08:30:00Z",
            "process_name": "powershell.exe",
            "hostname": "HOST",
        }
        ttps = [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]
        misp = {"threat_level": "High"}
        composite, details = scorer.score(alert, ttps, misp, config)
        assert 0.0 <= composite <= 1.0
        assert "raw_weighted_score" in details
        assert "calibrated_score" not in details

    def test_calibrated_adjusts_score(self):
        from sklearn.isotonic import IsotonicRegression
        ir = IsotonicRegression()
        ir.fit([0.0, 0.2, 0.4, 0.6, 0.8, 1.0], [0.0, 0.1, 0.35, 0.6, 0.85, 1.0])
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(ir, f)
            path = f.name
        try:
            scorer = CalibratedScorer(calibrator_path=path)
            assert scorer.is_calibrated is True
            with open(_SCORING_CONFIG_PATH) as f2:
                config = json.load(f2)
            alert = {
                "alert_id": "TEST-002",
                "event_type": "process_creation",
                "timestamp": "2025-06-11T08:30:00Z",
                "process_name": "powershell.exe",
                "hostname": "HOST",
            }
            ttps = [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]
            misp = {"threat_level": "High"}
            composite, details = scorer.score(alert, ttps, misp, config)
            assert "calibrated_score" in details
            assert details["calibrated_score"] != details["raw_weighted_score"]
        finally:
            os.unlink(path)


class TestCalibratedScorerWithTriageEngine:
    def test_score_with_calibrator_path(self):
        from src.triage_engine import score
        from sklearn.isotonic import IsotonicRegression

        ir = IsotonicRegression()
        ir.fit([0.0, 0.2, 0.4, 0.6, 0.8, 1.0], [0.0, 0.1, 0.35, 0.6, 0.85, 1.0])
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(ir, f)
            path = f.name
        try:
            with open(_SCORING_CONFIG_PATH) as f2:
                config = json.load(f2)
            alert = {
                "alert_id": "CAL-001",
                "event_type": "process_creation",
                "timestamp": "2025-06-11T08:30:00Z",
                "process_name": "powershell.exe",
                "hostname": "HOST",
            }
            ttps = [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]
            misp = {"threat_level": "High"}
            severity, summary, recs = score(
                alert, ttps,
                misp_enrichment=misp,
                scoring_config=config,
                calibrator_path=path,
            )
            assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN")
        finally:
            os.unlink(path)

    def test_score_without_calibrator_falls_back(self):
        from src.triage_engine import score

        with open(_SCORING_CONFIG_PATH) as f:
            config = json.load(f)
        alert = {
            "alert_id": "CAL-002",
            "event_type": "process_creation",
            "timestamp": "2025-06-11T08:30:00Z",
            "process_name": "cmd.exe",
            "hostname": "HOST",
        }
        ttps = [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]
        misp = {"threat_level": "High"}
        severity, summary, recs = score(
            alert, ttps,
            misp_enrichment=misp,
            scoring_config=config,
            calibrator_path="/nonexistent/calibrator.pkl",
        )
        assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN")
