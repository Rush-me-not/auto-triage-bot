import json
import os
import pickle
from typing import Any

from src.mitre_mapper import TTP_SEVERITY

_TTP_SEV_NUMERIC: dict[str, float] = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
}


class CalibratedScorer:
    def __init__(self, calibrator_path: str | None = None):
        self._calibrator = None
        self._config = None
        if calibrator_path is not None:
            self._load_calibrator(calibrator_path)

    def _load_calibrator(self, path: str) -> None:
        try:
            with open(path, "rb") as f:
                self._calibrator = pickle.load(f)
        except (FileNotFoundError, pickle.UnpicklingError, OSError):
            self._calibrator = None

    @property
    def is_calibrated(self) -> bool:
        return self._calibrator is not None

    def compute_raw_score(
        self,
        alert: dict[str, Any],
        ttps: list[dict[str, str]],
        misp_enrichment: dict[str, Any] | None,
        config: dict[str, Any],
    ) -> float:
        weights = config["weights"]
        ttp_count_max = config.get("ttp_count_max", 3)
        event_type_scores = config.get("event_type_scores", {})
        misp_threat_map = config.get("misp_threat_map", {})
        temporal_windows = config.get("temporal_windows_hours", {})

        ttp_count = min(len(ttps), ttp_count_max)
        ttp_count_score = ttp_count / ttp_count_max if ttp_count_max > 0 else 0.0

        ttp_max_sev = 0.0
        for ttp in ttps:
            sev_label = TTP_SEVERITY.get(ttp["id"], "low")
            sev_val = _TTP_SEV_NUMERIC.get(sev_label, 0.3)
            if sev_val > ttp_max_sev:
                ttp_max_sev = sev_val

        misp_threat = 0.0
        if misp_enrichment:
            threat_label = misp_enrichment.get("threat_level", "None")
            misp_threat = misp_threat_map.get(threat_label, 0.0)

        event_type = (alert.get("event_type") or "").lower()
        event_type_score = event_type_scores.get(event_type, event_type_scores.get("default", 0.3))

        from datetime import datetime, timezone
        temporal_score = 0.0
        ts_str = alert.get("timestamp", "")
        if ts_str:
            try:
                ts_str_clean = ts_str.replace("Z", "+00:00")
                alert_dt = datetime.fromisoformat(ts_str_clean)
                now = datetime.now(timezone.utc)
                if alert_dt.tzinfo is None:
                    alert_dt = alert_dt.replace(tzinfo=timezone.utc)
                age_hours = (now - alert_dt).total_seconds() / 3600.0
                recent_h = temporal_windows.get("recent", 1)
                moderate_h = temporal_windows.get("moderate", 24)
                if age_hours <= recent_h:
                    temporal_score = 1.0
                elif age_hours <= moderate_h:
                    temporal_score = 0.5
                else:
                    temporal_score = 0.1
            except (ValueError, TypeError):
                temporal_score = 0.0

        composite = (
            weights.get("ttp_count", 0.35) * ttp_count_score
            + weights.get("ttp_max_severity", 0.25) * ttp_max_sev
            + weights.get("misp_threat_level", 0.20) * misp_threat
            + weights.get("event_type_baseline", 0.10) * event_type_score
            + weights.get("temporal_proximity", 0.10) * temporal_score
        )
        return composite

    def score(
        self,
        alert: dict[str, Any],
        ttps: list[dict[str, str]],
        misp_enrichment: dict[str, Any] | None,
        config: dict[str, Any],
    ) -> tuple[float, dict[str, float]]:
        raw = self.compute_raw_score(alert, ttps, misp_enrichment, config)

        factor_details = {
            "raw_weighted_score": raw,
        }

        if self.is_calibrated:
            calibrated = float(self._calibrator.transform([raw])[0])
            calibrated = max(0.0, min(1.0, calibrated))
            factor_details["calibrated_score"] = calibrated
            factor_details["composite"] = calibrated
        else:
            factor_details["composite"] = raw

        return factor_details["composite"], factor_details
