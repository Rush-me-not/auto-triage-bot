"""
triage_engine.py — Severity scoring and triage summary generation.

Rules (threshold mode, default):
  HIGH:   2+ mapped TTPs, OR 1 TTP with high-severity rating.
  MEDIUM: 1 mapped TTP (medium or low severity).
  LOW:    0 TTPs but the event exhibits an unusual pattern
           (e.g. unusual process, abnormal parent-child relationship).
  CLEAN:  0 TTPs, normal event.

Weighted mode (when scoring_config is provided):
  Computes a weighted composite score (0–1 float) from multiple factors
  and maps to severity labels: CRITICAL>=0.80, HIGH>=0.55,
  MEDIUM>=0.30, LOW>=0.10, else CLEAN.
"""

import json
import os
from typing import Any

from src.calibrated_scorer import CalibratedScorer
from src.mitre_mapper import TTP_SEVERITY

# Patterns that make an event "unusual" even with zero TTPs
_UNUSUAL_PATTERNS = [
    "powershell", "cmd.exe",  # scripting shells at baseline
    "rundll32", "regsvr32",
    "mshta", "cscript", "wscript",
    "certutil", "bitsadmin",
    "schtasks", "at.exe",
]

# Default scoring config path (relative to this file)
_DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "scoring_config.json")


def _load_scoring_config(config_path: str | None = None) -> dict[str, Any] | None:
    """Load a scoring configuration JSON file.

    Args:
        config_path: Path to the JSON config file. If None, tries the default
                     ``src/scoring_config.json`` location.

    Returns:
        The parsed config dict, or None if the file cannot be found/parsed.
    """
    path = config_path or _DEFAULT_CONFIG_PATH
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _compute_weighted_score(
    alert: dict[str, Any],
    ttps: list[dict[str, str]],
    misp_enrichment: dict[str, Any] | None,
    config: dict[str, Any],
) -> tuple[float, dict[str, float]]:
    """Compute a weighted composite severity score from multiple factors.
    Delegates to CalibratedScorer for the raw computation.

    Args:
        alert: The parsed EDR alert dictionary.
        ttps: List of mapped MITRE ATT&CK technique dicts.
        misp_enrichment: MISP enrichment data (or None).
        config: The scoring configuration dict.

    Returns:
        A tuple of ``(composite_score, factor_details)`` where
        ``factor_details`` maps factor names to their individual scores.
    """
    scorer = CalibratedScorer()
    raw = scorer.compute_raw_score(alert, ttps, misp_enrichment, config)
    return raw, {"composite": raw}


def _weighted_severity_label(composite: float, config: dict[str, Any]) -> str:
    """Map a composite score to a severity label using configured thresholds.

    Args:
        composite: The weighted composite score (0–1).
        config: The scoring configuration dict.

    Returns:
        One of ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, or ``CLEAN``.
    """
    thresholds = config.get("thresholds", {})
    if composite >= thresholds.get("CRITICAL", 0.80):
        return "CRITICAL"
    elif composite >= thresholds.get("HIGH", 0.55):
        return "HIGH"
    elif composite >= thresholds.get("MEDIUM", 0.30):
        return "MEDIUM"
    elif composite >= thresholds.get("LOW", 0.10):
        return "LOW"
    else:
        return "CLEAN"


def score(
    alert: dict[str, Any],
    ttps: list[dict[str, str]],
    misp_enrichment: dict[str, Any] | None = None,
    scoring_config: dict[str, Any] | None = None,
    scoring_config_path: str | None = None,
    calibrator_path: str | None = None,
) -> tuple[str, str, list[str]]:
    """Determine severity, generate a triage summary, and produce recommendations.

    When *scoring_config* (or *scoring_config_path*) is provided, uses the
    weighted multi-factor scoring model.  Otherwise falls back to the
    original threshold-based logic for backward compatibility.

    Args:
        alert: The parsed EDR alert dictionary.
        ttps: List of mapped MITRE ATT&CK technique dicts (each with
              ``id``, ``name``, ``tactic``).
        misp_enrichment: Optional MISP enrichment data (used by weighted model).
        scoring_config: Optional pre-loaded scoring configuration dict.
        scoring_config_path: Optional path to a scoring config JSON file.

    Returns:
        A tuple of ``(severity, triage_summary, recommendations)``.
    """
    # ── Load scoring config if a path is given and no dict provided ──
    if scoring_config is None and scoring_config_path is not None:
        scoring_config = _load_scoring_config(scoring_config_path)

    # ── Weighted multi-factor scoring mode (with optional calibration) ──
    if scoring_config is not None:
        scorer = CalibratedScorer(calibrator_path=calibrator_path)
        composite, factor_details = scorer.score(
            alert, ttps, misp_enrichment, scoring_config
        )
        severity = _weighted_severity_label(composite, scoring_config)
        ttp_count = len(ttps)
    else:
        # ── Original threshold-based scoring (backward compatible) ────
        ttp_ids = [t["id"] for t in ttps]
        ttp_count = len(ttp_ids)
        composite = None  # not computed in threshold mode
        factor_details = None

        if ttp_count >= 2:
            severity = "HIGH"
        elif ttp_count == 1:
            tid = ttp_ids[0]
            if TTP_SEVERITY.get(tid, "low") == "high":
                severity = "HIGH"
            else:
                severity = "MEDIUM"
        else:
            # 0 TTPs — check for unusual patterns
            proc_name = (alert.get("process_name") or "").lower()
            parent = (alert.get("parent_process") or "").lower()
            cmd = (alert.get("command_line") or "").lower()
            event = (alert.get("event_type") or "").lower()

            is_unusual = any(
                p in proc_name or p in cmd or p in parent
                for p in _UNUSUAL_PATTERNS
            )
            # Also flag abnormal parent-child relationships
            office_parents = ("winword", "excel", "powerpnt", "outlook")
            if any(p in parent for p in office_parents) and proc_name not in ("", "explorer.exe"):
                is_unusual = True
            if "suspicious" in event:
                is_unusual = True

            severity = "LOW" if is_unusual else "CLEAN"

    # ── Triage summary ────────────────────────────────────────────────
    summary_parts: list[str] = []
    proc = alert.get("process_name", "unknown")
    host = alert.get("hostname", "unknown")
    event_type = alert.get("event_type", "unknown")

    if severity == "CRITICAL":
        summary_parts.append(
            f"Critical-severity alert on {host}: process '{proc}' "
            f"({event_type}) mapped to {ttp_count} MITRE ATT&CK technique(s)."
        )
        if ttps:
            ttp_names = [t["name"] for t in ttps]
            summary_parts.append(
                f"Techniques observed: {', '.join(ttp_names)}."
            )
        if factor_details:
            summary_parts.append(
                f"Weighted composite score: {factor_details['composite']:.2f}"
            )
    elif severity == "HIGH":
        summary_parts.append(
            f"High-severity alert on {host}: process '{proc}' "
            f"({event_type}) mapped to {ttp_count} MITRE ATT&CK technique(s)."
        )
        if ttps:
            ttp_names = [t["name"] for t in ttps]
            summary_parts.append(
                f"Techniques observed: {', '.join(ttp_names)}."
            )
    elif severity == "MEDIUM":
        summary_parts.append(
            f"Medium-severity alert on {host}: process '{proc}' "
            f"matched 1 technique ({ttps[0]['name']})."
        )
    elif severity == "LOW":
        summary_parts.append(
            f"Low-severity alert on {host}: process '{proc}' "
            f"({event_type}). No direct TTP match, but unusual "
            f"process/behaviour detected — worth monitoring."
        )
    else:
        summary_parts.append(
            f"Clean alert on {host}: process '{proc}' "
            f"({event_type}). No suspicious indicators."
        )

    triage_summary = " ".join(summary_parts)

    # ── Recommendations ──────────────────────────────────────────────
    recommendations: list[str] = []

    if severity == "CRITICAL":
        recommendations.append("IMMEDIATE INCIDENT RESPONSE REQUIRED.")
        recommendations.append("Isolate affected host from network immediately.")
        recommendations.append("Collect full memory and disk forensics.")
        recommendations.append("Notify security leadership and initiate incident response plan.")
        if any(t["id"] == "T1053.005" for t in ttps):
            recommendations.append(
                "Review scheduled tasks for persistence mechanisms."
            )
        if any(t["id"] == "T1059.001" for t in ttps):
            recommendations.append(
                "Review PowerShell execution policy and logging."
            )
        if any(t["id"] == "T1003.001" for t in ttps):
            recommendations.append(
                "Check for LSASS credential dumping artefacts."
            )
    elif severity == "HIGH":
        recommendations.append("Immediate investigation required.")
        recommendations.append("Isolate affected host from network.")
        recommendations.append("Collect full memory and disk forensics.")
        if any(t["id"] == "T1053.005" for t in ttps):
            recommendations.append(
                "Review scheduled tasks for persistence mechanisms."
            )
        if any(t["id"] == "T1059.001" for t in ttps):
            recommendations.append(
                "Review PowerShell execution policy and logging."
            )
        if any(t["id"] == "T1003.001" for t in ttps):
            recommendations.append(
                "Check for LSASS credential dumping artefacts."
            )
    elif severity == "MEDIUM":
        recommendations.append(
            "Escalate to SOC analyst for manual review."
        )
        recommendations.append(
            f"Correlate {proc} activity with endpoint telemetry."
        )
    elif severity == "LOW":
        recommendations.append(
            "Monitor host for further suspicious activity."
        )
        recommendations.append(
            "Consider adding process hash to watchlist."
        )
    else:
        recommendations.append("No action required.")

    return severity, triage_summary, recommendations
