"""
triage_engine.py — Severity scoring and triage summary generation.

Rules:
  HIGH:   2+ mapped TTPs, OR 1 TTP with high-severity rating.
  MEDIUM: 1 mapped TTP (medium or low severity).
  LOW:    0 TTPs but the event exhibits an unusual pattern
           (e.g. unusual process, abnormal parent-child relationship).
  CLEAN:  0 TTPs, normal event.
"""

from typing import Any

# Re-use the TTP severity table from mitre_mapper
from src.mitre_mapper import TTP_SEVERITY

# Patterns that make an event "unusual" even with zero TTPs
_UNUSUAL_PATTERNS = [
    "powershell", "cmd.exe",  # scripting shells at baseline
    "rundll32", "regsvr32",
    "mshta", "cscript", "wscript",
    "certutil", "bitsadmin",
    "schtasks", "at.exe",
]


def score(alert: dict[str, Any], ttps: list[dict[str, str]]) -> tuple[str, str, list[str]]:
    """Determine severity, generate a triage summary, and produce recommendations.

    Args:
        alert: The parsed EDR alert dictionary.
        ttps: List of mapped MITRE ATT&CK technique dicts (each with
              ``id``, ``name``, ``tactic``).

    Returns:
        A tuple of ``(severity, triage_summary, recommendations)``.
    """
    ttp_ids = [t["id"] for t in ttps]
    ttp_count = len(ttp_ids)

    # ── Severity ──────────────────────────────────────────────────────
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

    if severity == "HIGH":
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

    if severity == "HIGH":
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
