"""
report.py — JSON report output.

Produces the final triage report in the schema defined by the project
requirements.
"""

import json
from datetime import datetime, timezone
from typing import Any

from src.mitre_mapper import TECHNIQUES


def build_report(
    findings: list[dict[str, Any]],
    correlation_chains: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble the final JSON report from the list of per-alert findings.

    Args:
        findings: A list of finding dicts, each produced by
                  :func:`build_finding`.
        correlation_chains: Optional list of correlation chain dicts from
                            :func:`correlator.correlate`.

    Returns:
        A complete report dictionary matching the project's output schema.
    """
    total = len(findings)
    clean_count = sum(1 for f in findings if f["severity"] == "CLEAN")
    suspicious_count = total - clean_count

    # ── TTP coverage ─────────────────────────────────────────────────
    ttp_coverage: dict[str, int] = {}
    for f in findings:
        for ttp in f["ttps"]:
            tid = ttp["id"]
            ttp_coverage[tid] = ttp_coverage.get(tid, 0) + 1

    # ── Top tactics ──────────────────────────────────────────────────
    tactic_counts: dict[str, int] = {}
    for f in findings:
        for ttp in f["ttps"]:
            tactic = ttp["tactic"]
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    top_tactics = sorted(tactic_counts, key=lambda t: tactic_counts[t], reverse=True)

    # ── Overall assessment ───────────────────────────────────────────
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")

    if high_count > 0:
        assessment = (
            f"CRITICAL: {high_count} high-severity alert(s) detected with "
            f"confirmed MITRE ATT&CK TTPs. Immediate response warranted."
        )
    elif med_count > 0:
        assessment = (
            f"WARNING: {med_count} medium-severity alert(s) found. "
            f"Review and correlate with additional telemetry."
        )
    elif low_count > 0:
        assessment = (
            f"CAUTION: {low_count} low-severity alert(s) with unusual "
            f"patterns. Monitor for escalation."
        )
    else:
        assessment = "CLEAN: No suspicious activity detected."

    report: dict[str, Any] = {
        "tool": "auto-triage-bot",
        "version": "1.0.0",
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_alerts": total,
        "clean_alerts": clean_count,
        "suspicious_alerts": suspicious_count,
        "findings": findings,
        "correlation_chains": correlation_chains or [],
        "summary": {
            "ttp_coverage": ttp_coverage,
            "top_tactics": top_tactics,
            "overall_assessment": assessment,
        },
    }

    return report


def build_finding(
    alert: dict[str, Any],
    ttps: list[dict[str, str]],
    misp_enrichment: dict[str, Any],
    severity: str,
    triage_summary: str,
    recommendations: list[str],
    semantic_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a single finding entry for one alert.

    Args:
        alert: Parsed EDR alert.
        ttps: Mapped MITRE ATT&CK techniques.
        misp_enrichment: MISP enrichment data.
        severity: One of HIGH / MEDIUM / LOW / CLEAN.
        triage_summary: Human-readable summary string.
        recommendations: List of recommendation strings.
        semantic_scan: Optional LLM semantic analysis result.

    Returns:
        A finding dict matching the output schema.
    """
    return {
        "alert_id": alert["alert_id"],
        "source": alert.get("source", ""),
        "timestamp": alert.get("timestamp", ""),
        "event_type": alert.get("event_type", ""),
        "hostname": alert.get("hostname", ""),
        "severity": severity,
        "ttps": ttps,
        "misp_enrichment": misp_enrichment,
        "semantic_scan": semantic_scan or {},
        "triage_summary": triage_summary,
        "recommendations": recommendations,
    }


def write_report(report: dict[str, Any], path: str) -> None:
    """Write the report dictionary to a JSON file.

    Args:
        report: The complete report dictionary.
        path: Filesystem path to write to.
    """
    with open(path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[+] Report written to {path}")
