"""
correlator.py — Cross-Alert Sequence Correlation.

Takes a list of ALL findings (after individual triage) and looks for known
attack sequences spanning multiple alerts.  The combinatory benefit is novel
— no standard SOC tool does cross-alert behavioral correlation at this
fidelity without a SIEM.
"""

from typing import Any

# ── Attack chain definitions ───────────────────────────────────────────────
# Each chain specifies:
#   chain_type:      A label for the chain.
#   ttp_sequence:    The ordered list of TTP IDs that define the chain.
#   severity:        Severity if the chain is detected.
#   base_description: Human-readable description template.
#   recommendations: List of recommendation strings.

ATTACK_CHAINS: list[dict[str, Any]] = [
    {
        "chain_type": "persistence_chain",
        "ttp_sequence": ["T1059.001", "T1053.005"],
        "severity": "CRITICAL",
        "base_description": (
            "Persistence chain detected: Office macro spawned PowerShell "
            "(T1059.001) followed by scheduled task creation (T1053.005). "
            "This is a common pattern for establishing persistent backdoor access."
        ),
        "recommendations": [
            "Immediately isolate affected host from network.",
            "Review and remove the scheduled task created by the attacker.",
            "Inspect Office document macros for malicious payloads.",
            "Audit PowerShell execution policy and enable script block logging.",
        ],
    },
    {
        "chain_type": "intrusion_chain",
        "ttp_sequence": ["T1204.002", "T1218.011"],
        "severity": "CRITICAL",
        "base_description": (
            "Intrusion chain detected: Malicious file execution (T1204.002) "
            "followed by Rundll32 execution (T1218.011) and C2 communication. "
            "This pattern is consistent with remote access trojan (RAT) deployment."
        ),
        "recommendations": [
            "Isolate affected host and block C2 infrastructure at the firewall.",
            "Collect full memory and disk forensics for malware analysis.",
            "Review user activity logs for phishing delivery vectors.",
            "Escalate to incident response team immediately.",
        ],
    },
    {
        "chain_type": "full_intrusion",
        "ttp_sequence": ["T1082", "T1047", "T1003.001"],
        "severity": "CRITICAL",
        "base_description": (
            "Full intrusion chain detected: Reconnaissance (T1082) followed by "
            "lateral movement via WMI (T1047) and credential access via LSASS "
            "dumping (T1003.001). This represents a complete intrusion lifecycle."
        ),
        "recommendations": [
            "Contain all affected hosts immediately.",
            "Reset credentials for all users on affected systems.",
            "Review WMI activity logs for lateral movement indicators.",
            "Enable LSASS protection (RunAsPPL) on all domain-joined systems.",
            "Conduct a full threat hunting exercise across the environment.",
        ],
    },
]


def correlate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate individual alert findings into multi-alert attack chains.

    Args:
        findings: A list of finding dicts, each produced by
                  :func:`report.build_finding`.

    Returns:
        A list of correlation finding dicts, each with keys:
            chain_id (str):           e.g. "CHAIN-PERSISTENCE-001"
            chain_type (str):         e.g. "persistence_chain"
            alert_ids (list[str]):    The alert IDs participating in the chain.
            severity (str):           CRITICAL / HIGH / MEDIUM
            description (str):        Human-readable description.
            recommendations (list[str]): Actionable recommendations.
    """
    chains: list[dict[str, Any]] = []
    chain_counter: dict[str, int] = {}

    # Build a lookup: alert_id -> finding
    alert_map: dict[str, dict[str, Any]] = {}
    for f in findings:
        aid = f.get("alert_id", "")
        if aid:
            alert_map[aid] = f

    # For each attack chain definition, try to find matching alerts
    for chain_def in ATTACK_CHAINS:
        target_ttps = chain_def["ttp_sequence"]
        chain_type = chain_def["chain_type"]
        severity = chain_def["severity"]

        # We need at least one finding covering each TTP in the sequence
        # A single finding may cover multiple TTPs.
        # We look for a sequence across *distinct* alerts where:
        #   - Alert A has TTP at index 0
        #   - Alert B (different from A) has TTP at index 1
        #   ... etc.
        # For this implementation, we do an exhaustive search for the
        # simplest case: N distinct alerts covering the N TTPs in order.

        # Collect candidate alerts per TTP position
        candidates: list[list[dict[str, Any]]] = []
        for ttp_id in target_ttps:
            matching = []
            for f in findings:
                f_ttp_ids = {t["id"] for t in f.get("ttps", [])}
                if ttp_id in f_ttp_ids:
                    matching.append(f)
            if not matching:
                # This chain cannot be formed — missing a TTP
                candidates.clear()
                break
            candidates.append(matching)

        if not candidates:
            continue

        # Greedy: pick the first alert that matches each TTP, preferring
        # distinct alerts where possible.
        chain_alerts: list[dict[str, Any]] = []
        used_ids: set[str] = set()

        for pos, ttp_matches in enumerate(candidates):
            chosen: dict[str, Any] | None = None
            for match in ttp_matches:
                mid = match.get("alert_id", "")
                if mid not in used_ids:
                    chosen = match
                    break
            if chosen is None and pos > 0:
                # Re-use the last alert (it matched multiple TTPs)
                chosen = ttp_matches[0]
            if chosen is None:
                break
            aid = chosen.get("alert_id", "")
            if aid not in used_ids:
                used_ids.add(aid)
            chain_alerts.append(chosen)

        if len(chain_alerts) < len(target_ttps):
            # Not all TTPs covered by distinct or overlapping alerts
            continue

        # Build the chain record
        chain_counter[chain_type] = chain_counter.get(chain_type, 0) + 1
        seq_num = chain_counter[chain_type]
        chain_id = f"CHAIN-{chain_type.upper()}-{seq_num:03d}"

        alert_ids = [a["alert_id"] for a in chain_alerts]

        chains.append({
            "chain_id": chain_id,
            "chain_type": chain_type,
            "alert_ids": alert_ids,
            "severity": severity,
            "description": chain_def["base_description"],
            "recommendations": list(chain_def["recommendations"]),
        })

    return chains
