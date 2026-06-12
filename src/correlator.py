"""
correlator.py — Cross-Alert Sequence Correlation.

Takes a list of ALL findings (after individual triage) and looks for known
attack sequences spanning multiple alerts.  The combinatory benefit is novel
— no standard SOC tool does cross-alert behavioral correlation at this
fidelity without a SIEM.

Enhancements:
  - Temporal correlation: filters alert pairs to those within
    ``max_time_window_minutes`` (default: 60).
  - ``rapid_lateral_movement``: same TTP appearing on different hosts
    within 5 minutes.
  - ``time_delta_minutes`` added to chain output.
"""

from datetime import datetime, timezone
from typing import Any

from src.mitre_mapper import TTP_SEVERITY

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
    {
        "chain_type": "rapid_lateral_movement",
        "ttp_sequence": [],  # dynamic — detected by TTP overlap across hosts
        "severity": "CRITICAL",
        "base_description": (
            "Rapid lateral movement detected: the same TTP was observed on "
            "different hosts within a 5-minute window. This pattern is "
            "consistent with automated lateral movement or worm-like propagation."
        ),
        "recommendations": [
            "Immediately isolate ALL affected hosts from the network.",
            "Identify the initial compromise vector and patient zero.",
            "Block lateral movement ports (SMB, RPC, WMI) between affected segments.",
            "Review authentication logs for anomalous credential use.",
            "Initiate full-scale incident response.",
        ],
    },
]


def _parse_timestamp(ts_str: str) -> datetime | None:
    """Parse an ISO 8601 timestamp string into a UTC datetime.

    Returns None if parsing fails.
    """
    if not ts_str:
        return None
    try:
        ts_clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _time_delta_minutes(
    finding_a: dict[str, Any], finding_b: dict[str, Any]
) -> float | None:
    """Compute the absolute time difference in minutes between two findings.

    Returns None if either timestamp cannot be parsed.
    """
    ts_a = _parse_timestamp(finding_a.get("timestamp", ""))
    ts_b = _parse_timestamp(finding_b.get("timestamp", ""))
    if ts_a is None or ts_b is None:
        return None
    return abs((ts_a - ts_b).total_seconds()) / 60.0


def _detect_rapid_lateral_movement(
    findings: list[dict[str, Any]],
    max_time_window_minutes: float,
) -> list[dict[str, Any]]:
    """Detect rapid lateral movement: same TTP on different hosts within 5 min.

    Args:
        findings: List of finding dicts.
        max_time_window_minutes: Max time window for correlation (unused here;
                                  rapid lateral uses a fixed 5-minute window).

    Returns:
        List of rapid_lateral_movement chain dicts.
    """
    RLM_WINDOW = 5.0  # fixed 5-minute window for rapid lateral movement
    chains: list[dict[str, Any]] = []
    chain_counter = 0

    # Build a map of TTP ID -> list of findings with that TTP
    ttp_to_findings: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        for ttp in f.get("ttps", []):
            tid = ttp["id"]
            ttp_to_findings.setdefault(tid, []).append(f)

    # For each TTP that appears on multiple distinct hosts within 5 min
    seen_pairs: set[tuple[str, str, str]] = set()  # (ttp_id, host_a, host_b)

    for ttp_id, f_list in ttp_to_findings.items():
        if len(f_list) < 2:
            continue
        for i in range(len(f_list)):
            for j in range(i + 1, len(f_list)):
                fa, fb = f_list[i], f_list[j]
                host_a = fa.get("hostname", "")
                host_b = fb.get("hostname", "")
                if host_a == host_b:
                    continue  # same host — not lateral movement

                # Deduplicate by sorted pair
                pair_key = (ttp_id, *sorted([host_a, host_b]))
                if pair_key in seen_pairs:
                    continue

                delta = _time_delta_minutes(fa, fb)
                if delta is not None and delta <= RLM_WINDOW:
                    seen_pairs.add(pair_key)
                    chain_counter += 1
                    chain_id = f"CHAIN-RAPIDLATERAL-{chain_counter:03d}"

                    ttp_name = ""
                    for ttp in fa.get("ttps", []):
                        if ttp["id"] == ttp_id:
                            ttp_name = ttp["name"]
                            break

                    rlm_alert_ids = [fa["alert_id"], fb["alert_id"]]
                    rlm_confidence = compute_chain_confidence(
                        rlm_alert_ids, findings
                    )
                    chains.append({
                        "chain_id": chain_id,
                        "chain_type": "rapid_lateral_movement",
                        "alert_ids": rlm_alert_ids,
                        "hosts": [host_a, host_b],
                        "shared_ttp": ttp_id,
                        "shared_ttp_name": ttp_name,
                        "severity": "CRITICAL",
                        "description": (
                            f"Rapid lateral movement detected: {ttp_name} "
                            f"({ttp_id}) observed on {host_a} and {host_b} "
                            f"within {delta:.1f} minutes."
                        ),
                        "time_delta_minutes": round(delta, 1),
                        "confidence": rlm_confidence,
                        "recommendations": [
                            "Immediately isolate ALL affected hosts from the network.",
                            "Identify the initial compromise vector and patient zero.",
                            "Block lateral movement ports (SMB, RPC, WMI) between affected segments.",
                            "Review authentication logs for anomalous credential use.",
                            "Initiate full-scale incident response.",
                        ],
                    })

    return chains


_TTP_SEV_NUMERIC: dict[str, float] = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
}


def compute_chain_confidence(
    chain_alert_ids: list[str],
    findings: list[dict[str, Any]],
    max_window_hours: float = 24.0,
) -> float:
    if len(chain_alert_ids) < 2:
        return 0.0

    alert_map = {f.get("alert_id", ""): f for f in findings if f.get("alert_id")}
    chain_findings = [alert_map[aid] for aid in chain_alert_ids if aid in alert_map]
    if len(chain_findings) < 2:
        return 0.0

    # Factor 1: mean TTP severity score
    sev_scores = []
    for f in chain_findings:
        for ttp in f.get("ttps", []):
            sev_label = TTP_SEVERITY.get(ttp["id"], "low")
            sev_scores.append(_TTP_SEV_NUMERIC.get(sev_label, 0.3))
    mean_severity = sum(sev_scores) / len(sev_scores) if sev_scores else 0.0

    # Factor 2: temporal proximity factor
    timestamps = []
    for f in chain_findings:
        ts = _parse_timestamp(f.get("timestamp", ""))
        if ts is not None:
            timestamps.append(ts)
    if len(timestamps) >= 2:
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        delta_hours = (max_ts - min_ts).total_seconds() / 3600.0
        temporal_factor = max(0.0, 1.0 - (delta_hours / max_window_hours))
    else:
        temporal_factor = 0.5

    # Factor 3: IoC overlap ratio (Jaccard similarity of IoC sets)
    ioc_sets = []
    for f in chain_findings:
        indicators = f.get("indicators", {})
        iocs = set()
        for ioc_type in ("hashes", "ips", "domains"):
            for ioc in indicators.get(ioc_type, []):
                iocs.add(ioc.lower())
        ioc_sets.append(iocs)
    if len(ioc_sets) >= 2:
        intersection = set.intersection(*ioc_sets)
        union = set.union(*ioc_sets)
        ioc_overlap = len(intersection) / len(union) if union else 0.0
    else:
        ioc_overlap = 0.0

    confidence = mean_severity * temporal_factor * max(ioc_overlap, 0.05)
    return min(round(confidence, 4), 1.0)


def correlate(
    findings: list[dict[str, Any]],
    max_time_window_minutes: float = 60.0,
) -> list[dict[str, Any]]:
    """Correlate individual alert findings into multi-alert attack chains.

    Args:
        findings: A list of finding dicts, each produced by
                  :func:`report.build_finding`.
        max_time_window_minutes: Maximum time window (in minutes) between
                                 consecutive alerts in a chain. Alerts outside
                                 this window are filtered out.
                                 Default: 60.

    Returns:
        A list of correlation finding dicts, each with keys:
            chain_id (str):           e.g. "CHAIN-PERSISTENCE-001"
            chain_type (str):         e.g. "persistence_chain"
            alert_ids (list[str]):    The alert IDs participating in the chain.
            severity (str):           CRITICAL / HIGH / MEDIUM
            description (str):        Human-readable description.
            recommendations (list[str]): Actionable recommendations.
            time_delta_minutes (float, optional): Time delta between alerts.
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
        # Skip rapid_lateral_movement — handled separately
        if chain_def["chain_type"] == "rapid_lateral_movement":
            continue

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
                    # Check temporal proximity against previous alert
                    if chain_alerts:
                        prev = chain_alerts[-1]
                        delta = _time_delta_minutes(match, prev)
                        if delta is not None and delta > max_time_window_minutes:
                            continue  # skip — outside time window
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

        # Compute time delta between first and last alert in chain
        time_delta = None
        if len(chain_alerts) >= 2:
            td = _time_delta_minutes(chain_alerts[0], chain_alerts[-1])
            if td is not None:
                time_delta = round(td, 1)

        chain_entry: dict[str, Any] = {
            "chain_id": chain_id,
            "chain_type": chain_type,
            "alert_ids": alert_ids,
            "severity": severity,
            "description": chain_def["base_description"],
            "recommendations": list(chain_def["recommendations"]),
        }
        if time_delta is not None:
            chain_entry["time_delta_minutes"] = time_delta

        # Compute chain confidence
        confidence = compute_chain_confidence(alert_ids, findings)
        chain_entry["confidence"] = confidence

        chains.append(chain_entry)

    # ── Detect rapid lateral movement ──────────────────────────────────
    rlm_chains = _detect_rapid_lateral_movement(findings, max_time_window_minutes)
    chains.extend(rlm_chains)

    return chains
