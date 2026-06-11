"""
mitre_mapper.py — MITRE ATT&CK TTP mapping from EDR alerts.

Uses pattern matching on process names, command lines, parent processes,
and event types to identify relevant ATT&CK techniques.  Every technique
is represented as a ``dict`` with keys ``id``, ``name``, and ``tactic``.
"""

from typing import Any

# ── MITRE ATT&CK technique definitions ───────────────────────────────────

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1204.002": {"name": "Malicious File", "tactic": "Execution"},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1047":     {"name": "Windows Management Instrumentation", "tactic": "Execution"},
    "T1082":     {"name": "System Information Discovery", "tactic": "Discovery"},
}

# Severity rating per TTP (used by triage engine)
TTP_SEVERITY: dict[str, str] = {
    "T1059.001": "high",
    "T1059.003": "medium",
    "T1053.005": "high",
    "T1204.002": "high",
    "T1218.011": "medium",
    "T1003.001": "high",
    "T1047":     "medium",
    "T1082":     "low",
}


def _pn(name: str) -> str:
    """Normalise a process name for matching."""
    return name.strip().lower()


def _cmd(command_line: str | None) -> str:
    """Return a lower-cased command line, defaulting to empty string."""
    return (command_line or "").lower()


def map_ttps(alert: dict[str, Any]) -> list[dict[str, str]]:
    """Map an EDR alert to MITRE ATT&CK techniques.

    Args:
        alert: A parsed EDR alert dictionary.  Expected fields:
            ``process_name``, ``parent_process``, ``command_line``,
            ``event_type``, ``indicators`` (optional).

    Returns:
        A list of technique dicts, each with keys ``id``, ``name``, ``tactic``.
        Empty list if no techniques matched.
    """
    detected: list[str] = []
    proc = _pn(alert.get("process_name", ""))
    parent = _pn(alert.get("parent_process", ""))
    cmd = _cmd(alert.get("command_line"))
    event = alert.get("event_type", "").lower()
    indicators = alert.get("indicators", {})

    # ── T1059.001: PowerShell ─────────────────────────────────────────
    if (
        "powershell" in proc
        or cmd.startswith("powershell")
        or "powershell.exe" in cmd
    ):
        # Bonus: Office parent increases confidence
        if any(
            p in parent
            for p in ("winword", "excel", "powerpnt", "outlook")
        ):
            detected.append("T1059.001")
        else:
            detected.append("T1059.001")

    # ── T1059.003: Windows Command Shell ──────────────────────────────
    if proc in ("cmd.exe", "cmd") or cmd.startswith("cmd"):
        # Suspicious if seen with encoded/obfuscated args or spawned by Office
        suspicious_cmd = any(
            kw in cmd
            for kw in ("/c", "/k", "encode", "bypass", "echo", "certutil", "bitsadmin")
        )
        if suspicious_cmd or any(p in parent for p in ("winword", "excel")):
            detected.append("T1059.003")

    # ── T1053.005: Scheduled Task ─────────────────────────────────────
    if proc in ("schtasks.exe", "schtasks") or "schtasks" in cmd:
        detected.append("T1053.005")

    # ── T1204.002: Malicious File ─────────────────────────────────────
    # Triggered by: file download indicators, suspicious file paths,
    # or event types indicating file execution
    file_paths = indicators.get("file_paths", [])
    hashes = indicators.get("hashes", [])
    if any(p.lower().startswith(("c:\\users\\", "c:\\programdata\\", "c:\\windows\\temp"))
           for p in file_paths):
        detected.append("T1204.002")
    if any(h in ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                 "e99a18c428cb38d5f260853678922e03")
           for h in hashes):
        detected.append("T1204.002")
    if event in ("file_execution_detected", "malware_detected"):
        detected.append("T1204.002")

    # ── T1218.011: Rundll32 ──────────────────────────────────────────
    if proc in ("rundll32.exe", "rundll32"):
        # Especially suspicious with no / minimal command-line arguments
        detected.append("T1218.011")

    # ── T1003.001: LSASS Memory ───────────────────────────────────────
    if any(
        kw in cmd or kw in proc
        for kw in ("lsass", "procdump", "mimikatz", "sekurlsa")
    ):
        detected.append("T1003.001")
    if "lsass" in cmd or "lsass" in proc:
        detected.append("T1003.001")

    # ── T1047: WMI ────────────────────────────────────────────────────
    if proc in ("wmic.exe", "wmic", "wmiprvse.exe") or "wmic" in cmd:
        detected.append("T1047")

    # ── T1082: System Information Discovery ──────────────────────────
    discovery_kws = ("systeminfo", "hostname", "whoami", "net config",
                     "reg query", "tasklist")
    if any(kw in cmd for kw in discovery_kws):
        detected.append("T1082")

    # De-duplicate while preserving order
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for tid in detected:
        if tid not in seen and tid in TECHNIQUES:
            seen.add(tid)
            result.append({
                "id": tid,
                "name": TECHNIQUES[tid]["name"],
                "tactic": TECHNIQUES[tid]["tactic"],
            })

    return result
