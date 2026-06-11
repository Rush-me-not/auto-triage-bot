"""
misp_enricher.py — MISP enrichment in mock mode.

By default this module operates in *mock* mode: it maps IoCs (hashes, IPs,
domains) found in EDR alerts to a built-in threat-intelligence lookup table
and returns enriched context as if a real MISP instance had been queried.

If the environment variable ``RAG_AUDIT_LLM_KEY`` is set, the module can
optionally load the DeepSeek V4 API key from the configured key path and
perform LLM-based semantic enrichment (future enhancement).
"""

import os
import json
from typing import Any

# ── Built-in mock threat-intelligence lookup ──────────────────────────────
# In a production deployment this would be replaced by a real MISP API client.

_MOCK_INTEL: dict[str, list[dict[str, Any]]] = {
    # Known-malicious hashes
    "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d": [
        {"tag": "misp:malware", "description": "Emotet payload hash"},
        {"tag": "misp:ttp:T1059.001", "description": "Associated with PowerShell abuse"},
    ],
    "e99a18c428cb38d5f260853678922e03": [
        {"tag": "misp:malware", "description": "Known CobaltStrike beacon hash"},
        {"tag": "misp:ttp:T1059.003", "description": "Cmd.exe lateral movement tooling"},
    ],
    "5d41402abc4b2a76b9719d911017c592": [
        {"tag": "misp:malware", "description": "Ransomware sample hash"},
    ],
    # Known-malicious IPs
    "185.130.5.251": [
        {"tag": "misp:ip:cnc", "description": "Known C2 server — Emotet infrastructure"},
        {"tag": "misp:ttp:T1204.002", "description": "User execution — payload delivery"},
    ],
    "45.33.32.156": [
        {"tag": "misp:ip:cnc", "description": "CobaltStrike C2 endpoint"},
    ],
    "91.121.87.54": [
        {"tag": "misp:ip:scanner", "description": "Internet scanning infrastructure"},
    ],
    # Known-malicious domains
    "evil.example.com": [
        {"tag": "misp:domain:malicious", "description": "Malware payload delivery domain"},
        {"tag": "misp:ttp:T1204.002", "description": "User-executed payload download"},
    ],
    "malware.download.xyz": [
        {"tag": "misp:domain:malicious", "description": "Secondary payload staging domain"},
    ],
}

# ── Key path for DeepSeek V4 (semantic enhancement) ──────────────────────

_DEFAULT_KEY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "rag-security-audit",
    "src",
    ".rag_audit_key",
)


def _load_llm_key() -> str | None:
    """Read the DeepSeek V4 API key from the configured key path.

    Returns the key string, or None if the file does not exist or is empty.
    """
    key_path = os.environ.get("RAG_AUDIT_LLM_KEY_PATH", _DEFAULT_KEY_PATH)
    try:
        with open(key_path) as f:
            key = f.read().strip()
        return key if key else None
    except (FileNotFoundError, PermissionError, OSError):
        return None


def enrich_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Enrich an alert with MISP-derived threat intelligence.

    In mock mode this performs a simple hash / IP / domain lookup against
    the built-in ``_MOCK_INTEL`` table.  Every indicator that matches
    contributes its associated tags and descriptions to the enrichment.

    Args:
        alert: A parsed EDR alert dictionary.

    Returns:
        A dictionary with keys:
          * ``matched_indicators`` — list of IoCs that had intel hits
          * ``tags`` — aggregated MISP tags
          * ``descriptions`` — aggregated descriptions
          * ``threat_level`` — ``"High"`` if any matched indicator is malware/C2,
            otherwise ``"None"``
    """
    indicators = alert.get("indicators", {})
    matched: list[str] = []
    tags: list[str] = []
    descriptions: list[str] = []
    has_malware = False
    has_c2 = False

    for ioc_type in ("hashes", "ips", "domains"):
        for ioc in indicators.get(ioc_type, []):
            ioc_lower = ioc.lower()
            if ioc_lower in _MOCK_INTEL:
                matched.append(ioc)
                for entry in _MOCK_INTEL[ioc_lower]:
                    tags.append(entry["tag"])
                    descriptions.append(entry["description"])
                    if "malware" in entry["tag"]:
                        has_malware = True
                    if "cnc" in entry["tag"] or "c2" in entry["description"].lower():
                        has_c2 = True

    # Duplicate removal (preserve order)
    seen_tags: set[str] = set()
    unique_tags: list[str] = []
    for t in tags:
        if t not in seen_tags:
            seen_tags.add(t)
            unique_tags.append(t)

    seen_desc: set[str] = set()
    unique_desc: list[str] = []
    for d in descriptions:
        if d not in seen_desc:
            seen_desc.add(d)
            unique_desc.append(d)

    threat_level = "High" if (has_malware or has_c2) else "None"

    return {
        "matched_indicators": matched,
        "tags": unique_tags,
        "descriptions": unique_desc,
        "threat_level": threat_level,
    }


def can_use_llm() -> bool:
    """Return True if the DeepSeek V4 key is available for semantic enrichment.

    Checks both the ``RAG_AUDIT_LLM_KEY`` environment variable and the
    configured key file on disk.
    """
    if os.environ.get("RAG_AUDIT_LLM_KEY"):
        return True
    if os.environ.get("RAG_AUDIT_LLM_KEY_PATH"):
        return _load_llm_key() is not None
    # default key path
    return _load_llm_key() is not None
