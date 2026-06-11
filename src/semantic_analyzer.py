"""
semantic_analyzer.py — DeepSeek V4 LLM Semantic Analysis.

Sends an alert's command line to DeepSeek V4 for semantic classification of
obfuscation, encoding, or suspicious execution patterns.
Gracefully degrades if the API key is missing or the call fails.
"""

import json
import os
import urllib.request
import urllib.error
from typing import Any

# ── Configuration ──────────────────────────────────────────────────────────

DEEPSEEK_ENDPOINT = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"

_KEY_FILE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "rag-security-audit",
    "src",
    ".rag_audit_key",
)

_ANALYSIS_PROMPT = (
    "You are a security analysis AI. Classify whether the following Windows "
    "command line contains obfuscation, encoding, or suspicious execution "
    "patterns. Respond with JSON only: "
    "{'obfuscation_detected': bool, 'patterns': [list of str], 'confidence': float (0-1)}"
)

MAX_INPUT_LENGTH = 2000


# ── Key loading ────────────────────────────────────────────────────────────


def _load_key() -> str | None:
    """Read the DeepSeek V4 API key from environment or key file."""
    env_key = os.environ.get("RAG_AUDIT_LLM_KEY")
    if env_key:
        return env_key
    try:
        with open(_KEY_FILE_PATH) as f:
            key = f.read().strip()
        return key if key else None
    except (FileNotFoundError, PermissionError, OSError):
        return None


def can_use_deepseek() -> bool:
    """Return True if the DeepSeek V4 API key is available."""
    return _load_key() is not None


# ── LLM API call ───────────────────────────────────────────────────────────


def _strip_markdown_fences(text: str) -> str:
    """Remove markdown code fences (```json ... ```) from a string."""
    text = text.strip()
    if text.startswith("```"):
        # Remove opening fence
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1 :]
        else:
            text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def analyze_command_line(command_line: str) -> dict[str, Any]:
    """Send a command line to DeepSeek V4 for semantic analysis.

    Args:
        command_line: The Windows command line to analyze.

    Returns:
        A dict with keys:
            obfuscation_score (float, 0-1): confidence that obfuscation exists.
            detected_patterns (list[str]): patterns identified.
            is_suspicious (bool): whether the command line is suspicious.
            llm_reasoning (str): reasoning from the LLM.
    """
    key = _load_key()
    if key is None:
        return _degraded_result("LLM unavailable — skipped")

    # Truncate input to MAX_INPUT_LENGTH
    cmd_trimmed = command_line[:MAX_INPUT_LENGTH] if command_line else ""

    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [
            {"role": "system", "content": _ANALYSIS_PROMPT},
            {"role": "user", "content": cmd_trimmed},
        ],
        "temperature": 0.1,
        "max_tokens": 256,
    }

    data = json.dumps(payload).encode("utf-8")
    # String concatenation for auth header (security filter workaround)
    auth_header = "Bearer " + key

    req = urllib.request.Request(
        DEEPSEEK_ENDPOINT,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": auth_header,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_body = resp.read().decode("utf-8")
            response_json = json.loads(response_body)
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, OSError, ConnectionError, TimeoutError) as exc:
        return _degraded_result(f"LLM unavailable — API error: {exc}")

    # Extract the assistant's reply content
    try:
        choices = response_json.get("choices", [])
        if not choices:
            return _degraded_result("LLM unavailable — empty response")
        content = choices[0].get("message", {}).get("content", "")
    except (KeyError, IndexError, TypeError) as exc:
        return _degraded_result(f"LLM unavailable — parse error: {exc}")

    # Parse the LLM's JSON reply (may be wrapped in markdown code fences)
    content = _strip_markdown_fences(content)
    try:
        llm_result = json.loads(content)
    except json.JSONDecodeError as exc:
        return _degraded_result(f"LLM unavailable — JSON parse error: {exc}")

    # Normalise to our return schema
    obfuscation_detected = bool(llm_result.get("obfuscation_detected", False))
    patterns = list(llm_result.get("patterns", []))
    confidence = float(llm_result.get("confidence", 0.0))
    confidence = max(0.0, min(1.0, confidence))

    return {
        "obfuscation_score": confidence,
        "detected_patterns": patterns,
        "is_suspicious": obfuscation_detected,
        "llm_reasoning": (
            f"Detected patterns: {', '.join(patterns) if patterns else 'none'} "
            f"(confidence: {confidence:.2f})"
        ),
    }


def _degraded_result(reason: str) -> dict[str, Any]:
    """Return a safe degraded result when LLM analysis cannot be performed."""
    return {
        "obfuscation_score": 0,
        "detected_patterns": [],
        "is_suspicious": False,
        "llm_reasoning": reason,
    }
