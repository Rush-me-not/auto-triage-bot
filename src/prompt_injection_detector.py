import re
from typing import Any

_INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|above)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a", re.IGNORECASE),
    re.compile(r"system\s*:\s*you", re.IGNORECASE),
    re.compile(r"act\s+as\s+if\s+you", re.IGNORECASE),
    re.compile(r"pretend\s+(you\s+are|to\s+be)", re.IGNORECASE),
    re.compile(r"override\s+(all\s+)?safety", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
]

_DELIMITER_PAIRS = [
    ("```", "```"),
    ("<<<", ">>>"),
    ("{{", "}}"),
    ("[[[", "]]]"),
    ("---", "---"),
]

_LENGTH_HEURISTIC_THRESHOLD = 2000
_LENGTH_HEURISTIC_MAX = 5000


def detect_prompt_injection(command_line: str) -> dict[str, Any]:
    if not command_line:
        return {
            "risk_score": 0.0,
            "flagged": False,
            "detected_patterns": [],
            "reason": "empty_input",
        }

    detected_patterns: list[str] = []
    risk_score = 0.0

    # Check 1: instruction-override patterns
    override_matches = 0
    for pattern in _INSTRUCTION_OVERRIDE_PATTERNS:
        if pattern.search(command_line):
            override_matches += 1
            detected_patterns.append(f"instruction_override:{pattern.pattern[:40]}")
    if override_matches > 0:
        risk_score += 0.45 + min(override_matches * 0.1, 0.3)

    # Check 2: delimiter-pair injection
    delimiter_matches = 0
    for open_d, close_d in _DELIMITER_PAIRS:
        if open_d in command_line and close_d in command_line:
            delimiter_matches += 1
            detected_patterns.append(f"delimiter_pair:{open_d}")
    if delimiter_matches > 0:
        risk_score += 0.45 + min(delimiter_matches * 0.1, 0.25)

    # Check 3: length heuristic
    cmd_len = len(command_line)
    if cmd_len > _LENGTH_HEURISTIC_MAX:
        risk_score += 0.55
        detected_patterns.append("excessive_length:>5000")
    elif cmd_len > _LENGTH_HEURISTIC_THRESHOLD:
        risk_score += 0.15
        detected_patterns.append("elevated_length:>2000")

    risk_score = min(risk_score, 1.0)
    flagged = risk_score > 0.5

    return {
        "risk_score": round(risk_score, 4),
        "flagged": flagged,
        "detected_patterns": detected_patterns,
    }
