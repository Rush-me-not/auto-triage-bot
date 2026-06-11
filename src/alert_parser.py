"""
alert_parser.py — Parse EDR alert JSON input.

Each alert is expected to conform to the following JSON schema:
{
  "alert_id": str,
  "source": str,
  "timestamp": str (ISO8601),
  "event_type": str,
  "hostname": str,
  "process_name": str,
  "command_line": str,
  "parent_process": str,
  "indicators": {
    "hashes": [str],
    "ips": [str],
    "domains": [str],
    "file_paths": [str]
  }
}
"""

import json
import os
from typing import Any


def parse_alert_file(path: str) -> dict[str, Any]:
    """Read and parse a single EDR alert JSON file.

    Args:
        path: Absolute or relative path to the JSON alert file.

    Returns:
        A dictionary representing the parsed alert.

    Raises:
        FileNotFoundError: If the path does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
        ValueError: If required fields are missing.
    """
    with open(path, "r") as f:
        alert = json.load(f)

    _validate(alert)
    return alert


def parse_alert_directory(directory: str) -> list[dict[str, Any]]:
    """Recursively parse all JSON files in a directory tree as EDR alerts.

    Args:
        directory: Path to a directory containing .json alert files,
                   possibly nested in subdirectories.

    Returns:
        A list of parsed alert dictionaries.
    """
    alerts: list[dict[str, Any]] = []
    for root, _dirs, files in os.walk(directory):
        for fname in sorted(files):
            if not fname.endswith(".json"):
                continue
            full_path = os.path.join(root, fname)
            try:
                alerts.append(parse_alert_file(full_path))
            except (json.JSONDecodeError, ValueError) as e:
                print(f"Warning: skipping {full_path} — {e}")
    return alerts


_REQUIRED_FIELDS = {
    "alert_id", "source", "timestamp", "event_type",
    "hostname", "process_name",
}


def _validate(alert: dict[str, Any]) -> None:
    """Validate that all required fields are present in an alert dict.

    Raises ValueError if any required field is missing.
    """
    missing = _REQUIRED_FIELDS - set(alert.keys())
    if missing:
        raise ValueError(
            f"Alert missing required fields: {', '.join(sorted(missing))}"
        )
