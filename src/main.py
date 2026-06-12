#!/usr/bin/env python3
"""
main.py — auto-triage-bot CLI entry point.

Usage:
    python src/main.py <input_dir> --format json --output results.json

Performs:
    1. Parse EDR alert JSON files from ``input_dir``.
    2. Enrich with mock MISP threat intelligence.
    3. Map to MITRE ATT&CK techniques.
    4. Score severity and produce triage summaries.
    5. Optionally run LLM semantic analysis on command lines.
    6. Optionally correlate findings across alerts for attack chains.
    7. Output a consolidated JSON report.
"""

import argparse
import os
import sys
from typing import Any

# Ensure the project root is on sys.path so that `src.*` imports work
# regardless of how the script is invoked (python3 src/main.py or python3 -m src.main).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.alert_parser import parse_alert_directory
from src.misp_enricher import enrich_alert, can_use_llm
from src.mitre_mapper import map_ttps
from src.triage_engine import score, _load_scoring_config
from src.report import build_finding, build_report, write_report
from src.semantic_analyzer import analyze_command_line, can_use_deepseek
from src.correlator import correlate


def _resolve_input_path(path: str) -> str:
    """Resolve a potentially relative path to an absolute one.

    If *path* is a relative path, it is resolved against the project root
    (one level up from ``src/``), not the current working directory.
    """
    if os.path.isabs(path):
        return path
    # Assume project root is the grandparent of this file's directory
    # i.e. <project>/src/main.py -> <project>
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    resolved = os.path.join(project_root, path)
    if os.path.exists(resolved):
        return resolved
    # Fallback: treat as relative to CWD
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="auto-triage-bot — EDR Alert Triage with MITRE ATT&CK Mapping",
    )
    parser.add_argument(
        "input_dir",
        nargs="?",
        default="test_corpus",
        help="Directory containing EDR alert JSON files (default: test_corpus/)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results.json",
        help="Output file path (default: results.json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-alert triage summaries to stdout",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM semantic analysis (DeepSeek V4)",
    )
    parser.add_argument(
        "--correlate",
        action="store_true",
        default=True,
        help="Enable cross-alert correlation (default: True)",
    )
    parser.add_argument(
        "--scoring-config",
        type=str,
        default=None,
        help="Path to scoring configuration JSON for weighted multi-factor scoring. "
             "If not provided, falls back to default threshold-based logic.",
    )
    parser.add_argument(
        "--calibrator",
        type=str,
        default=None,
        help="Path to a pickled isotonic regression calibrator (.pkl). "
             "If provided with --scoring-config, calibrated scoring is used.",
    )

    args = parser.parse_args()

    input_dir = _resolve_input_path(args.input_dir)
    if not os.path.isdir(input_dir):
        print(f"Error: input directory '{input_dir}' not found.", file=sys.stderr)
        sys.exit(1)

    # ── Parse alerts ──────────────────────────────────────────────
    alerts = parse_alert_directory(input_dir)
    if not alerts:
        print(f"Warning: no JSON alert files found in '{input_dir}'.", file=sys.stderr)
        # Still produce an empty report

    if args.verbose:
        llm_available = can_use_llm()
        if llm_available:
            print("[+] DeepSeek V4 key found — LLM semantic enrichment available.")

    # Determine if we should run LLM analysis
    run_llm = not args.no_llm and can_use_deepseek()

    # Load scoring config if specified
    scoring_config = None
    if args.scoring_config:
        scoring_config = _load_scoring_config(args.scoring_config)
        if scoring_config is None:
            print(f"Warning: could not load scoring config from '{args.scoring_config}'. "
                  "Falling back to threshold-based scoring.", file=sys.stderr)
        elif args.verbose:
            print(f"[+] Loaded weighted scoring config from '{args.scoring_config}'.")

    # ── Process each alert ────────────────────────────────────────
    findings: list[dict[str, Any]] = []
    for alert in alerts:
        # 1. MISP enrichment (mock mode)
        misp_data = enrich_alert(alert)

        # 2. MITRE ATT&CK mapping
        ttps = map_ttps(alert)

        # 3. Semantic analysis (LLM) — run before scoring so we can
        #    optionally factor obfuscation into recommendations
        semantic_result = None
        if run_llm:
            cmd_line = alert.get("command_line", "")
            if cmd_line:
                semantic_result = analyze_command_line(cmd_line)
                if args.verbose and semantic_result.get("is_suspicious"):
                    print(
                        f"  [LLM] {alert['alert_id']}: obfuscation detected "
                        f"(score={semantic_result['obfuscation_score']:.2f})"
                    )

        # 4. Triage scoring
        severity, triage_summary, recommendations = score(
            alert, ttps,
            misp_enrichment=misp_data,
            scoring_config=scoring_config,
            calibrator_path=args.calibrator,
        )

        # 5. Build finding
        finding = build_finding(
            alert=alert,
            ttps=ttps,
            misp_enrichment=misp_data,
            severity=severity,
            triage_summary=triage_summary,
            recommendations=recommendations,
            semantic_scan=semantic_result,
        )
        findings.append(finding)

        if args.verbose:
            print(f"  [{severity:5s}] {alert['alert_id']}: {triage_summary[:120]}")

    # ── Cross-alert correlation ───────────────────────────────────
    correlation_chains: list[dict[str, Any]] = []
    if args.correlate and findings:
        correlation_chains = correlate(findings)
        if args.verbose and correlation_chains:
            for chain in correlation_chains:
                print(
                    f"  [CHAIN {chain['severity']:8s}] {chain['chain_id']}: "
                    f"{chain['description'][:100]}..."
                )

    # ── Build & write report ──────────────────────────────────────
    report = build_report(findings, correlation_chains=correlation_chains)
    write_report(report, args.output)

    # Also print a quick summary
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    h = sum(1 for f in findings if f["severity"] == "HIGH")
    m = sum(1 for f in findings if f["severity"] == "MEDIUM")
    l = sum(1 for f in findings if f["severity"] == "LOW")
    c = sum(1 for f in findings if f["severity"] == "CLEAN")
    print(f"\nSummary: {len(findings)} alerts processed "
          f"(CRITICAL={crit}, HIGH={h}, MEDIUM={m}, LOW={l}, CLEAN={c})")
    if correlation_chains:
        print(f"Correlation chains detected: {len(correlation_chains)}")


if __name__ == "__main__":
    main()
