# auto-triage-bot

EDR alert triage pipeline with MISP enrichment, MITRE ATT&CK mapping, optional DeepSeek V4 semantic analysis, and cross-alert correlation. Built with Python stdlib — zero external dependencies.

## Problem

SOC analysts receive thousands of EDR alerts daily. Each alert requires manual cross-referencing against threat intelligence (MISP), manual mapping to MITRE ATT&CK techniques, and mental correlation across alerts to detect multi-step attack chains. This process is slow, inconsistent, and does not scale with alert volume.

## Approach

auto-triage-bot is a modular triage pipeline that automates the entire workflow: parse → enrich → map → analyze → score → correlate → report. Each stage is a discrete Python module with a single responsibility, making the pipeline testable, extensible, and auditable.

### Key design decisions

- **stdlib-only core:** No pip install required. The pipeline runs on any Python 3.11+ environment with only standard library modules.
- **Mock MISP mode:** A local IoC database replaces live MISP API calls, enabling offline execution and reproducible test runs.
- **Optional LLM bolt-on:** DeepSeek V4 semantic analysis is detected at runtime. If the API key is present, it runs. If not, the pipeline degrades gracefully.
- **Deterministic ATT&CK mapping:** Rule-based regex matching for known binaries and command-line patterns ensures explainable, auditable technique assignment.
- **Calibrated scoring:** Optional isotonic regression calibration refines the weighted score into better-calibrated probabilities (use `--scoring-config` + `--calibrator`).
- **Correlation confidence:** Each attack chain includes a confidence score (0–1) based on mean TTP severity, temporal proximity, and IoC overlap.
- **Prompt injection guard:** Command-line strings are inspected for delimiter-pair injection, instruction-override patterns, and excessive-length heuristics before LLM submission.

## Tech Stack

- **Language:** Python 3.11+
- **Key libraries:** Python stdlib only (json, os, sys, re, argparse, pathlib)
- **Optional:** DeepSeek V4 API (via httplib/urllib) for LLM semantic analysis
- **Data sources:** EDR alert JSON files (process_creation, user_login, service_start events)
- **Output:** Consolidated JSON report with findings, correlation chains, and summary

## Implementation

### Module 1: `alert_parser.py` — Alert Ingestion

Reads JSON files from a directory, normalizes fields (alert_id, timestamp, hostname, process_name, command_line), and validates required fields. Returns a list of parsed alert dictionaries ready for downstream processing.

### Module 2: `misp_enricher.py` — Threat Intelligence

Maintains an internal mock MISP threat intelligence database keyed by IoCs (SHA1 hashes, IP addresses, domains). For each alert, extracts IoCs from the command line and event data, matches them against the database, and returns matched indicators with tags, descriptions, and a threat level score (High/None).

### Module 3: `mitre_mapper.py` — ATT&CK Technique Mapping

Uses rule-based detection on process names and command-line patterns to map alerts to MITRE ATT&CK techniques:

| Technique ID | Name | Detection Logic |
|---|---|---|
| T1059.001 | PowerShell | Process name is `powershell.exe` |
| T1204.002 | Malicious File | Suspicious executable invocation patterns |
| T1053.005 | Scheduled Task | `schtasks.exe` with `/create` flag |
| T1218.011 | Rundll32 | `rundll32.exe` with no arguments |

### Module 4: `triage_engine.py` — Severity Scoring

Scores each alert based on: number of mapped TTPs, MISP threat level, and event type. Produces a severity label (HIGH/CLEAN), a plain-English triage summary, and prioritized recommendations. The scoring algorithm weights multi-TTP alerts with confirmed MISP matches as highest priority. Supports optional isotonic regression calibration via `--scoring-config` and `--calibrator` flags for better-calibrated probability scores.

### Module 5: `semantic_analyzer.py` — LLM Analysis (Optional)

Detects whether a DeepSeek V4 API key is available at runtime. If so, sends command-line strings for semantic analysis and returns an obfuscation score plus detected suspicious patterns. If the LLM is unavailable, returns a clean result with an explanatory message.

### Module 6: `correlator.py` — Cross-Alert Correlation

Analyzes all findings for cross-alert patterns: shared IoCs (same IPs, hashes, or domains across alerts), sequential tactic chains (Execution → Persistence, Execution → Defense Evasion), and temporal proximity. Produces correlation chain objects with chain type (persistence_chain, intrusion_chain), critical severity, and consolidated recommendations.

### Module 7: `report.py` — Report Generation

Collects all findings and correlation chains into a structured JSON report. Aggregates TTP coverage statistics, top tactics by frequency, and an overall assessment. Writes the report to disk in the specified output format (JSON or text).

### Module 0: `main.py` — Pipeline Orchestration

CLI entry point with argument parsing, pipeline orchestration, and user feedback. Supports `--verbose`, `--no-llm`, `--format`, and `--output` flags.

## Results

### Test Corpus

**5 alerts processed** (3 injected, 2 clean):

| Alert ID | Severity | TTPs | MISP Threat Level |
|---|---|---|---|
| ALERT-2025-001-CLEAN | CLEAN | — | None |
| ALERT-2025-002-CLEAN | CLEAN | — | None |
| ALERT-2025-003-SUSP | HIGH | T1059.001, T1204.002 | High |
| ALERT-2025-004-SUSP | HIGH | T1059.001, T1053.005, T1204.002 | High |
| ALERT-2025-005-SUSP | MEDIUM | T1204.002, T1218.011 | None |

### MITRE ATT&CK Coverage

| Tactic | Technique ID | Technique Name | Occurrences |
|---|---|---|---|
| Execution | T1059.001 | PowerShell | 2 |
| Execution | T1204.002 | Malicious File | 3 |
| Persistence | T1053.005 | Scheduled Task | 1 |
| Defense Evasion | T1218.011 | Rundll32 | 1 |

### Correlation Chains

1. **CHAIN-PERSISTENCE_CHAIN-001** (CRITICAL): ALERT-003 (PowerShell) → ALERT-004 (Scheduled Task). Pattern: Office macro → PowerShell → persistence.
2. **CHAIN-INTRUSION_CHAIN-001** (CRITICAL): ALERT-003 (Malicious File) → ALERT-005 (Rundll32 C2). Pattern: Payload delivery → defense evasion + C2.

**Overall assessment:** CRITICAL — 3 HIGH alerts with confirmed MITRE ATT&CK TTPs. Immediate response warranted.

## Lessons Learned

1. **Mock mode is underrated.** Building a mock MISP database forced me to think deeply about IoC types and matching logic — more than if I had simply slapped a PyMISP wrapper on a live instance. The mock-first approach made the architecture cleaner and the testing more thorough.
2. **Rule-based mapping is fragile but explainable.** Regex rules for ATT&CK mapping catch exactly what you tell them to catch, which means zero false positives — but also means gaps in coverage. The tradeoff between precision and recall is real; an LLM layer helps bridge it.
3. **Cross-alert correlation is where the intelligence lives.** Individual alert triage produces findings. Cross-alert correlation produces attack chains. The chain view is far more valuable to an incident responder than a list of individual alerts.
4. **Graceful degradation matters.** The LLM analysis is a bolt-on, not a dependency. This pattern — detect capability at runtime, use it if available, degrade if not — should be the default for security tools that want to be production-ready without forcing API dependencies.
5. **Python stdlib is sufficient for a surprising amount of security engineering.** No pandas, no requests, no numpy. The entire pipeline runs on built-in modules. This matters for air-gapped environments, containerized deployments, and CI pipelines where adding dependencies requires approval.

## Future Work

- Live MISP API integration (PyMISP)
- EDR API connectors (SentinelOne, CrowdStrike, QRadar)
- Expanded MITRE ATT&CK coverage (all enterprise techniques)
- Real-time directory watch mode
- SIEM output formats (CEF, LEEF, Elastic ECS)
- Web UI for interactive triage review
- Replace pickle serialization for calibrator with safetensors or signed JSON format
- Credential scrubbing before LLM submission
- Structured audit logging with append-only log file

## Build Log

- **Started:** June 11, 2026
- **Completed:** June 11, 2026
- **Total time:** ~2 hours
- **Tech stack:** Python 3.11 stdlib, DeepSeek V4 (optional), MITRE ATT&CK v15

## Usage

```bash
# Basic run with test corpus
python3 src/main.py test_corpus/

# JSON output to specific file
python3 src/main.py test_corpus/ --format json --output results.json

# Verbose mode with per-alert summaries
python3 src/main.py test_corpus/ --verbose

# Skip LLM analysis
python3 src/main.py test_corpus/ --no-llm

# Text summary output
python3 src/main.py test_corpus/ --format text

# Calibrated scoring with scoring config and calibrator
python3 src/main.py test_corpus/ --scoring-config src/scoring_config.json --calibrator calibrator.pkl

# Help
python3 src/main.py --help
```

## Repository

GitHub: https://github.com/Rush-me-not/auto-triage-bot (private)
