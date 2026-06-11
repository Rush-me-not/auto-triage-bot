# auto-triage-bot — Project Brief

**Author:** Rushaan | IT Security Analyst, Concordia University
**Date:** June 11, 2026
**Target Audience:** Security engineers, hiring managers, AI/ML practitioners

---

## The Problem

SOC analysts drown in alert volume. A mid-size organization generates thousands of EDR alerts per day, and each one requires manual triage: checking process names, cross-referencing threat intelligence, mapping to MITRE ATT&CK techniques, and prioritizing response. This process does not scale.

MISP enrichment and MITRE ATT&CK correlation are almost always manual steps. Analysts eyeball IoCs, search threat intel platforms, and mentally connect alerts into attack chains. By the time a persistence chain is detected, the attacker has already established a foothold.

The gap is not detection — modern EDR tools detect plenty. The gap is triage speed, intelligence enrichment, and cross-alert correlation at machine speed.

---

## What This Tool Does

auto-triage-bot is a triage pipeline that converts raw EDR alerts into actionable intelligence. It processes alerts in five stages:

### Stage 1: Alert Parsing (alert_parser.py)
- Reads JSON-format EDR alerts from a directory
- Normalizes fields (process name, event type, hostname, command line)
- Validates required fields for downstream processing

### Stage 2: MISP Enrichment (misp_enricher.py)
- Matches alert IoCs (hashes, IPs, domains) against a mock MISP threat intel database
- Returns matched indicators, tags, descriptions, and a threat level (High/None)
- Mock-mode: no external API dependency, self-contained for offline evaluation

### Stage 3: MITRE ATT&CK Mapping (mitre_mapper.py)
- Rule-based regex matching: known-binary names and command-line patterns map to TTPs
- Detects PowerShell (T1059.001), Scheduled Tasks (T1053.005), Rundll32 (T1218.011), Malicious File execution (T1204.002)

### Stage 4: Semantic Analysis (semantic_analyzer.py)
- Optional DeepSeek V4 LLM analysis of command-line strings
- Obfuscation scoring and suspicious pattern detection
- Graceful degradation when LLM is unavailable

### Stage 5: Triage Scoring + Correlation (triage_engine.py + correlator.py)
- Severity scoring: number of TTPs × threat level weighting
- Cross-alert chain detection: links alerts sharing IoCs or sequential TTP patterns
- Produces triage summaries and prioritized recommendations

---

## How It Works

```
EDR Alert (JSON) ──> +-----------------------+
                     | 1. alert_parser.py    │  Parse raw EDR alerts
                     +----------+------------+
                                |
                     +----------v------------+
                     │ 2. misp_enricher.py   │  Mock MISP enrichment
                     +----------+------------+
                                |
                     +----------v------------+
                     │ 3. mitre_mapper.py    │  MITRE ATT&CK mapping
                     +----------+------------+
                                |
                     +----------v------------+
                     │ 4. semantic_analyzer  │  (Optional) DeepSeek V4
                     +----------+------------+
                                |
                     +----------v------------+
                     │ 5. triage_engine.py   │  Scoring + severity + recs
                     +----------+------------+
                                |
                     +----------v------------+
                     │ 6. correlator.py      │  Cross-alert chain detection
                     +----------+------------+
                                |
                     +----------v------------+
                     │ 7. report.py          │  JSON report output
                     +-----------------------+
                                |
                                v
                          results.json
```

**Design decisions:**
- **stdlib-only core:** The entire pipeline uses Python stdlib; no external packages required. The only optional dependency is the DeepSeek V4 API key for LLM analysis.
- **Mock MISP mode:** No real MISP API calls. A local IoC database lets the tool run offline, making it CI-friendly and reproducible for evaluation.
- **DeepSeek V4 optional:** LLM semantic analysis is a bolt-on, not a dependency. If the API key is present, the tool runs command-line analysis. If not, it degrades gracefully with a clear message.
- **Rule + ML hybrid:** MITRE ATT&CK mapping uses deterministic rules (reliable, explainable); the LLM layer adds semantic detection of obfuscation (flexible, context-aware).

---

## Test Results

| Metric | Value |
|--------|-------|
| **Total alerts processed** | 5 |
| **HIGH severity** | 3 |
| **CLEAN severity** | 2 |
| **MITRE ATT&CK TTPs mapped** | 4 (T1059.001, T1204.002, T1053.005, T1218.011) |
| **Correlation chains detected** | 2 |
| **Overall assessment** | CRITICAL |

**Alert breakdown:**
- `clean/user_login.json` (logonui.exe) → CLEAN — benign user activity
- `clean/service_start.json` (services.exe) → CLEAN — routine service start
- `injected/powershell_from_office.json` (powershell.exe) → HIGH — 2 TTPs, MISP threat level: High
- `injected/schtasks_persistence.json` (schtasks.exe) → HIGH — 3 TTPs, MISP threat level: High
- `injected/rundll32_no_args.json` (rundll32.exe) → HIGH — 2 TTPs, MISP threat level: None

**Correlation chains:**
1. **CHAIN-PERSISTENCE_CHAIN-001** (CRITICAL): PowerShell → Scheduled Task persistence — links alerts 003 and 004
2. **CHAIN-INTRUSION_CHAIN-001** (CRITICAL): Malicious File → Rundll32 C2 — links alerts 003 and 005

---

## Architecture

```
src/
├── main.py              — CLI entry point: argument parsing, pipeline orchestration
├── alert_parser.py      — Reads & normalizes EDR alert JSON from directory
├── misp_enricher.py     — Mock MISP IoC matching and threat level assignment
├── mitre_mapper.py      — Rule-based process → MITRE ATT&CK technique mapping
├── triage_engine.py     — Severity scoring and recommendation generation
├── semantic_analyzer.py — Optional DeepSeek V4 command-line analysis
├── correlator.py        — Cross-alert correlation for attack chain detection
├── report.py            — Builds and writes the consolidated JSON report
└── __init__.py
```

**Test corpus:**
```
test_corpus/
├── clean/
│   ├── user_login.json              — CLEAN (benign)
│   └── service_start.json           — CLEAN (benign)
└── injected/
    ├── powershell_from_office.json  — HIGH (T1059.001, T1204.002)
    ├── schtasks_persistence.json    — HIGH (T1059.001, T1053.005, T1204.002)
    └── rundll32_no_args.json        — HIGH (T1204.002, T1218.011)
```

---

## What This Proves

- **SOC automation viability:** A stdlib-only Python pipeline can triage 5 alerts in under 2 seconds, enriching each with MISP context, MITRE ATT&CK techniques, and severity scoring.
- **AI-augmented triage:** DeepSeek V4 adds semantic analysis without being a hard dependency — the tool works without it and improves with it.
- **MISP + ATT&CK fluency:** The pipeline demonstrates understanding of both MISP threat intelligence workflows and MITRE ATT&CK framework structure, including tactic-level correlation.
- **Cross-alert correlation:** The correlator detects multi-step attack chains (persistence, intrusion) that a single-alert view would miss.
- **Reproducible evaluation:** Self-contained test corpus and mock MISP mode means anyone can run the full pipeline without external accounts or services.

---

## Limitations

**Current:**
- **Mock MISP (no real API):** The MISP enricher uses a local JSON lookup table instead of a live MISP instance. Real MISP APIs would return fresher intelligence and support write-back.
- **No live EDR integration:** Alerts must be pre-exported as JSON files. No direct SIEM/EDR API ingestion (e.g., SentinelOne, CrowdStrike, QRadar).
- **Rule-based ATT&CK mapping:** Current rules cover 4 techniques; a production system would need broader coverage and fuzzy matching.
- **LLM reliability:** DeepSeek V4 analysis depends on API availability and model consistency.

**Planned enhancements:**
- Live MISP API integration with PyMISP
- EDR API connectors (SentinelOne, CrowdStrike)
- Expanded MITRE ATT&CK coverage (all enterprise techniques)
- SIEM output formats (CEF, LEEF)
- Real-time monitoring mode (watch directory for new alerts)

---

## Usage

```bash
# Basic run with test corpus
python src/main.py test_corpus/

# JSON output to specific file
python src/main.py test_corpus/ --format json --output results.json

# Verbose mode with per-alert summaries
python src/main.py test_corpus/ --verbose

# Skip LLM analysis
python src/main.py test_corpus/ --no-llm

# Text summary output
python src/main.py test_corpus/ --format text
```

---

## Why This Matters

Every SOC team faces the same fundamental problem: more alerts than analysts can triage. The industry response has been expensive SIEM platforms, SOAR playbooks, and managed detection services — all of which help, but none of which solve the core bottleneck of converting raw telemetry into structured, actionable intelligence at machine speed.

auto-triage-bot demonstrates that a lightweight, stdlib-only pipeline can bridge this gap. By combining mock MISP enrichment, deterministic MITRE ATT&CK mapping, optional LLM semantic analysis, and cross-alert correlation, it produces what every SOC analyst needs: a prioritized, context-rich triage report that surfaces attack chains — not just individual alerts.

This is the architecture that scales. Not a bigger SIEM. Smarter automation.
