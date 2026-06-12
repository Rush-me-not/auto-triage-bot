# STRIDE Threat Model: auto-triage-bot

**System:** auto-triage-bot — EDR alert triage pipeline  
**Version:** 1.1.0  
**Date:** 2026-06-12  
**Author:** AI Security Lab

---

## 1. System Overview

auto-triage-bot is a modular Python pipeline that:

1. Ingests EDR alert JSON files from a local directory.
2. Enriches alerts with mock MISP threat intelligence.
3. Maps alerts to MITRE ATT&CK techniques via rule-based detection.
4. Scores alert severity using a weighted multi-factor model (with optional isotonic regression calibration).
5. Optionally sends command-line strings to DeepSeek V4 LLM for semantic analysis.
6. Correlates findings into multi-alert attack chains with probabilistic confidence.
7. Outputs a consolidated JSON report.

The system is designed for air-gapped or network-constrained environments (stdlib-only core) with an optional LLM bolt-on.

---

## 2. Data-Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        TRUST BOUNDARY: FILESYSTEM                       │
│                                                                         │
│  ┌──────────┐     ┌──────────────┐     ┌────────────────────────────┐  │
│  │ EDR Alert│────>│ alert_parser │────>│ Parsed alert dicts         │  │
│  │ JSON Dir │     └──────────────┘     │ (in-process Python dicts)  │  │
│  └──────────┘            │               └────────┬─────────────────┘  │
│                          │                         │                    │
│                          v                         v                    │
│               ┌──────────────────┐         ┌───────────────────┐       │
│               │ misp_enricher     │<────────│ Alert dict         │       │
│               │ (mock MISP DB)   │         │ + IoC matches      │       │
│               └────────┬─────────┘         └────────┬──────────┘       │
│                        │                          │                    │
│                        v                          v                    │
│               ┌──────────────────┐   ┌────────────────────────┐       │
│               │ mitre_mapper      │  │ triage_engine            │       │
│               │ (regex rules)     │  │ (weighted + calibrated) │       │
│               └────────┬─────────┘   └────────────┬─────────────┘      │
│                        │                          │                    │
│                        v                          v                    │
│         ┌──────────────────────────────────────────────┐               │
│         │           Finding dict                       │               │
│         │  (severity, TTPs, MISP data, summary)        │               │
│         └──────────────┬───────────────────────────────┘              │
│                        │                                               │
│          ┌─────────────┼─────────────────┐                            │
│          v             v                   v                            │
│  ┌──────────────┐ ┌────────────┐ ┌──────────────────┐                │
│  │ correlator    │ │ prompt_    │ │ semantic_analyzer │                │
│  │ (chain       │ │ injection_ │ │ (DeepSeek V4)     │                │
│  │  detection + │ │ detector   │ │  [EXTERNAL API]   │                │
│  │  confidence) │ │ [GUARD]    │ └────────┬──────────┘                │
│  └──────┬───────┘ └────────────┘          │                             │
│         │                         ┌───────┴────────┐                  │
│         v                         │ TRUST BOUNDARY: │                  │
│  ┌──────────────┐                │ EXTERNAL NETWORK │                  │
│  │ report.py     │                │ (api.deepseek)  │                  │
│  │ (JSON output) │                └─────────────────┘                  │
│  └──────┬───────┘                                                     │
│         │                   ┌───────────────────────┐                  │
│         v                   │ calibrator.pkl        │                  │
│  ┌──────────────┐           │ (isotonic regression) │                  │
│  │ results.json │           └───────────────────────┘                  │
│  └──────────────┘                                                     │
│                                                                       │
│         ┌───────────────────────┐                                     │
│         │ scoring_config.json   │                                     │
│         └───────────────────────┘                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Trust Boundaries

| Boundary | Description |
|---|---|
| **TB-1: Filesystem** | Alert JSON files are read from the local filesystem. Any process with write access to the input directory can inject malicious alert data. |
| **TB-2: External Network** | Communication with DeepSeek V4 API traverses the network. The LLM endpoint receives command-line strings and returns classification data. |
| **TB-3: Model Filesystem** | `scoring_config.json` and `calibrator.pkl` are loaded from disk. A compromised config/calibrator can manipulate scoring results. |
| **TB-4: In-Process** | Data flows between modules as Python dicts within a single process. No inter-process trust boundary, but mutable shared state is a concern. |

---

## 3. STRIDE Analysis

### S — Spoofing

| ID | Component | Threat | Impact | Mitigation |
|---|---|---|---|---|
| S-1 | alert_parser | Malicious alert JSON with spoofed `alert_id` or `hostname` fields could be crafted to hide attacker activity or create false chains. | False negatives (missed attacks) or false positives (fake chains) | Validate alert schema strictly; cross-reference alert source with EDR platform. |
| S-2 | semantic_analyzer | DeepSeek V4 API responses could be spoofed via MITM if TLS is not verified. | Attacker-controlled obfuscation scores | `urllib.request.urlopen` uses system TLS. Verify `https://` scheme and consider certificate pinning in production. |
| S-3 | correlator | Spoofed timestamps across alerts could create fake temporal chains. | False correlation chains | Correlation confidence formula reduces confidence for temporally distant alerts. Validate alert timestamp sources. |

### T — Tampering

| ID | Component | Threat | Impact | Mitigation |
|---|---|---|---|---|
| T-1 | scoring_config.json | An attacker with filesystem access could modify weights or thresholds to suppress HIGH alerts. | All alerts scored as CLEAN/LOW | Verify config file integrity (checksum). Run with minimal permissions. |
| T-2 | calibrator.pkl | Pickle deserialization executes arbitrary code. A crafted `calibrator.pkl` grants RCE. | **CRITICAL**: Full system compromise | Never load untrusted pickle files. Validate file ownership/permissions. Consider signing the calibrator with HMAC-SHA256. |
| T-3 | alert_parser | Injection of malformed JSON (e.g., `__reduce__` in key names) could cause unexpected behavior in downstream processing. | Processing errors, potential code injection in dynamic evaluation contexts | Strict JSON schema validation; never `eval()` alert data. |
| T-4 | prompt_injection_detector | An attacker could craft command lines that bypass the detector's regex patterns. | Malicious strings sent to LLM | Defense in depth: the detector reduces risk but cannot guarantee 100% coverage. LLM output is treated as untrusted. |
| T-5 | report.json | Output file tampering could present fake triage results to analysts. | Incorrect analyst actions | Write output to a secure directory. Consider signing the output report. |

### R — Repudiation

| ID | Component | Threat | Impact | Mitigation |
|---|---|---|---|---|
| R-1 | main.py | No audit trail of which alerts were processed and what scoring decisions were made. | Analysts cannot verify or reproduce triage decisions | Log scoring decisions (factor details, confidence) to an append-only audit log. |
| R-2 | semantic_analyzer | LLM calls and their responses are not logged. | Cannot verify whether LLM analysis was performed or what it returned | Log LLM request/response metadata (not full content) for audit purposes. |
| R-3 | correlator | Chain formation decisions are not persisted separately from the output report. | Cannot audit why a specific chain was formed | Include chain confidence and reasoning in output. Log chain formation criteria. |

### I — Information Disclosure

| ID | Component | Threat | Impact | Mitigation |
|---|---|---|---|---|
| I-1 | semantic_analyzer | Command-line strings (which may contain credentials, paths, tokens) are sent to DeepSeek V4 over the network. | Credential leakage, PII exposure to third-party LLM provider | Strip known credential patterns before LLM submission. Use `--no-llm` flag for highly sensitive environments. Prompt injection detector provides a second layer. |
| I-2 | report.json | Output JSON contains full alert data including hostnames, usernames, file paths, and IoCs. | Information disclosure if report is stored/accessed insecurely | Restrict file permissions on output. Consider redacting hostnames/usernames in reports shared outside the SOC. |
| I-3 | misp_enricher | Mock MISP database is embedded in source code. | IoC intelligence disclosed to anyone with source access | In production, replace mock DB with MISP API calls that use authenticated sessions. |
| I-4 | calibrator.pkl | Trained calibrator model weights could reveal information about the labeled training corpus. | Insight into what the SOC classifies as malicious | The training corpus itself is more valuable; protect it separately. Calibrator reveals only score-to-probability mapping. |

### D — Denial of Service

| ID | Component | Threat | Impact | Mitigation |
|---|---|---|---|---|
| D-1 | alert_parser | Flooding the input directory with thousands of alert files. | Pipeline takes excessive time; timely triage impossible | Implement rate limiting on input directory size. Alert the SOC if processing exceeds time thresholds. |
| D-2 | semantic_analyzer | DeepSeek V4 API rate limits or outages. | LLM analysis unavailable for all alerts | Graceful degradation (already implemented). Consider request queuing with backoff. |
| D-3 | correlator | Quadratic time complexity for alert pair comparison. | Processing stalls for large alert batches | Limit correlation to alerts within `max_time_window_minutes`. Consider incremental correlation for streaming use cases. |
| D-4 | prompt_injection_detector | Extremely long strings (MBytes) could cause regex backtracking. | CPU exhaustion, pipeline hang | Input already truncated to 2000 chars in `semantic_analyzer.py`. Apply truncation before detector as well. |

### E — Elevation of Privilege

| ID | Component | Threat | Impact | Mitigation |
|---|---|---|---|---|
| E-1 | calibrator.pkl | **Pickle deserialization RCE.** A specially crafted pickle file executes arbitrary code during `CalibratedScorer.__init__()`. | **CRITICAL**: Full code execution in the pipeline process | Use `pickle.Unpickler` with restricted globals or switch to `safetensors`/JSON format. Validate file integrity before loading. |
| E-2 | scoring_config.json | Malicious config could set all weights to 0, classifying all alerts as CLEAN. | All threats ignored by the SOC | Validate config values are within expected ranges (weights sum to 1.0, thresholds are in [0, 1]). |
| E-3 | main.py | The pipeline runs with the user's privileges. If a SOC analyst has elevated access, the pipeline inherits it. | Unintended file writes (e.g., to system directories) | Run the pipeline with minimum necessary privileges. Write output only to designated directories. |
| E-4 | semantic_analyzer | LLM response could instruct the parser to perform privileged actions if output is misinterpreted as code. | Unlikely (output is treated as data), but risk exists if downstream systems auto-act on LLM labels | Never execute LLM responses. Only parse specific JSON fields (`obfuscation_detected`, `patterns`, `confidence`). |

---

## 4. Risk Summary

| Priority | Threat ID | Threat | Severity | Recommended Action |
|---|---|---|---|---|
| P0 | T-2, E-1 | Pickle deserialization RCE | **Critical** | Replace pickle with JSON or signed binary format; validate calibrator integrity |
| P1 | I-1 | Credential leakage to LLM | **High** | Strip credentials before LLM submission; enforce `--no-llm` in sensitive environments |
| P1 | T-1 | Config tampering | **High** | Verify config file checksum; run with minimal permissions |
| P2 | S-1 | Alert spoofing | **Medium** | Validate alert schema; cross-reference with EDR platform |
| P2 | D-1 | Directory flooding DoS | **Medium** | Rate-limit input; timeout guard |
| P3 | R-1 | No audit trail | **Low** | Add structured logging for scoring decisions |
| P3 | I-2 | Report information disclosure | **Low** | Restrict output file permissions |
| P3 | D-3 | Correlation O(n²) | **Low** | Time-window filtering; streaming architecture for production |

---

## 5. Mitigations Already Implemented

1. **Graceful LLM degradation** (`semantic_analyzer.py`): If DeepSeek V4 is unavailable, the pipeline continues with threshold-based analysis.
2. **Prompt injection guard** (`prompt_injection_detector.py`): Command lines are inspected for injection patterns before LLM submission. High-risk inputs are blocked.
3. **Input truncation** (`semantic_analyzer.py`): LLM input is truncated to 2000 characters.
4. **Temporal window filtering** (`correlator.py`): Alert pairs outside the time window are excluded, preventing correlation of temporally distant events.
5. **Calibrated scorer fallback** (`calibrated_scorer.py`): If the calibrator file is missing or corrupt, the system falls back to the weighted model.
6. **No dynamic code execution**: The pipeline never calls `eval()` or `exec()` on alert data.

---

## 6. Recommended Future Mitigations

1. **Replace pickle with safetensors or JSON** for the calibrator file (addresses P0).
2. **Add HMAC-SHA256 signature** to `scoring_config.json` and `calibrator.pkl`.
3. **Credential scrubbing** before LLM submission (strip `password=`, `token=`, `-Secret` patterns).
4. **Structured audit logging** with append-only log file.
5. **Input rate limiting** (max alerts per run, max directory size).
6. **Streaming correlation** architecture for production-scale alert volumes.
