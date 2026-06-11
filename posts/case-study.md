# Case Study: auto-triage-bot

## Problem

SOC analysts at mid-size organizations face a fundamental scalability problem. A typical deployment generates thousands of EDR alerts per day. Each alert must be manually triaged: check the process name, cross-reference against threat intelligence, map to MITRE ATT&CK techniques, determine severity, and decide whether to escalate. When an analyst needs to correlate alerts across time to detect multi-step attack chains — PowerShell execution followed by scheduled task creation, for example — the process becomes entirely manual and error-prone.

The gap is not detection. Modern EDR tools detect anomalous activity reliably. The gap is triage speed, intelligence enrichment, and cross-alert correlation at machine speed.

## Approach

auto-triage-bot is a modular triage pipeline built in Python stdlib — zero external dependencies. The architecture is a linear processing chain: parse raw EDR alerts, enrich with MISP threat intelligence, map to MITRE ATT&CK techniques, run optional LLM semantic analysis, score severity, correlate across alerts for attack chain detection, and output a consolidated JSON report.

Each stage is a discrete Python module with a single responsibility. This makes the pipeline testable, extensible, and auditable — each transformation from raw alert to triage finding is transparent and debuggable.

Key design decisions:
- **stdlib-only core.** No pip install. No pandas, no requests, no numpy. The entire pipeline runs on Python built-in modules, which matters for air-gapped environments and CI pipelines where dependency approval is slow.
- **Mock MISP mode.** A local IoC database replaces live MISP API calls. This enables offline execution and reproducible test runs without requiring a MISP instance or API key.
- **Optional LLM bolt-on.** DeepSeek V4 semantic analysis is detected at runtime. If the API key is present, command-line strings are analyzed for obfuscation. If not, the pipeline degrades gracefully with a clear notice.
- **Deterministic ATT&CK mapping.** Rule-based regex matching for known binaries and command-line patterns ensures explainable, auditable technique assignment.

## Implementation

The pipeline consists of 7 modules orchestrated by a CLI entry point:

1. **alert_parser.py** — Reads JSON alert files from a directory, normalizes fields, and validates required data.
2. **misp_enricher.py** — Maintains an internal mock MISP threat intelligence database keyed by SHA1 hashes, IP addresses, and domains. Matches alert IoCs against the database and returns matched indicators with tags, descriptions, and threat level.
3. **mitre_mapper.py** — Uses process name and command-line rules to map alerts to MITRE ATT&CK techniques. Covers T1059.001 (PowerShell), T1204.002 (Malicious File), T1053.005 (Scheduled Task), and T1218.011 (Rundll32).
4. **triage_engine.py** — Scores each alert based on TTP count, MISP threat level, and event type. Produces severity labels, plain-English summaries, and prioritized recommendations.
5. **semantic_analyzer.py** — Optional DeepSeek V4 analysis of command-line strings. Returns obfuscation scores and detected suspicious patterns when the LLM is available.
6. **correlator.py** — Analyzes all findings for cross-alert patterns: shared IoCs, sequential tactic chains, and temporal proximity. Produces correlation chain objects with critical severity and consolidated recommendations.
7. **report.py** — Collects findings and correlation chains into a structured JSON report with TTP coverage statistics and overall assessment.

The test corpus contains 5 alerts: 3 injected with malicious indicators (PowerShell from Office macro, schtasks persistence, rundll32 with no arguments) and 2 clean benign alerts (user login, service start). This split tests both the detection pipeline and the false-positive handling.

## Results

The pipeline processed all 5 alerts in under 2 seconds. Results:

- **3 HIGH severity**, 2 CLEAN — correct classification of all test cases
- **4 MITRE ATT&CK TTPs mapped**: T1059.001 (2 occurrences), T1204.002 (3), T1053.005 (1), T1218.011 (1)
- **2 correlation chains detected**: persistence_chain (PowerShell → Scheduled Task) and intrusion_chain (Malicious File → Rundll32 C2)
- **Overall assessment**: CRITICAL — immediate response warranted

The correlation chains are the most significant output. Individually, each HIGH alert would trigger investigation. But the correlator connects ALERT-003 (PowerShell) to ALERT-004 (Scheduled Task) into a persistence chain, and ALERT-003 to ALERT-005 (Rundll32) into an intrusion chain. A single-alert triage pipeline would miss these relationships entirely.

## Lessons

Building auto-triage-bot confirmed several patterns I've observed across security engineering projects:

1. **Mock mode forces better architecture.** Building a mock MISP database forced me to think about IoC types and matching logic more carefully than wrapping PyMISP would have.
2. **Cross-alert correlation is where the intelligence lives.** Individual alert triage produces findings. Correlation produces attack chains. Responders need the latter.
3. **Graceful degradation should be the default.** The LLM layer is a bolt-on, not a dependency. This pattern — detect capability at runtime, use it if available, degrade if not — is broadly applicable to security tools that want production readiness without API dependencies.
4. **Python stdlib is sufficient for a surprising amount of security engineering.** The entire pipeline runs on built-in modules. No pandas, no requests, no numpy. This matters for environments where adding dependencies requires approval cycles.

The tool is available at github.com/Rush-me-not/auto-triage-bot.

#infosec #mitreattack #socautomation
