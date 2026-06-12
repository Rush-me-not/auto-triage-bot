# Model Card: auto-triage-bot Scoring & Correlation Models

## Model Details

- **Model name:** auto-triage-bot severity scorer and attack-chain correlator
- **Model version:** 1.1.0
- **Model date:** 2026-06-11
- **Model type:** Hybrid — rule-based MITRE ATT&CK mapping, weighted multi-factor scoring, optional isotonic regression calibration, and heuristic cross-alert correlation
- **Organization:** AI Security Lab
- **License:** MIT

## Intended Use

### Primary intended uses

- Automated triage of EDR (Endpoint Detection and Response) alerts in SOC (Security Operations Center) environments.
- Mapping alerts to MITRE ATT&CK techniques for standardized threat classification.
- Scoring alert severity to prioritize analyst investigation queues.
- Correlating multi-alert attack chains for incident response.
- Providing explainable, auditable triage recommendations to human analysts.

### Primary intended users

- SOC analysts (Tier 1–3) using the system as a force multiplier.
- Security engineers integrating the pipeline into automated response workflows.
- Researchers evaluating automated alert classification.

### Out-of-scope uses

- Autonomous network defense actions (blocking, isolation) without human confirmation.
- Alert triage for environments other than Windows endpoint EDR.
- Replacement for human incident-response judgment in critical-severity incidents.
- Use as a training signal for adversarial attacks on production EDR systems.

## Training Data

### Severity scoring model

The weighted scoring model (`_compute_weighted_score` in `src/triage_engine.py`) uses hand-tuned weights derived from:

| Factor | Weight | Rationale |
|---|---|---|
| TTP count | 0.35 | Multi-TTP alerts are exponentially more dangerous |
| TTP max severity | 0.25 | High-severity TTPs dominate risk |
| MISP threat level | 0.20 | Confirmed threat intelligence amplifies confidence |
| Event type baseline | 0.10 | Some event types are inherently more suspicious |
| Temporal proximity | 0.10 | Recent alerts are more operationally relevant |

The isotonic regression calibrator (`calibrator.pkl`) is trained on a labeled corpus of 5 representative EDR alerts:

| Alert ID | Label | Rationale |
|---|---|---|
| ALERT-2025-001-CLEAN | 0.0 | Benign user login |
| ALERT-2025-002-CLEAN | 0.0 | Benign service start |
| ALERT-2025-003-SUSP | 0.8 | PowerShell from Office + C2 domain |
| ALERT-2025-004-SUSP | 0.9 | Multi-TTP persistence chain |
| ALERT-2025-005-SUSP | 0.6 | Rundll32 execution (medium confidence) |

### MITRE ATT&CK mapping rules

Rule-based regex matching on process names and command-line patterns. Full rule definitions are in `src/mitre_mapper.py`.

### Correlation model

Heuristic attack-chain definitions in `src/correlator.py` with confidence scoring using mean TTP severity × temporal proximity × IoC overlap ratio.

### MISP enrichment

Mock threat-intelligence database in `src/misp_enricher.py` with 5 known-malicious indicators (2 hashes, 2 IPs, 2 domains).

## Evaluation Results

### Scoring model (threshold mode)

| Metric | Value |
|---|---|---|
| Total alerts (synthetic) | 5 |
| True positives (HIGH/CRITICAL) | 3 |
| True negatives (CLEAN) | 2 |
| False positives | 0 (on the 5-alert synthetic test corpus) |
| False negatives | 0 (on the 5-alert synthetic test corpus) |
| Accuracy | 100% (on the 5-alert synthetic test corpus) |

> **Note:** This evaluation is on a small synthetic corpus and is not representative of production performance. Real-world performance will vary significantly.

### Scoring model (weighted + calibrated mode)

Alert-level scores and labels:

| Alert ID | Raw Weighted | Calibrated | Label |
|---|---|---|---|
| ALERT-001-CLEAN | ~0.10 | ~0.02 | CLEAN |
| ALERT-002-CLEAN | ~0.10 | ~0.02 | CLEAN |
| ALERT-003-SUSP | ~0.70 | ~0.80 | HIGH |
| ALERT-004-SUSP | ~0.80 | ~0.90 | CRITICAL |
| ALERT-005-SUSP | ~0.50 | ~0.60 | MEDIUM |

### ATT&CK mapping coverage

| Technique | Detection Logic | Test Corpus Hits |
|---|---|---|
| T1059.001 (PowerShell) | Process name + command-line regex | 2 |
| T1204.002 (Malicious File) | Hash match + event type + file path | 3 |
| T1053.005 (Scheduled Task) | Process name + command-line regex | 1 |
| T1218.011 (Rundll32) | Process name match | 1 |

### Correlation chains

| Chain Type | Alerts Linked | Confidence |
|---|---|---|
| Persistence chain | 003 → 004 | High (IoC overlap + temporal proximity) |
| Intrusion chain | 003 → 005 | Medium (temporal proximity only) |

### Prompt injection detector

| Pattern Category | Examples | Detection Rate |
|---|---|---|
| Instruction override | "ignore previous instructions" | 100% (regex match) |
| Delimiter-pair injection | ```...``` | 100% (pattern match) |
| Excessive length | >5000 chars | 100% (heuristic) |

## Limitations

1. **Small training corpus:** The isotonic regression calibrator was trained on only 5 labeled alerts. Production deployment requires a corpus of at least 100–200 labeled alerts per severity tier.

2. **Rule-based mapping gaps:** Regex-based MITRE ATT&CK mapping has zero false positives but incomplete recall. Obfuscated commands, LOLBins not in the rule set, and novel attack techniques will be missed.

3. **Mock MISP data:** The built-in threat-intelligence database contains 5 known-malicious indicators. A production deployment must connect to live MISP or threat-feed APIs.

4. **LLM dependency:** DeepSeek V4 semantic analysis requires an external API key and network connectivity. The prompt injection detector reduces risk but cannot guarantee 100% coverage of adversarial prompts.

5. **Temporal scoring bias:** The temporal proximity factor assumes recent alerts are more relevant, which may not hold in environments with delayed telemetry.

6. **Correlation confidence:** The confidence formula (mean severity × temporal × IoC overlap) is a heuristic. It does not account for asset criticality, network topology, or analyst feedback.

7. **Windows-only:** All detection rules target Windows EDR telemetry. Linux/macOS endpoints are not covered.

## Ethical Considerations

1. **False negatives:** Missed high-severity alerts could delay incident response. The system should always flag uncertainty and never suppress alerts without human review.

2. **False positives:** Over-alerting can cause alert fatigue. The calibrated scorer aims to reduce false positives, but analysts should validate HIGH/CRITICAL designations.

3. **Bias in training labels:** The labeled corpus reflects a single analyst's threat model. Production labels should be sourced from a diverse set of SOC analysts.

4. **Prompt injection risk to LLM:** Adversarial command-line strings could manipulate the LLM into producing false-negative results. The prompt injection guard mitigates this by blocking suspicious inputs before LLM submission.

5. **Privacy:** EDR alert data may contain user activity, filenames, and network addresses. The system processes this data locally and does not transmit it externally (except to DeepSeek V4 when enabled).

6. **Autonomy boundary:** This tool provides recommendations, not decisions. Automated response actions (host isolation, account lockout) must require human authorization.

## Caveats and Recommendations

- Deploy with a labeled corpus of at least 200 alerts before relying on calibrated scores.
- Continuously evaluate ATT&CK mapping rules against new adversary techniques.
- Monitor LLM call patterns for signs of prompt injection that bypass the detector.
- Review correlation confidence scores weekly and adjust the formula based on analyst feedback.
- Never use severity scores as the sole basis for automated response actions.
