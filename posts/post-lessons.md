# What I Learned Building a Mock-Mode SOC Triage Tool

I spent 2 hours building auto-triage-bot — a Python stdlib EDR triage pipeline with MISP enrichment, MITRE ATT&CK mapping, and cross-alert correlation. Here are the takeaways.

First, mock mode forces better architecture. Building a local MISP database made me think about IoC types, matching logic, and data modeling more deeply than wrapping PyMISP around a live instance would have.

Second, cross-alert correlation is where the intelligence lives. Individual alert findings are table stakes. Attack chains are what incident responders actually need.

Third, Python stdlib is surprisingly sufficient. No pandas, no requests, no numpy. The entire pipeline — JSON parsing, regex mapping, data aggregation — runs on built-in modules. This matters for air-gapped and containerized environments.

Fourth, dual-mode capability (LLM optional, deterministic fallback) should be the default pattern. Detect capability at runtime, use it if available, degrade gracefully if not. No hard dependencies.

Fifth, 5 alerts taught me more about triage pipeline design than 500 alerts would have. Small, focused test corpora surface architecture decisions faster than scale ever does.

#infosec #python #soc
