# The Triage Scoring Algorithm Behind auto-triage-bot

One specific thing worth stealing: the triage scoring function.

It weights three factors: number of mapped MITRE ATT&CK TTPs, MISP enrichment threat level, and event type severity baseline. A powershell.exe alert with 2 TTPs and a High MISP match scores higher than a rundll32.exe alert with 2 TTPs and no MISP match — even though both are HIGH severity.

The function produces three outputs: a severity label (HIGH/CLEAN), a plain-English triage summary, and a prioritized recommendation list.

The key insight: scoring is not classification. Classification says "what." Scoring says "what, how bad, and what to do about it." The recommendation generation is the part that saves analysts actual time.

Built with Python stdlib. MITRE ATT&CK framework. DeepSeek V4 optional.

github.com/Rush-me-not/auto-triage-bot

#infosec #detectionengineering
