# Cross-Alert Correlation Chain Detection in auto-triage-bot

The most valuable output from auto-triage-bot is not the individual triage findings — it is the correlation chains.

The correlator module analyzes findings across all processed alerts for three patterns: shared IoCs (same C2 IP or hash appearing in multiple alerts), sequential tactic progressions (Execution followed by Persistence or Defense Evasion), and temporal proximity (alerts occurring within a defined window on the same host).

When ALERT-003 (PowerShell from Office, T1059.001) and ALERT-004 (Scheduled Task creation, T1053.005) fired within 45 minutes on the same workstation, the correlator produced a persistence chain. It recognized that macro-delivered PowerShell followed by schtasks.exe /create is a textbook persistence establishment pattern.

The chain output includes chain type, linked alert IDs, a plain-English description, and consolidated recommendations that span both alerts — something no single-alert triage system can produce.

Built with Python stdlib. MITRE ATT&CK framework. DeepSeek V4 optional.

The question I keep coming back to: how many attack chains are your individual-alert triage tools missing right now?

#mitreattack #correlation #threathunting
