# Reviewer Notes: cluster-protected-data

These are main-Codex working notes only. They are not final disposition and do
not update the formal index.

| CA-ID | Agent signal | Main-Codex preliminary read | Discussion focus |
| --- | --- | --- | --- |
| CA-10 | Investigator: likely real/fix-worthy. Adversary: `real-low`. | Plausible state-machine hardening issue, but narrow and local. Impact is protected-data availability/data loss, not disclosure. | Determine if first-domain creation/cleanup overlap is practical in shipped UI or only synthetic. |
| CA-36 | Investigator: real low. Adversary: `real-low`. | Real robustness bug: malformed local/corrupt envelope can trap before recovery. Low severity, but central validation fix seems sensible. | Decide whether local corrupt-state traps belong in security follow-ups or robustness backlog. |

Suggested discussion order: CA-10 first because it touches root-secret lifecycle; CA-36 second.

