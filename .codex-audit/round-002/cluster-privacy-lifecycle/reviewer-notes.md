# Reviewer Notes: cluster-privacy-lifecycle

These are main-Codex working notes only. They are not final disposition and do
not update the formal index.

| CA-ID | Agent signal | Main-Codex preliminary read | Discussion focus |
| --- | --- | --- | --- |
| CA-14 | Investigator: confirmed. Adversary: `real-low`. | Likely real only if our privacy promise is "opaque/no visual inference." Current evidence supports low-severity hardening, not a demonstrated readable-content leak. | Decide whether auth/privacy shields must be opaque or whether material blur is acceptable. |
| CA-15 | Investigator: confirmed. Adversary: `real-needs-fix`. | Plausibly real. Stale operation-prompt generation can suppress a later real inactive/resign event, especially on macOS where there is no background event to rescue the state. | Check whether current tests already prove the stale-generation case and whether fix should be expiration/context based. |
| CA-16 | Investigator: confirmed with updated mechanism. Adversary: `real-needs-fix`. | Plausibly real but timing-sensitive. The risky pattern is an in-flight resume task clearing blur after backgrounding while post-auth work completes. | Discuss whether to cancel/guard resume tasks by scene generation before recording as pending fix. |
| CA-31 | Investigator: confirmed. Adversary: `real-low`. | Mechanism real, impact probably low on current HEAD because protected data is not loaded before app-session auth. First-frame exposure appears mostly chrome/placeholders. | Decide whether first frame should default covered anyway as defense-in-depth. |

Suggested discussion order: CA-14 first for privacy boundary, then CA-31, then the two lifecycle races CA-15/CA-16 together.

