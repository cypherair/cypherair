# Reviewer Notes: cluster-decrypt-verify-ui

These are main-Codex working notes only. They are not final disposition and do
not update the formal index.

| CA-ID | Agent signal | Main-Codex preliminary read | Discussion focus |
| --- | --- | --- | --- |
| CA-20 | Investigator: real shipped local availability. Adversary: `real-low`. | Likely real-low. Unbounded detailed signature collection/rendering can hang/crash, but it is local/user-mediated and not confidentiality/integrity impact. | Decide cap location: Rust, Swift mapper, UI display, or layered. |
| CA-29 | Investigator: real but narrowed. Adversary: `real-low`. | Likely real-low. Manual cancel looks mostly handled; remaining issue is abandon/route disappear while decrypt continues and later adopts plaintext temp output. | Discuss desired behavior on route disappearance: cancel vs allow background completion. |
| CA-33 | Investigator: real. Adversary: `real-needs-fix`. | Strongest item in this cluster. Shared signature state can be shown next to a different mode's output; this is a user-trust UI bug worth fixing. | Decide whether to clear inactive mode results or model output+signature atomically per mode. |
| CA-42 | Investigator: real mechanism, not security. Adversary: `real-low`. | Likely not a security issue; maybe UX/local availability. Needs UI evidence before treating as fix-worthy security work. | Consider closing as non-security or tracking as UX if focus/cursor loss is confirmed. |

Suggested discussion order: CA-33 first, then CA-29, then availability-only CA-20/CA-42.

