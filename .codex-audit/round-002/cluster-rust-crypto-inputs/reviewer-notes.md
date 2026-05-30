# Reviewer Notes: cluster-rust-crypto-inputs

These are main-Codex working notes only. They are not final disposition and do
not update the formal index.

| CA-ID | Agent signal | Main-Codex preliminary read | Discussion focus |
| --- | --- | --- | --- |
| CA-30 | Investigator: partially real, original claim stale. Adversary: `real-low`. | Original predictable temp path is stale/mostly mitigated; remaining Rust primitive should use symlink-safe/exclusive temp handling. | Decide whether to close original as false-positive/currently mitigated or record narrowed hardening. |
| CA-34 | Investigator: false positive against product contract. Adversary: `false-positive`. | Likely false positive. Standalone verify intentionally returns graded status; AEAD/decrypt hard-fail invariant is separate. | Consider only a docs/comment/API-ergonomics cleanup, not a security fix. |
| CA-39 | Investigator: real latent service. Adversary: `real-low`. | Real at Rust service layer, not shipped UI reachable. Similar to CA-21 but separate S2K work/memory bound. | Decide whether to record now as latent pending-fix or defer until password-message UI is productized. |

Suggested discussion order: CA-34 first to close if user agrees, then CA-30/CA-39 as latent/low hardening.

