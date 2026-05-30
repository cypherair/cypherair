# Reviewer Notes: cluster-secret-memory-zeroization

These are main-Codex working notes only. They are not final disposition and do
not update the formal index.

| CA-ID | Agent signal | Main-Codex preliminary read | Discussion focus |
| --- | --- | --- | --- |
| CA-25 | Investigator: real macOS availability hardening. Adversary: `real-low`. | Likely real-low. Total RAM on macOS is a weak guard but impact is local import DoS, not secret disclosure. | Decide if macOS should use stricter fixed/headroom cap. |
| CA-27 | Investigator: real zeroization gap. Adversary: `uncertain`. | Code pattern is concerning, but practical trigger needs proof. Since zeroization is a project invariant, this may still be worth pending-fix if cheap. | Look for/import fixture where Rust returns secret data then a helper fails before caller defer. |
| CA-32 | Investigator: real. Adversary: `real-needs-fix`. | Strongest item in this cluster. Private signing key unwrap occurs before a possible no-default encrypt-to-self throw and before zeroizing defer. | Discuss as likely pending-fix unless current UI state makes it impossible. |
| CA-35 | Investigator: real availability. Adversary: `real-low`. | Likely real-low. Oversized in-memory FFI inputs can trap, but practical path is local huge file and availability-only. | Decide size-limit policy across all in-memory FFI/file import paths. |

Suggested discussion order: CA-32, CA-27, then availability-only CA-25/CA-35.

