# Reviewer Notes: cluster-contact-certification-state

These are main-Codex working notes only. They are not final disposition and do
not update the formal index.

| CA-ID | Agent signal | Main-Codex preliminary read | Discussion focus |
| --- | --- | --- | --- |
| CA-06 | Investigator: real legacy residual. Adversary: `real-low`, possible `wont-fix`. | This is not current Contacts trust reachability. It is about old unsupported flat files not being deleted by Reset All Local Data. | Decide whether reset promises cleanup of unsupported historical app-created data. |
| CA-09 | Investigator: real trust-state confusion. Adversary: `real-low`. | Likely real-low if "Certified" UI implies trusted endorsement. It does not alter manual verification or recipient encryption policy. | Decide semantics: cryptographically valid certification vs trusted certification. |
| CA-17 | Investigator: real shipped availability. Adversary: `real-low`. | Likely real-low. Unbounded local signature-file import can crash, but user-mediated and availability-only. | Set detached certification signature size policy and content-type limits. |
| CA-41 | Investigator: tutorial-only real. Adversary: `real-low`. | Likely low/informational reliability issue, not production security. | Decide if tutorial double-open should be hardened or closed as acceptable tutorial-only availability. |

Suggested discussion order: CA-09 first because it affects trust wording/UI, then CA-06, CA-17, CA-41.

