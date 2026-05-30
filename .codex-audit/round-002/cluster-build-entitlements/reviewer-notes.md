# Reviewer Notes: cluster-build-entitlements

These are main-Codex working notes only. They are not final disposition and do
not update the formal index.

| CA-ID | Agent signal | Main-Codex preliminary read | Discussion focus |
| --- | --- | --- | --- |
| CA-07 | Investigator: real CI risk. Adversary: `real-low`. | Likely real-low. It weakens PR Swift-test signal but docs currently frame hosted Swift as preview while local validation is authoritative during runner lag. | Decide whether branch protection treats warning-skipped Swift tests as merge-ready. |
| CA-26 | Investigator: false positive/stale. Adversary: `false-positive`. | Likely false positive. Apple docs/release notes support the current `-string` entitlement keys. | Maybe add archive entitlement dump to release validation, but close finding as stated. |
| CA-40 | Investigator: real design risk. Adversary: `real-low`. | Mocks are compiled into app module, but current real app wiring uses hardware/keychain; tutorial/UI-test use is intentional and isolated. | Decide whether to rename/move tutorial simulation primitives or exclude test-only mocks later. |
| CA-43 | Investigator: false positive/already non-issue. Adversary: `false-positive`. | Likely false positive. `@Observable` via `Foundation` is current pattern; if broken, app would not build. | Close unless normal CI/build later contradicts this. |

Suggested discussion order: CA-26/CA-43 likely closures first, then CA-07/CA-40 low-risk process/design issues.

