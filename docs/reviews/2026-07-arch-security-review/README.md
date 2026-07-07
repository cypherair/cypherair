# CypherAir X — Architecture & Security Review (July 2026)

Preserved artifacts from the two-workflow codebase review run 2026-07-06/07 (architecture/code-health + security/crypto-correctness). **This bundle is kept for the record via a closed (unmerged) PR** so the review materials survive the remediation work without landing on `main`.

Read-only outputs — nothing here changes app behavior. The actionable findings were filed as GitHub issues (below); these files are the underlying evidence, scripts, and reports.

## Filed issues

**Architecture / code-health (WF1)**
- #606 — Dead-code removal sweep (231 confirmed declarations + 19 candidates + 2 unused UniFFI exports)
- #607 — Fix stale documentation (pre-#591 "six families" / Profile A/B naming)
- #608 — Decompose oversized files + collapse nine-family / tool-screen duplication
- Comment on #561 — 12 behaviorally-verified vestigial migration/capability removes
- Comment on #557 — non-real-guard test-prune candidates

**Security / crypto-correctness (WF2)**
- #609 — Certification verification omits revocation/expiration/policy checks (revoked signer's forged cert reads as Valid) — MEDIUM integrity, the headline confirmed bug
- #610 — ProtectedData custody-layer thread-safety: data races on decrypted key material (reopened HIGH)
- #611 — Untrusted-input DoS (decompression bomb + attacker-controlled Argon2)
- #612 — Zeroization gaps (passphrase String at FFI + un-zeroized plaintext/secret buffers)
- Comment on #577 — re-verification: WCR-03/04/05 confirmed still-open; WCR-02 + SR-FIX-05 refuted

## Contents

| Path | What it is |
|---|---|
| `wf1-architecture-inventory.md` | Full WF1 map: dead code, vestigial, oversized files, duplication, tests, docs, FFI-leak candidates, crypto touchpoints |
| `wf2-security-report.md` | Full WF2 report: 12 confirmed / 1 contested / 10 refuted findings, with adversarial-verification votes + completeness gaps |
| `workflows/wf1-map.workflow.mjs` | The WF1 map & triage workflow script (recall-oriented dead-code: mechanical enumeration + periphery floor + symmetric verdicts) |
| `workflows/wf2-security.workflow.mjs` | The WF2 security workflow script (19 assessment lenses → dedup → tiered adversarial verification → completeness critic) |
| `data/wf1-aggregated.json` | Raw aggregated WF1 agent outputs |
| `data/wf1-deadcode-grouped.json` | Dead-code declarations grouped by area |
| `data/periphery.json` | Deterministic `periphery` unused-declaration baseline (219 findings) |
| `data/wf2-touchpoints-by-lens.json` | Crypto/security touchpoint files grouped by lens (WF2 input) |
| `data/wf2-known-findings.md` | #577 open findings re-verified by WF2 |
| `data/wf2-assess-findings.json` | 23 WF2 candidate findings (pre-verification) |
| `data/wf2-verified.json` | 23 findings with adversarial-verification verdicts + votes |

## Method (for reproducibility)

- **Recall-oriented mapping** with mechanical floors: `periphery` (deterministic Swift unused-declaration detection) + mandatory per-file declaration enumeration, so misses require both the tool and the model to miss. 91 dead declarations were caught only by periphery, 73 only by enumeration.
- **Producer-consumer analysis** for reachable-but-obsolete (vestigial) migration/capability code — reference tools can't find code that still runs but whose triggering precondition can no longer occur.
- **Adversarial verification**: WF2 candidates were verified by independent skeptics (HIGH findings by a 3× max-effort panel with a trace+exploit reality-gate; others by an xhigh verifier). ~43% of candidates were refuted with reasons.
- **Independent pre-launch critiques** of each workflow script caught real coverage blockers before spending the budget.
- **Cost control**: assess-first gating + tiered verification kept WF2 to ~4.3M tokens (vs a ~40–80M all-out ceiling).

Total campaign ≈ 15M tokens (WF1 ~9.7M, WF2 ~4.3M, critiques the rest).
