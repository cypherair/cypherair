# Round 002 Codex Security Audit

This directory is local-only and git-excluded. It stores sub-agent evidence for
discussion; it is not the formal finding record.

Sources:

- Index: `docs/CODEX_SECURITY_REVIEW_INDEX.md`
- CSV: `codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- Stable finding anchor: `finding_url`
- Workflow: `docs/CODEX_SECURITY_AUDIT_WORKFLOW.md`

Agents must not edit repository files, update the index, or close Codex
findings. Final disposition requires user review in the main Codex session.

## Clusters

| Cluster | CA-IDs | Status |
| --- | --- | --- |
| `cluster-privacy-lifecycle` | CA-14, CA-15, CA-16, CA-31 | complete |
| `cluster-decrypt-verify-ui` | CA-20, CA-29, CA-33, CA-42 | complete |
| `cluster-contact-certification-state` | CA-06, CA-09, CA-17, CA-41 | complete |
| `cluster-protected-data` | CA-10, CA-36 | complete |
| `cluster-secret-memory-zeroization` | CA-25, CA-27, CA-32, CA-35 | complete |
| `cluster-rust-crypto-inputs` | CA-30, CA-34, CA-39 | complete |
| `cluster-build-entitlements` | CA-07, CA-26, CA-40, CA-43 | complete |

## Expected Files Per Cluster

- `investigator.md`
- `investigator-trace.md`
- `adversary.md`
- `adversary-trace.md`
- `reviewer-notes.md`
