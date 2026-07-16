# Workflow

> Status: Canonical current-state.
> Purpose: How work flows through this repository — the agent-era development loop, what "done" requires, the security gate, and the documentation contract.
> Audience: AI coding tools and human developers.
> Update triggers: validation commands, the security gate, doc classes, or the development loop change.

This document assumes a capable model that knows how to write correct, idiomatic, well-tested code without being told the obvious. It records only the load-bearing rules — the project-specific contracts and the few gates that matter — not a checklist of things a good engineer already does.

## 1. The development loop

Most work follows one loop: **discuss the goal → investigate → design → implement → verify → open a PR → human merge.**

- **Discuss the goal.** The maintainer describes what they want. Clarify scope only where a wrong assumption would cost real rework; otherwise proceed.
- **Investigate and design.** Read the relevant code and canonical docs. For a substantial or multi-part feature, settle the shape (invariants, red lines, seam boundaries) before writing code — a short design pass, not a document series. Large designs may land as a design doc when the invariants deserve a durable home (e.g. [POST_QUANTUM.md](POST_QUANTUM.md)); most work does not need one. When a design needs maintainer decisions, settle them one at a time — options with a recommendation, the choice recorded on the issue — rather than bundling them into one large plan for wholesale approval.
- **Implement** at the right altitude: architecturally correct for long-term maintainability over the smallest patch. This sets the *depth* of a change, not its *scope* — keep the work focused on the request; do not fold in unrelated cleanup, and do not hide new behavior in the wrong place to shrink a diff. Shared components live in their own files in the right area, with Xcode file-system sync, target membership, and test-target exclusions reflecting that structure.
- **Verify** before calling it done (§2).
- **Multi-phase work.** When a feature lands as several PR-sized stages against a written plan, run a fresh-context adversarial verification after each stage (`.claude/skills/stage-verify`) and resolve its findings before the next stage builds on the seam. The RFC 9980 campaign (#567) is the worked example. Keep campaign state outside the session as it accrues — decisions as issue comments, a worklog, the PR opened early — so any fresh session can resume the work mid-flight.
- **Review depth scales with blast radius.** Small mechanical changes need nothing beyond the validation lanes. A normal PR gets one independent fresh-context verification, and the maintainer runs their own code review in a separate session before merging. Campaign stages add the per-stage pass above. A whole-codebase review is a deliberate, rare event — multi-agent workflows with assess-first cost control and a mechanical floor (e.g. `periphery`) beneath model judgment.
- **Verdicts are evidence-based in both directions.** A reported defect needs its failure path traced end to end; a "refuted" or "this code is live" verdict needs the same standard — cite the reference or the guard, not the absence of proof. A verdict that oscillates across review rounds (#610: high → refuted → re-raised → settled as a nit) is the signal that nobody has traced the whole chain yet; run one decisive full-trace investigation rather than another round of judgment.
- **PR and merge.** Git mechanics live in CLAUDE.md (topic branch, regular merge commit, signed conventional commits); the maintainer makes the merge decision.

## 2. What "done" requires

Before considering a code task complete:

- Rust compiles for all targets (`aarch64-apple-ios`, `-ios-sim`, `-darwin`, `-visionos`, `-visionos-sim`) and `cargo +stable test --manifest-path pgp-mobile/Cargo.toml` passes.
- The relevant Swift lane passes locally — `CypherAir-UnitTests` on `platform=macOS,arch=arm64e` is the source of truth for Swift validation (the hosted preview lane can warning-skip; rely on the local run). Device/SE-hardware behavior runs under `CypherAir-DeviceTests` on Apple Silicon or a physical device.
- **rust-sync when needed.** Rust changes under `pgp-mobile/src`, `Cargo.toml`/`Cargo.lock`, or the UniFFI interface do **not** auto-refresh the `PgpMobile.xcframework` and generated bindings that Xcode links. When Swift-visible behavior can change, run the full pinned sync **before** Swift validation (`.claude/skills/rust-sync`). Rust-only test changes, comments, and docs do not need it.
- Tests follow CLAUDE.md's Testing rule — judgment-based, most changes need none. New `Tests/` files need only `git add`; a new `Sources/` file needs its pbxproj test-target membership exception. New `Device*` test classes must be added to the unit plan's `skippedTests` or they will run — and prompt for biometrics — in the unit lane.
- Commits are SSH-signed with a conventional prefix (`feat:`/`fix:`/`refactor:`/`test:`/`docs:`). Load the signing key with `ssh-add --apple-load-keychain` if the agent has no identity. Never create an unsigned commit.

Docs-only changes that touch no code, generated files, project files, entitlements, release metadata, or build settings skip the Rust/Xcode runs — just keep the text-hygiene check clean (`python3 scripts/check_text_hygiene.py`) and links valid.

## 3. The security gate

The hard constraints — zero network, AEAD hard-fail (never partial plaintext), no key material in logs, memory zeroing, secure random only, MIE enabled, profile-correct message format — are canonical in [CLAUDE.md](../CLAUDE.md) and [SECURITY.md](SECURITY.md) §10. They are never violated.

A change is **security-critical** when it touches the areas listed in [SECURITY.md](SECURITY.md) §10. For those changes:

- Call out every security-critical edit explicitly — file, what changed, why — in both the work summary and the PR description.
- Add a test when it guards something a later edit could quietly break — in security code that is usually the invariant itself (decryption aborts on a bad tag, a revoked key is refused, memory is zeroed), not the happy path; skip it when there's nothing real to protect.
- Human review is required before merge.

The maintainer's independent Codex security review (run outside this repository, tracked via CSV + issues) and the per-phase stage-verify are the backstops; this gate is what the authoring session owes them.

## 4. Documentation contract

Docs are classed as **entry** (`README.md`, `CLAUDE.md`, `AGENTS.md` — orient and point to canon), **canonical current-state** (must match shipped code — PRD, TDD, SECURITY, ARCHITECTURE, TESTING, SECURE_ENCLAVE_CUSTODY, PERSISTED_STATE_INVENTORY, RELEASE, ARM64E_STATUS, APP_STORE_LISTING, this doc), **decision records** (a recorded choice plus the triggers that reopen it — FFI_ARTIFACT_DECISION, ARM64E_UPSTREAMING), and **roadmap/rationale** (future-facing or design-why — POST_QUANTUM; must say so explicitly and not describe shipped behavior). Canonical docs carry a short metadata header (status, purpose, audience, update triggers). Agent skills under `.claude/skills/` are workflow choreography, not documentation — they defer to the canonical docs they cite and never become the sole home of a rule.

**Keep docs load-bearing.** Record the project-specific contracts a reader genuinely needs; do not narrate stage history, restate what the code already shows, or spell out what a capable model knows by default. When a durable fact ships, move it into the canonical doc that owns it and let the roadmap doc shrink toward rationale.

**Update docs in the same change** when the underlying surface changes:

| When you change… | Update |
|---|---|
| Build / linkage model | README, CLAUDE.md, AGENTS.md, TDD, TESTING |
| Test plans or the dev workflow | CLAUDE.md, AGENTS.md, TESTING, this doc |
| Release / compliance surface | RELEASE, CLAUDE.md, AGENTS.md |
| Rust / FFI contract, service ownership | ARCHITECTURE, TDD (durable semantics), TESTING |
| User-visible product surface | PRD |
| Secret lifecycle, auth boundary, custody | SECURITY, SECURE_ENCLAVE_CUSTODY, PRD |
| Persisted keys, defaults, temp paths, cleanup | PERSISTED_STATE_INVENTORY, ARCHITECTURE, TDD |

`CLAUDE.md` (Claude sessions) and `AGENTS.md` (Codex) are separate entry docs; keep shared constraints semantically aligned when either changes, but let tool-specific wording diverge. Active docs are written in English.
