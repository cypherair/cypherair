# Workflow

> Status: Canonical current-state.
> Purpose: How work flows through this repository — the agent-era development loop, what "done" requires, and the documentation contract.
> Audience: AI coding tools and human developers.
> Update triggers: validation commands, doc classes, or the development loop change.

This document assumes a capable model that knows how to write correct, idiomatic, well-tested code without being told the obvious.

## 1. The development loop

Most work follows one loop: **discuss the goal → investigate → design → implement → verify → open a PR → merge.**

- **Discuss the goal.** The maintainer describes what they want. Clarify scope only where a wrong assumption would cost real rework; otherwise proceed.
- **Investigate and design.** Read the relevant code and canonical docs. For a substantial or multi-part feature, settle the shape (invariants, red lines, seam boundaries) before writing code — a short design pass, not a document series. Large designs may land as a design doc when the invariants deserve a durable home (e.g. the storage-rebuild design sections in [STORAGE.md](STORAGE.md)); most work does not need one. When a design needs maintainer decisions, settle them one at a time — options with a recommendation, the choice recorded on the issue — rather than bundling them into one large plan for wholesale approval.
- **Implement** at the right altitude: architecturally correct for long-term maintainability over the smallest patch. This sets the *depth* of a change, not its *scope* — keep the work focused on the request; do not fold in unrelated cleanup, and do not hide new behavior in the wrong place to shrink a diff. Shared components live in their own files in the right area, with Xcode file-system sync, target membership, and test-target exclusions reflecting that structure.
- **Verify** before calling it done (§2).
- **Multi-phase work.** When a feature lands as several PR-sized stages against a written plan, run a fresh-context adversarial verification after each stage (`.claude/skills/stage-verify`) and resolve its findings before the next stage builds on the seam. Keep campaign state outside the session as it accrues — decisions as issue comments, a worklog, the PR opened early — so any fresh session can resume the work mid-flight.
- **Review depth scales with blast radius — importance, not diff size.** The §2 validation lanes are the floor for every change. A PR skips the independent fresh-context verification (its stage-verify) only when the lanes fully cover it and it touches no canonical-doc surface; the main session makes that call and, when in doubt, runs the verification. Campaign stages add the per-stage pass above. A whole-codebase review is a deliberate, rare event — multi-agent workflows with assess-first cost control and a mechanical floor beneath model judgment.
- **Verdicts are evidence-based in both directions.** A reported defect needs its failure path traced end to end; a "refuted" or "this code is live" verdict needs the same standard — cite the reference or the guard, not the absence of proof. A verdict that oscillates across review rounds is the signal that nobody has traced the whole chain yet; run one decisive full-trace investigation rather than another round of judgment.
- **PR and merge.** Git mechanics live in CLAUDE.md (regular merge commit, signed conventional commits; the main session manages branches, worktrees, and delegation). A PR merges once its verification has passed and both the authoring agent and the main session hold high confidence — agent merges leave a note naming the merging model (e.g. "Merged-By: Claude Fable 5.1"). The governance documents (CLAUDE.md and this doc) always receive the maintainer's own independent review, and the maintainer merges them; every other change merges through the verification flow above.

## 2. What "done" requires

Before considering a code task complete:

- Rust compiles for all targets (`aarch64-apple-ios`, `-ios-sim`, `-darwin`, `-visionos`, `-visionos-sim`) and `cargo +stable test --manifest-path pgp-mobile/Cargo.toml` passes.
- The relevant Swift lane passes locally — `CypherAir-UnitTests` on `platform=macOS,arch=arm64e` is the source of truth for Swift validation. Device/SE-hardware behavior runs under `CypherAir-DeviceTests` on Apple Silicon or a physical device.
- **rust-sync when needed.** Rust changes under `pgp-mobile/src`, `Cargo.toml`/`Cargo.lock`, or the UniFFI interface do **not** auto-refresh the `PgpMobile.xcframework` and generated bindings that Xcode links. When Swift-visible behavior can change, run the full pinned sync **before** Swift validation (`.claude/skills/rust-sync`). Rust-only test changes (`pgp-mobile/tests/**`) and non-crate docs do not need it; comment edits in fingerprinted crate sources DO — the staleness gate hashes content (docs/BUILD.md §6).
- Tests follow CLAUDE.md's Testing rule — judgment-based, most changes need none. New `Tests/` files need only `git add`; a new `Sources/` file needs its pbxproj test-target membership exception. New test classes under `Tests/DeviceSecurityTests/` must be added to the unit plan's `skippedTests` or they will run — and prompt for biometrics — in the unit lane; a repo-tracked check enforces it.

Docs-only changes that touch no code, generated files, project files, entitlements, release metadata, or build settings skip the Rust/Xcode runs — just keep the text-hygiene check clean (`python3 scripts/check_text_hygiene.py`) and links valid.

## 4. Documentation contract

Docs are classed as **entry** (`README.md`, `CLAUDE.md`, and the documentation map `docs/CLAUDE.md` — orient and point to canon), **canonical current-state** (must match shipped code — PRODUCT, SECURITY, CUSTODY, STORAGE, ARCHITECTURE, TESTING, BUILD, this doc — plus ARM64E_STATUS as a machine-parsed pin stub), **decision records** (a recorded choice plus the triggers that reopen it — marked sections inside canonical docs, e.g. BUILD §5's FFI-artifact decision and §4's carry chains), and **roadmap/rationale** (future-facing or design-why — the explicitly marked roadmap-class sections inside canonical docs, e.g. STORAGE's target design; must say so explicitly and never describe shipped behavior). Agent skills under `.claude/skills/` are workflow choreography, not documentation — they defer to the canonical docs they cite and never become the sole home of a rule.

**Keep docs load-bearing.** Record the project-specific contracts a reader genuinely needs; do not narrate stage history, restate what the code already shows, or spell out what a capable model knows by default. When a durable fact ships, move it into the canonical doc that owns it and let the roadmap doc shrink toward rationale.

**Update docs in the same change** when the underlying surface changes:

| When you change… | Update |
|---|---|
| Build / linkage model | README, CLAUDE.md, TESTING |
| Test plans or the dev workflow | CLAUDE.md, TESTING, this doc |
| Release / compliance surface | BUILD, CLAUDE.md |
| Rust / FFI contract, service ownership | ARCHITECTURE (contract rules), TESTING |
| User-visible product surface | PRODUCT |
| Secret lifecycle, auth boundary, custody | SECURITY, CUSTODY, PRODUCT |
| Persisted keys, defaults, temp paths, cleanup | STORAGE, ARCHITECTURE |

Active docs are written in English.
