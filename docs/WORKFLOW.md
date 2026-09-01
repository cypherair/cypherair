# Workflow

> Status: Canonical current-state.
> Purpose: How work flows through this repository — the development loop, what "done" requires, and the documentation contract.
> Audience: AI coding tools and human developers.
> Update triggers: validation commands, doc classes, or the development loop change.

This document assumes a capable model that knows how to write correct, idiomatic, well-tested code without being told the obvious.

## 1. The development loop

- **Design decisions go to the maintainer one at a time** — options with a recommendation, the choice recorded on the issue — not bundled into one large plan for wholesale approval. A design doc is for the rare design whose invariants deserve a durable home (e.g. the storage-rebuild sections in [STORAGE.md](STORAGE.md)).
- **Shared components live in their own files in the right area**, with Xcode file-system sync, target membership, and test-target exclusions reflecting that structure.
- **Multi-phase work.** When a feature lands as several PR-sized stages against a written plan, a fresh-context subagent verifies each stage adversarially against the plan before the next stage builds on it. Keep the work's state outside the session as it accrues — decisions as issue comments, a worklog, the PR opened early — so any fresh session can resume it.
- **Verification depth follows blast radius, not diff size.** The §2 lanes are the floor for every change. A PR skips the independent fresh-context verification only when the lanes fully cover it and it touches no canonical doc; the main session makes that call and, when in doubt, runs it.
- **PR and merge** rules live in CLAUDE.md.

## 2. What "done" requires

Before considering a code task complete:

- Rust compiles for all targets (`aarch64-apple-ios`, `-ios-sim`, `-darwin`, `-visionos`, `-visionos-sim`) and `cargo +stable test --manifest-path pgp-mobile/Cargo.toml` passes.
- The relevant Swift lane passes locally — `CypherAir-UnitTests` on `platform=macOS,arch=arm64e` is the source of truth for Swift validation. Device/SE-hardware behavior runs under `CypherAir-DeviceTests` on Apple Silicon or a physical device.
- **Sync when needed.** Rust changes that touch the fingerprinted crate inputs do not refresh what Xcode links; run the pinned sync before Swift validation. Which changes need it, the command, and the stale-artifact symptoms: docs/BUILD.md §6.
- Tests follow CLAUDE.md's Testing rule. New `Tests/` files need only `git add`; a new `Sources/` file needs its pbxproj test-target membership exception. New test classes under `Tests/DeviceSecurityTests/` must be added to the unit plan's `skippedTests` or they will run — and prompt for biometrics — in the unit lane; a repo-tracked check enforces it.

Docs-only changes that touch no code, generated files, project files, entitlements, release metadata, or build settings skip the Rust/Xcode runs — just keep the text-hygiene check clean (`python3 scripts/check_text_hygiene.py`) and links valid.

## 3. Documentation contract

Docs are classed as **entry** (`README.md`, `CLAUDE.md`, and the documentation map `docs/CLAUDE.md` — orient and point to canon), **canonical current-state** (must match shipped code — PRODUCT, SECURITY, CUSTODY, STORAGE, ARCHITECTURE, TESTING, BUILD, this doc — plus ARM64E_STATUS as a machine-parsed pin stub), **decision records** (a recorded choice plus the triggers that reopen it — marked sections inside canonical docs, e.g. BUILD §5's FFI-artifact decision and §4's carry chains), and **roadmap/rationale** (future-facing or design-why — the explicitly marked roadmap-class sections inside canonical docs, e.g. STORAGE's target design; must say so explicitly and never describe shipped behavior).

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
