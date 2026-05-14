# Architecture Refactor Roadmap

> Status: Active roadmap.
> Purpose: Translate the architecture refactor goals, target-state reference, and current-state audit into phased execution guidance.
> Audience: Human developers, reviewers, and AI coding tools planning architecture refactor work.
> Related: [Architecture Refactor Goals](ARCHITECTURE_REFACTOR_GOALS.md), [Architecture Refactor Target](ARCHITECTURE_REFACTOR_TARGET.md), [Architecture Refactor Current-State Audit](ARCHITECTURE_REFACTOR_AUDIT.md), [Architecture](ARCHITECTURE.md), [Security](SECURITY.md), [Testing](TESTING.md), [Documentation Governance](DOCUMENTATION_GOVERNANCE.md).
> Current-state note: This document is future-facing. It is not a statement of current shipped architecture, a detailed implementation plan, or authorization to change code without a phase-specific plan.

## Summary

This roadmap organizes the architecture refactor into phases that can be planned and reviewed independently. It intentionally focuses on architectural goals and validation gates rather than concrete implementation mechanics.

The refactor should prioritize boundary convergence over broad file splitting. The main objectives are:

- contain generated UniFFI / `PgpEngine` knowledge behind an FFI adapter / mapper boundary
- keep app-owned models free of generated FFI, presentation, and Security implementation concerns
- move normal Contacts runtime away from the legacy flat `Contact` projection
- make UI route views render ScreenModel state instead of orchestrating workflows directly
- narrow App-layer ownership of Security, ProtectedData, and reset/auth orchestration policy

Every phase below still requires a detailed implementation plan before code changes begin. That plan should name the exact boundaries, temporary exceptions, tests, and rollout order for the specific PR or PR sequence.

## Roadmap Rules

- Preserve user-visible behavior unless a phase-specific plan explicitly changes it.
- Keep legacy migration support until a separate human-approved support cutoff exists.
- Do not use this roadmap to justify package modularization, broad large-file splitting, release metadata changes, or a general Sendable cleanup.
- Do not hand-edit generated UniFFI bindings in `Sources/PgpMobile/pgp_mobile.swift`.
- Treat sensitive boundaries from `SECURITY.md` and `AGENTS.md` as review gates, not ordinary refactor surfaces.
- Update canonical current-state docs only when shipped code actually changes.

## Phase 0: Baseline And Guardrails

Purpose: establish shared phase language and measurable guardrails before broad refactor work begins.

### Candidate PRs

- **PR 0A: Roadmap document**
  - Add this roadmap with governance metadata, related-doc links, phase boundaries, and validation expectations.
  - Keep it explicitly future-facing and non-canonical for shipped behavior.

- **PR 0B: Architecture source-audit guardrails**
  - Add or expand source-audit checks where practical.
  - Initial guardrails should focus on measurable leaks: generated FFI types above the adapter boundary, `PgpError` handling in UI and ScreenModels, SwiftUI presentation policy in Models, and ordinary runtime `[Contact]` dependencies.
  - Guardrails should allow explicit temporary exceptions so incremental PRs can land safely.

### Exit Markers

- Future refactor PRs can state whether they reduce, preserve, or intentionally defer known architecture debt.
- New guardrails catch clear boundary regressions without blocking planned transitional states.
- Documentation makes the distinction between target architecture, audit evidence, and phased execution clear.

### Validation

- Documentation-only PRs should run `git diff --check` and any local documentation consistency or link checks available in the workspace.
- Guardrail PRs should include tests proving both violation detection and allowed temporary exceptions.

## Phase 1: FFI Adapter And Error Containment

Purpose: contain generated UniFFI interaction and generated-error interpretation behind adapter / mapper boundaries.

### Candidate PRs

- **PR 1A: Key metadata, key profile, and selector adapters**
  - Move generated key-info and selector mapping toward adapter-owned contracts.
  - Avoid exposing generated selector records as app-facing request or result values.

- **PR 1B: Encrypt, decrypt, and password-message adapters**
  - Keep two-phase decrypt behavior intact while moving generated operation calls, progress bridging, cancellation interpretation, and generated result cleanup toward the FFI boundary.

- **PR 1C: Sign, verify, certification, and revocation adapters**
  - Convert generated signature, verification, certification, and revocation records into app-owned result models before they reach Services, ScreenModels, or UI.

- **PR 1D: QR, contact import, and self-test adapters**
  - Normalize generated key-inspection and QR/import errors at the boundary.
  - Keep untrusted input parsing behavior and self-test coverage unchanged.

### Exit Markers

- Normal production Services call adapter / mapper contracts rather than exposing generated records upward.
- Generated error normalization, cancellation checks, progress protocol bridging, and result cleanup live at the FFI boundary.
- `PgpEngine`, `PgpError`, generated selectors, and generated operation result records are confined to adapter, composition, tests, or explicitly documented temporary exceptions.

### Validation

- Run targeted source-audit checks for generated types above the adapter boundary.
- Preserve Rust and Swift behavior coverage for both profiles.
- For Swift-visible Rust / UniFFI behavior changes, regenerate the XCFramework through the documented workflow before Xcode validation.
- For decrypt and signature changes, prove AEAD hard-fail, two-phase decrypt auth, cancellation, tamper handling, and detailed verification behavior remain intact.

## Phase 2: App-Owned Models And Presentation Boundary

Purpose: make Models a stable app-owned vocabulary rather than a container for generated FFI, presentation, or Security implementation details.

### Candidate PRs

- **PR 2A: Generated enum replacement**
  - Replace generated enum vocabulary with app-owned values where it appears in persisted data, service contracts, ScreenModel state, or UI-facing summaries.
  - Preserve schema compatibility with explicit migration or compatibility handling where needed.

- **PR 2B: Error vocabulary cleanup**
  - Keep `CypherAirError` as the shared app-owned error model.
  - Move generated `PgpError` mapping and generated cancellation interpretation out of Models.

- **PR 2C: Presentation policy extraction**
  - Move display-only helpers such as colors, icons, localized labels, and view-specific display text out of core Models and into presentation helpers or ScreenModel-prepared display state.

- **PR 2D: Security vocabulary cleanup**
  - Remove ProtectedData and Security implementation vocabulary from app-owned domain models where those details can be represented by app-level availability or validation results.

### Exit Markers

- Core Models do not import SwiftUI for colors, icons, or view-specific display policy.
- Core Models do not perform generated FFI mapping.
- Persisted app-owned payloads are not tied to generated Swift enum case names unless explicitly documented as a transitional compatibility contract.
- ProtectedData and Security details are not embedded in ordinary domain model contracts except where a phase-specific plan records a temporary exception.

### Validation

- Run model and persistence tests affected by enum or schema changes.
- Add migration or compatibility tests before changing persisted payload vocabulary.
- Run localization checks when moving user-facing strings.
- Run targeted source-audit checks for SwiftUI imports and generated FFI symbols in Models.

## Phase 3: Contacts Runtime Consolidation

Purpose: make the protected, person-centered Contacts domain the ordinary runtime model and isolate legacy flat-contact compatibility.

### Candidate PRs

- **PR 3A: Contacts service contracts**
  - Move normal service APIs toward `ContactIdentity`, `ContactKeyRecord`, summaries, tags, and app-owned import/merge/certification result models.
  - Stop shaping ordinary results around legacy `Contact` where a current domain model exists.

- **PR 3B: UI and ScreenModel call-site migration**
  - Move Contacts UI, recipient selection, import confirmation, contact detail, tags, verification context, and certificate-signature screens onto current domain summaries and request/result models.

- **PR 3C: Legacy compatibility isolation**
  - Keep old-install migration and compatibility behavior behind explicit migration or compatibility boundaries.
  - Ensure legacy/quarantine sources are not ordinary fallback state after protected-domain cutover.

- **PR 3D: Legacy runtime projection removal**
  - Remove ordinary runtime dependence on `[Contact]` after current call sites have moved and retained migration paths are isolated.
  - Keep compatibility tests only where they prove migration or explicitly retained support behavior.

### Exit Markers

- Normal Contacts runtime uses person-centered protected-domain models as the source of truth.
- Ordinary Contacts flows do not depend on `[Contact]`.
- Recipient selection, import/update, merge, tags, verification context, certification artifacts, and certificate-signature screens use current Contacts-domain vocabulary.
- Legacy flat `Contact` appears only in migration, compatibility adapters, or focused tests with documented purpose.

### Validation

- Prove protected-domain authority, no legacy/quarantine fallback, migration safety, relock cleanup, schema compatibility, and recovery behavior.
- Preserve search ranking, tag normalization, per-key verification/certification state, recipient selection, and certification artifact behavior.
- Run Contacts service and ScreenModel tests affected by each PR.
- Use source-audit checks to track remaining `[Contact]` production dependencies and approved exceptions.

## Phase 4: UI And ScreenModel Ownership

Purpose: make route views thin and make ScreenModels the owner of user-driven workflow state.

### Candidate PRs

- **PR 4A: Remaining key-management route ScreenModels**
  - Move workflow-heavy key generation, import, backup, key detail, expiry, and selective-revocation behavior into ScreenModel-owned actions and state where not already complete.

- **PR 4B: Contacts and QR route ScreenModels**
  - Move QR display/generation, contact detail mutations, import confirmation, and tag/contact route workflow state behind ScreenModels or narrow presentation coordinators.

- **PR 4C: Settings-adjacent ScreenModel cleanup**
  - Reduce Settings ScreenModel exposure to concrete Security and reset internals by using narrower service-level workflows planned in Phase 5.

- **PR 4D: ScreenModel public API cleanup**
  - Replace concrete service internals, generated enums, and low-level file/progress infrastructure in ScreenModel public state with app-owned request/result/display models where practical.

### Exit Markers

- Route views own layout, lifecycle wiring, navigation presentation, import/export modifiers, sheets, alerts, and platform chrome.
- Async workflow, error normalization, cancellation, importer/exporter state, cleanup, and cross-service coordination live outside view bodies.
- ScreenModel public APIs use app-owned vocabulary and expose UI-consumable state.

### Validation

- Run affected ScreenModel unit tests.
- Run targeted macOS UI smoke coverage for route ownership, tutorial-host behavior, and settings flows when those surfaces change.
- Use source-audit checks for view-level service orchestration and generated-error handling in UI.
- Verify tutorial configuration and output-interception behavior when shared production views are refactored.

## Phase 5: Security And App Composition Boundary

Purpose: reduce App-layer ownership of Security, ProtectedData, local reset, and post-unlock policy while preserving all security invariants.

### Candidate PRs

- **PR 5A: Auth-mode switching workflow boundary**
  - Route Settings auth-mode switching through a narrower service-level workflow.
  - Preserve current-mode authentication, rewrap recovery, and High Security behavior.

- **PR 5B: Local reset workflow boundary**
  - Move local reset policy behind a service boundary that owns the destructive storage and security coordination contract.
  - Keep reset confirmation and presentation in App/UI code.

- **PR 5C: Protected settings and authorization handoff boundary**
  - Narrow App-layer knowledge of ProtectedData authorization handoff, mutation recovery, and `LAContext` lifecycle.

- **PR 5D: Post-unlock composition cleanup**
  - Keep `AppContainer` and tutorial sandbox as composition roots, but move operation policy and sequencing out of wiring code where feasible.

### Exit Markers

- App composition constructs dependencies without becoming the owner of operation policy.
- App/ScreenModel code does not directly coordinate Keychain, Secure Enclave, ProtectedData root-secret, relock, or `LAContext` mechanics except through approved bridge surfaces.
- Tutorial sandbox wiring shares production composition boundaries where practical without weakening isolation.

### Validation

- Treat each PR in this phase as security-sensitive.
- Preserve AEAD hard-fail, two-phase decrypt auth, private-key zeroization, ProtectedData fail-closed behavior, no plaintext/private-key logging, and zero network access.
- Run focused unit tests for auth mode, local reset, ProtectedData access gates, relock cleanup, recovery, and startup/post-unlock behavior.
- Require device-only validation when Secure Enclave, biometric, access-control, or real-device ProtectedData behavior changes.

## Phase 6: Closure And Canonical Sync

Purpose: close the roadmap cleanly after implementation, update canonical docs to match shipped behavior, and archive superseded planning material.

### Candidate PRs

- **PR 6A: Target acceptance sweep**
  - Re-run source-audit checks and targeted manual review against the acceptance markers in `ARCHITECTURE_REFACTOR_TARGET.md`.
  - Document remaining exceptions with owner, reason, and intended follow-up.

- **PR 6B: Canonical current-state documentation sync**
  - Update `ARCHITECTURE.md`, `SECURITY.md`, `TESTING.md`, `PERSISTED_STATE_INVENTORY.md`, and `CODE_REVIEW.md` only where shipped behavior changed.
  - Do not rewrite canonical docs to describe target-state work before it ships.

- **PR 6C: Roadmap and audit disposition**
  - Archive, supersede, or mark this roadmap and the current-state audit as consumed when they stop being active planning references.

### Exit Markers

- Target acceptance markers hold for normal production code.
- Remaining architecture exceptions are explicit, owned, and test-covered.
- Canonical current-state docs match the shipped architecture.
- Active docs no longer present completed roadmap material as future work.

### Validation

- Run the full validation set appropriate for the changed surfaces.
- Run documentation consistency and link checks.
- Confirm archived docs are not newly cited as current source of truth.

## Cross-Phase Validation Matrix

| Change surface | Minimum validation expectation |
| --- | --- |
| Documentation-only | `git diff --check`, documentation consistency checks, and link checks where available. |
| Source-audit guardrails | Unit tests for violations and allowed exceptions; confirm fixture/source manifests are updated when needed. |
| Swift app-only architecture refactor | Affected unit tests, targeted source-audit checks, and `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'` when behavior or contracts change. |
| UI route, tutorial, or settings flow | Affected ScreenModel tests plus targeted macOS UI smoke coverage. |
| Contacts runtime or persistence | Contacts service tests, Contacts ScreenModel tests, migration/recovery tests, relock cleanup tests, and source-audit checks for legacy projection use. |
| Security, ProtectedData, authentication, or reset | Focused security unit tests, recovery/fail-closed tests, and device-only tests when real Secure Enclave, biometric, access-control, or hardware ProtectedData behavior changes. |
| Rust / UniFFI-visible behavior | Rust tests, UniFFI regeneration through the documented workflow, XCFramework refresh when Swift-visible behavior changes, then relevant Xcode validation. |
| Decrypt, signature, or trust-facing behavior | Positive and negative tests for both profiles, AEAD hard-fail, two-phase decrypt auth, tamper handling, cancellation, and detailed verification semantics. |

## Working Assumptions

- Active documentation remains English per `DOCUMENTATION_GOVERNANCE.md`.
- Current code, `ARCHITECTURE.md`, `SECURITY.md`, `TESTING.md`, and `PERSISTED_STATE_INVENTORY.md` outrank this roadmap for shipped behavior.
- Phase boundaries are allowed to change if later implementation planning discovers a safer dependency order.
- Legacy migration code should be isolated before it is deleted.
- Broad file splitting is not a success criterion unless it directly supports a boundary objective in a phase-specific plan.
