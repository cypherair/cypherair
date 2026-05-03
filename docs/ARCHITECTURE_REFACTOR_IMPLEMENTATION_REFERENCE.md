# Architecture Refactor Implementation Reference

> Status: Draft implementation reference for future architecture refactor planning.
> Purpose: Convert the architecture refactor audit into a boundary-first,
> reviewable implementation roadmap with explicit goals, TODOs, and acceptance
> standards.
> Audience: Engineering, security review, QA, and AI coding tools.
> Companion document: [ARCHITECTURE_REFACTOR_AUDIT](ARCHITECTURE_REFACTOR_AUDIT.md).
> Primary authorities: [ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md),
> [TESTING](TESTING.md), [CONVENTIONS](CONVENTIONS.md), and
> [CODE_REVIEW](CODE_REVIEW.md).
> Related Contacts references:
> [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)
> and
> [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md).
> Last reviewed: 2026-05-03.

Current code and active canonical docs outrank this future-facing reference.
This document is not a statement of current shipped architecture. It is an
implementation reference for later behavior-preserving refactor PRs.

## 1. Role And Source-Of-Truth Rules

`ARCHITECTURE_REFACTOR_AUDIT.md` is the evidence snapshot. This document is the
implementation reference that turns that evidence into an ordered refactor
roadmap.

Use this document to decide:

- which boundaries should be separated first
- what each refactor workstream is expected to accomplish
- which behavior must remain unchanged
- which tests and review gates prove the refactor is acceptable

Do not use this document to override current product, security, testing, or
coding rules. When there is a conflict:

- current code wins for observed behavior
- `ARCHITECTURE.md` wins for current module ownership
- `SECURITY.md` wins for security invariants and sensitive boundaries
- `TESTING.md` wins for validation commands and test-layer expectations
- `CONVENTIONS.md` wins for source organization and style
- `CODE_REVIEW.md` wins for PR review gates
- Contacts-specific current planning stays in the Contacts implementation plan
  and surface inventory

This document should be updated when a future architecture refactor PR changes
the intended sequence, completes a workstream, or discovers that an acceptance
standard needs to be tightened.

## 2. Refactor Goals And Desired End State

The refactor program is behavior-preserving by default. Its goal is to make the
existing security, lifecycle, crypto, and UI ownership easier to review without
changing user-visible behavior or weakening any protected-data invariant.

Desired end state:

- Sensitive boundaries are explicit. ProtectedData recovery, root-secret
  authorization, relock, authentication mode switching, private-key rewrap, QR
  URL parsing, and Rust crypto operations are reviewable in focused units.
- Composition roots assemble dependencies but do not own domain policy.
- SwiftUI hosts own presentation and binding mechanics, while workflow policy,
  authorization decisions, and mutation rules live in dedicated models or
  coordinators.
- Rust modules group key operations by capability family instead of collecting
  generation, parsing, public updates, secret import/export, revocation, S2K,
  and expiry mutation in one file.
- Contacts has one clear app-facing facade and one clear protected-domain source
  of truth. Transitional PR-stage helper names are removed from production APIs.
- Generated UniFFI outputs remain generated-only and are never hand-edited.
- File sizes become a symptom to monitor, not the primary success metric. The
  real success metric is clearer ownership plus unchanged behavior.

## 3. Global Refactor Rules

Every implementation PR in this program must follow these rules.

- Preserve behavior unless the PR explicitly declares a reviewed behavior
  change.
- Keep PRs small enough that one security or lifecycle boundary can be reviewed
  at a time.
- Do not modify `MARKETING_VERSION`, `CURRENT_PROJECT_VERSION`, entitlements,
  permission strings, or release metadata as incidental refactor work.
- Do not change public Swift APIs, UniFFI exports, Rust-visible behavior,
  ProtectedData schema, persisted storage layout, or generated bindings unless
  that PR declares the change and carries the required validation.
- Do not hand-edit `Sources/PgpMobile/pgp_mobile.swift`,
  `bindings/pgp_mobile.swift`, or generated FFI headers.
- Keep one primary type per file where practical, and group files by feature
  according to `CONVENTIONS.md`.
- Preserve zero network access, minimal permissions, AEAD hard-fail behavior,
  secure randomness, secret-data zeroization, and no plaintext/private-key
  logging.
- Preserve ProtectedData registry authority, explicit pending-mutation recovery,
  no-silent-reset behavior, relock zeroization, and `restartRequired`
  fail-closed semantics.
- Add or update tests before relying on a split as behavior-preserving.
- Update canonical docs only when an implementation PR changes current shipped
  behavior, ownership, validation expectations, or persisted-state
  classification.

## 4. Boundary-First Workstreams

The workstreams below are ordered by boundary risk. Complete earlier security
and crypto boundaries before lower-risk UI and composition cleanup unless a
later PR explicitly proves that a UI extraction is needed as preparation.

### 4.1 ProtectedData Framework And Domain Split

Evidence source:
`ProtectedDomainRecoveryCoordinator.swift` currently combines generic domain
recovery, generic post-unlock opening, and the concrete `protected-settings`
store.

Goal:
make framework-level recovery and post-unlock coordination reviewable without
requiring the reader to inspect a specific product-domain store.

TODO:

- [ ] Split the generic recovery protocol and dispatcher from concrete
  domain-store code.
- [ ] Split post-unlock domain-opening context, opener, outcome, and
  coordinator into a focused framework file.
- [ ] Move `ProtectedSettingsStore` and its recovery conformance into
  protected-settings-owned files.
- [ ] Keep protected-settings schema, ordinary-settings migration,
  payload encryption, domain state, and relock behavior unchanged.
- [ ] Add focused tests if any split exposes missing coverage around pending
  create/delete recovery, post-unlock open outcomes, or protected-settings
  recovery classification.

Acceptance standards:

- Pending mutation recovery behavior is unchanged for create and delete phases.
- Post-unlock domain open behavior returns the same outcomes for missing
  context, missing domains, recovery-needed registry state, authorization
  denial, and opener failure.
- Protected-settings migration, reset, open, update, recovery, and relock
  behavior are unchanged.
- Sensitive wrapping-root-key and domain-master-key buffers are still zeroized.
- No public API, schema, or persisted storage path changes occur unless a PR
  declares them explicitly.

### 4.2 ProtectedData Session And App Access Gate

Evidence source:
`ProtectedDataSessionCoordinator.swift` combines root-secret persistence,
legacy migration, wrapping-root-key derivation, framework state, relock
participant registration, relock fan-out, and restart-required latching.
`AppSessionOrchestrator.swift` combines UI-facing session state, resume
lifecycle, `LAContext` handoff, post-auth execution, relock, and ProtectedData
access-gate evaluation.

Goal:
separate root-secret lifecycle from app-session presentation state and make
ProtectedData access-gate classification independently testable.

TODO:

- [ ] Extract root-secret load/save/reprotect and legacy migration helpers from
  the session coordinator while preserving its public coordination role.
- [ ] Extract relock participant registration and relock fan-out into a focused
  session teardown component or helper.
- [ ] Extract ProtectedData access-gate classification from app privacy-screen
  presentation state.
- [ ] Keep authenticated-context consume/borrow semantics explicit and
  single-owner.
- [ ] Preserve resume, grace-period, content-clear, post-auth handler, relock,
  and failure-state behavior.

Acceptance standards:

- App resume behavior is unchanged for bypass, grace-period valid, grace-period
  expired, auth success, auth failure, operation prompt in progress, and
  protected-data recovery-needed states.
- `LAContext` handoff is not reused after consumption and is invalidated at the
  same lifecycle boundaries as before.
- Access-gate unit tests cover empty steady state, pending mutation recovery,
  framework recovery, locked session, and authorized session.
- Relock still clears wrapping-root-key material and unlocked domain master keys.
- Any participant relock failure still moves the framework into
  `restartRequired` according to current fail-closed behavior.

### 4.3 Private-Key Authentication And Rewrap Recovery

Evidence source:
`AuthenticationManager.swift` combines `LAContext` evaluation, auth-mode reads,
private-key control integration, mode switching, Secure Enclave and Keychain
bundle migration, protected rewrap journal handling, and crash recovery.

Goal:
make authentication evaluation, mode-switch orchestration, Keychain bundle
rewrap, and interrupted-rewrap recovery independently reviewable.

TODO:

- [ ] Separate LAContext evaluation and policy mapping from mode-switch
  mutation logic.
- [ ] Extract the rewrap phase workflow into a focused component that owns
  pending namespace creation, verification, deletion, promotion, and cleanup.
- [ ] Extract interrupted rewrap recovery into a focused component or helper
  with explicit phase-aware outcomes.
- [ ] Keep `AuthenticationManager` as the app-facing coordinator unless a later
  PR explicitly introduces a reviewed facade.
- [ ] Add negative tests for phase-A failure, phase-B failure, missing pending
  bundle, partial pending bundle, and commit-required recovery where current
  coverage is insufficient.

Acceptance standards:

- Standard mode continues to allow passcode fallback; High Security continues to
  require biometrics only.
- Switching to High Security still requires at least one backed-up key.
- Current-mode authentication still happens before any Keychain mutation.
- Phase-A failure still leaves old permanent items authoritative and cleans up
  pending items.
- Phase-B failure still preserves pending items and leaves recovery state for
  next launch.
- Commit-required recovery still promotes pending bundles only when safe and
  distinguishes safe cleanup, retryable failure, and unrecoverable failure.

### 4.4 Rust Key Operations And QR Boundary

Evidence source:
`pgp-mobile/src/keys.rs` collects many OpenPGP key capability families.
`pgp-mobile/src/lib.rs` is mostly a UniFFI facade but implements QR URL
encode/decode inline, while Swift `QRService` also parses URL input.

Goal:
make Rust key capability families and the untrusted QR URL boundary auditable
without changing the exported `PgpEngine` surface by default.

TODO:

- [ ] Split `keys.rs` internally by capability family: generation, key info,
  selector discovery, public certificate validation/merge, secret
  import/export, revocation, profile/S2K helpers, and expiry mutation.
- [ ] Keep re-export or module wiring internal so existing UniFFI method names
  and Swift call sites remain unchanged.
- [ ] Move QR URL encode/decode implementation out of the `lib.rs` facade into
  a dedicated Rust module.
- [ ] Keep Swift `QRService` as the app-facing service for URL routing,
  display metadata, and Swift-side input checks.
- [ ] If a future PR intentionally changes QR validation ownership, document the
  Swift/Rust contract before implementation.

Acceptance standards:

- Rust tests for both Profile A and Profile B continue to pass.
- Existing UniFFI public records, enums, errors, and method names remain
  source-compatible unless a PR declares an API change.
- Secret certificate inputs remain zeroized or wrapped in zeroizing ownership at
  the FFI boundary where current code requires it.
- Profile-correct generation, export S2K, merge/update rejection of secret
  material, revocation generation, S2K parsing, and expiry mutation behavior are
  unchanged.
- QR decoding still rejects invalid schemes, oversized URLs, invalid base64url,
  invalid OpenPGP data, and secret key material.
- If Rust-visible behavior or UniFFI surface changes, the PR regenerates
  bindings and runs the full Rust artifact refresh before Xcode validation.

### 4.5 Contacts Protected-Domain Authority

Evidence source:
Contacts authority is split across `ContactService`,
`ContactsDomainStore`, and `AppContainer`; production helpers still carry
`ContactsPR1` naming.

Goal:
make Contacts availability, migration, mutation persistence, protected-domain
storage, and cleanup ownership answerable from one app-facing facade and one
protected-domain source of truth.

TODO:

- [ ] Keep `ContactService` as the only UI/app-facing Contacts facade.
- [ ] Document or extract the internal ownership split between availability,
  query APIs, mutation APIs, migration/quarantine cleanup, protected-domain
  persistence, and relock cleanup.
- [ ] Remove production helper names that include PR-stage labels such as
  `ContactsPR1`.
- [ ] Keep Contacts schema decisions aligned with the Contacts implementation
  plan and surface inventory; do not redefine schema in this architecture
  refactor.
- [ ] Keep `AppContainer` responsible for dependency assembly only, not Contacts
  domain policy.

Acceptance standards:

- Contacts availability has one authoritative state model exposed through
  `ContactService`.
- Protected-domain open, legacy compatibility fallback, migration/quarantine
  warning, mutation persistence, rollback, and relock cleanup behavior are
  unchanged.
- Contacts helper names in production code no longer reference historical PR
  staging.
- Tests cover protected-domain open success, fallback eligibility, recovery
  state, mutation rollback, relock cleanup, and legacy compatibility where
  relevant.
- Contacts docs are updated only when implementation changes current Contacts
  behavior or surface ownership.

### 4.6 Protected Settings Host And App/UI Composition

Evidence source:
`ProtectedSettingsHost.swift` combines SwiftUI-facing state with ProtectedData
authorization and mutation policy. `AuthenticationShieldHost.swift` combines a
shield coordinator, environment key, view modifier, platform lifecycle hooks,
overlay views, animation, dismissal timing, and tracing. `CypherAirApp.swift`
and `AppContainer.swift` own broad scene construction, environment injection,
URL import orchestration, warning presentation, reset behavior, default graph,
UI-test graph, and post-auth wiring.

Goal:
make app-layer files thinner by moving workflow policy into dedicated models or
coordinators while keeping views responsible for layout, bindings, and
presentation wiring.

TODO:

- [ ] Extract protected-settings access and mutation authorization policy from
  the SwiftUI-facing host into a focused model/coordinator.
- [ ] Keep protected-settings UI state, section state mapping, and view
  environment injection presentation-oriented.
- [ ] Split authentication shield state transitions from overlay rendering and
  platform lifecycle adapters.
- [ ] Split app launch configuration, incoming URL import orchestration,
  load-warning presentation, and reset restart behavior from the scene body
  where practical.
- [ ] Reduce duplicated dependency wiring between default and UI-test
  containers by extracting shared construction helpers that do not hide test
  differences.

Acceptance standards:

- Views retain layout, bindings, environment reads, and presentation modifiers;
  business policy and security decisions live outside view rendering code.
- Protected settings access behavior remains unchanged for locked, unavailable,
  recovery-needed, pending-retry, pending-reset, handoff-only, and authorized
  states.
- Authentication shield presentation, dismissal timing, lifecycle handling,
  tracing, and hit-testing remain unchanged.
- App launch, route ownership, URL import, load warnings, tutorial handling,
  local-data reset restart behavior, and post-auth wiring remain unchanged.
- Route ownership, settings, tutorial-host, or macOS UI workflow changes run
  targeted macOS UI smoke coverage.

## 5. Cross-Workstream Acceptance Gates

Each future refactor PR must declare which workstream it belongs to and satisfy
the gates below.

Behavior gate:

- Existing user-visible behavior remains unchanged unless the PR explicitly
  declares a reviewed behavior change.
- Existing persisted data remains readable.
- Existing recovery and warning states remain reachable and fail closed.

Security gate:

- No network APIs, telemetry, update checks, sockets, or network SDKs are added.
- Only the existing biometric permission description remains allowed.
- No plaintext, private-key material, passphrases, decrypted data, fingerprints
  in sensitive diagnostics, or root-secret material are logged.
- Sensitive Swift `Data` and Rust secret buffers are still zeroized.
- AEAD authentication failure still aborts without exposing partial plaintext.

API and storage gate:

- Public Swift APIs, Rust/UniFFI exports, generated bindings, ProtectedData
  schema, storage paths, entitlements, permissions, and release metadata do not
  change accidentally.
- Any intentional change in those surfaces is named in the PR description and
  reflected in the relevant canonical docs.

Testing gate:

- Swift unit tests cover changed coordinator, session, recovery, migration,
  relock, authorization, or UI-state behavior.
- Rust tests cover changed `pgp-mobile` modules.
- Full Rust artifact refresh is required before Xcode validation when a Rust
  change affects Swift-visible behavior, UniFFI, bindings, or packaged
  artifacts:
  `ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=latest ./build-xcframework.sh --release`
- macOS UI smoke coverage is required for route ownership, settings, tutorial
  host, app lifecycle, or visible workflow changes.
- Device-only coverage remains required for Secure Enclave, biometric,
  authentication mode, MIE, or hardware-bound ProtectedData root-secret behavior.

Documentation gate:

- Update canonical docs in the same PR only when current behavior, ownership,
  validation, persisted-state classification, or security rules actually change.
- Do not cite archived documents as current authority.
- Keep active documentation in English.

## 6. PR Sequencing Guidance

Use this sequence unless a future blocker proves a different order is safer.

1. Documentation and test-baseline preparation
   - Add missing focused tests for behavior that later splits must preserve.
   - Keep this phase docs/test-only where possible.

2. ProtectedData framework/domain split
   - Separate generic recovery and post-unlock coordination from
     `ProtectedSettingsStore`.
   - Keep schema and behavior unchanged.

3. ProtectedData session and app access-gate split
   - Isolate root-secret lifecycle, relock fan-out, app-session presentation
     state, and access-gate classification.

4. Private-key authentication and rewrap split
   - Isolate authentication evaluation, mode-switch mutation, Keychain bundle
     rewrap, and interrupted recovery.

5. Rust key module and QR boundary split
   - Move Rust capability families behind stable internal module wiring.
   - Keep UniFFI surface unchanged unless explicitly reviewed.

6. Contacts authority cleanup
   - Clarify Contacts source-of-truth and remove PR-stage helper naming.
   - Stay aligned with Contacts-specific implementation docs.

7. App/UI composition cleanup
   - Thin SwiftUI hosts, app root, and dependency graph assembly after the
     security and crypto boundaries are less tangled.

Each PR should include a short "Refactor safety notes" section that lists:

- behavior intentionally preserved
- tests added or reused as proof
- public API or storage surfaces intentionally unchanged
- sensitive files reviewed

## 7. Out Of Scope

This implementation reference does not authorize:

- rewriting the app architecture from scratch
- introducing a second ProtectedData vault, registry, or root-secret model
- changing Contacts schema outside the Contacts implementation plan
- changing OpenPGP profile semantics or message format selection
- changing the UniFFI public API surface as incidental cleanup
- changing entitlements, permission strings, MIE capability, release metadata,
  or build numbers
- hand-editing generated UniFFI Swift or FFI headers
- altering App Store release process or arm64e packaging behavior
- adding new user-visible features while performing architecture cleanup

If a future PR needs any out-of-scope change, it must first update the relevant
canonical planning document or create a dedicated proposal with explicit
security, migration, and validation requirements.
