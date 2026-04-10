# Service / View Refactor Implementation Specification

> Purpose: Define the implementation baseline for a future Service and View refactor without changing user-visible behavior or current security semantics.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [SERVICE_VIEW_REFACTOR_ASSESSMENT](SERVICE_VIEW_REFACTOR_ASSESSMENT.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [CONVENTIONS](CONVENTIONS.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)
> Spec posture: This document is an execution baseline for future refactor work. It is intentionally more specific than the assessment, but it does not authorize implementation before the assessment is reviewed and accepted.

## 1. Intent

This refactor exists to solve a structural problem, not a product problem.

CypherAir already has working behavior across the current production app and the guided tutorial. The problem is that several services and screens now mix rendering, coordination, state machines, persistence decisions, and integration seams in ways that increase review cost and slow safe iteration.

The intent of the refactor is to:

- keep every current user-visible behavior intact
- keep every current security semantic intact
- reduce overloaded service and view ownership
- preserve tutorial compatibility while production pages are restructured
- make future feature work cheaper to review and less likely to regress adjacent flows

This specification assumes the assessment in [SERVICE_VIEW_REFACTOR_ASSESSMENT](SERVICE_VIEW_REFACTOR_ASSESSMENT.md) has already been reviewed and accepted. No implementation phase should start before that review gate is passed.

## 2. Refactor Goals

The refactor must achieve all of the following:

1. Keep the existing production service entry points stable for downstream callers.
2. Reduce `KeyManagementService` and `ContactService` from multi-owner implementations into facades over smaller internal collaborators.
3. Move workflow coordination out of the largest production screens and into dedicated `@Observable` screen models.
4. Preserve the current `Configuration`-driven tutorial adaptation pattern so the tutorial continues to wrap real production pages instead of forking them.
5. Reduce `CypherAirApp` back toward a composition root by moving app-flow coordination into dedicated coordinators.
6. Stage the work in four function-cluster waves so validation and review stay bounded.

The refactor does not need to make every screen tiny. It does need to restore clear ownership boundaries.

## 3. Target Architecture

### 3.1 Service Layer

#### 3.1.1 General Rule

Current environment-injected service types remain the public app-level facade layer:

- `KeyManagementService`
- `ContactService`
- `EncryptionService`
- `DecryptionService`
- `SigningService`
- `QRService`

The first refactor wave must not require widespread caller migration away from those names.

#### 3.1.2 `KeyManagementService`

`KeyManagementService` remains the facade exposed to views and other services, but its internal ownership is split into smaller collaborators with stable, narrow responsibilities.

Target collaborator boundaries:

- `KeyCatalogStore`
  - owns loading, in-memory key collection updates, default-key state, and metadata persistence coordination
- `KeyProvisioningService`
  - owns generate/import workflows and the transition from raw engine output into stored identities
- `KeyExportService`
  - owns secret-key export, public-key export, and revocation export workflows
- `KeyMutationService`
  - owns expiry mutation, deletion, and related transactional mutation flows
- `PrivateKeyAccessService`
  - owns Secure Enclave unwrap access and raw private-key retrieval for downstream crypto flows

Rules:

- `KeyManagementService` keeps the current public methods in the first wave.
- `keys` and `defaultKey` remain observable through the facade.
- security-sensitive sequencing must remain unchanged even if internal ownership moves.
- no first-wave change may alter the current behavior of `AuthenticationManager`, Secure Enclave wrapping, Keychain access-control semantics, or crash-recovery semantics.

#### 3.1.3 `ContactService`

`ContactService` remains the facade exposed to the App layer, but internal ownership is split into:

- `ContactRepository`
  - owns contact file persistence, metadata manifest persistence, and load/save operations
- `ContactImportService`
  - owns validation, same-fingerprint merge decisions, replacement detection, and import/update result shaping

Rules:

- the current `ContactService` public methods remain compatible in the first wave.
- the contact-import public-only validation path must remain intact.
- file naming, metadata format, duplicate/update/replacement semantics, and verification-state persistence remain unchanged.

#### 3.1.4 Other Services

First-wave treatment of the remaining services:

- `EncryptionService`: keep public API unchanged; internal helper extraction is allowed only to support cleaner screen-model integration.
- `DecryptionService`: keep public API unchanged and preserve the Phase 1 / Phase 2 boundary exactly.
- `SigningService`: keep public API unchanged; internal helper extraction is allowed but not required.
- `PasswordMessageService` and `SelfTestService`: no structural refactor required in the first wave.

### 3.2 View Layer

#### 3.2.1 General Rule

Large production pages move to a screen-model-backed structure:

- the top-level view remains the routing and call-site type
- a dedicated `@Observable` screen model owns workflow state, async actions, transient results, and presentation state
- the rendered content binds to that screen model

The screen model becomes the owner of:

- task and progress lifecycle
- async action orchestration
- input/output state invalidation
- file importer and exporter state
- error and confirmation state
- output interception decisions

The view remains responsible for:

- layout
- bindings
- local rendering-only derivations
- wiring toolbar, sheet, alert, and navigation modifiers to model state

#### 3.2.2 Required First-Wave Screen Models

The first refactor wave must explicitly target these screen models:

- `EncryptScreenModel`
- `DecryptScreenModel`
- `SignScreenModel`
- `VerifyScreenModel`
- `SettingsScreenModel`
- `KeyDetailScreenModel`
- `AddContactScreenModel`

These are the mandatory screen-model surfaces for the first wave because they correspond to the largest current coordination hotspots.

#### 3.2.3 First-Wave Pages Not Required To Become Screen Models

The following pages are not mandatory screen-model targets in the first wave:

- `KeyGenerationView`
- `ImportKeyView`
- `BackupKeyView`
- `ModifyExpirySheetView`
- tutorial hub and onboarding screens

They may receive smaller helper extraction if needed for compatibility, but they are not the first-wave architecture drivers.

#### 3.2.4 Shared App Helpers

The refactor should preserve and reuse the current App-layer helper seams instead of replacing them wholesale:

- `OperationController`
- `FileExportController`
- `SecurityScopedFileAccess`
- `ImportedTextInputState`
- `PublicKeyImportLoader`
- `ContactImportWorkflow`
- `ImportConfirmationCoordinator`

The preferred change is ownership relocation, not helper deletion. For example, a screen model may own an `OperationController`, but the utility itself should remain reusable.

### 3.3 Tutorial / Onboarding Compatibility

Tutorial compatibility is a hard constraint, not a nice-to-have.

The first refactor wave must keep the current adaptation model:

- production screens keep their `Configuration` structs
- tutorial restrictions continue to flow through `TutorialConfigurationFactory`
- tutorial route hosting continues to flow through `TutorialRouteDestinationView`, `TutorialSurfaceView`, and `TutorialShellDefinitionsBuilder`
- `TutorialSessionStore` remains the tutorial state machine and artifact owner
- `TutorialSandboxContainer` remains a separate composition root

Rules:

- do not rewrite the tutorial state machine in the first wave
- do not merge the production and tutorial containers
- do not remove the existing callback-driven `Configuration` hooks before replacement seams are proven

### 3.4 App Root And Flow Coordination

`CypherAirApp` should end the refactor as a composition root plus top-level scene declaration, not as a multi-flow coordinator.

Target coordinator boundaries:

- `AppPresentationCoordinator`
  - owns onboarding/tutorial presentation state and handoff rules
- `IncomingURLImportCoordinator`
  - owns `cypherair://` public-key import coordination and alert state

Rules:

- startup behavior currently performed by `AppStartupCoordinator` remains intact
- tutorial launch semantics and onboarding dismissal rules remain unchanged
- global alert content and timing remain unchanged

## 4. Compatibility Rules

The following are non-negotiable first-wave constraints:

- No user-visible behavior changes.
- No string changes, route changes, tutorial module-order changes, or export filename changes.
- No changes to current import/export semantics, clipboard behavior, or output-interception behavior.
- No changes to current ready markers used by UI tests.
- No changes to `UITEST_*` launch-environment semantics.
- No first-wave Rust changes.
- No first-wave behavior changes under `Sources/Security/`.
- No first-wave behavioral changes to `AuthenticationManager`.
- `Configuration` types for existing production pages remain source-compatible.
- Existing environment-injected facade types remain the primary entry points for the App layer.

Specific compatibility rules by area:

- `DecryptionService` Phase 1 / Phase 2 behavior must remain byte-for-byte compatible from the caller perspective.
- `KeyManagementService` recovery and unwrap behavior must remain externally identical.
- `ContactService` duplicate/update/replacement semantics must remain externally identical.
- `TutorialConfigurationFactory` must remain capable of expressing current tutorial restrictions and callbacks without requiring tutorial-only forks of production pages.

## 5. Phased Rollout

Implementation is fixed to four function-cluster phases. Do not collapse them into one branch-sized rewrite.

### 5.1 Phase 1: Key Lifecycle + Settings

**Scope**

- internal split of `KeyManagementService`
- `SettingsScreenModel`
- `KeyDetailScreenModel`
- any minimal adapter work needed to keep key-detail and settings flows compatible with the new internals

**Required outputs**

- `KeyManagementService` facade preserved
- internal collaborator boundaries established and covered by unit tests
- `SettingsView` no longer directly coordinates mode switching
- `KeyDetailView` no longer directly owns its export/delete/revocation/expiry workflow state

**Completion definition**

- callers still use `KeyManagementService`
- key detail and settings retain current behavior
- no behavior change to auth-mode warnings, mode switching, revocation export, default-key changes, delete flow, or modify-expiry flow

**Out of scope**

- `AuthenticationManager` behavior changes
- `KeyGenerationView`, `ImportKeyView`, `BackupKeyView`, and `ModifyExpirySheetView` full screen-model conversion

### 5.2 Phase 2: Encrypt / Decrypt / Sign / Verify

**Scope**

- `EncryptScreenModel`
- `DecryptScreenModel`
- `SignScreenModel`
- `VerifyScreenModel`
- thin host/content restructuring for the four production screens
- helper extraction in `EncryptionService`, `DecryptionService`, and `SigningService` only when needed to support the screen-model split

**Required outputs**

- workflow state moves out of the four views
- current `Configuration` structs remain usable by both production and tutorial hosts
- export/import/cancel/error/presentation behavior remains unchanged

**Completion definition**

- `EncryptView`, `DecryptView`, `SignView`, and `VerifyView` primarily bind to screen-model state
- file inspection, invalidation, and cleanup logic are no longer interleaved with rendering code
- `DecryptionService` Phase 1 / Phase 2 semantics are unchanged

**Out of scope**

- service facade renaming
- password-message UI activation

### 5.3 Phase 3: Contacts Import Flows

**Scope**

- internal split of `ContactService`
- `AddContactScreenModel`
- compatibility updates for QR-photo import and confirmation-host flows

**Required outputs**

- `ContactService` facade preserved
- contact persistence and contact-import workflow responsibilities split internally
- `AddContactView` no longer owns the main import workflow state machine

**Completion definition**

- duplicate/update/replacement semantics remain unchanged
- current confirmation coordinator and import-confirmation UI remain intact
- tutorial add-contact flow still works through `TutorialConfigurationFactory`

**Out of scope**

- redesign of the contact-import user experience
- tutorial-specific contact flow rewrite

### 5.4 Phase 4: App Root + Tutorial / Onboarding Host

**Scope**

- `AppPresentationCoordinator`
- `IncomingURLImportCoordinator`
- adaptation of tutorial host layers to the new screen-model-backed production pages

**Required outputs**

- `CypherAirApp` is reduced to composition and top-level scene wiring
- onboarding/tutorial handoff logic moves into a dedicated coordinator
- URL import coordination moves out of the app root
- tutorial host wrappers remain compatible with production-page configuration

**Completion definition**

- tutorial launch, replay, and dismissal behavior are unchanged
- startup warnings and import alerts are unchanged
- production pages still render correctly in tutorial and onboarding-connected contexts

**Out of scope**

- rewriting `TutorialSessionStore`
- merging tutorial and production containers
- redesigning tutorial host UX

## 6. Testing And Validation Gates

### 6.1 Baseline Gate Before Any Code Phase

Before starting any implementation phase, confirm the branch baseline with the current repository commands:

```bash
cargo test --manifest-path pgp-mobile/Cargo.toml
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'
```

If baseline is not green, fix or isolate baseline breakage before beginning refactor work.

### 6.2 Mandatory Validation For Every Phase

Every phase must end with:

- `cargo test --manifest-path pgp-mobile/Cargo.toml`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'`
- targeted review against [CODE_REVIEW](CODE_REVIEW.md)

### 6.3 Phase-Specific Test Expectations

#### Phase 1

- expand or add unit tests for new `KeyManagementService` collaborators
- keep `KeyManagementServiceTests` green
- keep relevant tutorial tests green when key detail and settings surfaces are exercised indirectly

#### Phase 2

- keep `EncryptionServiceTests`, `DecryptionServiceTests`, `SigningServiceTests`, and `StreamingServiceTests` green
- add screen-model tests for:
  - import/export state transitions
  - cancellation behavior
  - invalidation and cleanup behavior
  - warning/confirmation state transitions
- extend macOS smoke coverage when new ready-state ownership changes require it

#### Phase 3

- keep `ContactServiceTests` green
- keep `TutorialSessionStoreTests` add-contact paths green
- add screen-model tests for add-contact mode switching, QR/file import, and replacement confirmation flow

#### Phase 4

- keep `TutorialSessionStoreTests` green
- keep `MacUISmokeTests` tutorial and settings launch flows green
- add coordinator tests for onboarding/tutorial handoff and URL import coordination

### 6.4 Device-Test Rule

Device-only test plans are required only if a phase unexpectedly changes behavior close to device-auth or Secure Enclave semantics. The intended first-wave design should avoid that by keeping security behavior unchanged.

## 7. Review Checkpoints

### 7.1 Documentation Gate

No code implementation starts until:

- [SERVICE_VIEW_REFACTOR_ASSESSMENT](SERVICE_VIEW_REFACTOR_ASSESSMENT.md) is reviewed
- this implementation specification is reviewed
- the phase order is accepted without reopening the architecture scope

### 7.2 Per-Phase Design Review

Before each phase starts, confirm:

- the target files and collaborators for the phase
- the explicit non-goals for the phase
- the tests that must be updated or added
- whether any sensitive boundary is being approached

### 7.3 Sensitive-Boundary Review

If a phase touches or risks touching any of the following, human review is mandatory before merge:

- `Sources/Security/`
- `Sources/Services/DecryptionService.swift`
- `Sources/Services/QRService.swift`
- `CypherAir.xcodeproj/project.pbxproj`
- onboarding/tutorial launch and auth-mode confirmation behavior

### 7.4 Behavior-Parity Review

At the end of each phase, perform a behavior-parity review against current production expectations:

- no visible navigation changes
- no alert sequencing changes
- no tutorial capability changes
- no import/export naming changes
- no changed settings semantics

## 8. Deferred Items

The following are explicitly deferred beyond the first refactor wave:

- rewriting the tutorial state machine in `TutorialSessionStore`
- unifying tutorial and production containers
- narrowing or renaming public service facades
- activating new product surfaces for `PasswordMessageService`
- broad conversion of every key-related screen to a first-wave screen-model requirement
- redesigning tutorial hub, onboarding copy, or tutorial host UX
- changing Rust, Secure Enclave, Keychain, or auth-mode behavior semantics

These deferments are intentional. They keep the first structural refactor focused on ownership boundaries and coordination flow.

## 9. Execution Summary

The future refactor should be treated as an architecture-preserving internal rewrite with strict compatibility constraints:

- preserve facades
- split internal ownership
- move screen workflow logic into dedicated `@Observable` screen models
- preserve tutorial `Configuration` compatibility
- preserve current security semantics
- move app-root coordination into dedicated coordinators

If an implementation proposal cannot satisfy those constraints, it should be treated as out of spec for the first wave and deferred rather than folded into the same refactor.
