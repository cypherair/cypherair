# Architecture Refactor Audit

> Status: archived architecture audit retained as historical evidence.
> Scope: oversized non-generated files, mixed responsibilities, and unclear
> boundaries in production code. This document is evidence only; refactor
> requirements and implementation tasks belong in follow-up documents.

## Audit Criteria

This audit uses the current production source tree as the baseline.

- Generated UniFFI bindings, generated FFI headers, resource blobs, fixtures, and
  third-party notices are excluded from production architecture findings.
- Production code, tests, docs, generated code, and resources are separated.
  Large tests may need separate test hygiene work, but they are not used as
  evidence of production boundary confusion here.
- Findings are judged against local repo rules and architecture constraints:
  one type per file, group by feature, keep sensitive security boundaries
  explicit, keep ProtectedData authorization and post-auth semantics clear, and
  avoid making composition roots own domain policy.
- A large file is not automatically an architectural defect. The issue recorded
  here is the combination of file size, multiple ownership axes, cross-layer
  dependencies, and security or lifecycle semantics that become hard to review
  in one place.
- All findings below are considered in scope for later refactor planning. This
  document intentionally does not split them into primary and secondary buckets.

## Evidence Summary

| Area | File(s) | Current size | Mixed responsibilities | Boundary concern | Evidence anchors |
| --- | --- | ---: | --- | --- | --- |
| ProtectedData recovery, post-unlock, and settings storage | `Sources/Security/ProtectedData/ProtectedDomainRecoveryCoordinator.swift` | 1316 lines | Generic pending-mutation recovery, post-unlock domain opening, and concrete `protected-settings` storage | A framework-level ProtectedData file also owns a product-domain store; this weakens one-type-per-file and makes security review span unrelated lifecycle layers | `ProtectedDomainRecoveryHandler` at line 5, `ProtectedDomainRecoveryCoordinator` at line 19, `ProtectedDataPostUnlockCoordinator` at line 189, `ProtectedSettingsStore` at line 364 |
| Rust key operations | `pgp-mobile/src/keys.rs` | 1483 lines | Key generation, key info parsing, selector discovery, public certificate merge, secret-key import/export, S2K parsing, revocation, profile detection, and expiry mutation | Crypto behavior for many different API surfaces is concentrated in one module, making profile correctness and secret-material handling harder to review in isolation | `generate_key_with_profile` at line 186, `parse_key_info` at line 283, `merge_public_certificate_update` at line 807, `export_secret_key` at line 926, `generate_key_revocation` at line 1148, `parse_s2k_params` at line 1317, `modify_expiry` at line 1412 |
| Protected settings UI host and security access policy | `Sources/App/Settings/ProtectedSettingsHost.swift` | 1137 lines | SwiftUI environment host, section state, `LAContext` authorization, migration authorization, ProtectedData gate evaluation, recovery/reset flows, and tracing | App settings presentation code directly owns ProtectedData access policy and mutation authorization details | `LiveDependencies` at line 96, `AccessAuthorizationMode` at line 90, `authorizeMutationIfNeeded` at line 554, `ensureProtectedSettingsAccess` at line 668, `currentAccessGateDecision` at line 920 |
| App session orchestration | `Sources/Security/ProtectedData/AppSessionOrchestrator.swift` | 624 lines | App privacy blur state, grace-period decisions, authentication failure state, content clearing, ProtectedData relock, post-auth callback execution, `LAContext` handoff, and ProtectedData access-gate evaluation | A file under `Security/ProtectedData` owns UI-facing session state as well as ProtectedData authorization decisions | UI-facing state at lines 20-22, `requestContentClear` at line 86, `handleResume` at line 220, `consumeAuthenticatedContextForProtectedData` at line 465, `borrowAuthenticatedContextForMetadataMigration` at line 479, `evaluateProtectedDataAccessGate` at line 491 |
| ProtectedData session coordinator | `Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift` | 637 lines | Root-secret persistence/loading, legacy migration, wrapping-root-key derivation, framework state, relock fan-out, relock participant registry, and restart-required latching | The coordinator sits on a sensitive boundary and combines authorization, cryptographic key lifecycle, migration, and teardown policy in one review unit | `frameworkState` at line 23, `persistSharedRight` at line 45, `beginProtectedDataAuthorization` at line 104, wrapping-root-key derivation around lines 191-231, `wrappingRootKeyData` at line 330, `registerRelockParticipant` at line 337, `relockCurrentSession` at line 345 |
| Contacts protected-domain transition | `Sources/Services/ContactService.swift`, `Sources/Security/ProtectedData/ContactsDomainStore.swift`, `Sources/App/AppContainer.swift` | 687, 473, and 959 lines | Protected-domain opening, legacy compatibility, migration source, quarantine cleanup, runtime contact mutations, relock participation, and app-container wiring | Contacts storage authority is split across service, ProtectedData domain store, and composition root; transitional PR naming remains in production helpers | `ContactService.openContactsAfterPostUnlock` at line 62, `ContactsDomainStore` at line 10, `ContactsDomainStore.replaceSnapshot` at line 166, `ContactsDomainStore` recovery conformance at line 418, `contactsAvailabilityForContactsPR1` at line 391, `AppContainer` domain-store construction at line 226, post-auth Contacts open at line 381 |
| Private-key authentication and rewrap recovery | `Sources/Security/AuthenticationManager.swift` | 1108 lines | LAContext evaluation, auth-mode reads, private-key control integration, mode switching, Secure Enclave and Keychain bundle migration, rewrap journal recovery, and warning/error mapping | The file is security-critical and combines user authentication, private-key storage mutation, and crash-recovery policy | dependencies at lines 97-110, `lastEvaluatedContext` at line 117, `evaluate` at line 199, `switchMode` at line 682, protected rewrap journal handling at lines 797-956, interrupted rewrap recovery at line 995 |
| Authentication shield host | `Sources/App/Common/AuthenticationShieldHost.swift` | 838 lines | Shield state machine, presentation state, environment key, view modifier, platform lifecycle hooks, SwiftUI overlay views, animation and dismissal tracing | Coordinator policy and SwiftUI rendering/lifecycle glue share one app-layer file, making UI state transitions harder to review independently | `AuthenticationShieldCoordinator` at line 30, presentation state at line 59, lifecycle methods at lines 107-115, environment key at line 453, `AuthenticationShieldHostModifier` at line 464, `lifecycleAwareBody` at line 508, `AuthenticationShieldView` at line 538 |
| App root and composition root | `Sources/App/CypherAirApp.swift`, `Sources/App/AppContainer.swift` | 980 and 959 lines | Scene construction, launch configuration, environment injection, local-data reset restart behavior, incoming URL import orchestration, load-warning presentation, default dependency graph, UI-test graph, and post-auth wiring | App root and container own a wide slice of lifecycle and domain assembly; the default and UI-test graphs duplicate a large amount of dependency wiring | `CypherAirApp` at line 30, `WindowGroup` at line 355, environment injection at lines 371-380 and 438-455, `onChange` handlers at lines 473-598, `AppLaunchConfiguration` at line 905, `AppContainer.makeDefault` graph around lines 118-501, `makeUITest` at line 505 |
| QR URL boundary across Swift and Rust | `pgp-mobile/src/lib.rs`, `Sources/Services/QRService.swift` | 726 and 131 lines | FFI facade forwards most crypto APIs but implements QR URL encode/decode inline; Swift `QRService` also owns URL input parsing and display metadata | The external URL parsing boundary is split between Swift service code and Rust facade code instead of being isolated as one domain boundary | `QRService` security note at line 7, Swift URL parsing at lines 43-97, `PgpEngine.encode_qr_url` at line 639, `PgpEngine.decode_qr_url` at line 677 |

## Detailed Findings

### ProtectedData Recovery, Post-Unlock Orchestration, And Settings Store

`Sources/Security/ProtectedData/ProtectedDomainRecoveryCoordinator.swift` is a
single 1316-line file containing at least three distinct ownership areas:

- Generic domain recovery protocol and dispatcher:
  `ProtectedDomainRecoveryHandler` starts at line 5 and
  `ProtectedDomainRecoveryCoordinator` starts at line 19.
- Generic post-unlock domain opening:
  `ProtectedDataPostUnlockOpenContext`, `ProtectedDataPostUnlockDomainOpener`,
  `ProtectedDataPostUnlockOutcome`, and `ProtectedDataPostUnlockCoordinator`
  span lines 126-363.
- A concrete product-domain store:
  `ProtectedSettingsStore` starts at line 364 and extends to its recovery
  conformance at line 1312.

The architectural problem is not only size. A framework-level recovery and
post-unlock coordinator is sharing a file with the concrete `protected-settings`
store. That store owns schema details, ordinary-settings migration, domain
state, payload encryption, and relock behavior. This makes the file hard to
review as a ProtectedData framework component because any reader must also
understand a specific settings domain implementation.

The risk is especially high because this file lives in a sensitive boundary:
ProtectedData registry state, pending mutations, authenticated `LAContext`
handoff, wrapping-root-key usage, domain master keys, and relock semantics all
intersect here.

### Rust Key Operations

`pgp-mobile/src/keys.rs` is 1483 lines and contains many separate OpenPGP
operations:

- Public API model definitions from `KeyProfile` at line 21 through
  `CertificateMergeResult` at line 153.
- Key generation through `generate_key` and `generate_key_with_profile` at
  lines 177 and 186.
- Certificate parsing and display metadata through `parse_key_info` at line
  283.
- Selector discovery and ranking through `discover_certificate_selectors` at
  line 393 and helper functions through the 700s.
- Public certificate validation and merge/update through
  `validate_public_certificate` at line 440 and
  `merge_public_certificate_update` at line 807.
- Secret-key export/import and S2K behavior through
  `export_secret_key` at line 926, `import_secret_key` at line 1028, and
  `parse_s2k_params` at line 1317.
- Revocation and expiry mutation through `generate_key_revocation` at line
  1148, user/subkey revocation functions through line 1241, and
  `modify_expiry` at line 1412.

The module holds profile-specific behavior, secret-key handling, public
certificate update logic, revocation generation, and key-lifecycle mutation in
one file. In a crypto wrapper, this increases review cost because unrelated
OpenPGP invariants share local helper state and imports. Profile A/Profile B
format selection, S2K choices, secret-material zeroization assumptions, and
selector semantics all become coupled at the file level.

### Protected Settings Host

`Sources/App/Settings/ProtectedSettingsHost.swift` is a 1137-line App-layer file
that imports `LocalAuthentication` and `SwiftUI` side by side. It contains UI
host state and ProtectedData security policy in the same unit:

- `SectionState` and `AccessAuthorizationMode` are defined at lines 78 and 90.
- `LiveDependencies` starts at line 96 and carries ProtectedData registry,
  migration, authorization, and tracing dependencies into the host.
- Mutation authorization lives in `authorizeMutationIfNeeded` at line 554.
- Settings migration orchestration starts at line 631.
- The central gate, `ensureProtectedSettingsAccess`, starts at line 668 and
  handles pre-authorization state, access-gate decisions, migration
  authorization, open/create behavior, tracing, and failure mapping.
- `currentAccessGateDecision` delegates into `AppSessionOrchestrator` at line
  920.

The boundary issue is that a SwiftUI-facing host owns security-domain access
decisions. A settings surface needs to present locked/recovery/open states, but
this file also knows how to authorize mutations, when to bootstrap or migrate a
ProtectedData domain, how to classify recovery states, and how to trace the
security flow. That makes UI review and ProtectedData review inseparable.

### App Session Orchestrator

`Sources/Security/ProtectedData/AppSessionOrchestrator.swift` is 624 lines and
is correctly named as an orchestrator, but its scope crosses several boundaries:

- UI-facing state is stored directly in the coordinator:
  `isPrivacyScreenBlurred`, `isAuthenticating`, and `authFailed` are at lines
  20-22.
- Content clearing and authenticated context invalidation are handled by
  `requestContentClear` at line 86.
- `handleResume` starts at line 220 and combines bypass handling, operation
  prompt suppression, grace-period decisions, content clearing, ProtectedData
  relock, app authentication, post-auth handler execution, blur state, and
  failure-state updates.
- `consumeAuthenticatedContextForProtectedData` and
  `borrowAuthenticatedContextForMetadataMigration` are at lines 465 and 479.
- `evaluateProtectedDataAccessGate` starts at line 491 and classifies registry,
  bootstrap, framework, and session state into app access decisions.

This file sits under `Security/ProtectedData`, but it owns presentation-facing
state and application lifecycle decisions. The resulting boundary is blurry:
it is partly a UI privacy-screen model, partly an app lifecycle coordinator,
partly an `LAContext` broker, and partly a ProtectedData access-gate evaluator.

### ProtectedData Session Coordinator

`Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift` is 637
lines and is deeply security-sensitive:

- `frameworkState` is the central state latch at line 23.
- Root-secret persistence is exposed through `persistSharedRight` at line 45.
- Authorization begins through `beginProtectedDataAuthorization` at line 104 and
  `beginProtectedDataAuthorizationReturningContext` at line 122.
- Root-secret load, legacy migration, and wrapping-root-key derivation happen
  across the authorization path, including the root-secret load result around
  line 191 and `deriveWrappingRootKey` around lines 225-226.
- `wrappingRootKeyData` at line 330 exposes the authorized wrapping root key to
  domain openers.
- Relock participant registration and relock fan-out live at lines 337 and 345.
- The file clears unlocked domain keys at line 379 and has private root-secret
  loading/migration helpers through the remainder of the file.

The coordinator has a legitimate central role, but the current file binds
authorization, storage migration, cryptographic key derivation, session state,
participant registration, relock teardown, and restart-required failure policy.
Those responsibilities are closely related yet independently security-critical.
Keeping them in one file raises the cost of proving relock and root-secret
invariants during review.

### Contacts Protected-Domain Transition

Contacts currently spans service logic, ProtectedData storage, and app-container
wiring:

- `ContactService` is 687 lines and owns runtime contacts, availability,
  legacy migration source, protected-domain store integration, mutation
  persistence, verification state, migration warnings, and relock cleanup.
- `openContactsAfterPostUnlock` starts at line 62 and handles gate decisions,
  wrapping-root-key use, first-open legacy snapshot construction, protected
  domain open, quarantine state, legacy compatibility fallback, and recovery
  state.
- Runtime mutations branch on `.availableProtectedDomain` in multiple places,
  including lines 174, 295, 344, and 366.
- Transitional helper names with `ContactsPR1` remain in production code at
  lines 391-431.
- `ContactsDomainStore` is 473 lines and owns the ProtectedData domain state at
  line 10, snapshot replacement at line 166, and recovery conformance at line
  418.
- `AppContainer` constructs `ContactsDomainStore` at line 226, registers it for
  relock, wires `ContactService`, and later calls
  `openContactsAfterPostUnlock` in the post-auth handler at line 381.

The boundary concern is that Contacts has become a protected-domain product
area, but its authority is distributed across service runtime state,
ProtectedData domain storage, legacy migration/quarantine behavior, and root
composition. The code also still carries PR-stage naming in user-facing
production helpers. That makes it harder to answer a basic ownership question:
which component is the source of truth for Contacts availability, migration,
mutation persistence, and cleanup at each phase of app unlock?

### Authentication Manager

`Sources/Security/AuthenticationManager.swift` is 1108 lines. It is more
cohesive than some files in this audit because it is centered on private-key
authentication and auth-mode switching, but it still combines several
security-critical responsibilities:

- Secure Enclave and Keychain dependencies are stored at lines 97-98.
- Private-key control integration is stored at line 110.
- `lastEvaluatedContext` is retained at line 117 so mode switching can reuse an
  authenticated context.
- `evaluate(mode:reason:source:)` starts at line 199 and maps `LAContext`
  behavior into app authentication semantics.
- `switchMode` starts at line 682 and performs backup gating, current-mode
  authentication, protected rewrap journal setup, Keychain bundle read/write,
  pending namespace storage, old-item deletion, pending promotion, and auth-mode
  persistence.
- Rewrap journal and pending item handling spans lines 797-956.
- Crash recovery begins at `checkAndRecoverFromInterruptedRewrap` at line 995
  and continues through `recoverInterruptedRewrapMigrations` at line 1038.

The file is an important security review target because user authentication,
Secure Enclave wrapping, Keychain mutation, protected control-domain state, and
crash recovery are interleaved. The behavior may be correct, but the file-level
boundary makes it difficult to review mode-switch atomicity and recovery
semantics without scanning the whole manager.

### Authentication Shield Host

`Sources/App/Common/AuthenticationShieldHost.swift` is 838 lines and combines a
state coordinator with SwiftUI host infrastructure:

- `AuthenticationShieldCoordinator` starts at line 30.
- Its computed `presentationState` begins at line 59.
- Scene lifecycle methods are at lines 107-115.
- The SwiftUI environment key starts at line 453.
- `AuthenticationShieldHostModifier` starts at line 464.
- Platform lifecycle wiring in `lifecycleAwareBody` starts at line 508.
- `AuthenticationShieldView` starts at line 538.
- The public view modifier extension starts at line 812.

This file blends presentation policy, lifecycle event interpretation, dismissal
timing, tracing, environment injection, platform-specific lifecycle hooks, and
the overlay view tree. That increases review cost for authentication shield
behavior because coordinator state transitions and SwiftUI rendering effects
are not isolated.

### App Root And Composition Root

`Sources/App/CypherAirApp.swift` is 980 lines and `Sources/App/AppContainer.swift`
is 959 lines. Together they own most app startup, dependency graph assembly, and
top-level lifecycle wiring:

- `CypherAirApp` starts at line 30 and constructs launch/configuration state.
- The main `WindowGroup` starts at line 355.
- Environment injection spans lines 371-380 and 438-455.
- Route, warning, URL import, and reset-related `onChange` handlers span lines
  473-598.
- `AppLaunchConfiguration` starts at line 905.
- `AppContainer` declares a broad set of services and stores from lines 4-38.
- The default graph constructs security, ProtectedData, Contacts, key
  management, crypto services, QR, self-test, and local-data reset dependencies
  across lines 118-501.
- The UI-test graph starts at `makeUITest` on line 505 and repeats a large
  amount of composition logic through line 868.

Composition roots naturally become larger than feature files. The issue here is
that lifecycle event handling, app presentation state, URL import orchestration,
post-auth ProtectedData/Contacts opening, warning presentation, local reset
restart behavior, and multiple dependency graph variants all live in two large
files. This makes boundary drift likely because the root files become convenient
places to add domain policy.

### QR URL Boundary Across Swift And Rust

`Sources/Services/QRService.swift` is small at 131 lines, but it exposes a
boundary split with `pgp-mobile/src/lib.rs`.

- `QRService` declares itself security-critical for untrusted external input at
  line 7.
- Swift URL parsing and key-display validation live around lines 43-97.
- `pgp-mobile/src/lib.rs` is mostly a UniFFI facade, but it implements QR URL
  encoding inline at `PgpEngine.encode_qr_url` on line 639 and QR URL decoding
  inline at `PgpEngine.decode_qr_url` on line 677.

The architectural problem is not file size on the Swift side. The concern is
that external URL shape, base64url parsing, QR size limits, public-certificate
validation, and secret-material rejection are split between a Swift service and
the Rust FFI facade. Because QR import is an untrusted input boundary, the
ownership line should be easy to audit.

## Not Refactor Targets From This Audit

The following large files are intentionally excluded from this production
architecture audit:

- `Sources/PgpMobile/pgp_mobile.swift` - 5219 lines, UniFFI-generated Swift.
- `bindings/pgp_mobile.swift` - 5219 lines, UniFFI-generated Swift.
- `bindings/pgp_mobileFFI.h` - 1104 lines, generated FFI header.
- Resource blobs such as string catalogs, app icon previews, fixtures, and open
  source notice data.

These files may be regenerated, validated, or checked for accidental hand edits,
but their size is not evidence of first-party architecture boundary confusion.
