# FFI Boundary Leak Audit

> Status: Audit snapshot, non-canonical.
> Date: 2026-05-19.
> Scope: First-party Swift production sources under `Sources/`, generated
> UniFFI Swift bindings as origin evidence, Swift FFI adapter files, selected
> service-level tests, and architecture review evidence.
> Purpose: Independently audit whether generated UniFFI and FFI-boundary
> vocabulary leak above the intended Swift adapter boundary.
> Audience: CypherAir maintainers, reviewers, and coding agents preparing
> follow-up FFI boundary work.
> Evidence roots: `Sources/PgpMobile/pgp_mobile.swift`,
> `Sources/Services/FFI/`, `Sources/App/AppContainer.swift`,
> `Sources/App/Onboarding/TutorialSandboxContainer.swift`,
> ordinary production Services under `Sources/Services/`,
> `Tests/ServiceTests/TestHelpers.swift`, service/device/FFI tests under
> `Tests/`, `docs/ARCHITECTURE.md`, `docs/TESTING.md`, and
> `docs/DOCUMENTATION_GOVERNANCE.md`.

This document is a point-in-time audit. It is not a target architecture, a
remediation plan, or a canonical current-state replacement for
`docs/ARCHITECTURE.md`, `docs/SECURITY.md`, or `docs/TESTING.md`. Current code
and canonical current-state documentation outrank this snapshot whenever they
drift.

Update: the 2026-06-26 testing cleanup retired the former text-scanning XCTest
guardrails and build-time repository snapshot. Current FFI boundary maintenance
relies on architecture review, behavior tests, and canonical current-state
documentation rather than source-text assertions.

## Summary

The main generated UniFFI leakage problem is currently contained in normal
production paths: after excluding `Sources/PgpMobile/**` and
`Sources/Services/FFI/**`, the production Swift source search for generated
OpenPGP symbols found generated `PgpEngine` references only in app composition
roots. No ordinary UI route, ScreenModel, Models file, or normal Service public
API was found exposing generated result/error/status records such as
`PgpError`, `KeyInfo`, `SignatureStatus`, `DetailedSignatureEntry`,
`UserIdSelectorInput`, `DecryptDetailedResult`, or `VerifyDetailedResult`.

The remaining boundary debt is narrower but real. App composition still stores
and passes `PgpEngine`; one UI-test preload path calls the generated engine
directly; ordinary Services depend on concrete FFI adapter classes; several
adapter-local `PGP*` contract types cross from `Sources/Services/FFI` into
normal Services; and service-level tests still exercise generated engine/error
types directly in places that are not purely FFI integration tests.

## Audit Method

The audit established the generated symbol set from
`Sources/PgpMobile/pgp_mobile.swift`, including `PgpEngine`,
`PgpEngineProtocol`, `PgpError`, `KeyInfo`, `KeyProfile`, `GeneratedKey`,
`CertificateSignatureResult`, `DecryptDetailedResult`,
`FileDecryptDetailedResult`, `VerifyDetailedResult`,
`FileVerifyDetailedResult`, `DetailedSignatureEntry`,
`DetailedSignatureStatus`, `SignatureStatus`, `SignatureVerificationState`,
`UserIdSelectorInput`, `DiscoveredCertificateSelectors`,
`PublicCertificateValidationResult`, `PasswordDecryptResult`, `S2kInfo`,
`PasswordMessageFormat`, and related generated enums.

Production Swift sources were then searched in three passes: generated UniFFI
symbols outside `Sources/PgpMobile/**` and `Sources/Services/FFI/**`, direct
`PgpEngine`/`PgpError`/`PGPErrorMapper` references across `Sources`, and
adapter-local `PGP*` contract vocabulary outside the adapter directory. The
matches were manually checked in the App composition roots, FFI adapters,
ordinary Services, Models, and selected tests.

The audit also reviewed the then-current architecture guardrail inventory,
including generated UniFFI type containment, generated error mapper
containment, App-layer `PgpError` handling, and App-layer FFI adapter usage.

## Findings

### 1. Generated UniFFI Types Are Mostly Contained Above The Adapter Boundary

Evidence: `Sources/PgpMobile/pgp_mobile.swift` exposes generated public types
such as `PgpEngine`, `PgpError`, `KeyInfo`, `SignatureStatus`,
`SignatureVerificationState`, `DetailedSignatureEntry`,
`DetailedSignatureStatus`, `UserIdSelectorInput`, `DecryptDetailedResult`, and
`VerifyDetailedResult`. Searching production `Sources` for these symbols while
excluding `Sources/PgpMobile/**` and `Sources/Services/FFI/**` found generated
type usage only in `AppContainer` and `TutorialSandboxContainer`, plus a
non-binding comment in `PGPKeyProfile`.

Risk: Low for ordinary production routes. The hard generated-result and
generated-error vocabulary no longer appears to be part of normal UI,
ScreenModel, Models, or ordinary Service public paths.

Recommendation: Keep generated-type ownership visible in review and avoid
broadening temporary exceptions. Treat any new generated symbol use outside
composition roots and `Sources/Services/FFI/**` as a regression until proven
otherwise.

### 2. App Composition Roots Still Expose `PgpEngine`

Evidence: `AppContainer` stores `let engine: PgpEngine`, accepts `engine:
PgpEngine` in its initializer, creates `PgpEngine()` in default and UI-test
factory paths, and passes it through `makePgpServiceGraph(...)`. The guided
tutorial sandbox similarly stores `let engine: PgpEngine`, initializes
`PgpEngine()`, and constructs the concrete FFI adapters inside
`TutorialSandboxContainer`.

Risk: Medium. A composition root may legitimately construct dependencies, but
storing and exposing the generated engine gives App-layer code a stable handle
to the generated API. That makes future direct engine calls easier to add and
keeps the exception larger than the minimum needed for wiring.

Recommendation: Narrow the composition-root exception over time. Prefer a
small OpenPGP adapter bundle or service-graph factory that owns the generated
engine privately and returns app-owned Services, so App code wires capabilities
without retaining a generated engine.

### 3. UI-Test Preload Directly Calls The Generated Engine

Evidence: `AppContainer.preloadUITestContact(engine:contactService:)` calls
`engine.generateKey(...)` directly and then imports `generated.publicKeyData`
through `ContactService`.

Risk: Medium. This is not an ordinary user path, but it is still App-layer code
calling a generated engine operation outside the FFI adapter boundary. It also
requires the `AppContainer` composition-root exception to cover more than
dependency wiring.

Recommendation: Move the preload key generation behind an app-owned service or
test bootstrap helper that depends on an adapter/service protocol. The App
composition root should request a preload contact capability rather than call
`PgpEngine.generateKey(...)` itself.

### 4. Ordinary Services Depend On Concrete FFI Adapter Classes

Evidence: Normal Services store concrete adapter classes, including
`PGPMessageOperationAdapter` in `EncryptionService`, `DecryptionService`,
`PasswordMessageService`, and `SigningService`; `PGPKeyOperationAdapter` and
`PGPCertificateOperationAdapter` in `KeyManagementService` and its internal
helpers; `PGPContactImportAdapter` in `ContactService`, `ContactSnapshotMutator`,
and `QRService`; and `PGPSelfTestOperationAdapter` in `SelfTestService`.

Risk: Medium. This is not a generated UniFFI type leak, because these adapters
are Swift code. It is still boundary coupling: ordinary Services know concrete
FFI adapter implementations instead of app-owned capability interfaces. That
makes service-level fakes harder and keeps FFI adapter vocabulary visible in
business-service constructors.

Recommendation: Introduce focused app-owned protocols only where they reduce
real testing or ownership friction. Good first candidates are message
operations, key operations, contact import, certificate operations, and
self-test operations. Avoid a single broad "PGP service" protocol.

### 5. Adapter-Local `PGP*` Contract Types Cross Into Ordinary Services

Evidence: `PGPMessageVerificationContext` is declared in
`PGPMessageOperationAdapter.swift` and is constructed by `DecryptionService`,
`PasswordMessageService`, `SigningService`, and `SelfTestService`.
`PGPCertificateVerificationContext` is declared in the certificate adapter and
constructed by `CertificateSignatureService`. `PGPSelfTestGeneratedKey` is
declared in the self-test adapter and used throughout `SelfTestService`.
`PGPValidatedPublicCertificate` is declared in the contact-import adapter and
used by `ContactImportMatcher` and `ContactSnapshotMutator`.

Risk: Medium. These are Swift app-owned helper types, not generated UniFFI
records. The leak is semantic: ordinary Services depend on FFI-adapter-local
contract names and shapes. This makes it harder to draw a clean boundary
between business orchestration and adapter mapping.

Recommendation: Promote durable cross-service contracts out of
`Sources/Services/FFI` into neutral app-owned Models or Service-support files,
or hide them behind adapter methods so normal Services pass app-domain inputs
and receive app-domain outputs.

### 6. Generated Error Mapping Is Contained In Production Sources

Evidence: Production `Sources` references to `PgpError` and `PGPErrorMapper`
are limited to `Sources/Services/FFI/**`; no App-layer production source
matches `PgpError` after comments and strings are stripped. The mapper
normalizes generated `PgpError` variants into app-owned `CypherAirError`.

Risk: Low. Generated error handling appears contained in production code.

Recommendation: Keep `PgpError` and `PGPErrorMapper` out of App, Models, and
ordinary Services. If a new generated error variant appears, update only the
FFI mapper boundary and add app-owned behavior tests around the consuming
service.

### 7. Tests Still Mix Service Assertions With Generated Engine/Error Details

Evidence: FFI integration and device/security tests intentionally instantiate
`PgpEngine` and assert generated `PgpError` variants. Service test helpers also
own `PgpEngine` and concrete FFI adapters, and several service-level tests call
`stack.engine` directly or catch `PgpError` in addition to app-owned
`CypherAirError`. `QRDisplayScreenModelTests` constructs a `QRService` with
`PGPContactImportAdapter(engine: PgpEngine())`.

Risk: Low to Medium. Direct generated usage is appropriate in FFI integration,
interop, device, and performance tests. In service and ScreenModel tests, it
can weaken the architectural signal by making generated types part of normal
test setup and expected failure vocabulary.

Recommendation: Keep FFI/device/interop tests direct. For service-level tests,
prefer adapter fakes or app-owned error assertions where the test intent is
service orchestration rather than Rust/UniFFI behavior. Convert test helpers
incrementally so the production boundary can tighten without a large test
rewrite.

### 8. Review Expectations Cover Hard Generated Leaks But Not All Coupling

Evidence: the boundary inventory covers generated UniFFI type containment,
generated error mapping containment, App-layer `PgpError` handling, and
App-layer FFI adapter usage. Temporary exceptions currently include
`AppContainer`, `TutorialSandboxContainer`, and FFI adapter files for
generated-type containment.

Risk: Medium. The current review expectations are valuable for preventing hard
regressions. They do not fully block ordinary Services from depending on
concrete FFI adapter classes or adapter-local helper contracts, because that
coupling is currently present and partly intentional.

Recommendation: Add new behavior-test or review guardrails only after choosing
the remediation shape. Prematurely blocking all adapter class mentions in
Services would fail on the current architecture. A better sequence is to
introduce app-owned protocols or neutral contracts first, then document the
review expectations that prevent new direct adapter coupling in migrated areas.

## Non-Findings

- No ordinary production UI route, ScreenModel, Models file, or normal Service
  public path was found exposing generated result/error/status records such as
  `PgpError`, `KeyInfo`, `SignatureStatus`, `DetailedSignatureEntry`,
  `UserIdSelectorInput`, `DecryptDetailedResult`, or `VerifyDetailedResult`.
- No `import PgpMobile`, `@_exported import PgpMobile`, or `PgpMobile.` usage
  was found in `Sources` or `Tests` outside the generated binding path.
- The `PGPKeyProfile` model has a comment about historical generated
  `KeyProfile` raw values, but the type itself is app-owned and Codable for
  persistence compatibility.
- Generated signature-result mapping is not spread through normal Services;
  it is concentrated in `PGPMessageResultMapper` under `Sources/Services/FFI`.
- Generated `UserIdSelectorInput` construction is concentrated in
  `PGPCertificateSelectionAdapter`, while app-facing selector state uses
  app-owned `UserIdSelectionOption`.

## Remediation Candidates

1. Replace `AppContainer.engine` with a private OpenPGP adapter bundle or
   service-graph factory that owns `PgpEngine` internally.
2. Move UI-test contact preload generation behind an app-owned bootstrap
   service or an existing key/contact service path.
3. Introduce narrow protocols for message, key, certificate, contact-import,
   and self-test operations where ordinary Services currently depend on
   concrete FFI adapter classes.
4. Move durable adapter-local helper records, especially verification contexts
   and validated public certificate records, into app-owned neutral contracts
   or hide them inside adapter methods.
5. Split service-level tests by intent: keep generated engine assertions in FFI
   integration tests, and use app-owned fakes/errors for service orchestration
   tests.
6. Add follow-up review expectations and behavior tests after each migrated
   area has a stable app-owned contract.

## Validation Notes

The original snapshot used the then-current architecture text-scanning XCTest
lane as supplementary evidence. That lane has since been removed; current
validation should run behavior tests for changed services/adapters and include
targeted reviewer inspection of generated-type ownership.

This docs-only audit does not require a full Rust or Swift validation run. Full
validation should be selected when a follow-up remediation changes Swift
Services, `Sources/Services/FFI`, generated UniFFI bindings, Rust code, or Xcode
project wiring.
