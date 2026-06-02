# Apple Secure Enclave Custody Implementation Roadmap

> Status: Draft implementation roadmap. This document describes proposed future
> work and does not describe shipped behavior.
> Date: 2026-05-31.
> Purpose: Provide staged PR planning guidance for Apple Secure Enclave-backed
> OpenPGP private-key custody.
> Audience: Product owners, Swift/Rust implementers, security reviewers,
> architecture reviewers, test owners, reviewers, and AI coding tools.
> Source authorities: [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> and [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md).
> Related: [Implementation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md).
> Companion current-state references: [Architecture](ARCHITECTURE.md),
> [Security](SECURITY.md), [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md),
> and [Testing](TESTING.md).
> Update triggers: Any completed phase, changed product exposure decision,
> changed security gate, changed hardware or interop evidence requirement,
> changed metadata/handle boundary, changed Rust/UniFFI boundary, or roadmap
> replacement.

## 1. Roadmap Decision

Secure Enclave custody must remain hidden, test-only, or otherwise unavailable
as a normal product choice until the active product, architecture, security,
implementation, hardware, interop, and release gates agree that it can be
exposed. This roadmap is not a release promise and does not replace
phase-specific implementation plans.

Each phase below may be split into multiple PRs. Every PR that changes code,
storage, Security behavior, Rust/UniFFI behavior, product surfaces, or tests
must have its own implementation plan before code work begins.

## 2. Global PR Rules

All phases must cite the active source authorities for exact product semantics,
architecture ownership, security red lines, persisted-state classification, and
validation commands. This roadmap adds only sequencing guidance:

- keep Secure Enclave custody hidden or test-only until the release gate passes;
- require a phase-specific implementation plan before code, storage, Security,
  Rust/UniFFI, UI, or test changes;
- call out sensitive boundaries before editing them;
- keep rollback paths centered on preserving existing software-custody behavior
  and disabling Secure Enclave custody rather than weakening a gate;
- update current-state docs only when shipped behavior, storage
  classification, security boundaries, or validation workflow actually changes.

Rollback in every phase means preserving existing software-custody behavior and
leaving Secure Enclave custody unavailable rather than weakening a security
gate.

## Phase 0: Documentation And Baseline Guardrails

Goal: establish implementation reference material, roadmap sequencing, and any
non-invasive guardrails needed before production code work begins.

Phase status: completed by PR #363. Documentation acceptance passed, and
read-only source baseline review completed. No `ArchitectureSourceAuditTests`
or other guardrail code was added because Phase 1/2 had not yet defined stable
measurable boundaries. Current-state docs were not updated because no shipped
behavior, storage classification, security boundary, or validation workflow
changed.

Completion anchor:

- Future phase plans can cite the implementation reference and this roadmap.
- Secure Enclave custody remains proposed future work, not shipped behavior.
- Any later guardrail work still needs a phase-specific plan and temporary
  exception mechanics for staged transitional states.

## Phase 1: Model And Metadata Foundation

Goal: introduce the app-owned model vocabulary and protected metadata migration
needed to represent configuration, custody, and operation capability separately.

Phase status: completed in the current implementation. Closeout confirmed that
the model vocabulary, protected `key-metadata` schema v2 migration, resolver
behavior, and failure-category taxonomy exist behind current software-key
behavior.

Completion anchor:

- `PGPKeyConfiguration`, `PGPPrivateKeyCustodyKind`, and `PGPKeyIdentity`
  separate OpenPGP configuration from private-key custody. Current Profile
  A/Profile B identities default to software secret-certificate custody.
- `PGPKeyCapabilityResolver` keeps current software-key operations supported,
  rejects invalid configuration/custody combinations, and leaves P-256 Secure
  Enclave custody unavailable in production policy and not implemented in
  test-only policy.
- `PGPKeyOperationFailureCategory` and `PGPKeyOperationResolution` provide the
  shared sanitized support/failure vocabulary for later router, Security,
  Rust/UniFFI, workflow-service, and UI mapping work.
- `KeyMetadataDomainStore` stores protected `key-metadata` schema v2 payloads,
  migrates schema v1 / legacy Profile A/Profile B metadata into software
  custody, validates representable P-256 Secure Enclave metadata as future
  state, and sends corrupt or mismatched committed metadata to recovery.

Deferred scope:

- Secure Enclave custody remains hidden, unavailable in production policy, and
  not product-selectable.
- Rust external private-operation APIs, Security-layer handle storage, workflow
  routing, and product UI exposure remain deferred to later phases.

## Phase 2: Rust External-Operation Boundary Proving

Goal: prove production-shaped Rust/OpenPGP seams for external signing and
ECDH/session-key acquisition without choosing product UI or hardware-runner
details.

Phase status: completed in the current implementation. Closeout confirmed the
Rust-only, test-only proof shape for external P-256 signing and
ECDH/session-key acquisition. The proof remains unavailable to Swift, UniFFI,
product UI, hardware handle storage, and normal workflow services.

Completion anchor:

- Phase 2A proves v4 and v6 public-only P-256 certificate candidates can sign
  through an external signer substitute while Sequoia owns OpenPGP signature
  construction and verification.
- Phase 2B proves v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD messages can recover
  session keys through an external ECDH substitute while Sequoia owns OpenPGP
  ECDH KDF, AES Key Wrap unwrap, session-key validation, payload
  authentication, and signature-status folding.
- Phase 2C proves wrong-role, wrong-public-binding, session-key validation
  failure, malformed external responses, external-operation failure, no
  software secret-certificate fallback, and payload authentication hard-fail
  negative coverage.
- The POC response-file/shared-secret bridge was not promoted. No public API,
  UniFFI surface, Swift workflow route, product exposure, hardware handle
  store, or software fallback was added.
- Validation passed with
  `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.

Detailed Rust boundary and test-contract guidance now lives in
[Implementation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md),
[Security](SECURITY.md), and [Testing](TESTING.md).

Deferred scope:

- Production Rust/UniFFI callback APIs, Swift/Security handoff, Security-layer
  handle storage, workflow routing, hardware evidence, and product UI exposure
  remain deferred to later phases.
- Later integration fallback posture remains unchanged: keep
  external-operation routes unavailable to workflow services and preserve
  existing software-custody behavior.

## Phase 3: Security Handle Store

Goal: implement Security-layer storage and lifecycle for distinct Secure Enclave
signing and key-agreement private-operation handles.

Recommended PR grouping:

- PR 3A: add handle creation, loading, role binding, public-key binding, and
  deletion behind Security-owned interfaces.
- PR 3B: add cleanup, local reset participation, and recovery classification for
  metadata/handle disagreement.
- PR 3C: add guarded device tests for access-control and handle-state failures.

Current implementation status:

- PR 3A is implemented: the Security layer can create, load, inspect, and delete
  distinct signing/key-agreement P-256 Secure Enclave custody handles behind
  hidden interfaces.
- PR 3B is implemented: the Security layer can inventory and reset-clean
  app-owned custody handles, including malformed owned tags, validate remaining
  handle count after Reset All Local Data, and classify expected metadata/handle
  disagreement through shared sanitized failure categories.
- PR 3C is implemented: guarded device tests exercise the production
  Security-owned custody handle store on real Secure Enclave hardware, covering
  handle creation/persistence, biometric private-operation access control,
  missing/partial/wrong-public handle-state failures, cleanup, and sanitized
  diagnostics.

Entry conditions:

- Phase 1 can represent custody state without product exposure.
- Phase 2 has a proven external-operation shape to consume handles.
- The phase-specific plan explicitly calls out edits under `Sources/Security/`.

Exit conditions:

- Signing and key-agreement handles are distinct.
- Reference access policy is enforced: `privateKeyUsage`, `biometryAny`, and no
  device-passcode fallback.
- Handle-related Keychain accessibility is evaluated against
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` as reference material.
- Role mismatch, public-key mismatch, missing handle, inaccessible handle, and
  local reset cleanup fail closed.
- The current `se-key` / `salt` / `sealed-key` software wrapping bundle is not
  reused as the custody handle store.

Validation:

- Security-layer unit tests with mocks for success, failure, cleanup, and
  recovery paths.
- Device-only tests guarded for Secure Enclave availability.
- No plaintext, private-key material, shared secrets, session keys, KEKs,
  Keychain locators, stable fingerprints, or temporary capability paths in logs
  or diagnostics.

Rollback:

- Delete or ignore newly created hidden/test handles through cleanup logic and
  keep Secure Enclave custody unavailable. Existing software key bundles remain
  authoritative for software custody. Rollback must leave hidden/test Secure
  Enclave metadata discoverable and cleanable, keep mismatches fail-closed, and
  avoid orphaning handles.

## Phase 4: Hidden Secure Enclave Generation

Goal: create hidden or test-only end-to-end generation for Secure Enclave
custody keys, including public certificate construction, metadata, handles, and
revocation artifact availability.

Recommended PR grouping:

- PR 4A: integrate model, Security handles, and Rust certificate construction
  for hidden v4 and v6 generation. **Implemented:** hidden/test generation now
  creates Security-owned P-256 handle pairs, uses a narrow UniFFI external
  signer callback for public-only certificate/revocation construction, persists
  P-256 Secure Enclave custody metadata only, and leaves software-key behavior
  and UI exposure unchanged.
- PR 4B: add generation cleanup, partial-failure recovery, and local reset
  behavior. **Implemented:** stored hidden Secure Enclave public certificates
  can be inspected for signing/key-agreement P-256 public bindings, and
  KeyManagement now maintains a sanitized in-memory recovery report that
  classifies metadata-only, handle-only, partial, ambiguous, wrong-public,
  public-certificate mismatch, metadata mismatch, missing revocation, and
  inventory/list-failure states. Reset All Local Data continues to delete
  hidden metadata and all app-owned custody handles, while startup/load
  classification does not silently delete orphan handles.
- PR 4C: add public certificate and revocation artifact export coverage for
  generated hidden keys. **Implemented:** hidden Secure Enclave custody public
  certificates export from stored public material, stored key-level revocation
  artifacts export without private-key access, missing revocation artifacts fail
  closed, and Secure Enclave custody private-key backup/export remains
  unsupported.

Entry conditions:

- Phases 1-3 provide model state, Rust external-operation capability, and
  Security handles.
- Product Design user commitments have an implementation-plan owner, even if UI
  remains hidden.

Exit conditions:

- Hidden/test generation creates a public certificate bound to distinct Secure
  Enclave signing and key-agreement public keys.
- Metadata records only non-secret state and does not store access-control
  policy.
- Partial generation failure does not leave a normal-looking usable key.
- Existing software generation defaults remain unchanged.

Validation:

- Swift unit tests for hidden generation success, partial failure, cleanup,
  metadata, public export, and revocation artifact presence.
- Rust tests for generated public certificate validity where applicable.
- Guarded hardware evidence for real handle generation when the phase plan
  requires it.

Rollback:

- Keep the generation choice hidden, remove newly generated test keys through
  local cleanup/reset paths, and leave software generation unchanged. Rollback
  must reconcile metadata and handles so hidden/test state is discoverable,
  cleanable, and never mistaken for a usable product key.

## Phase 5: Signing-Class Workflow Integration

Goal: route Product-approved signing-class MVP operations for Secure Enclave
custody through the external signer path.

Recommended PR grouping:

- PR 5A: private-operation router foundation, shared route vocabulary,
  unsupported/unavailable outcomes, sanitized error mapping, hidden/test policy
  hooks, and Security handle lookup helpers. This PR must not integrate a user
  workflow. **Implemented:** Phase 5A adds internal Swift routing contracts,
  independent resolver policy gates, software and Secure Enclave signer route
  outcomes, blocked decrypt/key-agreement outcomes, a shared sanitized failure
  mapper, and Security signing-handle lookup by public bindings. Production
  remains unavailable and no workflow service consumes the router yet.
- PR 5B: Rust/UniFFI external signer runtime API plus cleartext message signing
  pilot. **Implemented:** Phase 5B adds a runtime Rust/UniFFI cleartext signing
  API that accepts a public certificate, expected signing-key fingerprint, and
  external P-256 signer callback; Swift wires only `SigningService.signCleartext`
  through the router. Software routes still unwrap and zeroize secret
  certificates as before, Secure Enclave signer routes use public certificate
  material plus a loaded signing handle, blocked routes surface sanitized
  unavailable categories, and production policy still blocks Secure Enclave
  custody.
- PR 5C: sign-plus-encrypt text optional signing.
  **Implemented:** Phase 5C adds a Rust/UniFFI armored text encrypt API that can
  sign with a public-only P-256 certificate through the external signer
  callback, and Swift routes only `EncryptionService.encryptText` optional
  signing through the private-operation router. Software routes retain the
  existing unwrap-and-zeroize path, Secure Enclave signer routes use public
  certificate material plus a loaded signing handle, unsigned text encryption
  does not route, blocked routes surface sanitized unavailable categories, and
  production policy still blocks Secure Enclave custody.
- PR 5D: password-message optional signing.
  **Implemented:** Phase 5D adds Rust/UniFFI password-message encrypt APIs for
  armored and binary outputs that can sign with a public-only P-256 certificate
  through the external signer callback, and Swift routes only
  `PasswordMessageService.encryptText` / `encryptBinary` optional signing
  through the private-operation router. Software routes retain the existing
  unwrap-and-zeroize path, Secure Enclave signer routes use public certificate
  material plus a loaded signing handle, unsigned password encryption does not
  route, blocked routes surface sanitized unavailable categories, and
  production policy still blocks Secure Enclave custody.
- PR 5E: streaming detached file signing.
- PR 5F: streaming encrypt-plus-sign.
- PR 5G: expiry and binding-refresh signing route, or explicit unsupported
  closeout.
- PR 5H: selective subkey and User ID revocation signing route.
- PR 5I: contact certification signing route.
- PR 5J: Phase 5 closure audit for no workflow-local custody switches, docs,
  and tests.

Entry conditions:

- Hidden generation can create usable signing handles.
- Phase 5A establishes resolver/router contracts before signing-class workflow
  PRs consume them.
- Product Design still approves the exact signing-class operation set targeted
  by the phase-specific plan.
- The phase-specific plan names any operation that remains unsupported and why.

Exit conditions:

- Every supported signing-class operation uses the router and Secure Enclave
  signer route.
- Unsupported signing-class operations produce explicit unsupported outcomes.
- No workflow-local custody switch bypasses the router.
- No supported operation unwraps or synthesizes a complete secret certificate
  for Secure Enclave custody.

Validation:

- Swift service tests for each supported signing-class workflow.
- Rust tests for signature semantics and negative cases.
- Wrong-role, wrong-public-binding, missing-handle, authentication-cancel, and
  no-fallback tests.
- Interop-oriented signature verification evidence for v4 where applicable.

Rollback:

- Mark incomplete signing-class operations unsupported for Secure Enclave
  custody and keep product exposure disabled. Software-custody signing remains
  unchanged.

## Phase 6: Decrypt And Streaming Integration

Goal: route message and file decrypt workflows through Secure Enclave
ECDH/session-key acquisition while preserving payload authentication and
success-only plaintext release.

Recommended PR grouping:

- PR 6A: external P-256 ECDH UniFFI callback, Swift key-agreement bridge, and
  router key-agreement route. This PR must not release a plaintext workflow.
- PR 6B: message decrypt integration for v4/v6, verification folding,
  recipient mismatch, tamper, and no fallback.
- PR 6C: streaming file decrypt integration with success-only output, progress,
  cancellation, cleanup, and tamper coverage.
- PR 6D: Phase 6 closure audit for mixed recipients, repeated operation
  artifacts, no partial plaintext, docs, and tests.

Entry conditions:

- Hidden generation can create usable key-agreement handles.
- Phase 2 ECDH/session-key behavior is proven through tests.
- Phase 6A owns only the ECDH route foundation and must not release a plaintext
  workflow.
- Before PR 6C starts, its phase-specific plan must describe
  temporary-artifact ownership, success-only output release, cancellation
  cleanup, and file protection behavior for streaming file decrypt.

Exit conditions:

- Secure Enclave custody decrypt uses the ECDH/session-key route.
- Payload authentication remains outside the router; Sequoia
  read-to-completion/message-processed behavior remains the plaintext-release
  gate.
- v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD tampering fail closed.
- Cancellation and authentication errors do not expose partial plaintext.
- Streaming progress, cancellation, and cleanup behavior remain intact.

Validation:

- Rust and Swift tests for v4/v6 decrypt, tamper, recipient mismatch, session
  validation failure, cancellation, and cleanup.
- File decrypt tests for success-only output contracts.
- Device-only tests for real ECDH handle use when hardware evidence is needed.

Rollback:

- Return Secure Enclave custody decrypt routes to explicit unsupported state.
  Preserve all existing software-custody decrypt behavior and cleanup paths.

## Phase 7: Product UI And Error Surfaces

Goal: prepare product surfaces for configuration choice, key detail,
availability, non-exportability, recovery consequences, and operation errors
without exposing Secure Enclave custody before the release gate.

Recommended PR grouping:

- PR 7A: resolver-backed generation-choice presentation behind hidden or
  disabled availability.
- PR 7B: key-detail and availability state presentation for hidden/test keys.
- PR 7C: operation error mapping and localized user-facing copy.

Entry conditions:

- Resolver outputs are stable enough for UI and tests.
- Product Design has approved the user commitments and compatibility language to
  implement.
- Security Requirements gates for unsupported operations are represented in the
  service layer.

Exit conditions:

- UI can distinguish compatibility target, OpenPGP configuration, custody model,
  public certificate state, revocation artifact state, private-key export state,
  and current private-operation availability.
- Secure Enclave custody communicates non-exportability and recovery
  consequences before generation when the surface is eventually enabled.
- Public-material workflows do not imply private custody capability.
- Product exposure remains disabled until release readiness.

Validation:

- ScreenModel and service tests for availability and error mapping.
- Localization validation for new user-visible strings.
- Targeted macOS UI smoke coverage when routes, launch behavior, settings, or
  tutorial surfaces change.

Rollback:

- Hide Secure Enclave custody UI paths and keep hidden/test keys inspectable only
  through development or recovery surfaces defined by the phase plan.

## Phase 8: Hardware And Interop Evidence

Goal: collect release-gate evidence on real Apple hardware and validated OpenPGP
interop paths.

Recommended PR grouping:

- PR 8A: real-hardware Secure Enclave generation, persistence, signing, ECDH,
  authentication-cancel, biometric-lockout, missing-handle, wrong-role,
  wrong-binding, and local-reset evidence.
- PR 8B: v4 GnuPG compatibility evidence.
- PR 8C: v6 RFC 9580 / AEAD evidence and evidence-packaging documentation.

Entry conditions:

- Hidden/test Secure Enclave custody paths cover the MVP private-operation
  surface intended for release.
- Evidence capture produces sanitized output.
- Hardware evidence lanes are separated from mandatory default CI.
- The phase-specific plan names the platform family matrix, evidence acceptance
  criteria, sanitizer expectations, and reviewer ownership without prescribing
  runner implementation details.

Exit conditions:

- Real Secure Enclave private operations are validated on supported Apple
  platform families required by the release decision.
- v4 GnuPG evidence covers public certificate import, signature verification,
  GnuPG-originated encryption, production-boundary decrypt and verify,
  bidirectional sign-plus-encrypt, and PKESK v3 ECDH plus SEIPDv1/MDC packet
  shape.
- v6 modern evidence covers RFC 9580 / AEAD behavior without making a GnuPG
  claim unless Product Design adds that claim.
- Evidence output excludes plaintext, private-key material, shared secrets,
  session keys, KEKs, Keychain locators, stable fingerprints, and temporary
  capability paths.

Validation:

- Manual or release-validation hardware lanes.
- GnuPG interop validation for v4.
- RFC 9580 / AEAD validation for v6.
- Review of sanitized evidence artifacts by security and release owners.

Rollback:

- Keep Secure Enclave custody hidden or test-only. Do not relax compatibility
  language, hardware scope, or evidence requirements to force release.

## Phase 9: Release Readiness And Product Exposure

Goal: decide whether Secure Enclave custody can become product-selectable and
prepare the release path if all gates pass.

Recommended PR grouping:

- PR 9A: release-gate closeout documentation and current-state doc updates.
- PR 9B: final product exposure switch for generation choices, if approved.
- PR 9C: release validation, App Store candidate preparation, and post-release
  documentation cleanup if the feature ships.

Entry conditions:

- Product, architecture, security, implementation, hardware, interop, and
  release owners agree the gates are satisfied.
- Full MVP private-operation surface is either supported through Secure Enclave
  private operations or explicitly unavailable for product launch.
- Current-state docs, persisted-state classification, test documentation, and
  user-facing strings are ready for shipped behavior.

Exit conditions:

- Secure Enclave custody is product-selectable only if the release gate passes.
- User commitments are visible before generation.
- Compatibility language matches validated evidence.
- Unsupported operations remain explicit and fail closed.
- Formal stable release and App Store candidate work follows
  [APP_RELEASE_PROCESS](APP_RELEASE_PROCESS.md).

Validation:

- Full relevant Rust, Swift, device-only, hardware, interop, UI, and release
  validation selected by the phase-specific release plan.
- Final security review of red lines, evidence artifacts, logging, storage, and
  rollback posture.

Rollback:

- Do not expose the generation choice. If a late issue appears after exposure
  but before release, disable generation and operation offering for Secure
  Enclave custody in the product surface while preserving local recovery paths
  for any test or pre-release keys. After release, any degradation plan must
  preserve already-created user Secure Enclave custody keys as secure local
  state: disable only affected new operations or new generation, keep public and
  revocation-artifact workflows available where possible, report unavailable
  private operations explicitly, and never add software fallback or weakened
  access control.

## Program-Level Stop Conditions

Return to product, architecture, and security review before continuing if any
phase appears to require:

- exporting Secure Enclave private-key material;
- importing an existing private key into Secure Enclave custody;
- storing a software fallback or complete secret certificate for Secure Enclave
  custody;
- using one Secure Enclave private key for both signing and key agreement;
- accepting wrong-role or wrong-public-binding handles;
- treating Keychain handles or locators as recoverable private-key backups;
- exposing partial plaintext after MDC/AEAD failure;
- logging secret material or stable sensitive identifiers;
- weakening current software-custody behavior;
- adding network, telemetry, new permissions, or release metadata churn as part
  of the feature.

## Roadmap Update Triggers

Update this roadmap when:

- a phase is completed, split, combined, abandoned, or replaced;
- Product Design changes first-version operation scope or compatibility claims;
- Architecture Plan changes model, resolver, router, or Rust/Swift ownership;
- Security Requirements changes access control, red lines, validation gates, or
  release gates;
- Feasibility evidence is superseded by production hardware or interop evidence;
- current-state docs change shipped storage, security, or testing contracts;
- release planning changes the product exposure posture.
