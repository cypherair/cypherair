# Apple Secure Enclave Custody Implementation Roadmap

> Status: Draft implementation roadmap. This document describes proposed future
> work and does not describe shipped behavior.
> Date: 2026-05-26.
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

Phase status: completed by PR #363. PR 0A documentation acceptance passed, and
PR 0B read-only source baseline review completed. No
`ArchitectureSourceAuditTests` or other guardrail code was added because Phase
1/2 have not yet defined stable measurable boundaries. Current-state docs were
not updated because no shipped behavior, storage classification, security
boundary, or validation workflow changed.

Recommended PR grouping:

- PR 0A: add the implementation reference and roadmap.
- PR 0B: add or update source-audit guardrails only if a later implementation
  plan identifies measurable boundaries that can be checked without blocking
  planned transitional states.

Entry conditions:

- Product Design, Architecture Plan, Security Requirements, and Feasibility
  Summary are active.

Exit conditions:

- Future phase plans can cite one implementation reference and one roadmap.
- The docs clearly state that Secure Enclave custody is proposed future work,
  not shipped behavior.
- Any added guardrails have explicit temporary-exception mechanics for staged
  work.

Validation:

- Documentation-only validation may use `git diff --check` and review of the
  rendered Markdown diff.
- Guardrail PRs must include positive and negative tests for the guardrail.

Rollback:

- Revert documentation or guardrail additions. No product behavior should have
  changed in this phase.

## Phase 1: Model And Metadata Foundation

Goal: introduce the app-owned model vocabulary and protected metadata migration
needed to represent configuration, custody, and operation capability separately.

Recommended PR grouping:

- PR 1A: introduce the successor configuration/custody/capability vocabulary
  behind existing software-key behavior.
- PR 1B: add protected metadata migration support that normalizes existing
  Profile A/Profile B keys into software custody.
- PR 1C: add resolver-level model tests for valid and invalid configuration plus
  custody combinations.
- PR 1D: define shared failure categories for resolver, router, Security, Rust,
  workflow services, and UI mapping without choosing final error type names.

Entry conditions:

- Phase 0 docs are available.
- The phase-specific plan identifies persisted-state classification and
  migration ownership before editing protected metadata code.

Exit conditions:

- Existing software keys still behave as before.
- Existing Profile A/Profile B records can be read through the new model
  without becoming Secure Enclave custody.
- Secure Enclave custody state can be represented as future or hidden state
  without exposing a product choice.
- Migration fails closed and does not silently reset corrupt committed protected
  state.
- Shared failure categories are stable enough for later workflow integration
  phases to map authentication, missing handle, binding mismatch, unsupported,
  not-yet-implemented, migration/recovery, and payload-authentication failures
  consistently.

Validation:

- Metadata migration and recovery tests.
- Resolver tests for legal, illegal, unavailable, and unsupported combinations.
- Persisted State Inventory and companion docs updated only if current
  persisted-state classification changes.

Rollback:

- Disable new Secure Enclave custody state creation and keep existing software
  metadata readers active. Rollback must leave software keys readable, preserve
  readable source state until migrated destination state is validated, classify
  partially migrated Secure Enclave state as recovery/cleanup state, and keep
  metadata/handle mismatches fail-closed.

## Phase 2: Rust External-Operation Boundary Proving

Goal: prove production-shaped Rust/OpenPGP seams for external signing and
ECDH/session-key acquisition without choosing product UI or hardware-runner
details.

Recommended PR grouping:

- PR 2A: add test-backed external signer behavior for v4 and v6 Secure
  Enclave-shaped certificates using substitutes, not real hardware as the only
  proof.
- PR 2B: add test-backed ECDH/session-key acquisition behavior for v4
  SEIPDv1/MDC and v6 SEIPDv2/AEAD paths.
- PR 2C: add negative tests for wrong role, wrong public binding, session-key
  validation failure, and payload authentication hard-fail.

Entry conditions:

- Phase 1 model work can describe Secure Enclave custody keys and operation
  intent.
- The phase-specific plan names the boundary between private operation,
  session-key processing, and payload processing.

Exit conditions:

- Rust can perform OpenPGP signing-class and decrypt-class semantics while
  delegating only the private signing or ECDH operation.
- The design does not require complete secret certificate bytes for Secure
  Enclave custody.
- The POC response-file pattern is not promoted to production.

Validation:

- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml` for Rust changes.
- Swift/Xcode validation after any Swift-visible Rust/UniFFI surface or packaged
  artifact change, following [Testing](TESTING.md).
- Negative tests for no fallback and hard-fail payload authentication.

Rollback:

- Keep new external-operation routes test-only and leave workflow services on
  existing software-custody paths.

## Phase 3: Security Handle Store

Goal: implement Security-layer storage and lifecycle for distinct Secure Enclave
signing and key-agreement private-operation handles.

Recommended PR grouping:

- PR 3A: add handle creation, loading, role binding, public-key binding, and
  deletion behind Security-owned interfaces.
- PR 3B: add cleanup, local reset participation, and recovery classification for
  metadata/handle disagreement.
- PR 3C: add mock and guarded device tests for access-control and handle-state
  failures.

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
  for hidden v4 and v6 generation.
- PR 4B: add generation cleanup, partial-failure recovery, and local reset
  behavior.
- PR 4C: add public certificate and revocation artifact export coverage for
  generated hidden keys.

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

- PR 5A: message signing and the signing half of sign-plus-encrypt.
- PR 5B: password-message optional signing and the signing half of streaming
  sign or encrypt-plus-sign workflows.
- PR 5C: other Product-approved signing-class operations, such as expiry,
  binding, revocation, selective-revocation, or contact-certification work if
  they remain in first-version scope.

Entry conditions:

- Hidden generation can create usable signing handles.
- Resolver and router contracts are in place for signing-class operations.
- Product Design still approves the exact signing-class operation set targeted
  by the phase-specific plan.
- The phase-specific plan names any operation that remains unsupported and why.

Exit conditions:

- Supported signing-class operations use the Secure Enclave signer route.
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

- PR 6A: message decrypt session-key acquisition and payload processing.
- PR 6B: streaming file decrypt and the decrypt-side streaming variants that
  need ECDH/session-key acquisition.
- PR 6C: cancellation, cleanup, tamper, and no-partial-plaintext hardening.

Entry conditions:

- Hidden generation can create usable key-agreement handles.
- Phase 2 ECDH/session-key behavior is proven through tests.
- The phase-specific plan describes temporary-file and output-release behavior.

Exit conditions:

- Secure Enclave custody decrypt uses the ECDH/session-key route.
- Sequoia payload authentication remains the plaintext-release gate.
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
