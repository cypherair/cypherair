# Apple Secure Enclave Custody Implementation Roadmap

> Status: Active implementation roadmap. Phases 0–7 are complete — Phase 7
> landed as one PR with staged commits (issue #501: key-family generation UX,
> device-bound key-detail/backup surfaces, per-category failure presentation,
> and the production exposure flip, which moved here from Phase 9 by
> maintainer decision). Phase 8 (hardware + GnuPG-interop evidence) landed as
> one PR with staged commits (issue #501): software-backed v4 interop is a
> mandatory CI lane, v6 AEAD correctness runs in default CI, and real-hardware +
> real-SE↔gpg evidence runs in operator/maintainer-run manual lanes (capture
> tracked in [Evidence](APPLE_SECURE_ENCLAVE_CUSTODY_EVIDENCE.md)). Phase 9
> (release gate; no exposure switch remains) is outstanding.
> Last reviewed: 2026-06-13.
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
- Secure Enclave custody is implemented and production-exposed (P7D); user
  exposure remains release-gated on Phases 8-9 (tag-first releases).
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

Phase status: completed in the current implementation. The Security layer can
create, load, inspect, delete, inventory, and reset-clean distinct signing and
key-agreement P-256 Secure Enclave custody handles behind hidden interfaces, with
guarded device evidence on real hardware.

Completion anchor:

- Two distinct role-tagged P-256 handles (`.signing`, `.keyAgreement`) per handle
  set, with `privateKeyUsage`, `biometryAny`, no device-passcode fallback, and the
  data-protection Keychain domain; the `se-key`/`salt`/`sealed-key` software bundle
  is not reused as the custody store.
- Load and inspect are authoritative only when the stored role and uncompressed
  X9.63 public-key binding match; role mismatch, public-key mismatch, missing,
  partial, ambiguous, inaccessible, and cleanup failures fail closed through shared
  sanitized categories.
- Reset All Local Data inventories and deletes app-owned custody rows (including
  malformed app-owned tags); no plaintext, private material, locators, fingerprints,
  or temporary paths appear in logs or diagnostics.
- Guarded device tests cover real creation/load/delete, biometric signing/ECDH
  private operations, unauthorized-interaction failure, and handle-state mismatch.

Deferred scope:

- The store stays hidden and production-blocked; it is connected only to the
  hidden/test generation, signer-route, and key-agreement consumers added in later
  phases, not to product generation or UI.

## Phase 4: Hidden Secure Enclave Generation

Goal: create hidden or test-only end-to-end generation for Secure Enclave
custody keys, including public certificate construction, metadata, handles, and
revocation artifact availability.

Phase status: completed in the current implementation. Hidden/test-only
end-to-end generation creates Secure Enclave custody keys with public certificate
construction, metadata, handles, recovery classification, and public-artifact
export.

Completion anchor:

- Hidden/test generation creates a P-256 handle pair and asks Rust to build a
  public-only v4/v6 certificate bound to distinct signing and key-agreement public
  keys plus a key-level revocation artifact, persisting only non-secret
  `PGPKeyIdentity` metadata (no private material, handle locator, or access-control
  policy).
- Recovery classification compares stored public bindings with Security inventory
  and keeps only a sanitized in-memory report for metadata-only, handle-only,
  partial, ambiguous, wrong-public, mismatch, and missing-revocation states;
  startup/load never silently deletes orphan handles.
- Public-key and revocation export use stored public artifacts; missing revocation
  fails closed and Secure Enclave private-key backup/export is unsupported.
- Partial generation failure does not leave a normal-looking usable key, and
  software generation defaults are unchanged.

Deferred scope:

- Generation stays hidden and production-blocked; product UI exposure is deferred.

## Phase 5: Signing-Class Workflow Integration

Goal: route Product-approved signing-class MVP operations for Secure Enclave
custody through the external signer path.

Phase status: completed in the current implementation. Every Product-approved
signing-class operation routes through the private-operation router and the
external P-256 signer path, with software custody unchanged and Secure Enclave
custody production-blocked.

Completion anchor:

- `PrivateKeyOperationRouter` and `PGPKeyCapabilityResolver` provide the shared
  route vocabulary, independent policy gates, software routes without unwrapping,
  hidden/test Secure Enclave signer routes after public-binding checks, and a
  shared sanitized failure mapper.
- The signer route backs cleartext signing, text/password/file sign-plus-encrypt,
  detached file signing, modify-expiry, selective subkey/User ID revocation export,
  and User ID contact certification; each keeps the existing software
  unwrap-and-zeroize path, sends only public certificate material plus a loaded
  signing handle to Rust, and has no software fallback on a Secure Enclave route.
- Modify-expiry refreshes explicit transport/ECDH subkey validity bindings, can
  recover already-expired keys without weakening ordinary signing liveness, and
  merges Secure Enclave public-metadata writeback against the current catalog
  identity; revocation/certification selector validation stays public-only before
  routing, and generated revocation/certification stay artifact-only.
- A closure source audit keeps workflow-local custody switches out of signing-class
  services and confines external P-256 signer runtime calls to FFI adapters, hidden
  generation, and router-owned helpers.

Deferred scope:

- Standalone `refreshBinding`, decrypt/ECDH (Phase 6), direct-key certification,
  key-level revocation-artifact generation, private export/backup, and product
  exposure remain outside Phase 5. Production policy still blocks Secure Enclave
  custody.

## Phase 6: Decrypt And Streaming Integration

Goal: route message and file decrypt workflows through Secure Enclave
ECDH/session-key acquisition while preserving payload authentication and
success-only plaintext release.

Phase status: completed in the current implementation. Recipient-key message and
streaming file decrypt route through the Secure Enclave ECDH/key-agreement path
while payload authentication and success-only plaintext release stay in
Rust/Sequoia.

Completion anchor:

- `DecryptionService` keeps its security-critical Phase 1/Phase 2 boundary
  (unauthenticated recipient parsing, matched-key guard before private-key access,
  verification-context construction) and delegates custody dispatch to router-owned
  `PrivateKeyMessageDecryptionService` and `PrivateKeyStreamingFileDecryptionService`.
- Software custody keeps the existing unwrap-and-zeroize decrypt; Secure Enclave
  custody loads only the `.keyAgreement` handle and calls the external P-256
  key-agreement message/file-decrypt APIs, while Rust/Sequoia own ECDH KDF, AES Key
  Wrap unwrap, session-key validation, payload authentication, verification folding,
  and the success-only `.tmp`-then-rename file output.
- v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD tampering fail closed with no partial
  plaintext; recipient-mismatch, wrong-binding, session-key, callback, and
  cancellation paths fail closed with sanitized categories and no software fallback;
  streaming progress, cancellation, and temp cleanup are preserved.
- The Phase 6 closure audit asserts `DecryptionService` never calls the external
  key-agreement runtime directly, and adds mixed-recipient, repeated-operation, and
  no-partial-plaintext Rust/Swift coverage plus a guarded real-hardware
  `.keyAgreement` decrypt device test.

Deferred scope:

- Standalone binding refresh, direct-key certification, key-level
  revocation-artifact generation, private export/backup, UI, product copy, and
  production availability remain deferred to Phase 7/9. Production policy still
  blocks Secure Enclave custody.

## Phase 7: Product UI And Error Surfaces

Goal: prepare product surfaces for configuration choice, key detail,
availability, non-exportability, recovery consequences, and operation errors
without exposing Secure Enclave custody before the release gate.

As built (issue #501, decisions recorded 2026-06-12): Phase 7 landed as ONE PR
with staged commits — 7A key-family generation UX + vocabulary rename and
device-bound commitment/post-generation surfaces, 7B key-detail "Key Type" +
device-bound explainer + custody badges + backup-surface gating, 7C
per-category failure presentation (all 27 sanitized categories, en + zh-Hans),
7D the production exposure flip + DI + prompt-session enrollment (moved here
from Phase 9 by maintainer decision: tag-first releases are the user-exposure
boundary), and 7E this docs alignment. Phase 9 no longer carries an exposure
switch.

Original PR grouping (superseded by the as-built note above):

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

As built (issue #501, 2026-06-13): Phase 8 landed as ONE PR with staged commits.
The evidence-capture mechanism is a committed run matrix
([Apple Secure Enclave Custody Evidence](APPLE_SECURE_ENCLAVE_CUSTODY_EVIDENCE.md))
fed by sanitized one-line summaries. Software-backed v4 GnuPG interop (production
seams + a software-P256 stand-in) is a mandatory default-CI lane via a
skip-forbidden knob; v6 RFC 9580/AEAD correctness runs in default CI; real Secure
Enclave hardware evidence and the bidirectional real-SE↔gpg harness are
operator/maintainer-run manual lanes (macOS captured now; iPhone/iPad pending;
visionOS excluded). Positive interactive auth-cancellation/biometric-lockout
evidence is intentionally out of scope (low-value attended edge case). The
grouping below is the original plan, superseded by this note.

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
  (Superseded: the exposure switch landed in Phase 7D by maintainer decision —
  no exposure switch remains in Phase 9.)
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
