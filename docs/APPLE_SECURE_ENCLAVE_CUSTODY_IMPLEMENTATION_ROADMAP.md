# Apple Secure Enclave Custody Implementation Roadmap

> Status: Active implementation roadmap proposal. This document describes
> proposed future PR sequencing and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Split Apple Secure Enclave Custody production work into staged,
> reviewable PR phases with validation gates and rollback rules.
> Audience: CypherAir maintainers, Swift/Rust implementers, security reviewers,
> architecture reviewers, test owners, product owners, QA, and AI coding tools.
> Related: [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Implementation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Roadmap Decision

Secure Enclave custody should land through small staged PRs. The feature must
remain hidden or test-only until the product, architecture, security,
implementation, hardware, and interop gates are complete.

This roadmap is not permission to ship a partial custody mode. Basic signing
and decrypt proof is not enough for product availability. Every MVP private
operation named in
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#mvp-private-operation-scope)
must either work through the Secure Enclave private-operation boundary or be
explicitly unavailable with security approval.

The default branch policy from [AGENTS](../AGENTS.md) still applies: work should
be carried on topic branches and submitted through pull requests. Release
metadata, entitlements, generated UniFFI Swift, and Xcode project files must not
be touched incidentally.

## Global PR Rules

Every PR in this program must follow these rules:

- Re-read [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
  [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md), and
  [Implementation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md)
  before touching sensitive boundaries.
- Keep one PR focused on one boundary or one narrow integration step.
- Do not hand-edit generated UniFFI Swift or headers.
- Do not modify `CURRENT_PROJECT_VERSION`, `MARKETING_VERSION`, entitlements,
  or permission strings unless the PR explicitly owns that release or platform
  change.
- Preserve zero network access, minimal permissions, AEAD/MDC hard-fail,
  secure randomness, sensitive-buffer zeroization, no plaintext/private-key
  logging, and profile-correct message-format selection.
- Do not create a software fallback for Secure Enclave custody.
- Do not reuse the POC raw shared-secret response-file bridge.
- Keep Secure Enclave custody behind a feature gate until all release gates are
  satisfied.
- Update canonical docs in the same PR whenever current behavior, storage
  classification, security boundary, or validation workflow changes.

## Phase 0: Documentation And Baseline Locks

Goal: lock terminology, feature gating, and baseline behavior before code
changes.

Recommended PRs:

- PR 0A: Add or update planning documents for implementation reference and
  roadmap.
- PR 0B: Add a hidden feature-gate decision record if later implementation PRs
  need a named gate before code exists.

Entry conditions:

- Existing APPLE_SECURE_ENCLAVE custody product, architecture, security, and
  feasibility documents are current.
- Current code baseline is understood as software secret-certificate custody.

Exit conditions:

- New docs clearly state that Secure Enclave custody is proposed future
  behavior, not shipped behavior.
- Product terminology separates OpenPGP configuration, custody, and operation
  capability.
- Existing Profile A/B behavior remains unchanged.

Validation:

- `git diff --check`
- Documentation review for links, status blocks, and no current-behavior
  overclaim.

Rollback:

- Revert or revise docs only. No runtime behavior should exist in this phase.

## Phase 1: Configuration, Custody, Capability, And Metadata Model

Goal: add the model foundation without changing private-key runtime behavior.

Recommended PRs:

- PR 1A: Introduce successor configuration and custody descriptor types.
- PR 1B: Add capability projection/resolver contracts behind tests.
- PR 1C: Add metadata v2 migration for existing Profile A/B records into
  configuration plus software custody.
- PR 1D: Update persisted-state docs and migration/recovery tests.

Entry conditions:

- Phase 0 docs are merged.
- No product UI path exposes Secure Enclave custody.

Exit conditions:

- Existing keys migrate to software custody with unchanged behavior.
- Metadata can represent future `secureEnclaveP256V1` records without storing
  private material.
- Resolver can describe supported and unsupported operations without triggering
  authentication or private operations.
- Corrupt committed protected state fails closed and remains a recovery
  surface.

Validation:

- Swift unit tests for metadata migration, resolver output, illegal
  configuration/custody combinations, and recovery behavior.
- Existing key-management and ProtectedData tests.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`

Rollback:

- Keep source metadata readable until migrated destination validation succeeds.
- If migration has risk, leave v2 reader/writer disabled behind a gate and
  revert only the disabled model PR.

## Phase 2: Rust External Operation Prototypes And Tests

Goal: prove Rust/Sequoia external private-operation seams with fake operations
before touching Apple Security code.

Recommended PRs:

- PR 2A: Add Rust external signer adapter tests with fake P-256 signing.
- PR 2B: Add fake external ECDH/session-key acquisition tests for v4 and v6
  messages.
- PR 2C: Add no-plaintext and streaming cleanup tamper tests for the external
  route.

Entry conditions:

- Phase 1 model can identify future SE custody records, even if no runtime path
  creates them.
- The Rust API design is documented in the implementation reference or a
  companion PR note.

Exit conditions:

- Rust can sign through a fake external signer without double hashing.
- Rust can recover session keys through a fake external ECDH path while keeping
  OpenPGP KDF, AES Key Wrap, and payload authentication in Rust/Sequoia.
- Tampered PKESK, ephemeral public point, wrapped session key, MDC, AEAD, and
  signature cases fail closed.

Validation:

- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`
- Focused Rust tests for external signer/decryptor modules.
- No generated UniFFI Swift hand edits.

Rollback:

- If Sequoia's reachable APIs cannot support the desired boundary, stop at a
  disabled test-only Rust prototype and return to architecture review. Do not
  move OpenPGP KDF or payload policy into Swift as a shortcut.

## Phase 3: Security Handle Provider And Store

Goal: implement Swift/Security storage for distinct Secure Enclave signing and
ECDH handles without exposing product UI.

Recommended PRs:

- PR 3A: Add handle-store protocols and mock store for signing/ECDH roles.
- PR 3B: Add real Secure Enclave key generation/loading/deletion for distinct
  signing and ECDH handles.
- PR 3C: Add role binding, public-key binding, cleanup, and local reset
  participation.
- PR 3D: Add hardware smoke tests in device/manual lanes.

Entry conditions:

- Phase 1 model and Phase 2 fake Rust path are available.
- Access-control policy is confirmed as the planned default:
  `privateKeyUsage + biometryAny`, with no default `userPresence` or
  `devicePasscode`.

Exit conditions:

- Signing and ECDH handles are generated separately.
- Wrong role, wrong public key, missing handle, cancellation, lockout, and
  platform unavailable states fail closed.
- Keychain locators and handle identifiers are not logged or surfaced.
- Local reset and key deletion clean up handle state.

Validation:

- Swift unit tests for mock handle store and cleanup classification.
- Hardware/manual tests for real Secure Enclave sign/ECDH smoke.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- Device-only tests when touching real hardware paths.

Rollback:

- Keep real handle creation behind a hidden/test-only gate.
- If access-control behavior differs by platform, disable the affected platform
  route and document the gap instead of weakening policy.

## Phase 4: Hidden Secure Enclave P-256 Key Generation

Goal: create hidden/test-only Secure Enclave custody keys and corresponding
OpenPGP public certificates.

Recommended PRs:

- PR 4A: Add P-256 public-certificate construction for v4 compatible and v6
  modern candidates.
- PR 4B: Add hidden/test-only SE key generation workflow that commits metadata
  and handles atomically.
- PR 4C: Add revocation artifact generation/export support for generated SE
  custody keys, or mark the feature blocked if it cannot be completed through
  external signing.
- PR 4D: Add generation recovery tests for partial metadata/handle failures.

Entry conditions:

- Phase 3 handle provider can generate distinct signing and ECDH public keys.
- Phase 2 Rust certificate/signing prototype is available.

Exit conditions:

- Generated SE custody records never create or store software secret cert
  fallback bytes.
- Metadata and handle state either commit together or recover cleanly.
- Public certificate digest and sign/ECDH public-key bindings are validated.
- Feature remains hidden or test-only.

Validation:

- Swift generation and recovery tests.
- Rust certificate parse/round-trip tests for v4 and v6 P-256 candidates.
- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`

Rollback:

- If metadata and handle commits cannot be made recoverable, keep generation
  test-only and do not proceed to workflow integration.

## Phase 5: Signing-Class Operation Integration

Goal: route signing, certification, revocation, and binding-signature workflows
through Secure Enclave external signing.

Recommended PRs:

- PR 5A: Add private-key operation router integration for message signing and
  sign-plus-encrypt.
- PR 5B: Add password-message optional signing and streaming signing routes.
- PR 5C: Add contact certification route.
- PR 5D: Add expiry modification, binding refresh, key-level revocation, and
  selective revocation routes, or explicitly keep unsupported operations gated
  with security approval.

Entry conditions:

- Phase 4 hidden SE generation can produce valid public certificates.
- Phase 2 external signer tests prove digest and signature conversion behavior.

Exit conditions:

- Every signing-class workflow uses the router.
- SE custody never calls `unwrapPrivateKey` or passes secret cert bytes for
  signing-class operations.
- Unsupported signing-class operations fail closed with product-level
  unavailable state.
- Existing software custody behavior remains unchanged.

Validation:

- Swift service tests for signing, encryption, password-message, certification,
  key mutation, and revocation paths.
- Rust signing and signature verification tests.
- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`

Rollback:

- Disable SE custody route for any operation that cannot satisfy no-fallback
  and no-secret-cert requirements. Do not open product UI with partial MVP
  coverage unless Product and Security change the launch gate.

## Phase 6: ECDH Decrypt And Streaming Integration

Goal: route recipient-key decryption through Secure Enclave ECDH while keeping
payload decrypt/authentication in Rust/Sequoia.

Recommended PRs:

- PR 6A: Add in-memory decrypt route through external ECDH/session-key
  acquisition.
- PR 6B: Add streaming decrypt route with success-only final output behavior.
- PR 6C: Add sign-plus-encrypt/decrypt interop coverage for SE custody.
- PR 6D: Add tamper and cancellation tests across in-memory and streaming
  routes.

Entry conditions:

- Phase 3 handle provider has real and mock ECDH operations.
- Phase 2 Rust fake ECDH tests prove KDF, unwrap, and tamper behavior.

Exit conditions:

- SE custody decrypt never unwraps a complete secret certificate.
- PKESK/session-key acquisition remains distinct from payload authentication.
- No plaintext is returned after MDC/AEAD failure.
- Streaming decrypt never leaves the final output file on failure.
- Mixed-recipient and v4/v6 message-format behavior remains consistent with
  project policy.

Validation:

- Rust decrypt, tamper, streaming, and cross-profile tests.
- Swift decryption and streaming service tests.
- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- Device/hardware decrypt smoke when real SE ECDH paths are touched.

Rollback:

- If recipient binding or payload authentication cannot be preserved, disable
  the SE decrypt route and return to Rust boundary design. Do not move PKESK
  parsing or payload release policy into Swift.

## Phase 7: Product UI, Copy, And Availability States

Goal: expose the planned product semantics in UI only after private-operation
coverage is ready behind the gate.

Recommended PRs:

- PR 7A: Add key-generation choice surfaces for portable compatible, portable
  modern, device-bound compatible, and device-bound modern families.
- PR 7B: Add pre-generation non-exportability and device-loss copy.
- PR 7C: Add key-detail custody, export, revocation artifact, and operation
  availability states.
- PR 7D: Add error surfaces for unsupported platform, biometric unavailable,
  cancellation, lockout, missing handle, public-binding mismatch, and
  non-exportability.

Entry conditions:

- Phase 5 and Phase 6 private-operation routes are implemented or explicitly
  gated as unsupported with security approval.
- Product Design copy is still current.

Exit conditions:

- Secure Enclave custody cannot be confused with a private-key backup or
  in-place upgrade.
- Existing software Profile A/B behavior remains unchanged.
- Private-key export UI rejects SE custody and offers public certificate or
  revocation artifact actions where appropriate.
- Feature remains hidden/test-only until Phase 8 and Phase 9 gates are
  complete.

Validation:

- Swift unit tests for generation choice and key-detail view models.
- Route ownership and tutorial/update smoke tests if navigation changes.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'`
  when route ownership, launch, tutorial-host, or macOS UI workflow changes.

Rollback:

- Hide the Secure Enclave family choices through the feature gate. Keep
  existing software generation as the default and only visible route.

## Phase 8: Hardware And Interop Evidence

Goal: produce release-grade evidence before product availability.

Recommended PRs or validation records:

- PR 8A: Add or update hardware evidence runners for Secure Enclave signing and
  ECDH.
- PR 8B: Record iOS, iPadOS, macOS, and visionOS hardware results.
- PR 8C: Record GnuPG v4 P-256 interop evidence.
- PR 8D: Record v6 RFC 9580 / AEAD evidence.
- PR 8E: Record no-passcode-fallback evidence for the chosen access policy.

Entry conditions:

- Phases 5, 6, and 7 are functionally complete behind a gate.
- Hardware validation instructions are documented in [Testing](TESTING.md) or
  an evidence companion.

Exit conditions:

- Distinct signing and ECDH handles work on supported Apple platform families.
- Cancellation, lockout, unavailable biometry, enrollment changes, missing
  handles, wrong roles, wrong public keys, and local reset cleanup are covered.
- v4 GnuPG-oriented public certificate, signature verification, encryption to
  SE custody, decrypt, and bidirectional sign-plus-encrypt are validated.
- v6 AEAD behavior is validated without GnuPG compatibility claims.
- No-passcode-fallback behavior is proven on real devices for the planned
  access-control policy.

Validation:

- Hardware/manual Secure Enclave tests.
- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`
- macOS unit tests.
- Device tests where available:
  `xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests -destination 'platform=iOS,name=<DEVICE_NAME>'`
- Native visionOS build probe:
  `xcodebuild build -scheme CypherAir -destination 'generic/platform=visionOS' CODE_SIGNING_ALLOWED=NO`
- Interop evidence scripts or manually recorded commands, with sanitized
  outputs.

Rollback:

- If a platform fails access-control or private-operation evidence, keep that
  platform unavailable and document the gap. Do not weaken the default policy
  to pass the evidence gate.

## Phase 9: Release Readiness And Documentation Sync

Goal: make Secure Enclave custody product-selectable only after all gates are
closed.

Recommended PRs:

- PR 9A: Update Product Design, Architecture, Security, Testing, Persisted State
  Inventory, and ARM64E/status documents to reflect implemented behavior.
- PR 9B: Remove or narrow hidden/test-only gates only for supported platforms
  and product families.
- PR 9C: Add final release-readiness checklist and review evidence.

Entry conditions:

- Phase 8 evidence is accepted by maintainers and security reviewers.
- No MVP private-operation route relies on software fallback.
- Product copy and recovery language are final enough for release.

Exit conditions:

- Canonical docs agree on current behavior.
- Supported and unsupported platforms are explicit.
- User-facing recovery and non-exportability language is complete.
- Release gates for security, hardware, interop, and tests are satisfied.

Validation:

- Full relevant Rust and Swift validation from [Testing](TESTING.md).
- Hardware and interop evidence review.
- Documentation link/status review.
- App Store or formal release processes must follow
  [APP_RELEASE_PROCESS](APP_RELEASE_PROCESS.md) when relevant.

Rollback:

- If any release gate reopens, restore hidden/test-only gating and update docs
  to show the blocked condition. Do not ship an undocumented partial custody
  mode.

## Program-Level Stop Conditions

Return to product, architecture, and security review before continuing if any
phase discovers that the implementation requires:

- Secure Enclave private-key import or export;
- a software fallback for Secure Enclave custody;
- complete secret cert bytes for Secure Enclave custody;
- weakening `privateKeyUsage + biometryAny` without explicit security approval;
- passcode fallback for the default Secure Enclave custody private operation;
- moving OpenPGP KDF, packet parsing, or payload authentication into Swift as a
  shortcut;
- releasing plaintext before Sequoia payload authentication completes;
- claiming GnuPG v6 compatibility, visionOS/Optic ID readiness, backup, or
  no-passcode-fallback behavior without evidence.

## Update Triggers

Update this roadmap when:

- any phase lands or is intentionally skipped;
- feature-gate policy changes;
- metadata schema or migration order changes;
- Rust/UniFFI boundary design changes;
- Secure Enclave access-control policy changes;
- hardware evidence expands or invalidates platform support;
- product MVP scope changes;
- release gates or validation commands change.
