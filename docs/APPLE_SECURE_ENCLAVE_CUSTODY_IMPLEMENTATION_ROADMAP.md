# Apple Secure Enclave Custody Implementation Roadmap

> Status: Active implementation roadmap proposal. This document describes
> proposed future PR sequencing and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Split Apple Secure Enclave Custody production work into staged,
> reviewable PR phases with entry conditions, validation, and rollback rules.
> Audience: CypherAir maintainers, Swift/Rust implementers, security reviewers,
> architecture reviewers, product owners, test owners, QA, and AI coding tools.
> Related: [Implementation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Roadmap Decision

Secure Enclave custody should land through small staged PRs. Each phase should
have its own implementation plan before code changes begin. This roadmap gives
the phase structure; it does not approve exact code interfaces, schemas, UI
copy, storage names, or release timing.

Secure Enclave custody must remain hidden or test-only until the active
Product, Architecture, Security, implementation, hardware, interop, and release
gates agree that product exposure is allowed.

## Global PR Rules

Every phase must follow the repository rules in [AGENTS](../AGENTS.md), the
validation workflow in [Testing](TESTING.md), and the Secure Enclave custody
gates in
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md).

Do not repeat global rules in each PR plan. Each PR plan should instead name
the boundary it touches, the source documents it consumes, the validation it
runs, and how it remains hidden, test-only, or product-visible after landing.

## Phase 0: Documentation And Baseline Locks

Goal: establish implementation planning documents and lock the current
software-custody baseline before code work begins.

Recommended PRs:

- PR 0A: add the implementation reference and this roadmap.
- PR 0B: add or update a hidden feature-gate decision record only if later
  implementation PRs need a named gate before runtime code exists.

Entry conditions:

- The active Product Design, Architecture Plan, Security Requirements, and
  Feasibility Summary are current.
- The current code baseline is understood as software secret-certificate
  custody.

Exit conditions:

- The implementation reference and roadmap clearly state proposed future
  behavior, not shipped behavior.
- The documents preserve the configuration/custody/capability separation.
- Existing Profile A/B behavior remains unchanged.

Validation:

- `git diff --check`.
- Documentation review for links, status blocks, and no current-behavior
  overclaim.
- Confirm the PR is docs-only.

Rollback:

- Revert or revise docs only. No runtime behavior should exist in this phase.

## Phase 1: Configuration, Custody, Capability, And Metadata Model

Goal: add the model foundation without changing private-key runtime behavior.

Recommended PRs:

- PR 1A: introduce successor configuration and custody descriptors or adapters.
- PR 1B: add capability projection and resolver contracts behind tests.
- PR 1C: add protected metadata migration for existing Profile A/B records into
  configuration plus software custody.
- PR 1D: update persisted-state docs and migration/recovery tests.

Entry conditions:

- Phase 0 docs are merged.
- No product UI path exposes Secure Enclave custody.
- Existing Profile A/B fixtures and key-management behavior are understood.

Exit conditions:

- Existing keys read as software custody with unchanged behavior.
- Metadata can represent future Secure Enclave custody records without storing
  private material.
- Resolver can describe supported and unsupported operations without
  authentication or private operations.
- Corrupt committed protected state remains a recovery surface and does not
  silently reset to empty state.

Validation:

- Swift unit tests for metadata migration, resolver output, invalid
  configuration/custody combinations, and recovery behavior.
- Existing key-management and ProtectedData tests.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`.

Rollback:

- Keep source metadata readable until migrated destination validation succeeds.
- If migration risk is unresolved, leave the new reader/writer disabled behind
  a gate and stop before runtime private-operation work.

## Phase 2: Rust External Operation Prototypes And Tests

Goal: prove Rust/Sequoia external private-operation seams with fake operations
before touching Apple Security code.

Recommended PRs:

- PR 2A: add Rust external signer adapter tests with fake P-256 private
  operations.
- PR 2B: add fake external key-agreement/session-key acquisition tests for v4
  and v6 messages.
- PR 2C: add no-plaintext and streaming cleanup tamper tests for the external
  route.

Entry conditions:

- Phase 1 model can identify future Secure Enclave custody records, even if no
  runtime path creates them.
- The Rust boundary plan names which OpenPGP responsibilities remain Rust-owned.

Exit conditions:

- Rust can sign through a fake external signer without hashing the message
  again.
- Rust can recover session keys through a fake external key-agreement path while
  keeping OpenPGP KDF, AES Key Wrap, and payload authentication in Rust/Sequoia.
- Wrong recipient, tampered ephemeral public point, tampered wrapped session
  key, malformed packet, MDC tamper, and AEAD tamper fail closed.

Validation:

- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.
- Focused Rust tests for external signer/decryptor modules.
- Confirm no generated UniFFI Swift is hand-edited.

Rollback:

- If Sequoia's reachable seams cannot support the boundary, stop at a disabled
  test-only Rust prototype and return to architecture review. Do not move
  OpenPGP KDF, packet parsing, or payload release policy into Swift as a
  shortcut.

## Phase 3: Security Handle Provider And Store

Goal: implement Swift/Security storage for distinct Secure Enclave signing and
key-agreement handles without exposing product UI.

Recommended PRs:

- PR 3A: add handle-store protocols and mock store for signing and
  key-agreement roles.
- PR 3B: add real Secure Enclave key generation, loading, and deletion for
  distinct handles.
- PR 3C: add role binding, public-key binding, cleanup, and local reset
  participation.
- PR 3D: add guarded hardware smoke checks in device/manual lanes.

Entry conditions:

- Phase 1 model and Phase 2 fake Rust paths are available.
- Security Requirements still define the planned access-control policy.
- The Phase 3 plan includes a handle-creation checklist for Secure Enclave
  token use, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` by default unless
  Security Requirements or an explicit security review chooses a stricter
  compatible accessibility class, private-key authorization, biometric policy,
  unsupported passcode fallback, and cleanup behavior.

Exit conditions:

- Signing and key-agreement handles are generated separately.
- Wrong role, wrong public key, missing handle, cancellation, lockout, and
  platform unavailable states fail closed through stable errors.
- Keychain locators and handle identifiers are not logged or surfaced.
- Local reset and key deletion clean up handle state or classify remaining
  mismatch state.

Validation:

- Swift unit tests for mock handle store, binding checks, and cleanup
  classification.
- Hardware/manual tests for real Secure Enclave signing and key-agreement smoke
  where available.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`.
- Device-only tests when real hardware paths are touched.

Rollback:

- Keep real handle creation behind a hidden/test-only gate.
- If platform access-control behavior differs from Security Requirements,
  disable the affected platform route and document the gap instead of weakening
  policy inside the implementation.

## Phase 4: Hidden Secure Enclave P-256 Key Generation

Goal: create hidden or test-only Secure Enclave custody keys and corresponding
OpenPGP public certificates.

Recommended PRs:

- PR 4A: add P-256 public-certificate construction for compatible and modern
  candidates.
- PR 4B: add hidden/test-only generation orchestration that commits metadata and
  handles together.
- PR 4C: add revocation artifact generation/export support for generated
  Secure Enclave custody keys, or mark generation blocked until it can be done
  without secret-certificate fallback.
- PR 4D: add generation recovery tests for partial metadata/handle failures.

Entry conditions:

- Phase 3 handle provider can generate distinct signing and key-agreement
  public keys.
- Phase 2 Rust public-certificate and signing fakes are available.

Exit conditions:

- Generated Secure Enclave custody records never create or store software
  secret certificate fallback bytes.
- Metadata and handle state either commit together or recover cleanly.
- Public certificate association and signing/key-agreement public bindings are
  validated.
- Feature remains hidden or test-only.

Validation:

- Swift generation and recovery tests.
- Rust certificate parse/round-trip tests for v4 and v6 P-256 candidates.
- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`.

Rollback:

- If metadata and handle commits cannot be made recoverable, keep generation
  test-only and do not proceed to workflow integration.

## Phase 5: Signing-Class Operation Integration

Goal: route signing, certification, revocation, and binding-signature workflows
through Secure Enclave external signing.

Recommended PRs:

- PR 5A: integrate router support for message signing and sign-plus-encrypt.
- PR 5B: integrate password-message optional signing and streaming signing.
- PR 5C: integrate contact certification.
- PR 5D: integrate expiry update, binding refresh, key-level revocation, and
  selective revocation, or explicitly keep those operations gated as
  unsupported.

Entry conditions:

- Phase 4 hidden Secure Enclave generation can produce valid public
  certificates.
- Phase 2 external signer tests prove Rust-owned signing semantics and
  no-repeat-hash behavior.

Exit conditions:

- Every integrated signing-class workflow uses the router.
- Secure Enclave custody never calls `unwrapPrivateKey` or passes secret
  certificate bytes for signing-class operations.
- Unsupported signing-class operations fail closed with product-level
  unavailable state.
- Existing software custody behavior remains unchanged.

Validation:

- Swift service tests for signing, encryption, password-message,
  certification, key mutation, and revocation paths touched by the phase.
- Rust signing and verification tests.
- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`.

Rollback:

- Disable the Secure Enclave route for any operation that cannot satisfy
  no-fallback and no-secret-certificate requirements. Keep product UI hidden
  unless Product and Security revise the launch gate.

## Phase 6: ECDH Decrypt And Streaming Integration

Goal: route recipient private work through Secure Enclave key agreement while
keeping payload decrypt/authentication in Rust/Sequoia.

Recommended PRs:

- PR 6A: add in-memory decrypt route through external key-agreement/session-key
  acquisition.
- PR 6B: add streaming decrypt route with success-only final output behavior.
- PR 6C: add sign-plus-encrypt/decrypt coverage for Secure Enclave custody.
- PR 6D: add tamper and cancellation tests across in-memory and streaming
  routes.

Entry conditions:

- Phase 3 handle provider has real and mock key-agreement operations.
- Phase 2 fake key-agreement tests prove KDF, unwrap, and tamper behavior.

Exit conditions:

- Secure Enclave custody decrypt never unwraps a complete secret certificate.
- Recipient/session-key acquisition remains distinct from payload
  authentication.
- No plaintext is returned after MDC/AEAD failure.
- Streaming decrypt never leaves the final output file on failure.
- Mixed-recipient and v4/v6 message-format behavior remains consistent with
  project policy.

Validation:

- Rust decrypt, tamper, streaming, and cross-profile tests.
- Swift decryption and streaming service tests.
- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`.
- Device/hardware decrypt smoke when real Secure Enclave key-agreement paths are
  touched.

Rollback:

- If recipient binding or payload authentication cannot be preserved, disable
  the Secure Enclave decrypt route and return to Rust boundary design. Do not
  move PKESK parsing or payload release policy into Swift.

## Phase 7: Product UI, Copy, And Availability States

Goal: expose planned product semantics in UI only after private-operation
coverage is ready behind the gate.

Recommended PRs:

- PR 7A: add key-generation choices for portable compatible, portable modern,
  device-bound compatible, and device-bound modern families.
- PR 7B: add pre-generation non-exportability and device-loss copy.
- PR 7C: add key-detail custody, export, revocation artifact, and operation
  availability states.
- PR 7D: add product-facing error surfaces for unsupported platform, biometric
  unavailable, cancellation, lockout, missing handle, public-binding mismatch,
  and non-exportability.

Entry conditions:

- Phase 5 and Phase 6 private-operation routes are implemented or explicitly
  gated as unsupported with security approval.
- Product Design copy and MVP scope are still current.

Exit conditions:

- Secure Enclave custody cannot be confused with private-key backup or in-place
  upgrade.
- Existing software Profile A/B behavior remains unchanged.
- Private-key export UI rejects Secure Enclave custody and offers public
  certificate or revocation artifact actions where appropriate.
- Feature remains hidden/test-only until Phase 8 and Phase 9 gates are complete.

Validation:

- Swift unit tests for generation choice and key-detail view models.
- Route ownership and tutorial/update smoke tests if navigation changes.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`.
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'`
  when route ownership, launch, tutorial-host, or macOS UI workflow changes.

Rollback:

- Hide Secure Enclave family choices through the feature gate. Keep existing
  software generation as the default and only visible route.

## Phase 8: Hardware And Interop Evidence

Goal: produce release-grade evidence before product availability.

Recommended PRs or validation records:

- PR 8A: add or update hardware evidence runners for Secure Enclave signing and
  key agreement.
- PR 8B: record iOS, iPadOS, macOS, and visionOS hardware results.
- PR 8C: record GnuPG v4 P-256 interop evidence for compatible claims.
- PR 8D: record v6 RFC 9580 / AEAD evidence.
- PR 8E: record no-passcode-fallback evidence for the chosen access policy.

Entry conditions:

- Phases 5, 6, and 7 are functionally complete behind a gate.
- Hardware validation instructions are documented in [Testing](TESTING.md) or
  an evidence companion.

Exit conditions:

- Distinct signing and key-agreement handles work on supported Apple platform
  families.
- Cancellation, lockout, unavailable biometry, enrollment changes, missing
  handles, wrong roles, wrong public keys, and local reset cleanup are covered.
- v4 compatibility claims are backed by GnuPG evidence.
- v6 AEAD behavior is validated without GnuPG compatibility claims unless
  Product Design changes that claim.
- No-passcode-fallback behavior is proven on real devices before release
  language claims it.

Validation:

- Hardware/manual Secure Enclave tests.
- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.
- macOS unit tests.
- Device tests where available:
  `xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests -destination 'platform=iOS,name=<DEVICE_NAME>'`.
- Native visionOS build probe:
  `xcodebuild build -scheme CypherAir -destination 'generic/platform=visionOS' CODE_SIGNING_ALLOWED=NO`.
- Sanitized interop evidence records.

Rollback:

- If a platform fails access-control or private-operation evidence, keep that
  platform unavailable and document the gap. Do not weaken the default policy to
  pass the evidence gate.

## Phase 9: Release Readiness And Documentation Sync

Goal: make Secure Enclave custody product-selectable only after all gates are
closed.

Recommended PRs:

- PR 9A: update Product Design, Architecture, Security, Testing, Persisted State
  Inventory, and platform/status docs to reflect implemented behavior.
- PR 9B: remove or narrow hidden/test-only gates only for supported platforms
  and product families.
- PR 9C: add final release-readiness checklist and evidence review.

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
- Formal release or App Store work follows
  [APP_RELEASE_PROCESS](APP_RELEASE_PROCESS.md) when relevant.

Rollback:

- If any release gate reopens, restore hidden/test-only gating and update docs
  to show the blocked condition. Do not ship an undocumented partial custody
  mode.

## Program-Level Stop Conditions

Return to Product, Architecture, and Security review before continuing if a
phase discovers that the implementation requires behavior forbidden by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
or if it requires changing product commitments from
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md).

Program stop conditions include:

- Secure Enclave private-key import or export;
- software fallback for Secure Enclave custody;
- complete secret certificate bytes for Secure Enclave custody;
- weakening the Security-owned access policy to make implementation easier;
- moving OpenPGP KDF, packet parsing, or payload authentication into Swift as a
  shortcut;
- releasing plaintext before Sequoia payload authentication succeeds;
- claiming unsupported platform, backup, recovery, or interoperability behavior
  without evidence.

## Update Triggers

Update this roadmap when:

- any phase lands, splits, or is intentionally skipped;
- feature-gate policy changes;
- metadata schema or migration order changes;
- Rust/UniFFI boundary design changes;
- Secure Enclave access-control policy changes;
- hardware evidence expands or invalidates platform support;
- product MVP scope changes;
- release gates or validation commands change.
