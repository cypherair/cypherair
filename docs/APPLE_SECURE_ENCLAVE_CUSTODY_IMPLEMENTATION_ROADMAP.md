# Apple Secure Enclave Custody Implementation Roadmap

> Status: Active implementation-preparation roadmap. This document describes
> proposed future work and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Define staged PR planning guidance for Apple Secure Enclave-backed
> OpenPGP private-key custody.
> Audience: Swift/Rust implementers, security reviewers, architecture
> reviewers, product owners, test owners, release owners, reviewers, and AI
> coding tools.
> Related: [Implementation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Roadmap Decision

Secure Enclave custody remains hidden or test-only until the product,
architecture, security, implementation, hardware, interop, documentation, and
release gates allow product exposure. No roadmap phase is a release promise.
Each phase still needs its own implementation plan before code work begins.

This roadmap names planning units and gates. It does not choose final Swift or
Rust APIs, persisted field names, Keychain item names, generated UniFFI shapes,
localized UI copy, fixture names, hardware-runner implementation details, or
release timing.

## Global PR Guidance

Every implementation PR should keep software-custody behavior stable unless the
PR explicitly changes it under Product Design and Security Requirements. Do not
add Secure Enclave custody by weakening Profile A/Profile B behavior, bypassing
ProtectedData, using workflow-local custody switches, or routing Secure Enclave
custody through APIs that require complete secret certificate bytes.

Sensitive areas require explicit implementation plans and security review
before editing. This includes `Sources/Security/`, `Sources/Security/ProtectedData/`,
`Sources/Services/DecryptionService.swift`, `pgp-mobile/src/`, Xcode project
files, entitlements, and app Info.plist changes. Follow
[Security](SECURITY.md#10-ai-coding-red-lines) and repository instructions.

Documentation-only PRs may use the docs-only validation path in
[Testing](TESTING.md#2-test-plans). Functional PRs must run validation that
matches their layer and risk. Rust or UniFFI behavior that affects Swift-visible
behavior must follow the artifact refresh and Xcode validation path in
[Testing](TESTING.md#24-rust-artifacts-uniffi-outputs-and-xcode-validation).

Rollback rule for all phases: if a phase cannot preserve no-fallback behavior,
payload hard-fail behavior, current software-custody compatibility, or
recoverable persisted-state semantics, stop and return to product,
architecture, and security review before continuing.

## Phase 0: Documentation And Baseline Lock

Goal:
Create the active implementation-preparation reference and roadmap, confirm
source authority, and keep the feature non-shipping.

Recommended PR grouping:
One docs-only PR for this roadmap and the implementation reference.

Entry conditions:
Product Design, Architecture Plan, Security Requirements, Feasibility Summary,
and current Architecture/Security/Testing/Persisted State docs exist and agree
on source ownership.

Exit conditions:
The implementation docs state that they describe proposed future work, link to
source authorities, define middle-contract implementation guidance, and do not
duplicate Product, Architecture, Security, or Testing.

Validation:
Run documentation consistency checks, active link/reference checks where
available, `git diff --check`, and review the diff. Rust and Xcode tests are
not required for docs-only changes.

Rollback:
Delete or revise the new implementation docs if they contradict source
authority, imply shipped behavior, or over-specify final code interfaces.

## Phase 1: Configuration, Custody, Metadata, And Migration Model

Goal:
Introduce the conceptual model that separates OpenPGP configuration,
private-key custody, and operation capability, plus protected metadata migration
for existing software keys.

Recommended PR grouping:
Keep model and migration work small enough for focused review. Metadata schema
work, migration behavior, and persisted-state inventory updates may be one PR
only if the implementation plan proves the blast radius is reviewable.

Entry conditions:
Phase 0 complete. A phase implementation plan defines migration approach,
rollback/recovery behavior, resolver inputs/outputs, and documentation updates
without selecting Secure Enclave handle storage yet.

Exit conditions:
Existing Profile A/B records normalize to configuration plus software custody.
The model can represent future P-256 v4/v6 Secure Enclave custody records
without treating custody as a `PGPKeyProfile`. Protected metadata can represent
non-secret public association, custody kind, exportability, revocation artifact
presence, and operation availability projection.

Validation:
Add mockable tests for legal/illegal configuration plus custody combinations,
metadata migration, corrupt committed state, no pre-auth key-list regression,
and software-custody behavior preservation. Update
[Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), [Architecture](ARCHITECTURE.md),
[Security](SECURITY.md), and [Testing](TESTING.md) as needed.

Rollback:
Keep old readable source state until migrated destination state is validated.
Do not silently reset unreadable committed protected state to empty data. If
migration proves unsafe, ship no Secure Enclave custody state and return to the
previous software-custody model.

## Phase 2: Rust External Private-Operation Proving

Goal:
Prove production-shaped Rust/Sequoia external-operation boundaries for signing
and recipient/session-key acquisition without using real app Keychain handles
or shipping product UI.

Recommended PR grouping:
Start with Rust-only or Rust-plus-adapter proof points behind test-only paths.
Avoid coupling this phase to product surfaces or Security handle persistence.

Entry conditions:
Phase 1 model direction is stable enough to identify software custody vs future
Secure Enclave custody paths. The phase implementation plan defines how test
callbacks or mocks represent external signing and ECDH without writing secrets
to files or logs.

Exit conditions:
Rust can build v4 and v6 P-256 OpenPGP signing/decrypt flows through external
operation seams. Rust still owns OpenPGP ECDH KDF, AES Key Wrap unwrap,
session-key validation, payload decrypt, MDC/AEAD verification, and signature
verification. The path rejects missing, wrong-role, and wrong-public-binding
operation providers without software fallback.

Validation:
Run Rust tests for external signer/decryptor success and negative paths, v4
MDC tamper hard-fail, v6 AEAD tamper hard-fail, and no secret output in errors.
If UniFFI or packaged artifacts change, run the full artifact sync and local
Xcode validation required by [Testing](TESTING.md#24-rust-artifacts-uniffi-outputs-and-xcode-validation).

Rollback:
Keep new Rust external-operation paths unreachable from product workflows until
later phases. If the boundary requires temporary files for shared secrets or
session keys, reject the approach and return to architecture/security review.

## Phase 3: Security Handle Storage

Goal:
Add Security-layer ownership for distinct Secure Enclave signing and
key-agreement private-operation handles, including role/public binding,
lifecycle, cleanup, local reset, and recovery classification.

Recommended PR grouping:
Implement handle storage behind test-only or internal callers first. Keep final
product generation and workflow integration out of this phase unless a later
implementation plan proves they are inseparable.

Entry conditions:
Phase 2 establishes the needed private-operation boundary. A security-reviewed
implementation plan defines access policy, Keychain accessibility, handle
lifecycle, metadata association, reset behavior, logging policy, and mock
strategy without choosing public UI copy.

Exit conditions:
Security can create, load, validate, use, and delete distinct signing and
key-agreement handles. It rejects missing handles, role substitution, public-key
mismatch, authentication cancellation/failure, and stale association. The
current software secret-certificate wrapping bundle remains separate.

Validation:
Add Swift mock tests for role/public binding, missing handle, recovery
classification, reset cleanup, no locator leakage, and no software fallback.
Add guarded device tests or manual evidence for real Secure Enclave operations
when the implementation first depends on hardware behavior.

Rollback:
Handle creation must be all-or-cleaned-up for test-only generation. If a
partial handle set or inconsistent metadata/handle association appears,
classify it as recovery or cleanup state, not as a usable key.

## Phase 4: Hidden Secure Enclave Generation

Goal:
Generate Secure Enclave custody keys through an internal or test-only path that
produces a public certificate, distinct private-operation capability, protected
metadata projection, and revocation artifact state.

Recommended PR grouping:
One focused hidden-generation PR after handle storage is stable. Keep public UI
exposure, broad workflow integration, and release compatibility claims out of
this phase.

Entry conditions:
Phases 1-3 complete. Product, architecture, and security agree on generation
semantics, access policy, metadata projection, and non-exportability language
for internal validation.

Exit conditions:
Internal/test generation works for v4 P-256 compatible and v6 P-256 modern
candidates, or explicitly records a source-authority decision to stage one
candidate first. Generated keys are not product-selectable. Public certificate
export/inspection and revocation artifact handling are available only through
approved internal or hidden surfaces.

Validation:
Test successful generation, aborted generation cleanup, duplicate/partial
handle cleanup, public certificate/handle binding, metadata persistence,
revocation artifact presence, local reset cleanup, and import/export rejection
for private material.

Rollback:
Remove or disable hidden generation if it cannot clean up partial Security or
metadata state. Do not leave a product-visible key family whose private
operations are incomplete.

## Phase 5: Signing-Class Workflow Integration

Goal:
Integrate Secure Enclave signer routing for operations that require private
signing but not recipient-key decryption.

Recommended PR grouping:
Group closely related signing-class workflows only when tests and review remain
clear. Message signing may land before certification, revocation, expiry, or
binding refresh, but product exposure remains gated by full MVP scope.

Entry conditions:
Hidden generation can produce usable signing handles and public certificates.
The router can distinguish software route, Secure Enclave signer route, and
unsupported route.

Exit conditions:
Supported signing-class workflows call the router, use the Secure Enclave
signing handle for Secure Enclave custody, preserve software-custody behavior,
and return stable unavailable/unsupported errors for incomplete operations.

Validation:
Add positive and negative tests for message signing, sign-plus-encrypt signing
participation, password-message optional signing, expiry/binding/revocation or
certification as each workflow lands, no secret-cert unwrap fallback, wrong-role
rejection, cancellation, and error mapping.

Rollback:
If a signing-class workflow cannot be implemented without complete secret
certificate bytes, mark that operation unsupported for Secure Enclave custody
and keep product exposure blocked.

## Phase 6: Decrypt And Streaming Integration

Goal:
Integrate Secure Enclave ECDH/session-key routing for message and streaming
decrypt while preserving payload authentication and success-only output.

Recommended PR grouping:
Keep recipient/session-key acquisition, message decrypt, and streaming decrypt
reviewable. Streaming file behavior may need its own PR because of progress,
cancellation, and temporary-artifact cleanup.

Entry conditions:
Phases 2-4 complete. The router can provide Secure Enclave ECDH/session-key
routes and the Rust boundary keeps payload decrypt and authentication in
Sequoia.

Exit conditions:
Message decrypt and streaming decrypt acquire session keys through the Secure
Enclave custody boundary for supported keys. v4 SEIPDv1/MDC and v6
SEIPDv2/AEAD hard-fail behavior remains intact. Temporary artifacts, progress,
cancellation, and relock cleanup preserve current guarantees.

Validation:
Add tests for v4 decrypt, v6 decrypt, tamper hard-fail, authentication
cancellation, missing handle, wrong role, wrong public binding, no partial
plaintext, streaming cancellation cleanup, and output only after successful
message processing. Run Rust, Swift, FFI, and device validation according to
the touched layers.

Rollback:
If decrypt or streaming cannot preserve no-partial-plaintext behavior, keep
Secure Enclave custody decrypt unsupported and stop product exposure.

## Phase 7: Product UI And Error Surfaces

Goal:
Expose the custody model, availability, non-exportability, and recovery
consequences in product surfaces only after the private-operation architecture
is complete enough for coherent user behavior.

Recommended PR grouping:
Separate generation-choice UI, key-detail/status UI, and operation-error UI
unless one product plan explicitly needs them together. Localized copy and final
screen layout belong to this phase's implementation plan, not this roadmap.

Entry conditions:
Core generation, signing, decrypt, streaming, and key mutation behavior is
implemented or explicitly unsupported with source-authority approval. Product
Design owns final user-facing commitments and compatibility language.

Exit conditions:
Generation shows complete valid choices, keeps software compatible custody as
the default unless Product Design changes it, and clearly presents
non-exportability and device-bound consequences before key creation. Key detail
surfaces separate compatibility, OpenPGP configuration, custody, public
certificate state, revocation artifact state, exportability, and private
operation availability.

Validation:
Run UI, screen-model, routing, localization, and macOS smoke validation
appropriate to changed surfaces. Test unavailable/unsupported/error states,
public-material workflows, private-key export rejection, import rejection, and
no pre-auth metadata exposure.

Rollback:
If UI cannot explain permanent-loss risk, non-exportability, or operation
availability accurately, keep Secure Enclave custody hidden and return to
Product Design.

## Phase 8: Hardware And Interop Evidence

Goal:
Collect release-quality evidence for real Secure Enclave operations on
supported Apple platform families and interoperability claims.

Recommended PR grouping:
Hardware evidence harnesses, sanitized reporting, and interop fixtures may land
separately from product code. Keep manual/release lanes distinct from mandatory
default CI unless Testing later changes that policy.

Entry conditions:
Product-shaped generation and private-operation workflows are implemented
behind appropriate gates. The evidence plan defines supported hardware,
platform families, sanitized outputs, and acceptance criteria.

Exit conditions:
Evidence covers generation and persistence of distinct handles, signing for v4
and v6 Secure Enclave custody certificates, ECDH/session-key recovery and
decrypt for v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD, authentication cancellation,
biometric lockout, missing handle, wrong role, wrong public binding, local reset
cleanup, and sanitized output. v4 GnuPG interop evidence covers import,
signature verification, encryption to the public certificate, decrypt/verify of
GnuPG-originated messages, bidirectional sign-plus-encrypt, and PKESK v3 ECDH
plus SEIPDv1/MDC packet shape. v6 validates RFC 9580 / AEAD behavior without
claiming GnuPG support.

Validation:
Run the hardware and interop evidence suites defined by Security Requirements
and Testing. Preserve evidence summaries without logging plaintext,
private-key material, shared secrets, session keys, KEKs, Keychain locators,
stable fingerprints, or temporary paths.

Rollback:
If hardware or interop evidence fails, remove product exposure claims and keep
the feature hidden or unavailable until the root cause has a reviewed fix.

## Phase 9: Release Readiness

Goal:
Allow product exposure only when full first-version scope and release gates are
satisfied.

Recommended PR grouping:
One release-readiness PR or release checklist update after all implementation,
product, validation, and documentation gates are satisfied.

Entry conditions:
Product Design, Architecture Plan, Security Requirements, Implementation
Reference, this Roadmap, Architecture, Security, Persisted State Inventory, and
Testing agree on shipped behavior. The full first-version private-operation
surface is implemented or explicitly descoped by source-authority updates.

Exit conditions:
Secure Enclave custody can become product-selectable only after configuration
and custody migration behavior, persisted-state classification, router and
Rust/UniFFI boundary, mockable security tests, hardware evidence, v4 GnuPG
interop evidence, v6 AEAD evidence, and user-facing recovery/non-exportability
language all pass review.

Validation:
Run the full release validation required by Testing and the release process for
the touched platform set. Include documentation review, static audits,
security-focused negative tests, hardware evidence, interop evidence, and
release notes or product docs if required by the release plan.

Rollback:
If any release gate fails, keep Secure Enclave custody unavailable in product
UI. Do not ship partial product exposure after only basic signing/decryption
success.

## Program-Level Stop Conditions

Stop implementation and return to product, architecture, and security review if
any phase requires:

- exporting Secure Enclave private-key material;
- importing an existing OpenPGP private key into Secure Enclave custody;
- storing a software private-key fallback;
- unwrapping or storing a complete secret certificate for Secure Enclave
  custody;
- treating handles, public keys, or locators as private-key backups;
- using one Secure Enclave private key for both signing and ECDH;
- accepting role or public binding mismatch;
- exposing partial plaintext after MDC or AEAD failure;
- logging secrets, locators, stable fingerprints, or temporary capability paths;
- weakening current software-custody behavior;
- shipping UI before full release gates are met.

## Roadmap Update Triggers

Update this roadmap when:

- Product Design changes first-version scope, compatibility language, or user
  commitments;
- Architecture Plan changes model separation, resolver/router ownership,
  metadata/handle split, or Swift/Rust boundary direction;
- Security Requirements change red lines, access policy, validation, hardware,
  interop, or release gates;
- implementation evidence proves a phase should split, combine, reorder, or
  stop;
- Testing changes documentation-only, Rust, Swift, device, hardware, or interop
  validation policy;
- Persisted State Inventory changes classification or migration expectations
  for Secure Enclave custody state.
