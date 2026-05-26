# Apple Secure Enclave Custody Implementation Roadmap

> Status: Active implementation-preparation roadmap. This document describes
> proposed future implementation sequencing and does not describe shipped
> behavior.
> Date: 2026-05-25.
> Purpose: Provide staged PR guidance for turning Apple Secure Enclave Custody
> planning into production-ready implementation work.
> Audience: Swift/Rust implementers, security reviewers, architecture reviewers,
> product owners, test owners, reviewers, release owners, and AI coding tools.
> Related: [Implementation Docs Guidance](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_DOCS_GUIDANCE.md),
> [Implementation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Roadmap Decision

Apple Secure Enclave Custody must remain hidden, disabled, or test-only until
the active product, architecture, security, implementation, hardware, interop,
documentation, and release gates allow product exposure. This roadmap is not a
release promise and not a complete implementation plan for any phase. Each phase
still needs its own implementation plan before code work begins.

The implementation should progress from model and boundary readiness toward
hidden end-to-end operation, then product exposure. A later phase may be split
or reordered when a phase-specific plan proves a different dependency graph, but
work must not skip the security gates in
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md).

## Global PR Rules

- Keep changes scoped and reviewable; avoid broad refactors that are not needed
  for the phase.
- Treat `Sources/Security/`, `Sources/Services/DecryptionService.swift`,
  `pgp-mobile/src/`, Xcode project files, entitlements, and release metadata as
  sensitive surfaces under the repository agent guide and current
  [Security](SECURITY.md).
- Do not hand-edit generated UniFFI Swift bindings.
- Do not expose product UI before the release gate in
  [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#release-gate)
  is satisfied.
- Do not weaken current portable software-key behavior to make Secure Enclave
  custody easier to integrate.
- Update current-state docs only when shipped code changes. Future-facing
  implementation plans should stay clearly marked as proposed work.
- Any PR that changes persisted state must update
  [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), current
  architecture/security/testing docs, migration tests, and recovery behavior in
  the same change.
- Any Swift-visible Rust behavior change must follow the Rust, UniFFI, and
  XCFramework validation workflow in [Testing](TESTING.md).

## Phase 0: Baseline Documents And Guardrails

Goal: establish implementation-facing guidance and measurable guardrails before
production code begins.

Recommended PR grouping:

- Add the Implementation Reference and this Roadmap.
- Add or extend source-audit guardrails only where a phase-specific plan can
  make them precise without blocking known transitional states.

Entry conditions:

- Product Design, Architecture Plan, Security Requirements, Feasibility Summary,
  and Implementation Docs Guidance are active.
- The branch is documentation-only unless a separate guardrail plan is approved.

Exit conditions:

- Future implementation plans can cite a shared middle-contract reference.
- The roadmap names phase gates, rollback rules, and stop conditions without
  pretending to be a code-level implementation plan.
- Documentation states that Secure Enclave Custody is proposed future work, not
  shipped behavior.

Validation:

- `git diff --check`.
- Manual diff review for source-link correctness, future-facing language, and
  avoidance of duplicate Product / Architecture / Security / Testing content.
- If guardrails are added, run their focused test target.

Rollback:

- Documentation-only changes can be reverted without app migration concerns.
- Guardrail changes must be reverted or relaxed if they block current legitimate
  code before the phase they are meant to protect.

## Phase 1: Configuration, Custody, And Metadata Foundation

Goal: introduce the app-owned model foundation that separates OpenPGP
configuration, private-key custody, and operation capability while preserving
existing Profile A/B behavior.

Recommended PR grouping:

- Successor configuration/custody modeling and adapters for existing Profile
  A/B records.
- Protected key metadata migration to represent software custody and future
  Secure Enclave custody state.
- Capability projection and recovery classification needed by UI and workflow
  services, without product-exposing Secure Enclave generation.

Entry conditions:

- Phase 0 docs are available.
- A phase-specific implementation plan names persisted migration strategy,
  compatibility behavior, recovery surfaces, and test coverage.
- Architecture and security reviewers agree that the plan does not model Secure
  Enclave custody as a `PGPKeyProfile` case.

Exit conditions:

- Existing keys behave the same but can be represented as configuration plus
  software custody.
- Protected metadata can represent future Secure Enclave custody public
  association and availability state without storing Security-layer handle
  internals or access-control policy as user-owned metadata.
- Corrupt or partially migrated metadata fails closed into recovery instead of
  silently resetting to empty.

Validation:

- Metadata migration and compatibility tests for existing Profile A/B keys.
- Resolver/model tests for legal and illegal configuration plus custody
  combinations.
- ProtectedData recovery tests for corrupt, pending, and mismatched metadata.
- Source-audit checks that prevent `PGPKeyProfile` from gaining a Secure
  Enclave case if practical.

Rollback:

- Keep old readable metadata until migrated state validates.
- If migration defects appear, disable the new metadata reader/writer path or
  restore the prior metadata model before shipping the migration.
- Do not delete legacy migration sources until a separate support-cutoff plan
  approves it.

## Phase 2: Rust External Private-Operation Boundary

Goal: prove and introduce production-shaped Rust/UniFFI boundaries for external
signing and ECDH/session-key acquisition without exposing product Secure Enclave
custody.

Recommended PR grouping:

- Rust signing boundary for externally performed P-256 ECDSA operations.
- Rust ECDH/session-key acquisition boundary for externally performed P-256 key
  agreement while Rust owns OpenPGP KDF, AES Key Wrap, session-key validation,
  and packet semantics.
- Streaming decrypt integration that preserves read-to-completion,
  message-processed, MDC, and AEAD hard-fail behavior.

Entry conditions:

- Phase 1 model work can describe the operation request without forcing a
  complete secret certificate.
- A Rust/Swift implementation plan explains how the production boundary avoids
  the non-production POC response-file bridge.
- Security review agrees that no shared secrets, session keys, KEKs, plaintext,
  or private-key material will be written to files, logs, stdout, diagnostics,
  or persisted state.

Exit conditions:

- Rust can construct and validate OpenPGP signing/decryption behavior while the
  private operation is supplied externally.
- Existing software-custody Rust APIs and behavior remain intact.
- Tamper failures still fail closed for v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD.
- Swift-visible behavior is available through reviewed adapters or generated
  bindings after the documented artifact refresh.

Validation:

- Rust unit and integration tests for external signing and external
  ECDH/session-key behavior.
- Negative tests for malformed external results, wrong role, wrong public
  association, cancellation/failure mapping, and no fallback to software secret
  certificates.
- Existing profile tests, tamper tests, and streaming tests affected by the
  boundary.
- XCFramework / UniFFI refresh and macOS Swift unit tests when Swift-visible
  Rust behavior changes.

Rollback:

- Keep the external-operation path hidden behind adapters or feature gates
  until integrated with Security handles.
- If artifact refresh or Swift-visible behavior regresses, revert the adapter
  exposure while preserving internal Rust tests only if they do not affect
  shipping behavior.

## Phase 3: Security Handle Store And Mockable Platform Boundary

Goal: add the Swift Security-layer private-operation handle store and mockable
boundary for distinct Secure Enclave signing and key-agreement handles.

Recommended PR grouping:

- Handle creation, loading, role binding, public-key binding, deletion, and
  local reset participation.
- Mock handle providers for unit tests.
- Availability and recovery classification for missing, invalid, mismatched, or
  unauthenticated handles.

Entry conditions:

- Phase 1 metadata can record non-secret public association and availability
  projection.
- Phase 2 Rust boundaries can consume external signing and ECDH operations.
- Security review approves the concrete access-control and Keychain
  accessibility choices in the phase-specific implementation plan.

Exit conditions:

- Signing and key-agreement handles are distinct and role-bound.
- Handle load/use fails closed on missing handle, authentication cancellation,
  biometric unavailability/lockout, wrong role, public-key mismatch, invalid
  Keychain state, or unavailable Secure Enclave support.
- Reset All Local Data and any key deletion path clean up Secure Enclave custody
  handles without touching unrelated app state.
- Tests can cover policy and failure behavior without real hardware.

Validation:

- Swift unit tests using mocks for creation, load, authenticate, role mismatch,
  public binding mismatch, missing handle, deletion, reset, and recovery.
- Source-audit or focused tests proving Keychain locators and handle details do
  not leak into app-owned Models or Rust-owned OpenPGP state.
- Device-only hardware smoke tests may be added here, but product exposure does
  not depend on this phase alone.

Rollback:

- Keep the handle store unused by product workflows until hidden generation and
  route integration are ready.
- If handle persistence is defective, disable Secure Enclave custody generation
  and delete only the new handle-store artifacts owned by this phase.

## Phase 4: Hidden Generation And Resolver/Router Integration

Goal: create hidden or test-only Secure Enclave custody keys end to end and
centralize operation routing without exposing the feature in product UI.

Recommended PR grouping:

- Hidden/test-only generation for device-bound compatible v4 and device-bound
  modern v6 candidates.
- Capability resolver output for generation, operation availability, and
  unsupported states.
- Private-key operation router integration for software, Secure Enclave
  signing, Secure Enclave ECDH/session-key, and explicit unsupported routes.

Entry conditions:

- Phase 1 metadata, Phase 2 Rust boundary, and Phase 3 handle store are merged
  or otherwise available behind hidden/test-only paths.
- Product review confirms hidden/test-only generation cannot be selected by
  ordinary users.
- A phase-specific implementation plan defines cleanup for failed generation
  across metadata, public certificate state, revocation artifacts, and handles.

Exit conditions:

- Hidden generation produces public certificate state, protected metadata,
  distinct private-operation handles, public binding, and revocation artifact
  state or fails closed with cleanup.
- Workflow services consume resolver/router output instead of implementing
  local custody switches.
- Existing software-custody generation, import, export, signing, and decrypt
  behavior remains unchanged.

Validation:

- Unit tests for successful hidden generation and failed partial generation
  cleanup.
- Resolver tests for product-enabled, hidden, unsupported, unavailable, and
  recovery states.
- Router dispatch tests for all route classes and forbidden fallback paths.
- Regression tests for existing Profile A/B software-custody workflows.

Rollback:

- Disable the hidden/test-only generation entry point.
- Leave migrated software metadata intact if it is already shipping and valid.
- Clean up only incomplete Secure Enclave custody artifacts created by the
  hidden path according to the phase cleanup plan.

## Phase 5: Signing-Class Workflow Integration

Goal: route all signing-class operations for Secure Enclave custody through the
Secure Enclave signing route.

Recommended PR grouping:

- Message signing and sign plus encrypt.
- Password-message optional signing.
- Certification, key-level revocation, selective revocation, expiry
  modification, and binding refresh where the operation can be performed
  without complete secret certificate mutation.

Entry conditions:

- Phase 4 router integration is available.
- Each workflow has a phase-specific plan naming the private signing point,
  unsupported cases, cancellation behavior, and tests.
- Security review confirms no workflow reconstructs or unwraps a complete
  secret certificate for Secure Enclave custody.

Exit conditions:

- Supported signing-class operations use the Secure Enclave signing route.
- Unsupported signing-class operations are explicit and user-safe.
- No workflow-local custody switches, software fallback, or secret-cert unwrap
  fallback are introduced.
- Software-custody behavior remains unchanged.

Validation:

- Workflow tests for each supported signing-class operation.
- Negative tests for unsupported operation, missing handle, wrong role, public
  binding mismatch, authentication cancellation, and no fallback.
- Existing signature, certification, revocation, expiry, and password-message
  tests for software custody.

Rollback:

- Disable Secure Enclave custody for the affected workflow in resolver output.
- Keep the router and hidden generation intact if their tests still pass.
- Revert only the workflow integration path if it cannot meet the no-fallback
  and no-secret-output requirements.

## Phase 6: Decrypt And Streaming Workflow Integration

Goal: route message and streaming decrypt operations for Secure Enclave custody
through the Secure Enclave ECDH/session-key route while preserving payload
authentication hard-fail behavior.

Recommended PR grouping:

- Message decrypt and sign-plus-encrypt receive/decrypt paths.
- Streaming file decrypt and encrypt-plus-sign receive/decrypt paths.
- Cancellation, progress, temporary artifact, and success-only output handling
  for Secure Enclave custody routes.

Entry conditions:

- Phase 4 router integration is available.
- Phase 2 streaming and payload authentication boundaries have passed tamper
  tests.
- A phase-specific plan names how session-key acquisition errors map to
  workflow errors without leaking secret material.

Exit conditions:

- Secure Enclave custody decrypt uses the ECDH/session-key route and Rust
  payload decrypt path.
- v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD tampering fail closed with no partial
  plaintext.
- File outputs are committed only after successful authenticated decrypt.
- Cancellation and authentication failure clean up temporary artifacts.

Validation:

- Message and file decrypt tests for v4 and v6 Secure Enclave custody paths.
- Tamper tests for MDC and AEAD failure after successful session-key
  acquisition.
- Negative tests for missing handle, wrong role, public binding mismatch,
  authentication cancellation, malformed PKESK/session-key data, cancellation,
  and no fallback.
- Existing two-phase decrypt and streaming regression tests for software
  custody.

Rollback:

- Mark Secure Enclave custody decrypt and streaming decrypt unsupported in
  resolver output.
- Keep signing-class support only if product/security agree that hidden or
  test-only partial support remains useful.
- Delete partial temporary artifacts created by failed test-only runs.

## Phase 7: Product UI, Availability, And Error Surfaces

Goal: add product-facing surfaces only after hidden end-to-end behavior is ready
and still keep the feature disabled until release evidence gates pass.

Recommended PR grouping:

- Generation choice presentation using complete valid product families.
- User commitments for non-exportability, device binding, no import/conversion,
  and device-loss consequences.
- Key detail availability, export/revocation actions, unavailable operation
  states, and error presentation.

Entry conditions:

- Hidden generation and all MVP private-operation routes are implemented or
  explicitly unsupported under Product/Security review.
- Product review approves the flow, information architecture, and final copy in
  a phase-specific UI plan.
- Security review confirms the UI does not imply private-key backup, handle
  recovery, or conversion from software custody.

Exit conditions:

- UI shows complete valid choices and does not expose invalid matrices.
- Default generation remains portable compatible software custody unless
  Product Design changes that decision.
- Secure Enclave custody availability and failures are user-visible without
  leaking handle details, Keychain locators, stable fingerprints, or secret
  material.
- Private-key export is unavailable for Secure Enclave custody while public
  certificate sharing and revocation artifact export remain clear.

Validation:

- ScreenModel and presentation tests for generation choices, key detail state,
  unavailable operation state, and export action availability.
- Localization/string-catalog validation for new user-facing strings.
- UI smoke tests for route ownership and visible workflow changes where
  required by [Testing](TESTING.md).

Rollback:

- Hide the Secure Enclave custody product choices and keep underlying hidden
  test-only routes unavailable to ordinary users.
- Revert UI surfaces independently when the model/router/security layers remain
  valid.

## Phase 8: Hardware, Interop, And Release Evidence

Goal: collect release-quality evidence on real hardware and interoperability
targets before product exposure.

Recommended PR grouping:

- Hardware validation lanes or manual evidence scripts for supported Apple
  platform families.
- v4 GnuPG interop evidence for device-bound compatible claims.
- v6 RFC 9580 / AEAD evidence without GnuPG compatibility claims unless Product
  Design later adds them.
- Sanitized evidence collection and release checklist updates.

Entry conditions:

- Hidden or disabled product implementation covers the full MVP private-operation
  scope, or Product/Security have explicitly removed an operation from launch
  scope.
- Hardware and interop plans define evidence storage, sanitization, skip
  behavior, and reviewer ownership without making real Secure Enclave tests
  mandatory default CI unless Testing is updated to require it.

Exit conditions:

- Real Secure Enclave evidence covers generation, persistence, signing,
  ECDH/session-key recovery, decrypt, cancellation, biometric lockout, missing
  handle, wrong role, wrong public binding, local reset cleanup, and sanitized
  output.
- v4 compatible evidence covers GnuPG import, signature verification,
  encryption to the Secure Enclave custody public certificate, production
  boundary decrypt/verify, bidirectional sign-plus-encrypt, and packet-shape
  assertion for PKESK v3 ECDH plus SEIPDv1/MDC.
- v6 modern evidence covers RFC 9580 / AEAD behavior.
- Release docs and validation checklists clearly state what was validated and
  what is not claimed.

Validation:

- Hardware evidence per
  [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#hardware-evidence-requirements).
- Interop evidence per
  [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#interop-evidence-requirements).
- Full relevant Rust, Swift unit, device, UI, and platform build validation
  defined by [Testing](TESTING.md) and the phase release plan.

Rollback:

- Keep Secure Enclave custody hidden if any hardware, interop, sanitization, or
  release evidence gate fails.
- Remove or narrow compatibility claims that are not validated.
- Disable product exposure without deleting already validated hidden test
  infrastructure.

## Phase 9: Release Readiness And Product Exposure

Goal: expose Secure Enclave Custody only after implementation and evidence meet
the product, architecture, security, testing, documentation, and release gates.

Recommended PR grouping:

- Product exposure flag or equivalent final enablement.
- Release notes, support docs, current-state documentation updates, and code
  review checklist updates.
- Final validation run and release evidence signoff.

Entry conditions:

- All active launch-scope MVP operations pass through Secure Enclave private
  operations directly or are explicitly unavailable by approved Product/Security
  decision.
- Product Design, Architecture Plan, Security Requirements, Implementation
  Reference, Testing, Security, Architecture, and Persisted State Inventory are
  updated to reflect shipped behavior where appropriate.
- Hardware and interop evidence gates pass.
- No stop condition below is active.

Exit conditions:

- Secure Enclave custody is product-selectable only through complete valid
  product choices.
- User commitments around non-exportability, no import/conversion, device-bound
  loss risk, revocation artifact export, and public-key sharing are present.
- Release validation records the exact supported platforms, operations,
  compatibility claims, and known unsupported states.

Validation:

- Full release validation required by [Testing](TESTING.md) and
  [APP_RELEASE_PROCESS](APP_RELEASE_PROCESS.md) when preparing a stable release
  or App Store candidate.
- Security review for red lines, logging/sanitization, persistent-state
  classification, no-fallback behavior, and hard-fail decrypt behavior.
- Product review for final user-facing commitments and compatibility language.

Rollback:

- Disable product exposure and return to hidden/test-only availability if any
  release gate fails.
- Revert UI enablement before reverting validated lower-layer infrastructure.
- If persisted production state shipped, follow a specific migration/rollback
  plan instead of deleting or silently resetting state.

## Program Stop Conditions

Return to product, architecture, and security review before continuing if any
implementation phase appears to require:

- exporting Secure Enclave private-key material;
- importing an existing OpenPGP private key into Secure Enclave custody;
- storing a software private-key fallback for a Secure Enclave custody key;
- unwrapping or storing a complete secret certificate for Secure Enclave
  custody;
- treating a Keychain handle, locator, or public key as recoverable private-key
  backup;
- using one Secure Enclave private key for both signing and key agreement;
- accepting signing and ECDH handles interchangeably;
- accepting a handle whose public key does not match the stored OpenPGP public
  association;
- exposing partial plaintext after MDC or AEAD failure;
- logging or persisting plaintext, private-key material, shared secrets, session
  keys, KEKs, Keychain locators, stable fingerprints, or temporary capability
  paths;
- weakening existing Profile A/B software-custody behavior;
- product-exposing Secure Enclave custody after only basic signing/decryption
  evidence instead of the full approved private-operation scope.

## Roadmap Update Triggers

Update this roadmap when:

- Product Design changes launch scope, user commitments, compatibility language,
  or default product choices;
- Architecture Plan changes configuration/custody/capability separation,
  resolver/router ownership, metadata/handle split, or Rust/Swift dependency
  direction;
- Security Requirements change access-control policy, red lines, evidence
  gates, release gates, or MVP security scope;
- Feasibility Summary changes because new evidence supersedes a POC caveat;
- Testing changes default validation lanes, hardware evidence ownership, interop
  requirements, or release validation commands;
- a phase completes, splits, combines, or changes order through an accepted
  phase-specific implementation plan;
- shipped code changes current-state architecture, security, persisted-state, or
  release-process documentation obligations.
