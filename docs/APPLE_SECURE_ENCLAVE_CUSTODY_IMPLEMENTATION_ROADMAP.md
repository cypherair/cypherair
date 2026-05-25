# Apple Secure Enclave Custody Implementation Roadmap

> Status: Active staged implementation roadmap. This document describes
> proposed future work and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Break Secure Enclave custody implementation into reviewable phases
> while leaving exact APIs, schemas, tests, and UI details to each phase plan.
> Audience: Implementers, reviewers, product owners, security reviewers, test
> owners, release owners, and AI coding tools.
> Related: [Implementation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Role Of This Roadmap

This roadmap is a sequencing guide. It does not approve code changes by itself,
and it does not replace per-phase implementation plans.

Each phase should open with a short plan that names the owning source documents,
the exact files or modules expected to change, the validation to run, and the
rollback behavior if the phase cannot satisfy the active Product, Architecture,
and Security documents.

The normal repository rules in `AGENTS.md`, [Testing](TESTING.md), and the
security-sensitive source docs still apply; this roadmap does not duplicate
them.

## Phase 0: Planning Baseline

Goal: establish the current planning baseline without changing runtime
behavior.

Planned PRs:

- PR 0A: add the implementation reference and this roadmap.
- PR 0B: update cross-links only if Product, Architecture, Security, or
  Feasibility docs need a pointer to the new planning documents.

Exit criteria:

- Main retains the four active source documents as authority.
- The new documents explain only the missing implementation-facing guidance and
  staged work.
- No code, generated files, Xcode project files, entitlements, or release
  metadata change.

Validation:

- Documentation diff review.
- Link and keyword checks for the two new documents.

## Phase 1: Model, Metadata, Resolver Foundation

Goal: introduce the app model needed to represent configuration, custody, and
operation capability without changing private-key execution.

Planned PRs:

- PR 1A: add successor model types or adapters that can read existing Profile
  A/B keys as software custody.
- PR 1B: design and implement protected metadata migration for non-secret
  custody and capability projection.
- PR 1C: add resolver contracts for valid configurations and operation
  availability.
- PR 1D: add the router entry point while routing all existing keys through the
  current software path.

Exit criteria:

- Existing software keys keep their current behavior.
- Secure Enclave custody can be represented as hidden or test-only state, but
  it does not perform private operations yet.
- Persisted-state documentation is updated by the PR that introduces new state.

Validation:

- Metadata migration and rollback tests.
- Resolver tests for valid, invalid, supported, and unsupported combinations.
- Existing Rust and Swift validation remains green for current Profile A/B
  behavior.

## Phase 2: Rust External Private-Operation Fakes

Goal: prove the Rust/OpenPGP side can use external private-operation providers
without real Secure Enclave code.

Planned PRs:

- PR 2A: add fake external signer tests for the OpenPGP signing paths that need
  Secure Enclave custody later.
- PR 2B: add fake external ECDH/session-key acquisition tests for decrypt and
  streaming decrypt paths.
- PR 2C: add tamper, no-plaintext, cancellation, and cleanup tests around the
  external-provider paths.

Exit criteria:

- Rust tests prove that OpenPGP semantics remain Rust-owned while private work
  is delegated to fakes.
- No production Swift Security handle store is required in this phase.
- Secret-certificate APIs remain available for software custody.

Validation:

- Rust tests for v4, v6, and mixed-recipient behavior where relevant.
- Negative tests for tamper hard-fail and no plaintext release on failure.

## Phase 3: Swift Security Handle Provider

Goal: add the Security-layer provider and local handle lifecycle needed for
Secure Enclave custody while keeping product entry points hidden.

Planned PRs:

- PR 3A: add a handle provider/store abstraction with mock support.
- PR 3B: implement Secure Enclave handle creation, loading, deletion, role
  checks, public binding checks, and local reset participation.
- PR 3C: connect the provider to the router behind a hidden or test-only gate.

Exit criteria:

- The Security layer can create and use distinct signing and key-agreement
  handles through mock tests and guarded hardware smoke tests.
- Metadata and handle mismatch states are classified for recovery or reset.
- The feature is still unavailable as a normal user choice.

Validation:

- Swift unit tests for the provider/store abstraction, mock custody, mismatch
  handling, deletion, and local reset behavior.
- Guarded device or manual smoke checks for real Secure Enclave access where
  the phase plan requires them.

## Phase 4: Hidden Secure Enclave Key Generation

Goal: generate Secure Enclave-backed P-256 OpenPGP public certificate state
behind a hidden or test-only path.

Planned PRs:

- PR 4A: add hidden generation orchestration that creates Security handles and
  OpenPGP public certificate material together.
- PR 4B: commit non-secret metadata only after public certificate association
  and handle binding checks pass.
- PR 4C: add cleanup behavior for partial generation failures.

Exit criteria:

- Hidden generation creates a locally usable Secure Enclave custody record.
- Partial failure does not leave confusing key-list state or orphaned handles
  without documented cleanup behavior.
- No existing software key is converted into Secure Enclave custody.

Validation:

- Unit tests for generation orchestration with mocks.
- Rust tests for generated public certificate material.
- Hardware smoke only where explicitly required by the phase plan.

## Phase 5: Signing-Class Workflow Integration

Goal: route signing-class workflows through the resolver, router, Rust external
private-operation path, and Swift Security provider.

Planned PRs:

- PR 5A: integrate message signing and sign-plus-encrypt.
- PR 5B: integrate file signing and password-message optional signing.
- PR 5C: integrate certification, revocation, expiry update, and binding-refresh
  workflows that Product keeps in MVP scope.

Exit criteria:

- Secure Enclave custody signing-class workflows no longer rely on secret
  certificate unwrap.
- Unsupported signing-class operations fail before attempting private work.
- Workflow services keep owning progress, cancellation, file cleanup, and
  product-facing error mapping.

Validation:

- Swift workflow tests for resolver/router use and unsupported routes.
- Rust tests for external signing paths.
- UI or smoke tests only for user-visible flows changed by the phase PR.

## Phase 6: Decrypt And Streaming Integration

Goal: route decrypt workflows through the Secure Enclave key-agreement path
while keeping OpenPGP processing and payload authentication in Rust/Sequoia.

Planned PRs:

- PR 6A: integrate message decrypt through external ECDH/session-key
  acquisition.
- PR 6B: integrate streaming file decrypt with success-only output behavior.
- PR 6C: add cleanup and cancellation coverage for temporary artifacts and
  failed authentication.

Exit criteria:

- Secure Enclave custody decrypt does not unwrap a complete secret certificate.
- Swift/Security provides only transient key-agreement output needed by the
  Rust-owned OpenPGP KDF and unwrap work.
- The old POC response-file bridge is not used.
- Payload authentication remains the final plaintext release gate.

Validation:

- Rust tamper and session-key tests.
- Swift workflow tests for cancellation, cleanup, unsupported routes, and
  missing local state.
- Hardware or interop evidence only when required by the phase plan.

## Phase 7: Product Surfaces And Availability

Goal: make Secure Enclave custody understandable in product surfaces after the
hidden implementation has enough coverage.

Planned PRs:

- PR 7A: update key-generation choices and detail surfaces for configuration,
  custody, exportability, and availability.
- PR 7B: add generation completion and revocation-export surfaces.
- PR 7C: add product-facing errors for cancellation, unavailable local state,
  unsupported platform, missing handles, and reset/recovery outcomes.

Exit criteria:

- Product copy reflects the commitments owned by Product Design.
- UI state is driven by resolver/router/Security results rather than
  workflow-local custody guesses.
- Secure Enclave custody may remain hidden if Security Requirements gates are
  not yet satisfied.

Validation:

- Swift unit tests for state mapping.
- Targeted UI smoke tests for changed flows.
- Product and security review of user-facing recovery and non-exportability
  language.

## Phase 8: Hardware, Interop, And Release Evidence

Goal: collect the evidence required before any user-selectable release.

Planned PRs or evidence drops:

- PR 8A: add or update guarded hardware evidence runners.
- PR 8B: record platform-family evidence for supported Apple platforms.
- PR 8C: record OpenPGP interoperability evidence for compatibility claims.
- PR 8D: update release-readiness docs with the accepted evidence links.

Exit criteria:

- Security Requirements evidence categories are satisfied for the release
  claim being made.
- Product compatibility language matches the evidence actually collected.
- Any unsupported platform or operation remains hidden or explicitly
  unavailable.

Validation:

- Evidence review against Security Requirements.
- Interop review against Product Design compatibility language.
- Release-owner review before product exposure.

## Phase 9: Documentation And Launch Readiness

Goal: prepare the feature to move from hidden/test-only work to a selectable
product capability, if all earlier gates are met.

Planned PRs:

- PR 9A: update active Product, Architecture, Security, Testing, and Persisted
  State docs to describe the implemented design.
- PR 9B: update user-facing docs and release notes only after product exposure
  is approved.
- PR 9C: remove temporary hidden gates only if Product, Architecture, Security,
  testing, and release owners agree that the release gate is satisfied.

Exit criteria:

- Active docs describe what shipped, what remains unsupported, and what evidence
  backs the product claims.
- No temporary test-only route remains reachable from normal product UI.
- Software custody behavior remains unchanged except for intentionally reviewed
  presentation updates.

Validation:

- Full validation set named by the launch PR plan.
- Documentation review against implemented behavior.
- Final release gate review.

## Roadmap Update Triggers

Update this roadmap when:

- a phase completes, splits, or is skipped;
- a future phase plan changes the dependency order;
- hardware, interop, or product evidence changes the launch scope;
- implementation discovers that an operation must remain unsupported;
- the active source documents change authority or scope.

The roadmap should stay useful as planning structure, not as a second copy of
the Product, Architecture, Security, or Testing documents.
