# Apple Secure Enclave Custody Reference

> Status: Proposal planning draft. This document describes future-facing
> validation and decision work; it does not describe shipped behavior.
> Purpose: Provide the single validation reference for deciding whether Apple
> Secure Enclave-backed OpenPGP private-key custody can become a production
> CypherAir custody mode.
> Scope: Validation goals, macOS-first proof details, evidence requirements,
> production decision gates, and stop conditions.
> Audience: Product, security reviewers, Swift/Rust implementers, test owners,
> and AI coding tools.
> Related: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Testing](TESTING.md), and
> [Documentation Governance](DOCUMENTATION_GOVERNANCE.md).
> Current-state note: This reference is not a production implementation plan,
> not a statement of shipped architecture, and not authorization to change
> security-sensitive code without a phase-specific plan.

## 1. Document Boundaries

The [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md) owns user-visible
semantics, recovery language, and product boundaries. The
[Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md) owns security goals,
hard requirements, recovery risks, and red lines. This reference owns the
validation track used to gather evidence before production design begins.

This reference intentionally avoids production implementation mechanics except
where disposable macOS proof work needs concrete technical checks. Each later
implementation phase requires a separate plan that names exact files, APIs,
temporary test hooks, and validation commands before code changes begin.

This reference does not decide:

- whether production certificates should use v4 or v6 OpenPGP packet shapes
- whether production should use Sequoia `Signer` / `Decryptor`, a
  fixed-session-key path, or a different narrow boundary
- which `SecAccessControl` policy is final for each app security mode
- which non-secret lifecycle operations are supported in v1, including expiry
  changes, selective revocation, contact certification, public-certificate
  export, revocation artifact export, or UI / error semantics for unsupported
  private-key export requests
- whether any prototype code is acceptable for production without redesign

Private-key export is not in the decision set for this custody mode. Secure
Enclave Custody must never export private-key material; later phases may decide
only how unsupported private-key export requests are presented or reported.

## 2. Validation Principles

- Every phase must produce an evidence note that records tested environment,
  positive results, failure results, residual risks, open questions, and the
  entry condition for the next phase.
- Validation work must not weaken current Profile A or Profile B behavior,
  AEAD/MDC hard-fail behavior, the zero-network model, no-secret-logging rules,
  the no-software-fallback requirement, or the no-private-key-export
  requirement.
- Prototype code, disposable bridges, and proof-only packet construction may
  prove compatibility, but they must not be treated as production architecture.
- Canonical current-state docs such as [Architecture](ARCHITECTURE.md),
  [Security](SECURITY.md), and [Testing](TESTING.md) should be updated only
  after behavior ships or after validation requirements become durable.
- Hardware validation and mockable contract validation should remain separate.
  Secure Enclave availability cannot be assumed on CI runners.

## 3. Unified Validation Track

### Phase 0: Baseline And Evidence Rules

Purpose: establish a shared validation record before prototype work begins.
Evidence note: [Phase 0 POC Baseline](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE0.md).

This phase should confirm source references, current code boundaries, and the
evidence-note format. It should also restate which existing security invariants
must be treated as non-negotiable by later phases, using links rather than
copying the full requirement set.

Exit markers:

- The evidence-note format is available for later phases.
- The current shipped wrapping model and proposed custody model are clearly
  separated for reviewers.
- Later phases can refer to one shared list of validation questions without
  duplicating the product and security documents.

### Phase 1: Apple Secure Enclave Primitive Validation

Purpose: prove the Apple platform primitive behavior needed by the custody
model.

The first validation target is macOS on Secure Enclave-capable hardware because
local builds, temporary harnesses, and debugging are easier than on iOS devices.
Successful macOS validation is necessary but not sufficient for production
readiness on iOS, iPadOS, macOS, or visionOS.

Build a disposable macOS-only probe that:

- Checks `SecureEnclave.isAvailable`.
- Generates a Secure Enclave P-256 signing key.
- Generates a separate Secure Enclave P-256 key-agreement key.
- Persists and reconstructs both key handles using the same broad shape as a
  future Keychain-backed app flow.
- Signs a known digest with the signing key and verifies the signature with the
  public key.
- Performs P-256 key agreement with the key-agreement key and a software
  ephemeral public key, then derives a repeatable shared secret.
- Confirms private scalars cannot be exported through supported APIs.
- Records behavior for cancellation, lockout, missing handle, and unavailable
  Secure Enclave cases.

Exit markers:

- Secure Enclave availability and failure behavior are documented.
- Signing and ECDH primitive behavior is proven with distinct keys.
- Missing handle, unavailable hardware, authentication failure, and cancellation
  behavior fail closed.

### Phase 2: OpenPGP Public Certificate Feasibility

Purpose: determine whether valid OpenPGP P-256 public certificates can be built
around Secure Enclave public keys while private scalars remain unavailable.

Use an isolated prototype to compare v4 and v6 certificate options without
selecting the final product shape unless the evidence clearly forces a decision.
The prototype should record which certification, binding, and revocation
artifacts are required, which Secure Enclave signing operation must produce
each signature, and whether Sequoia's public-key APIs can parse, validate, and
select the resulting certificate.

The prototype should model algorithm/profile and custody as separate dimensions
and route user-visible options through a small capability resolver, even if the
resolver is only a disposable proof table.

Exit markers:

- P-256 public certificate material can be parsed and selected by the OpenPGP
  stack used by CypherAir.
- Required binding and revocation artifact questions are understood.
- Handle/public-certificate mismatch and key-role substitution risks are
  captured as later validation cases.

### Phase 3: External Signing Feasibility

Purpose: prove that Secure Enclave ECDSA output can be used as OpenPGP
signatures accepted by the app's verification stack.

Prototype a Secure Enclave-backed OpenPGP signer path that:

- Lets Sequoia or a narrow prototype compute the OpenPGP signature digest.
- Delegates P-256 ECDSA signing to the Secure Enclave signing key.
- Converts Secure Enclave ECDSA output into OpenPGP ECDSA `r` and `s` MPIs.
- Verifies the produced signature with Sequoia using only public certificate
  material.
- Exercises cleartext, detached, and message-signing shapes if the first path is
  successful.

This phase should evaluate an external-signer seam such as Sequoia's `Signer`
trait where practical, but may use a narrower disposable bridge to prove
cryptographic compatibility first.

Exit markers:

- Clear evidence shows Secure Enclave P-256 signatures verify as OpenPGP
  signatures.
- The signing boundary alternatives and their security implications are
  recorded.
- Unsupported signing-related workflows are explicitly deferred or carried into
  later phase planning.

### Phase 4: ECDH And Decrypt Feasibility

Purpose: prove that Secure Enclave P-256 ECDH can recover an OpenPGP session
key and preserve CypherAir decrypt security behavior.

Prototype a Secure Enclave-backed ECDH decrypt path that:

- Generates or imports a test message encrypted to the P-256 OpenPGP public key
  associated with the Secure Enclave key-agreement key.
- Matches PKESK recipients using public certificate material only.
- Uses Secure Enclave P-256 key agreement for the recipient private operation.
- Performs the OpenPGP ECDH KDF and AES Key Wrap unwrap in software.
- Feeds the recovered session key into the existing detailed decrypt path or an
  equivalent disposable harness.
- Proves tampered ciphertext hard-fails without exposing partial plaintext.

This phase should evaluate whether Sequoia's `Decryptor` trait, a
fixed-session-key route, or another boundary is most appropriate after the
session key is recovered.

Exit markers:

- At least one P-256 encrypted message decrypts through the proposed custody
  private operation.
- Tampered ciphertext does not expose partial plaintext.
- The decrypt boundary recommendation is evidence-backed, including any
  remaining memory-exposure and zeroization concerns.

### Phase 5: App Architecture Integration Feasibility

Purpose: validate that the custody concept can fit the app architecture without
collapsing existing boundaries.

This phase should evaluate custody metadata, capability resolution, service
routing, user-visible availability states, mockable test seams, and non-SE CI
coverage. It should also identify which current workflows must branch by
custody kind and which are unsupported until later production work.

Exit markers:

- The app can model algorithm/profile and custody as separate dimensions.
- Capability resolution can reject unsupported combinations before key creation
  or UI exposure.
- Test ownership is split between hardware validation and mockable contract
  validation.

### Phase 6: Production Readiness Decision

Purpose: decide whether the evidence supports production planning, more
validation work, or a no-go outcome.

This phase should summarize all phase evidence and produce the decision inputs
needed for a later production plan. It should not implement the feature.

Exit markers:

- v4/v6 certificate recommendation, Swift/Rust boundary recommendation,
  supported non-secret lifecycle operations and export/error semantics, and
  access-control policy recommendation are recorded as evidence-backed decisions
  or explicit open issues.
- No-go conditions are checked and documented.
- If feasible, the next step is a dedicated production-design plan.

## 4. Evidence Requirements

Before production planning, the evidence record should include:

- Tested macOS version and hardware class.
- Whether v4, v6, or both certificate shapes worked.
- Which Secure Enclave API path was used for signing and key agreement.
- Proof that the signing and key-agreement handles refer to distinct Secure
  Enclave keys.
- Signature encoding details: DER versus raw representation, and how `r`/`s`
  were obtained.
- ECDH details: public point encoding, shared secret bytes shape, KDF inputs,
  and AES Key Wrap compatibility.
- Sequoia integration notes for `Signer`, `Decryptor`, fixed-session-key
  helpers, or any limitations encountered.
- Failure-mode behavior for wrong handles, missing key handles, unavailable
  hardware, user cancellation, lockout, authentication failures, and tampered
  ciphertext.
- Capability resolver behavior for unsupported algorithm/profile/custody
  combinations.
- Regression evidence that current Profile A and Profile B behavior remains
  unaffected by experiments.

Most CI runners cannot be assumed to expose usable Secure Enclave hardware. The
production test strategy should therefore separate:

- Hardware validation: Secure Enclave tests run manually or on known capable
  hardware.
- Contract validation: mock signer/decryptor paths prove packet construction,
  failure handling, capability resolution, and service behavior without real
  Secure Enclave.
- Regression validation: existing Rust and Swift tests continue to cover
  Profile A/B, AEAD/MDC hard-fail, recipient matching, detailed signatures, and
  current Secure Enclave wrapping.

## 5. Decision Gates And No-Go Conditions

Production planning must not begin until the evidence shows that:

- Secure Enclave keys can be generated and used without importing or exporting
  private scalars.
- Separate Secure Enclave P-256 signing and key-agreement keys can be generated,
  persisted, reconstructed, and used on supported hardware.
- The OpenPGP certificate and signature formats are valid and interoperable for
  the chosen scope.
- Secure Enclave ECDSA signatures verify as OpenPGP signatures.
- Secure Enclave ECDH can recover a valid OpenPGP session key for at least one
  P-256 encrypted message.
- The decrypt path preserves AEAD/MDC hard-fail behavior and does not expose
  partial plaintext on authentication failure.
- Unsupported custody/profile combinations can be rejected before creation or UI
  exposure.
- Missing hardware, wrong handles, missing handles, auth cancellation, lockout,
  and tampering all fail closed.
- Current Profile A and Profile B behavior remains unaffected by experiments.

The effort should stop or return to earlier phases if it requires any of the
following:

- importing an existing private key into Secure Enclave
- storing a software private key fallback for a Secure Enclave custody key
- exporting, backing up, or representing Secure Enclave private-key material or a
  key handle as a recoverable private-key backup
- reusing one Secure Enclave key for both signing and ECDH
- accepting a decrypt path that can expose unauthenticated partial plaintext
- shipping behavior whose critical failure modes cannot be tested

## 6. Documentation And Validation

Documentation-only changes to this reference should use docs-level validation:

- `rg "APPLE_SECURE_ENCLAVE_CUSTODY_(POC|FEASIBILITY)" docs`
- `git diff --check`
- manual review of relative links

Later implementation phases should choose validation from [Testing](TESTING.md)
based on the changed surfaces. Rust / UniFFI-visible behavior, Swift security
services, Secure Enclave access control, device-only behavior, and UI workflow
changes each require their own phase-specific validation plan.
