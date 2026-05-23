# Apple Secure Enclave Custody Feasibility Validation Roadmap

> Status: Proposal planning draft. This document defines future-facing
> feasibility validation work and does not describe current shipped behavior.
> Purpose: Organize the evidence-gathering path for deciding whether Apple
> Secure Enclave-backed OpenPGP private-key custody can become a production
> CypherAir custody mode.
> Audience: Product, security reviewers, Swift/Rust implementers, test owners,
> and AI coding tools.
> Related: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md),
> [POC Plan](APPLE_SECURE_ENCLAVE_CUSTODY_POC.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Testing](TESTING.md), and
> [Documentation Governance](DOCUMENTATION_GOVERNANCE.md).
> Current-state note: This roadmap is not a production implementation plan,
> not a statement of shipped architecture, and not authorization to change
> security-sensitive code without a phase-specific plan.

## Summary

This roadmap connects the Apple Secure Enclave Custody product, security, and
POC documents into a single feasibility-validation track. It focuses on the
questions that must be answered before production design begins: whether
Secure Enclave P-256 keys can safely perform OpenPGP long-term signing and
ECDH private-key operations, whether CypherAir can preserve its existing
security invariants, and where the app / Rust / Sequoia boundaries should sit.

The roadmap intentionally avoids implementation mechanics. Each phase requires
a separate implementation plan before code changes begin. Those later plans
should name exact files, APIs, temporary test hooks, and validation commands for
that phase.

## Purpose And Scope

The feasibility effort should determine whether Apple Secure Enclave can act as
a future private-key custody boundary for OpenPGP P-256 keys in CypherAir. The
security goal, non-goals, recovery posture, and red lines are owned by the
[Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md). The user-facing
product semantics and recovery language are owned by the
[Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md). The first macOS proof path is
owned by the [POC Plan](APPLE_SECURE_ENCLAVE_CUSTODY_POC.md).

This roadmap does not decide:

- whether production certificates should use v4 or v6 OpenPGP packet shapes
- whether production should use Sequoia `Signer` / `Decryptor`, a
  fixed-session-key path, or a different narrow boundary
- which `SecAccessControl` policy is final for each app security mode
- which lifecycle operations are supported in v1, including expiry changes,
  selective revocation, contact certification, or secret-key export
- whether any prototype code is acceptable for production without redesign

## Validation Principles

- Every phase must produce an evidence note that records tested environment,
  positive results, failure results, residual risks, open questions, and the
  entry condition for the next phase.
- Feasibility work must not weaken current Profile A or Profile B behavior,
  AEAD/MDC hard-fail behavior, the zero-network model, no-secret-logging rules,
  the no-software-fallback requirement, or the no-private-key-export
  requirement.
- Prototype code, disposable bridges, and POC-only packet construction may
  prove compatibility, but they must not be treated as production architecture.
- Canonical current-state docs such as [Architecture](ARCHITECTURE.md),
  [Security](SECURITY.md), and [Testing](TESTING.md) should be updated only
  after behavior ships or after validation requirements become durable.
- Hardware validation and mockable contract validation should remain separate.
  Secure Enclave availability cannot be assumed on CI runners.

## Phased Feasibility Roadmap

### Phase 0: Baseline And Evidence Rules

Purpose: establish a shared validation record before prototype work begins.

This phase should confirm source references, current code boundaries, and the
evidence-note format. It should also restate which existing security invariants
must be treated as non-negotiable by later phases, using links rather than
copying the full requirement set.

Exit markers:

- The evidence-note format is available for later phases.
- The current shipped wrapping model and proposed custody model are clearly
  separated for reviewers.
- Later phases can refer to one shared list of feasibility questions without
  duplicating the product and security documents.

### Phase 1: Apple Secure Enclave Primitive Validation

Purpose: prove the Apple platform primitive behavior needed by the custody
model.

This phase corresponds to the Apple primitive probe in the
[POC Plan](APPLE_SECURE_ENCLAVE_CUSTODY_POC.md). It should validate that
separate Secure Enclave P-256 signing and key-agreement keys can be generated,
persisted, reconstructed, and used on suitable macOS hardware without exposing
private scalars.

Exit markers:

- Secure Enclave availability and failure behavior are documented.
- Signing and ECDH primitive behavior is proven with distinct keys.
- Missing handle, unavailable hardware, authentication failure, and cancellation
  behavior fail closed.

### Phase 2: OpenPGP Public Certificate Feasibility

Purpose: determine whether valid OpenPGP P-256 public certificates can be built
around Secure Enclave public keys while private scalars remain unavailable.

This phase should compare feasible certificate shapes and identify which
binding, certification, and revocation artifacts are required. It should record
interoperability evidence without choosing the production v4/v6 shape unless
the evidence clearly forces a decision.

Exit markers:

- P-256 public certificate material can be parsed and selected by the OpenPGP
  stack used by CypherAir.
- Required binding and revocation artifact questions are understood.
- Handle/public-certificate mismatch and key-role substitution risks are
  captured as later validation cases.

### Phase 3: External Signing Feasibility

Purpose: prove that Secure Enclave ECDSA output can be used as OpenPGP
signatures accepted by the app's verification stack.

This phase should validate OpenPGP digest ownership, Secure Enclave signing,
ECDSA output encoding, and verification against public certificate material. It
should evaluate the external-signing seam, but should not commit production to
any one bridge before the evidence is reviewed.

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

This phase should validate PKESK matching, Secure Enclave ECDH, OpenPGP KDF /
AES Key Wrap compatibility, session-key handling, payload decrypt, detailed
verification, and tamper hard-fail behavior. It should evaluate whether a
Sequoia `Decryptor`, a fixed-session-key route, or another boundary is most
appropriate after the session key is recovered.

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

Purpose: decide whether the evidence supports production planning, more POC
work, or a no-go outcome.

This phase should summarize all phase evidence and produce the decision inputs
needed for a later production plan. It should not implement the feature.

Exit markers:

- v4/v6 certificate recommendation, Swift/Rust boundary recommendation,
  lifecycle-operation support set, and access-control policy recommendation are
  recorded as evidence-backed decisions or explicit open issues.
- No-go conditions are checked and documented.
- If feasible, the next step is a dedicated production-design plan.

## Decision Gates

Production planning must not begin until the evidence shows that:

- Secure Enclave keys can be generated and used without importing or exporting
  private scalars.
- The OpenPGP certificate and signature formats are valid and interoperable for
  the chosen scope.
- The decrypt path preserves AEAD/MDC hard-fail behavior and does not expose
  partial plaintext on authentication failure.
- Unsupported custody/profile combinations can be rejected before creation.
- Missing hardware, missing handles, auth cancellation, lockout, and tampering
  all fail closed.
- Current Profile A and Profile B behavior remains unaffected by experiments.

The effort should stop or return to earlier phases if it requires any of the
following:

- importing an existing private key into Secure Enclave
- storing a software private key fallback for a Secure Enclave custody key
- exporting Secure Enclave private-key material or representing a key handle as
  a private-key backup
- reusing one Secure Enclave key for both signing and ECDH
- accepting a decrypt path that can expose unauthenticated partial plaintext
- shipping behavior whose critical failure modes cannot be tested

## Documentation And Validation

Documentation-only changes to this roadmap should use docs-level validation:

- `git diff --check`
- manual review of relative links

Later implementation phases should choose validation from [Testing](TESTING.md)
based on the changed surfaces. Rust / UniFFI-visible behavior, Swift security
services, Secure Enclave access control, device-only behavior, and UI workflow
changes each require their own phase-specific validation plan.
