# Apple Secure Enclave Custody POC Plan

> Status: Proposal planning draft. This document defines feasibility validation,
> not production implementation steps.
> Purpose: Define the macOS-first proof-of-concept path for Apple Secure
> Enclave-backed OpenPGP custody.
> Audience: Swift/Rust implementers, security reviewers, test owners, and AI
> coding tools.
> Related: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md),
> [Feasibility Roadmap](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY.md), and
> [Architecture](ARCHITECTURE.md).

## 1. POC Objective

Validate whether CypherAir can support a device-bound OpenPGP custody mode where
Apple Secure Enclave P-256 private keys perform signing and ECDH operations
without exposing the long-term private scalar to Swift or Rust memory.

The first validation target is macOS on Secure Enclave-capable hardware. macOS
is preferred for early work because local builds, temporary harnesses, and
debugging are easier than on iOS devices. Successful macOS validation does not
by itself prove production readiness for iOS, iPadOS, or visionOS.

The POC must use two independent Secure Enclave keys: one P-256 signing key and
one P-256 key-agreement key.

## 2. Validation Phases

### Phase 1: Apple Primitive Probe

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

### Phase 2: OpenPGP Certificate Probe

Use an isolated prototype to determine whether valid OpenPGP P-256 public
certificates can be assembled from Secure Enclave public keys while private
scalars remain unavailable to the process.

The probe should compare v4 and v6 certificate options without selecting the
final product shape. It should record which certification and binding
signatures are required, which Secure Enclave signing operation must produce
each signature, and whether Sequoia's existing public-key APIs can parse,
validate, and select the resulting certificate.

The prototype should model algorithm/profile and custody as separate dimensions
and route user-visible options through a small capability resolver, even if the
resolver is only a disposable POC table.

### Phase 3: Signing Round Trip

Prototype a Secure Enclave-backed OpenPGP signer path:

- Let Sequoia or a narrow prototype compute the OpenPGP signature digest.
- Delegate P-256 ECDSA signing to the Secure Enclave signing key.
- Convert Secure Enclave ECDSA output into OpenPGP ECDSA `r` and `s` MPIs.
- Verify the produced signature with Sequoia using only public certificate
  material.
- Exercise cleartext, detached, and message-signing shapes if the first path is
  successful.

This phase should prefer an external-signer seam such as Sequoia's `Signer`
trait where practical, but the POC may use a narrower disposable bridge to prove
cryptographic compatibility first.

### Phase 4: Decryption Round Trip

Prototype a Secure Enclave-backed ECDH decrypt path:

- Generate or import a test message encrypted to the P-256 OpenPGP public key
  associated with the Secure Enclave key-agreement key.
- Match PKESK recipients using public certificate material only.
- Use Secure Enclave P-256 key agreement for the recipient private operation.
- Perform the OpenPGP ECDH KDF and AES Key Wrap unwrap in software.
- Feed the recovered session key into the existing detailed decrypt path or an
  equivalent disposable harness.
- Prove tampered ciphertext hard-fails without exposing partial plaintext.

The POC should evaluate whether Sequoia's `Decryptor` trait is the right
production seam, and whether `decrypt_with_fixed_session_key_detailed` is useful
only as a validation shortcut or as part of a later design.

## 3. Acceptance Criteria

The POC is considered feasible only if all of these are true:

- Separate Secure Enclave P-256 signing and key-agreement keys can be generated,
  persisted, reconstructed, and used on macOS without exposing private scalars.
- OpenPGP P-256 public certificate material can be created and parsed reliably.
- Secure Enclave ECDSA signatures verify as OpenPGP signatures.
- Secure Enclave ECDH can recover a valid OpenPGP session key for at least one
  P-256 encrypted message.
- Wrong handle, missing handle, user cancellation, unavailable hardware, and
  authentication failure all fail closed.
- The capability resolver rejects unsupported algorithm/profile/custody
  combinations and never exposes them as selectable options.
- Existing Profile A and Profile B tests continue to pass unchanged in the real
  workspace after any later implementation work.
- Tampered encrypted messages still satisfy CypherAir's AEAD/MDC hard-fail rule.

## 4. Evidence To Capture

The POC should produce a short evidence note before product implementation is
planned:

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
- Failure-mode behavior for missing key handles and authentication failures.

## 5. Non-SE CI Strategy

Most CI runners cannot be assumed to expose usable Secure Enclave hardware. The
production test strategy should therefore separate:

- Hardware validation: macOS Secure Enclave tests run manually or on known
  capable hardware.
- Contract validation: mock signer/decryptor paths prove packet construction,
  failure handling, capability resolution, and service behavior without real
  Secure Enclave.
- Regression validation: existing Rust and Swift tests continue to cover
  Profile A/B, AEAD/MDC hard-fail, recipient matching, detailed signatures, and
  current Secure Enclave wrapping.

## 6. Decisions After POC

Do not proceed to production design until the POC answers:

- Should production use v4 or v6 OpenPGP key packets for P-256?
- Where should the Swift/Rust boundary sit for external signing and ECDH?
- Which creation-time revocation and recovery indicators are mandatory at key
  creation?
- Which operations are supported in v1, such as expiry modification, selective
  revocation, or contact certification?
- Which custody combinations should the capability resolver expose on each
  Apple platform?
