# Apple Secure Enclave Profile POC Plan

> Status: Planning draft. This document defines a feasibility-validation plan,
> not production implementation steps.

## 1. POC Objective

Validate whether CypherAir can support a device-bound OpenPGP key mode where
Apple Secure Enclave P-256 private keys perform signing and ECDH operations
without exposing the long-term private scalar to Swift or Rust memory.

The first validation target is macOS on Secure Enclave-capable hardware. macOS
is preferred for early work because local builds, temporary harnesses, and
debugging are easier than on iOS devices. Successful macOS validation does not
by itself prove production readiness for iOS, iPadOS, or visionOS.

## 2. Validation Phases

### Phase 1: Apple Primitive Probe

Build a disposable macOS-only probe that:

- Checks `SecureEnclave.isAvailable`.
- Generates Secure Enclave P-256 signing and key-agreement keys.
- Persists and reconstructs key handles using the same broad shape as a future
  Keychain-backed app flow.
- Signs a known digest and verifies the signature with the public key.
- Performs P-256 key agreement with a software ephemeral public key and derives a
  repeatable shared secret.
- Confirms the private scalar cannot be exported through supported APIs.
- Records behavior for cancellation, lockout, missing handle, and unavailable
  Secure Enclave cases.

### Phase 2: OpenPGP Certificate Probe

Use an isolated prototype to determine whether valid OpenPGP P-256 public
certificates can be assembled from Secure Enclave public keys while private
scalars remain unavailable to the process.

The probe should compare v4 and v6 certificate options without selecting the
final product shape. It should record which certification and binding signatures
are required, which signer must produce each signature, and whether Sequoia's
existing public-key APIs can parse, validate, and select the resulting
certificate.

### Phase 3: Signing Round Trip

Prototype a Secure Enclave-backed OpenPGP signer path:

- Let Sequoia or a narrow prototype compute the OpenPGP signature digest.
- Delegate P-256 ECDSA signing to Secure Enclave.
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

- Generate or import a test message encrypted to a P-256 OpenPGP public key.
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

- Secure Enclave P-256 keys can be generated, persisted, reconstructed, and used
  on macOS without exposing private scalars.
- OpenPGP P-256 public certificate material can be created and parsed reliably.
- Secure Enclave ECDSA signatures verify as OpenPGP signatures.
- Secure Enclave ECDH can recover a valid OpenPGP session key for at least one
  P-256 encrypted message.
- Wrong handle, missing handle, user cancellation, unavailable hardware, and
  authentication failure all fail closed.
- Existing Profile A and Profile B tests continue to pass unchanged in the real
  workspace after any later implementation work.
- Tampered encrypted messages still satisfy CypherAir's AEAD/MDC hard-fail rule.

## 4. Evidence To Capture

The POC should produce a short evidence note before product implementation is
planned:

- Tested macOS version and hardware class.
- Whether v4, v6, or both certificate shapes worked.
- Which Secure Enclave API path was used for signing and key agreement.
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
  failure handling, and service behavior without real Secure Enclave.
- Regression validation: existing Rust and Swift tests continue to cover
  Profile A/B, AEAD/MDC hard-fail, recipient matching, detailed signatures, and
  current Secure Enclave wrapping.

## 6. Decisions After POC

Do not proceed to production design until the POC answers:

- Is this a new `PGPKeyProfile`, a custody option, or a combined type?
- Should production use v4 or v6 OpenPGP key packets for P-256?
- Are separate Secure Enclave keys required for signing and ECDH?
- Where should the Swift/Rust boundary sit for external signing and ECDH?
- Which user-visible recovery artifacts are mandatory at key creation?
- Which operations are unsupported in v1, such as expiry modification,
  selective revocation, or contact certification?
