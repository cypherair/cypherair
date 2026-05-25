# Apple Secure Enclave Custody POC Phase 0

> Status: Archived historical Secure Enclave Custody POC material.
> Archived: 2026-05-25.
> Archive reason: Secure Enclave Custody POC validation completed and handed off to active planning docs.
> Successor: [Feasibility Summary](../../APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md).
> Current planning: [Product Design](../../APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](../../APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md), and
> [Security Requirements](../../APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md).
> Current-state note: Current code and active docs outrank this archived file; use it only as historical evidence and context.


> Status: Validation snapshot for a proposal planning track.
> Date: 2026-05-24.
> Purpose: Provide the Phase 0 POC baseline and reference index before any
> Apple Secure Enclave Custody prototype code is written.
> Audience: Product, security reviewers, Swift/Rust implementers, test owners,
> and AI coding tools.
> Truth sources: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md), and
> [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md).
> Evidence roots: [Architecture](../../ARCHITECTURE.md), [Security](../../SECURITY.md),
> [Testing](../../TESTING.md), current Swift and Rust implementation files, Apple
> Secure Enclave documentation, RFC 9580, RFC 6637, and Sequoia 2.3
> documentation/source.
> Current-state note: This file is an evidence baseline for proposed future
> behavior. It does not describe shipped behavior, authorize production
> implementation, or change CypherAir's current security architecture.

## 1. Phase 0 Role

Phase 0 is a POC starting record, not a second product model, security model,
or production design. Later POC phases should use this file to find the current
code touchpoints, research anchors, and minimum evidence expectations.

This phase confirms only that:

- The current shipped wrapping model and proposed custody model are separate.
- POC work has a compact source index before prototype code begins.
- Later phases must record evidence before making design claims.
- No Swift, Rust, Xcode project, entitlement, generated binding, release
  metadata, or app behavior changed in Phase 0.

Phase 1 still requires a separate phase-specific plan before any probe,
harness, or production file is changed.

## 2. POC Branch Policy

Exploratory Apple Secure Enclave Custody POC work must be carried on the
dedicated branch `poc/apple-secure-enclave-custody` unless a later approved
plan explicitly names a different branch. Prototype code, disposable harnesses,
and POC evidence commits should target that branch rather than ordinary topic
branches, because the POC needs the app codebase but is not intended to enter
`main` while validation remains exploratory.

Production-bound work must be split into later dedicated production PRs only
after the [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md) validation
track produces enough evidence to support that decision.

## 3. Source Ownership

Do not duplicate or reinterpret the custody model here:

- Product semantics, recovery language, and user-visible boundaries live in
  the [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md).
- Security goals, hard requirements, validation security questions, and red
  lines live in the [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md).
- Phase ordering, evidence requirements, decision gates, and no-go conditions
  live in the [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md).
- Current shipped architecture, security, and validation expectations remain
  governed by [Architecture](../../ARCHITECTURE.md), [Security](../../SECURITY.md), and
  [Testing](../../TESTING.md).

This Phase 0 file only points to those authorities and records the POC starting
context.

## 4. Current Code Touchpoints

The shipped app currently protects complete OpenPGP secret certificate bytes
with Secure Enclave-backed wrapping. It does not yet implement direct Secure
Enclave P-256 private-key custody.

Useful starting points for POC orientation:

- [pgp-mobile/src/keys/generation.rs](../../../pgp-mobile/src/keys/generation.rs)
  currently generates full OpenPGP secret certificate material.
- [Sources/Security/SecureEnclaveManager.swift](../../../Sources/Security/SecureEnclaveManager.swift)
  owns the shipped Secure Enclave wrapping primitive.
- [Sources/Services/KeyManagement/PrivateKeyAccessService.swift](../../../Sources/Services/KeyManagement/PrivateKeyAccessService.swift)
  owns unwrapping complete secret certificate material for callers.
- [Sources/Services/SigningService.swift](../../../Sources/Services/SigningService.swift)
  and [Sources/Services/DecryptionService.swift](../../../Sources/Services/DecryptionService.swift)
  currently unwrap secret material before Rust signing/decryption calls.
- [pgp-mobile/src/sign.rs](../../../pgp-mobile/src/sign.rs) and
  [pgp-mobile/src/decrypt.rs](../../../pgp-mobile/src/decrypt.rs) currently use
  in-memory Sequoia `KeyPair` values.

These files are touchpoints for understanding the current boundary. They are
not authorization to edit security-sensitive code without a later
phase-specific plan.

## 5. POC Reference Links

Apple documentation to cite during later proof work:

- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave)
- [SecureEnclave.P256.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
- [SecureEnclave.P256.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey)
- [kSecAttrTokenIDSecureEnclave](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [SecAccessControlCreateFlags.privateKeyUsage](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage)
- [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly)

OpenPGP and Sequoia references:

- [RFC 9580: OpenPGP](https://www.rfc-editor.org/rfc/rfc9580)
- [RFC 6637: ECC in OpenPGP](https://www.rfc-editor.org/rfc/rfc6637.html)
- [Sequoia `Signer`](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/crypto/trait.Signer.html)
- [Sequoia `Decryptor`](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/crypto/trait.Decryptor.html)
- [Sequoia ECDH module](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/crypto/ecdh/index.html)

The current local dependency baseline is Sequoia OpenPGP 2.3.0 in
[pgp-mobile/Cargo.toml](../../../pgp-mobile/Cargo.toml) and
[pgp-mobile/Cargo.lock](../../../pgp-mobile/Cargo.lock). If the dependency changes,
later phase evidence must identify the exact version used.

## 6. Later POC Evidence Checklist

Later POC notes should stay phase-specific and short. At minimum, record:

- tested environment and hardware
- disposable harness scope
- positive and failure results
- security invariants checked by reference to the [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md)
  and [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md)
- residual questions
- next-phase entry condition

Do not copy the hard requirements or red lines into each POC note unless a
phase has a specific result that changes how reviewers should read them.

## 7. POC Question Index

Use the [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md) as the phase
map, especially Phase 1 through Phase 6. Use the [Security Model validation
questions](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md#7-validation-security-questions)
for the durable security questions.

Phase 0 adds only these orientation reminders:

- Start with Apple primitive behavior before OpenPGP packet construction.
- Keep Secure Enclave hardware validation separate from mockable contract
  validation.
- Treat Sequoia `Signer` / `Decryptor` as candidate seams to test, not as
  production decisions.
- Keep current Profile A and Profile B behavior outside the POC blast radius.

## 8. Exit Markers

Phase 0 is complete when:

- This evidence file exists and can be cited by later phase plans.
- The current wrapping model and proposed custody model are separated.
- The POC reference links are available.
- The later POC evidence checklist is available.
- Documentation-only checks pass.

This is POC documentation only and does not authorize production implementation.
