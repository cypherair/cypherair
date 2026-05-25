# Apple Secure Enclave Custody Security Requirements

> Status: Active security proposal. This document describes proposed future
> requirements and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Define the security requirements and validation gates for turning
> Apple Secure Enclave Custody POC evidence into production planning.
> Audience: Security reviewers, Swift/Rust implementers, test owners, product
> owners, reviewers, and AI coding tools.
> Related: [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security](SECURITY.md), [Testing](TESTING.md), and
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md).

## Security Decision

Apple Secure Enclave Custody may proceed to production planning only if the
production design preserves the POC's core security properties:

- Secure Enclave owns the long-term P-256 private signing and ECDH operations;
- software never stores or unwraps a complete secret certificate for this
  custody mode;
- software fallback is impossible for Secure Enclave custody keys;
- OpenPGP payload authentication hard-fails without partial plaintext exposure;
- persisted state follows existing ProtectedData and Keychain protection rules.

This document is a requirement proposal, not implementation approval.

## Access-Control Policy

The first production design should use a biometrics-only Secure Enclave private
operation policy equivalent to `privateKeyUsage + biometryAny`, without
device-passcode fallback.

`biometryCurrentSet` is not planned as a first-version or later user-selectable
option. It binds access to the currently enrolled biometric set and can
invalidate access when Touch ID fingers are added or removed or Face ID is
re-enrolled. That creates a high permanent-loss risk for a custody mode whose
private keys cannot be exported. The product should avoid exposing that risk as
a user setting.

The current Standard/High Security rewrap model remains a software-custody
concept. Secure Enclave custody should not be rewrapped in place to change
access policy.

## Required Red Lines

Production design must return to security review if it requires any of the
following:

- exporting Secure Enclave private-key material;
- importing an existing OpenPGP private key into Secure Enclave;
- storing a software private-key fallback for a Secure Enclave custody key;
- unwrapping or storing a complete secret certificate for the Secure Enclave
  custody path;
- using a single Secure Enclave private key for both signing and ECDH;
- treating a Keychain handle or locator as a recoverable private-key backup;
- accepting partial plaintext after MDC or AEAD authentication failure;
- logging plaintext, private-key material, session keys, ECDH shared secrets,
  KEKs, Keychain locators, stable fingerprints, or temporary capability paths;
- weakening existing portable software-key behavior to make integration easier.

## Operation Requirements

The first-version product target covers the full set of private operations that
can be expressed through Secure Enclave signing or ECDH:

- cleartext and detached signing;
- text and file decryption;
- sign plus encrypt;
- password-message optional signing;
- streaming file sign, decrypt, and encrypt-plus-sign;
- expiry modification;
- key-level revocation artifact generation and export;
- selective subkey and User ID revocation;
- contact certification.

Every supported operation must use the Secure Enclave private operation
directly or fail closed. If an operation cannot preserve no-fallback behavior,
secret-output policy, and OpenPGP hard-fail semantics, it must remain
unavailable for Secure Enclave custody until redesigned.

Private-key export, private-key backup, importing existing private keys into
Secure Enclave, and device-loss decrypt recovery are explicitly unsupported.

## OpenPGP Format Requirements

The production validation matrix must cover both Secure Enclave P-256
configurations planned for first-version product scope:

- v4 P-256 / PKESK v3 ECDH / SEIPDv1/MDC for GnuPG-oriented compatibility;
- v6 P-256 / SEIPDv2/AEAD for RFC 9580-oriented behavior.

The v4 path must keep GnuPG interoperability as a release gate for import,
verify, encrypt-to-SE, decrypt/verify, and bidirectional sign-plus-encrypt
scenarios. The v6 path must not claim GnuPG interoperability unless later
GnuPG support and production validation justify that claim.

Mixed-recipient message-format behavior must continue to preserve the existing
project rule: v4 recipient output uses SEIPDv1, v6 recipient output uses
SEIPDv2, and mixed output uses SEIPDv1 unless a later canonical policy changes
that rule.

## Persistent-State Requirements

Secure Enclave custody metadata and handle state must follow the existing data
protection model:

- non-secret key metadata belongs in the protected key-metadata model or an
  equivalent ProtectedData migration;
- Secure Enclave signing and key-agreement handles belong in Keychain-protected
  private-operation-handle storage;
- no new persistent state may be introduced in plaintext app storage unless it
  is a documented exception;
- implementation must update [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md)
  and related canonical docs when new persisted state is added.

Key metadata must not store the Secure Enclave access policy. Metadata may
record non-secret configuration, custody kind, public certificate association,
availability projection, revocation artifact state, and private-key export
state. Access policy is enforced by Secure Enclave handle creation and Security
layer ownership.

Handle storage must preserve role separation and public-key binding. A signing
handle must not be accepted for ECDH, an ECDH handle must not be accepted for
signing, and a handle whose public key does not match the stored OpenPGP public
certificate must fail closed.

## Validation Requirements

Production validation should be split into mockable contract tests and hardware
evidence.

Mockable tests should cover:

- capability resolution for valid and invalid configuration/custody
  combinations;
- no software fallback and no secret-cert unwrap fallback;
- missing handle, wrong role, wrong public key, and unavailable hardware;
- key metadata migration and recovery behavior;
- workflow services requesting private-operation routes rather than unwrapped
  secret cert bytes;
- no partial plaintext after MDC/AEAD failure;
- no secret material in logs, stdout, errors, or persisted diagnostics.

Hardware evidence should cover:

- macOS, iPhone, iPadOS, and visionOS availability and failure behavior;
- Secure Enclave signing and ECDH for distinct keys;
- v4 and v6 message decrypt and signing;
- v4 GnuPG interoperability;
- authentication cancellation, lockout, unavailable biometrics, missing
  handles, and local reset cleanup.

Hardware tests should not become mandatory default CI checks. They should be
owned as release evidence or manually triggered validation lanes with sanitized
output.

## Memory And Boundary Requirements

The Phase 4 raw shared-secret JSON bridge is not production acceptable.
Production design must use a narrower boundary that avoids temporary-file
transfer of ECDH shared secrets and minimizes shared-secret lifetime in Swift
and Rust memory.

Rust/Sequoia should own OpenPGP KDF, AES Key Wrap unwrap, session-key
validation, payload decrypt, and verification. Swift/Security should own Apple
platform private operations and Keychain access. Product services should own
workflow decisions and user-visible errors.

Sensitive buffers must be zeroized where the platform allows it. Known platform
limitations must be documented explicitly and must not become justification for
persisting secrets outside protected storage.
