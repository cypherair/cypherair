# Apple Secure Enclave Custody Security Requirements

> Status: Active security proposal. This document describes proposed future
> requirements and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Define security constraints and validation gates for turning Apple
> Secure Enclave Custody POC evidence into production work.
> Audience: Security reviewers, Swift/Rust implementers, test owners, product
> owners, reviewers, and AI coding tools.
> Related: [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security](SECURITY.md), [Testing](TESTING.md), and
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md).

## Security Decision

Secure Enclave Custody can proceed toward production only if the design keeps
long-term P-256 private signing and key-agreement operations inside
Secure Enclave-owned private keys. Software may orchestrate OpenPGP operations,
but it must not gain a complete secret certificate or a software fallback for
this custody mode.

This document defines security requirements and release gates. Product semantics
are defined in [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
and architecture ownership is defined in
[Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md).

## Access-Control Requirement

The default Secure Enclave private-operation policy is:

- `privateKeyUsage`;
- `biometryAny`;
- no device-passcode fallback.

`biometryAny` keeps the key usable when the enrolled biometric set changes,
while still requiring biometric authentication for private-key use. This is the
planned product policy for Secure Enclave custody private operations.

`biometryCurrentSet` must not be exposed as a first-version or later
user-selectable option. It can invalidate access when Touch ID fingers are added
or removed, or when Face ID is re-enrolled. For non-exportable private keys,
that creates a high permanent-loss risk that should not be offered as a normal
setting.

The existing Standard/High Security private-key rewrap model remains a
software-custody model. Secure Enclave custody must not use in-place rewrap to
change access policy.

## Required Red Lines

Production design must return to security review if it requires any of the
following:

- exporting Secure Enclave private-key material;
- importing an existing OpenPGP private key into Secure Enclave custody;
- storing a software private-key fallback for a Secure Enclave custody key;
- unwrapping or storing a complete secret certificate for the Secure Enclave
  custody path;
- treating a Keychain handle, public key, or locator as a recoverable
  private-key backup;
- using one Secure Enclave private key for both signing and key agreement;
- accepting a signing handle for ECDH, or an ECDH handle for signing;
- accepting a handle whose public key does not match the stored OpenPGP public
  certificate association;
- accepting partial plaintext after MDC or AEAD authentication failure;
- logging plaintext, private-key material, session keys, ECDH shared secrets,
  KEKs, Keychain locators, stable fingerprints, or temporary capability paths;
- weakening current portable software-key behavior to make integration easier.

## Private-Operation Security

Signing and key agreement must use distinct Secure Enclave private keys. Each
operation must bind the requested OpenPGP key role to the expected Secure
Enclave handle role and public key.

The external signer/decryptor boundary mechanics are defined by
[Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md#sequoia-and-uniffi-boundary).
This section owns the security rule: a failure to load, authenticate, validate,
or bind the required handle must fail closed.

No private-operation boundary may write shared secrets, session keys, KEKs, or
plaintext to temporary files, diagnostics, stdout, or persistent logs.

## Payload Hard-Fail Requirement

Secure Enclave custody must preserve the existing OpenPGP authentication
contract:

- v4 SEIPDv1/MDC tampering fails closed;
- v6 SEIPDv2/AEAD tampering fails closed;
- streaming file decrypt writes only through a success-only output contract;
- cancellation and authentication errors do not expose partial plaintext;
- mixed-recipient format behavior remains consistent with the project's current
  message-format policy unless a later canonical policy changes it.

The private-operation route may recover a session key, but final plaintext
release remains gated by Sequoia payload authentication and the caller's
read-to-completion / message-processed contract.

## MVP Security Gate

Secure Enclave custody should not become product-selectable after proving only
basic signing and decryption. The release gate must cover the full first-version
private-operation surface defined by
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#mvp-private-operation-scope).

Every supported operation must use the Secure Enclave private operation directly
or fail closed. If any operation cannot preserve no-fallback behavior,
secret-output policy, and OpenPGP hard-fail semantics, it must remain
unavailable for Secure Enclave custody until redesigned.

Private-key export, private-key backup, importing existing private keys into
Secure Enclave, and device-loss decrypt recovery are explicitly unsupported.

## Persistent-State Security

Secure Enclave custody persistent state must follow the canonical state
classification in [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md) and
the security invariants in [Security](SECURITY.md). This document does not
define a separate storage policy.

The metadata and handle-storage split is owned by
[Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md#metadata-migration-and-state)
and
[Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md#secure-enclave-handle-storage).
Production implementation must classify and document every new persisted item in
the same change that introduces it, including local reset, recovery, and cleanup
behavior.

## Mockable Validation Requirements

Automated mockable tests must cover the contracts that should not require real
Secure Enclave hardware:

- legal and illegal OpenPGP configuration plus custody combinations;
- migration of existing Profile A/B metadata into successor configuration plus
  software custody;
- metadata corruption and recovery behavior;
- resolver output for supported and unsupported operations;
- operation-router dispatch without workflow-local custody switches;
- no software fallback and no secret-cert unwrap fallback;
- wrong role, wrong public key, missing handle, and metadata/handle mismatch;
- no partial plaintext after MDC/AEAD failure;
- no secret material in logs, errors, diagnostics, or persisted state.

These tests should prove the architecture contracts before hardware-specific
tests run.

## Hardware Evidence Requirements

Hardware evidence must cover real Secure Enclave private operations on the
supported Apple platform families before release. Evidence should run through
manual or release-validation lanes, not mandatory default CI.

The evidence set must include:

- generation and persistence of distinct signing and key-agreement handles;
- signing for v4 and v6 Secure Enclave custody certificates;
- ECDH/session-key recovery and decrypt for v4 SEIPDv1/MDC and v6
  SEIPDv2/AEAD;
- authentication cancellation, biometric lockout, missing handle, wrong role,
  wrong public binding, and local reset cleanup;
- sanitized output with no plaintext, private-key material, shared secrets,
  session keys, KEKs, Keychain locators, stable fingerprints, or temporary
  paths.

## Interop Evidence Requirements

Product compatibility claims are owned by
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#compatibility-language).
The v4 compatible path must keep GnuPG interoperability as a release gate. The
validated scenarios must include:

- importing the Secure Enclave custody public certificate;
- verifying Secure Enclave-generated signatures;
- encrypting from GnuPG to the Secure Enclave custody public certificate;
- decrypting and verifying GnuPG-originated messages through the production
  Secure Enclave custody boundary;
- bidirectional sign-plus-encrypt.

The v4 path must also assert that GnuPG output for the Secure Enclave-compatible
certificate uses PKESK v3 ECDH plus SEIPDv1/MDC, not an unexpected AEAD packet
shape.

The v6 modern path must validate RFC 9580 / AEAD behavior. It has no GnuPG
interop release gate unless Product Design later adds that claim.

## Release Gate

Secure Enclave custody must remain unavailable in product UI until the product,
architecture, and security documents agree on:

- configuration and custody migration behavior;
- persisted-state classification and migration;
- private-operation router and Rust/UniFFI boundary;
- mockable security tests;
- hardware evidence;
- v4 GnuPG interop evidence;
- user-facing recovery and non-exportability language.
