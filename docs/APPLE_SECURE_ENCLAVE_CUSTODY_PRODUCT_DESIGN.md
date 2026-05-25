# Apple Secure Enclave Custody Product Design

> Status: Active product proposal. This document describes proposed future
> behavior and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Define the high-level product direction for Apple Secure
> Enclave-backed OpenPGP private-key custody after the Phase 0-5 feasibility
> work.
> Audience: Product, design, security reviewers, Swift/Rust implementers,
> reviewers, and AI coding tools.
> Related: [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md), [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md),
> [Architecture](ARCHITECTURE.md), and [Security](SECURITY.md).

## Product Decision

Apple Secure Enclave Custody should move from POC feasibility into product
planning as an explicit device-bound private-key custody option. It should not
replace the current portable software-key model and should not be presented as
an upgrade path for existing private keys.

The first product direction should plan four user-visible configuration
families:

- portable compatible software custody;
- portable modern software custody;
- device-bound compatible Secure Enclave custody;
- device-bound modern Secure Enclave custody.

These are product families, not final UI copy or implementation type names.
The default key-generation experience should remain portable compatible to
preserve current behavior. Device-bound compatible Secure Enclave custody should
be the recommended device-bound option because the POC showed GnuPG
interoperability for the v4 P-256 shape. Device-bound modern Secure Enclave
custody remains a first-version product candidate for RFC 9580 / AEAD users,
but it must not claim GnuPG compatibility.

## Product Positioning

The feature should be described as private-key isolation and device binding,
not as universally stronger cryptography. Secure Enclave P-256 protects the
long-term private operation from export, but P-256 is not stronger than the
existing Ed448/X448 software-key profile.

User-facing copy must make these points clear before key generation:

- the private keys are generated on this device;
- the private keys cannot be exported or backed up;
- existing private keys cannot be imported into Secure Enclave;
- losing the device, Secure Enclave state, Keychain handles, or required
  biometric access can permanently remove signing and decrypt capability;
- revocation artifacts and public certificates can be exported, but they are
  not private-key backups.

The product should target users who value device-bound private-key isolation
over portability. It should not be framed as the right default for every user.

## Configuration Experience

Key generation should use a product configuration surface backed by capability
resolution. The UI should show only valid, supported combinations. Users should
not be asked to freely combine low-level algorithm, packet-format, custody, and
access-control choices.

The configuration surface should communicate each available option using:

- compatibility target, such as broad GnuPG compatibility or modern OpenPGP;
- custody model, such as portable private-key backup or device-bound Secure
  Enclave custody;
- backup and recovery consequence;
- availability limits, including platform and hardware requirements;
- whether private-key export is supported.

The UI may present these as cards or another guided selection pattern. The
important product requirement is that each choice represents a complete valid
configuration and that unsupported combinations are not exposed as selectable.

## User Journey

The generation journey should remain familiar for portable software keys and
become more explicit for Secure Enclave custody:

1. Choose a complete key configuration.
2. Enter identity and validity details.
3. For Secure Enclave custody, show device-bound and no-private-key-backup
   consequences before generation completes.
4. Generate the public certificate, Secure Enclave private-operation handles,
   and key-level revocation artifact.
5. Show a post-generation page with information and actions.

For Secure Enclave custody, the post-generation page should use an
information-plus-actions pattern:

- explain that the private key cannot be exported or backed up;
- offer revocation artifact export;
- offer public key sharing, including QR where supported;
- offer key detail navigation;
- avoid "backup complete" language for the private key.

The post-generation page should not require revocation export before completion
in this high-level product direction. Later usability testing may strengthen
the prompt if users misunderstand the recovery boundary.

## Key Detail And Availability

Key detail UI should separate these concepts:

- OpenPGP configuration and compatibility;
- private-key custody model;
- public certificate state;
- Secure Enclave handle availability;
- revocation artifact availability;
- private-key backup/export availability.

Secure Enclave custody should have explicit unavailable states. Examples
include hardware unavailable, biometric authentication unavailable, handle
missing, public-certificate/handle mismatch, and operation unsupported. These
states should fail closed and should not invite software fallback.

Portable software keys can continue to show private-key backup/export status.
Secure Enclave custody should instead show that private-key backup is not
available, while revocation artifact export and public key sharing remain
available when the relevant artifacts exist.

## First-Version Workflow Target

The first product target should plan feature parity for private operations
where Secure Enclave can perform the private signing or ECDH operation without
exporting private scalars:

- message signing;
- message decryption;
- sign plus encrypt;
- password-message signing;
- streaming file sign, decrypt, and encrypt-plus-sign;
- expiry modification;
- selective revocation;
- contact certification.

This target does not include private-key export, private-key backup, importing
an existing private key into Secure Enclave, or device-loss decrypt recovery.
If any workflow cannot satisfy the security requirements, it must remain
unavailable for Secure Enclave custody until redesigned.

## Compatibility Language

The compatible Secure Enclave option should be described as the GnuPG-oriented
device-bound option only after production validation confirms the Phase 4.5
interop result under production boundaries.

The modern Secure Enclave option should be described as an RFC 9580 / AEAD
device-bound option. It should not imply GnuPG compatibility unless a later
GnuPG version supports the needed v6 behavior and the app validates that path.

Existing portable software-key behavior remains unchanged by this proposal.
Future copy may retire the Profile A / Profile B labels in favor of clearer
product language, but the underlying cryptographic behavior must remain stable
unless a separate migration plan changes it.

## Non-Goals

This product design does not approve production implementation. It does not
define exact UI layouts, Swift/Rust type names, strings, migrations, or release
timelines.

The product must not promise:

- private-key export for Secure Enclave custody;
- importing existing private keys into Secure Enclave;
- recovery after device or handle loss;
- passcode fallback for Secure Enclave private-key operations;
- software fallback for a Secure Enclave custody key.
