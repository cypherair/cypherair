# Apple Secure Enclave Custody Product Design

> Status: Active product proposal. This document describes proposed future
> behavior and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Define the product direction for Apple Secure Enclave-backed
> OpenPGP private-key custody after the Phase 0-5 feasibility work.
> Audience: Product, design, security reviewers, Swift/Rust implementers,
> reviewers, and AI coding tools.
> Related: [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [PRD](PRD.md), [Architecture](ARCHITECTURE.md), and
> [Security](SECURITY.md).

## Product Decision

Apple Secure Enclave Custody should become a planned device-bound private-key
custody capability. It is not a replacement for portable software keys and is
not an upgrade path for existing private keys. A user chooses it when they want
the long-term private operation to stay bound to the current device.

The future key-generation product model should move away from presenting
Profile A and Profile B as the primary user-facing shape. Instead, users should
see complete, valid configuration families that combine two product dimensions:

- portability: portable software custody or device-bound Secure Enclave
  custody;
- compatibility target: compatible OpenPGP or modern OpenPGP.

The initial product families are:

| Product family | Current or new behavior | Product meaning |
| --- | --- | --- |
| Portable compatible software custody | Current Profile A behavior | Exportable software private key, broad GnuPG compatibility. |
| Portable modern software custody | Current Profile B behavior | Exportable software private key, modern RFC 9580 behavior. |
| Device-bound compatible Secure Enclave custody | New SE v4 P-256 candidate | Non-exportable device-bound key, GnuPG-oriented compatibility. |
| Device-bound modern Secure Enclave custody | New SE v6 P-256 candidate | Non-exportable device-bound key, RFC 9580 / AEAD-oriented behavior. |

These names describe product families, not final UI strings or implementation
type names. The default key-generation choice should remain portable compatible
software custody so current user expectations are preserved.

## Migration From Profile A/B Language

Existing keys must keep their cryptographic behavior. Product migration changes
how the app describes key choices; it must not rewrite an existing key's
algorithm, packet format, export behavior, or interoperability semantics.

The migration mapping is:

- existing Profile A keys become portable compatible software-custody keys in
  product surfaces;
- existing Profile B keys become portable modern software-custody keys in
  product surfaces;
- new Secure Enclave keys are generated as new device-bound compatible or
  device-bound modern keys.

Profile A/B may remain visible in legacy explanations, migration notes, or
technical detail views if needed, but they should not remain the primary product
choice once the new model ships. The product should never imply that an existing
software key can be converted into Secure Enclave custody.

## Configuration Experience

Key generation should present complete product choices, not a free-form matrix
of low-level algorithm, packet format, custody, access-control, and export
settings. A resolver-backed product surface should show only choices that are
valid under the current product and security design.

Each available choice should communicate:

- compatibility target, for example GnuPG-oriented compatibility or modern
  OpenPGP;
- custody model, for example portable private-key backup or device-bound Secure
  Enclave custody;
- backup and recovery consequence;
- whether private-key export is supported.

The configuration surface should not include a platform or device-capability
warning as a normal choice attribute. CypherAir's supported modern Apple
platforms are assumed to provide the required local security capabilities for a
shipped Secure Enclave custody feature. Operational failures, missing local
state, and authentication failures are key-status or error states, not
configuration marketing copy.

## User Commitments

Before creating a Secure Enclave custody key, the product must communicate:

- the private keys are generated for this device-bound custody mode;
- the private keys cannot be exported or backed up;
- existing private keys cannot be imported into Secure Enclave custody;
- losing the device, Secure Enclave private-operation handles, or required
  biometric access can permanently remove signing and decrypt capability;
- revocation artifacts and public certificates can be exported, but they are
  not private-key backups.

This should be clear enough that the user understands the portability tradeoff
before generation, without turning normal key generation into a long security
tutorial.

## Generation And Completion

Portable software-key generation should remain familiar. Secure Enclave custody
generation should add the device-bound consequences at the moment where the user
is committing to a non-exportable key.

For Secure Enclave custody, successful generation should produce:

- an OpenPGP public certificate;
- distinct Secure Enclave private-operation handles for signing and key
  agreement;
- key metadata that lets the app present the configuration and custody model;
- a key-level revocation artifact available for later export.

The post-generation surface for Secure Enclave custody should use an
information-plus-actions pattern:

- explain that private-key backup and private-key export are unavailable;
- offer revocation artifact export;
- offer public-key sharing;
- offer key-detail navigation;
- avoid language such as "private-key backup complete."

Revocation artifact export should be strongly visible, but this proposal does
not make export a hard requirement before the user can complete key generation.

## Key Detail Product Requirements

Key detail should separate product concepts that are currently compressed into
profile labels:

- compatibility target;
- OpenPGP configuration;
- custody model;
- public certificate state;
- revocation artifact state;
- private-key export or non-exportability;
- current private-operation availability.

For Secure Enclave custody keys, unavailable private operations must be explicit
and fail closed. Examples include missing handles, authentication cancellation,
biometric lockout, public-certificate mismatch, and operations that are not yet
implemented for this custody model. The UI must not suggest that a software
private key can be used as a fallback.

Public-key sharing, public-certificate inspection, and contact-import style
operations remain public-material workflows. Their product copy should not make
private-key custody sound relevant when the operation does not need private
material.

## Compatibility Language

The compatible Secure Enclave option may be described as GnuPG-oriented only if
production validation preserves the Phase 4.5 interop result under production
boundaries.

The modern Secure Enclave option should be described as RFC 9580 / AEAD-oriented
OpenPGP. It must not claim GnuPG interoperability unless a later validated GnuPG
path supports that behavior.

Software portable compatible and software portable modern keys keep the current
Profile A/B cryptographic behavior. Any future text change should make the
product model clearer without changing that behavior.

## Product Boundaries

This document does not approve implementation, final naming, final UI layout,
or release timing. Architecture requirements live in
[Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md). Security
requirements and release gates live in
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md).

The product must not promise:

- private-key export for Secure Enclave custody;
- importing existing private keys into Secure Enclave custody;
- recovery after device or handle loss;
- passcode fallback for Secure Enclave private operations;
- software fallback for a Secure Enclave custody key.
