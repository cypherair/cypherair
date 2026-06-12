# Apple Secure Enclave Custody Product Design

> Status: Approved product design, implemented through Phase 7 (issue #501):
> the key-family generation choice, device-bound commitment and post-generation
> surfaces, key-detail/availability presentation, per-category failure copy,
> and the production exposure flip are in code. Final UI vocabulary (decided
> 2026-06-12): Portable Compatible, Portable Modern, Device-Bound Compatible,
> Device-Bound Modern. User exposure remains release-gated on Phase 8 evidence
> and the Phase 9 release gate (tag-first releases are the exposure boundary).
> Last reviewed: 2026-06-12.
> Purpose: Define the product shape, user commitments, and first-version scope
> for Apple Secure Enclave-backed OpenPGP private-key custody.
> Audience: Product, design, security reviewers, Swift/Rust implementers,
> reviewers, and AI coding tools.
> Related: [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [PRD](PRD.md), [Architecture](ARCHITECTURE.md), and [Security](SECURITY.md).

## Product Decision

Apple Secure Enclave Custody should be planned as an explicit device-bound
private-key custody capability. It does not replace portable software keys, it
does not upgrade existing private keys in place, and it must not be presented as
universally stronger cryptography. Its product value is that long-term P-256
private signing and key-agreement operations stay bound to the current device.

The key-generation product model should move away from exposing Profile A and
Profile B as the primary product choice. Users should instead see complete,
valid configuration families that combine message compatibility and private-key
custody:

| Product family | Existing mapping | Product meaning |
| --- | --- | --- |
| Portable compatible software custody | Current Profile A behavior | Exportable software private key with broad GnuPG compatibility. |
| Portable modern software custody | Current Profile B behavior | Exportable software private key with modern RFC 9580 behavior. |
| Device-bound compatible Secure Enclave custody | New SE v4 P-256 candidate | Non-exportable device-bound key with GnuPG-oriented compatibility. |
| Device-bound modern Secure Enclave custody | New SE v6 P-256 candidate | Non-exportable device-bound key with RFC 9580 / AEAD-oriented behavior. |

These family names are planning labels, not final UI strings or implementation
type names. The default key-generation choice should remain portable compatible
software custody so existing user expectations do not change.

## Profile Language Migration

Existing Profile A and Profile B keys must keep their cryptographic behavior.
The product change is about presentation and future modeling, not rewriting old
keys.

The intended migration of product language is:

- Profile A becomes portable compatible software custody in primary product
  surfaces.
- Profile B becomes portable modern software custody in primary product
  surfaces.
- New Secure Enclave keys are generated as device-bound compatible or
  device-bound modern keys.

Profile A/B wording may remain in technical details, migration notes, or
advanced explanations. It should not remain the main key-generation vocabulary
after the new model ships. The product must never imply that an existing
software private key can be converted into Secure Enclave custody.

## Configuration Experience

Key generation should present complete choices, not a free-form matrix of
algorithm, packet version, custody, access-control, and export settings. The UI
should show only valid choices; the implementation-side resolver contract is
defined by [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md#capability-resolver).

Each available choice should communicate:

- compatibility target, such as GnuPG-oriented or modern OpenPGP behavior;
- custody model, such as portable private-key backup or device-bound Secure
  Enclave custody;
- backup and recovery consequence;
- whether private-key export is supported.

Operational failures, missing local state, or authentication failures should be
shown as key status or operation errors. They should not be normal choice
attributes on the configuration surface.

## User Commitments

Before creating a Secure Enclave custody key, the product must make these
commitments understandable:

- The private keys are generated for this device-bound custody mode.
- The private keys cannot be exported or backed up.
- Existing private keys cannot be imported into Secure Enclave custody.
- Losing the device, local device-bound key state, or required
  biometric access can permanently remove signing and decrypt capability.
- Public certificates and revocation artifacts can be exported, but they are
  not private-key backups.

The biometric access policy is defined by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#access-control-requirement);
this section owns the user-facing consequence, not the access-control flags.

This should be direct product copy, not a long technical tutorial. The user must
understand the portability tradeoff before committing to a non-exportable key.

## Generation And Completion

Portable software-key generation should remain familiar. Secure Enclave custody
generation should add the device-bound consequence at the point where the user
chooses the custody model.

Successful Secure Enclave custody generation should produce:

- an OpenPGP public certificate;
- device-bound private-operation capability for signing and decryption;
- key metadata sufficient to present the product family and custody state;
- a key-level revocation artifact available for later export.

The handle split and role binding behind that capability are defined by
[Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md#secure-enclave-handle-storage)
and
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#private-operation-security).

The post-generation surface should use an information-plus-actions pattern:

- state that private-key backup and private-key export are unavailable;
- offer revocation artifact export;
- offer public-key sharing;
- offer key-detail navigation;
- avoid "private-key backup complete" language.

Revocation artifact export should be prominent, but this proposal does not make
export a hard blocker before the user can finish key generation.

## Key Detail And Availability

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
in product surfaces. Examples include authentication cancellation, unavailable
private-operation capability, and operations that are not yet implemented for
this custody model. The unavailable-operation mechanics are owned by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#required-red-lines).

Public-key sharing, public-certificate inspection, and contact-import style
operations remain public-material workflows. Their product copy should not make
private-key custody sound relevant when the operation does not need private
material.

## MVP Private-Operation Scope

The first-version product target should cover the full private-operation surface
that CypherAir users would reasonably expect from a local private key, as long
as each operation can be implemented through Secure Enclave signing or ECDH
without exporting private scalars:

- message signing;
- message decryption;
- sign plus encrypt;
- password-message optional signing;
- streaming file sign, decrypt, and encrypt-plus-sign;
- expiry modification and binding refresh;
- key-level revocation artifact generation and export;
- selective subkey and User ID revocation;
- contact certification.

This is a product scope target, not a claim that the current code already
supports those operations. If an MVP operation cannot satisfy the security
requirements, then Secure Enclave custody should remain unavailable for that
operation or for the product launch. The security gate for that decision is
defined by [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#mvp-security-gate).

The user commitments above are part of this scope: MVP coverage must not imply
private-key export, private-key backup, import into Secure Enclave, or
device-loss decrypt recovery.

## Compatibility Language

The device-bound compatible option may be described as GnuPG-oriented only if
production validation preserves the Phase 4.5 interop result under the release
evidence requirements in
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#interop-evidence-requirements).

The device-bound modern option should be described as RFC 9580 / AEAD-oriented
OpenPGP. It must not claim GnuPG interoperability unless a later validated GnuPG
path supports that behavior.

Software portable compatible and software portable modern keys keep the current
Profile A/B cryptographic behavior. Any future text change should make the
product model clearer without changing that behavior.

## Product Boundaries

This document does not approve implementation, final naming, final UI layout,
or release timing. Architecture integration rules live in
[Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md). Security
red lines and validation gates live in
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md).
