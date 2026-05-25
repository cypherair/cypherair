# Apple Secure Enclave Custody Architecture Plan

> Status: Active architecture proposal. This document describes proposed future
> architecture and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Define architecture requirements for integrating Apple Secure
> Enclave-backed OpenPGP private-key custody after the Phase 0-5 POC.
> Audience: Swift/Rust implementers, security reviewers, architecture
> reviewers, product owners, test owners, and AI coding tools.
> Related: [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Architecture Goal

Production Secure Enclave Custody must fit CypherAir by separating concepts that
the current software-key model partly compresses:

- OpenPGP configuration: key version, algorithm family, packet/message-format
  preferences, interoperability target, and software export/S2K behavior.
- Private-key custody: software secret certificate or Apple Secure Enclave
  private-operation handles.
- Operation capability: what the key can do now for signing, decryption,
  certification, certificate mutation, public export, revocation export, or
  explicit unsupported states.

The implementation may choose final type names later. The architecture
requirement is that these concepts are represented separately and do not leak
across ownership boundaries.

## Current Integration Facts

The current app code is a software-secret-certificate architecture:

- `PGPKeyProfile` has only `.universal` and `.advanced`.
- `PGPKeyIdentity` and the protected `key-metadata` schema v1 do not record
  custody kind or Secure Enclave private-operation handle state.
- Private workflows call `KeyManagementService.unwrapPrivateKey`, which returns
  complete OpenPGP secret certificate bytes as `Data`.
- Swift FFI adapters pass `signingKey`, `signerCert`, or `secretKeys` bytes to
  Rust.
- Rust currently extracts Sequoia keypairs from secret certificates for signing,
  decryption, certification, revocation, and expiry mutation.

These facts are not defects in the shipped software. They define the integration
work needed for a new custody model.

## Configuration Model

The current `PGPKeyProfile` vocabulary is not sufficient as the long-term
configuration model. It describes current software-key choices, but cannot
represent P-256 v4, P-256 v6, or custody without becoming misleading.
Product-facing migration language is owned by
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#profile-language-migration);
this section defines the implementation-facing configuration requirement.

Production work must introduce a profile successor model, or an equivalent
configuration model, that can represent at least:

- OpenPGP key version, including v4 and v6;
- primary signing/certification algorithm and encryption subkey algorithm;
- message-format preferences and advertised feature flags;
- interoperability target, including GnuPG-oriented and RFC 9580-oriented
  choices;
- software private-key export and S2K behavior where software custody supports
  private-key export;
- which custody kinds are valid for the OpenPGP configuration.

`PGPKeyProfile` must not gain a Secure Enclave case. It may be used as a
migration source or read adapter for existing Profile A/B data, but it should
not remain the primary persisted model after migration.

The required conceptual mapping is:

| Source | Configuration meaning | Custody meaning |
| --- | --- | --- |
| Existing Profile A | Compatible v4 software-key configuration | Software secret-certificate custody |
| Existing Profile B | Modern v6 software-key configuration | Software secret-certificate custody |
| New SE v4 generation | Compatible P-256 v4 configuration | Apple Secure Enclave custody |
| New SE v6 generation | Modern P-256 v6 configuration | Apple Secure Enclave custody |

This migration preserves existing key behavior. It changes how the app models
and displays keys; it does not convert existing private keys into Secure
Enclave custody.

## Custody Model

Custody must be an independent model dimension. At minimum, production planning
needs these custody kinds:

- software secret-certificate custody, matching today's portable private-key
  storage and export behavior;
- Apple Secure Enclave custody, where signing and key agreement are performed
  through non-exportable device-bound P-256 private-operation handles.

The custody model should answer whether a private-operation route exists. It
should not define OpenPGP packet format, algorithm suite, message-format
preference, or compatibility target.

Unsupported routes must be explicit. Private-key export is valid for software
custody and unsupported for Secure Enclave custody. Existing private-key import
can create software-custody keys, but cannot create Secure Enclave custody keys.

## Metadata Migration And State

Secure Enclave custody requires metadata v2, or an equivalent versioned
migration, for protected key metadata. The migrated model must normalize old
Profile A/B records into configuration plus software custody, and it must
support newly generated Secure Enclave custody records.

Protected key metadata should contain only non-secret state needed for app
behavior, such as:

- configuration identity;
- custody kind;
- public certificate association and validation digest;
- public signing and agreement key association needed to bind metadata to
  handles;
- operation availability projection needed by UI and workflow services;
- revocation artifact presence;
- private-key export state, including non-exportability for Secure Enclave
  custody.

Protected key metadata must not record the Secure Enclave access-control policy.
That policy is a Security-layer handle-creation requirement, not user-owned key
metadata.

Persistent-state classification must follow the canonical rules in
[Persisted State Inventory](PERSISTED_STATE_INVENTORY.md),
[Security](SECURITY.md), and [Architecture](ARCHITECTURE.md). Production work
that adds Secure Enclave custody state must update the inventory and companion
architecture, security, and testing documents in the same implementation
change.

## Secure Enclave Handle Storage

Secure Enclave custody handle storage must be separate from the current
`se-key` / `salt` / `sealed-key` bundle. The current bundle protects complete
software secret certificate bytes. It is not a private-operation-handle model.

The production handle boundary must provide distinct storage and lifecycle for:

- signing private-operation handle;
- key-agreement private-operation handle;
- role binding for each handle;
- public-key binding for each handle;
- cleanup and local reset participation;
- recovery classification when metadata and handles disagree.

The Keychain/Secure Enclave boundary owns private-operation handles. Protected
metadata owns only the non-secret projection and public association needed for
app behavior. Rust must not persist Apple handle locators or treat them as
OpenPGP secret-key material.

## Capability Resolver

The capability resolver is a policy component. It answers which complete
product configurations and which operations are valid before a workflow starts.

Inputs may include:

- product policy;
- OpenPGP configuration;
- custody kind;
- migrated key metadata;
- recorded public-certificate and handle association;
- runtime authentication and local-state availability reduced to
  user-displayable status.

Outputs should be complete capabilities, not low-level choices. The UI should
use resolver output to show only valid key-generation choices. Workflow services
should use resolver output to decide whether an operation can be offered.

The resolver must not perform private-key operations, call Sequoia packet
decrypt, mutate Keychain rows, or own workflow-specific side effects.

## Private-Key Operation Router

The private-key operation router is an execution component. It receives a
resolved operation request from a workflow service and returns one of these
routes:

- software secret-certificate route for existing portable keys;
- Secure Enclave signer route for signing, certification, revocation, and
  binding-signature operations;
- Secure Enclave ECDH/session-key route for recipient-key decryption;
- explicit unsupported route.

The router must not own product workflows, UI wording, metadata migration, or
OpenPGP packet semantics. It centralizes custody-specific dispatch so signing,
decryption, encryption, password-message, key-management, and certificate
services do not each grow their own custody switch.

## Dependency Direction

Workflow services own user-visible workflows. They may ask the resolver for
availability and the router for a private-operation route, but they should not
know Keychain row details or Secure Enclave access-control flags.

The Security layer owns Apple platform primitives:

- Secure Enclave key creation and loading;
- Keychain handle storage and deletion;
- access-control enforcement;
- role and public-key binding checks;
- cleanup and local reset participation.

The Rust/OpenPGP layer owns OpenPGP semantics:

- certificate construction and parsing;
- packet construction;
- ECDH KDF and AES Key Wrap processing;
- session-key validation;
- streaming payload decrypt and MDC/AEAD hard-fail behavior;
- signature, revocation, and certification verification.

The service layer owns orchestration across those layers. It must not force
Secure Enclave custody through APIs that require complete secret certificate
bytes.

## Sequoia And UniFFI Boundary

Production Rust/UniFFI work must add an external private-operation boundary for
Secure Enclave custody. The boundary should let Rust and Sequoia keep OpenPGP
semantics while delegating only private signing or ECDH operations to Apple
platform code.

The signing path should use a Sequoia `crypto::Signer`-style seam. Rust builds
the OpenPGP signature context, then delegates the private ECDSA operation.

The decrypt path has two separate pieces:

- a PKESK/session-key acquisition seam, where a Sequoia `crypto::Decryptor`-
  compatible path delegates P-256 ECDH to Apple platform code and Rust performs
  the OpenPGP ECDH KDF, AES Key Wrap unwrap, and session-key validation;
- the streaming payload decrypt path, where Sequoia's parse/decrypt pipeline
  consumes the recovered session key, decrypts the payload, verifies MDC/AEAD,
  and only succeeds when the caller completes the message-processing contract.

`parse::stream::DecryptionHelper` belongs to the recipient/session-key
acquisition part of the chain. It must not be described as replacing the
streaming payload decryptor or owning payload authentication by itself.
The corresponding security invariants are defined by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#private-operation-security)
and
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#payload-hard-fail-requirement).

## MVP Architecture Target

The first-version private-operation product scope is owned by
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#mvp-private-operation-scope).
Architecture must support that scope through the resolver, router, Security
handle layer, and Rust external private-operation boundary without adding
workflow-local bypasses.

For any Product-declared MVP operation, the architecture must route private
signing work through the external signer path and recipient-key decryption
through the external ECDH/session-key acquisition path. Streaming workflows must
preserve progress, cancellation, temporary-artifact cleanup, and success-only
plaintext release.

If any operation cannot fit this boundary, the architecture should mark that
operation unsupported for Secure Enclave custody until it is redesigned. It
must not create an alternate path forbidden by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#required-red-lines).

## Migration And Failure Rules

Metadata migration must fail closed:

- preserve readable source state until the migrated destination is validated;
- never silently reset unreadable committed state to empty data;
- make corrupt committed protected state a recovery surface;
- avoid pre-auth key-list reads or empty-key-list flashes;
- keep private-key material and private-operation handles outside plaintext app
  storage.

Existing software keys remain software custody. There is no architecture path
that converts an existing software private key into Secure Enclave custody.
The persisted-state security gate is defined by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#persistent-state-security).
