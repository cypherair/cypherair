# Apple Secure Enclave Custody Architecture Plan

> Status: Active architecture proposal. This document describes proposed future
> architecture and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Define the high-level architecture direction for integrating Apple
> Secure Enclave-backed OpenPGP private-key custody after the Phase 0-5 POC.
> Audience: Swift/Rust implementers, security reviewers, architecture
> reviewers, product owners, test owners, and AI coding tools.
> Related: [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Architecture Decision

Production planning should separate OpenPGP algorithm/format configuration from
private-key custody. P-256 v4 and P-256 v6 are OpenPGP configuration candidates.
Apple Secure Enclave is a custody model. It must not be modeled as a profile by
itself.

This document intentionally avoids locking concrete Swift/Rust type names or
file layout. A later implementation plan should choose names and migration
steps after product and security requirements are complete.

## Model Boundaries

Future production design should have at least these conceptual dimensions:

- OpenPGP configuration: key version, algorithm family, message-format
  preferences, export/S2K behavior for software keys, and interoperability
  target.
- Custody kind: software secret certificate, Apple Secure Enclave, or future
  external custody.
- Operation capability: sign, decrypt, certify, mutate certificate state,
  export public material, export revocation artifact, or unsupported.

Existing Profile A/B metadata should remain readable. Production work may keep
the current profile vocabulary as a compatibility layer or migration source,
but the new model should be able to represent P-256 v4 and P-256 v6
configurations without pretending that custody is a profile.

## Persistent State Direction

Secure Enclave custody should extend the existing protected key-metadata model
through metadata v2 or an equivalent migration. A new ProtectedData domain is
not the preferred direction for the first production design.

Protected key metadata should contain non-secret state needed for app behavior,
such as:

- OpenPGP configuration;
- custody kind;
- public certificate association;
- durable availability or recovery projection needed by the UI;
- revocation artifact presence;
- private-key backup/export state, including "not exportable" for Secure
  Enclave custody.

Protected key metadata should not record Secure Enclave access policy. The
access policy is a security design requirement for how Secure Enclave handles
are created and used, not user-owned key metadata.

Secure Enclave signing and key-agreement handles should live in Keychain-owned
storage under a private-key-material / private-operation-handle boundary. They
must be separate from the current `se-key` / `salt` / `sealed-key` bundle used
to wrap complete software secret certificates. The handle storage must preserve
role separation and public-key binding so signing and key-agreement handles
cannot be swapped silently.

Any implementation that adds persisted state must update
[Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), [Architecture](ARCHITECTURE.md),
[Security](SECURITY.md), [Testing](TESTING.md), and other required governance
docs in the same production change. New persistent state should default to
ProtectedData or Keychain protection. Plaintext storage is allowed only for
documented boot, test, ephemeral cleanup, legacy cleanup, framework bootstrap,
or out-of-app-custody exceptions.

## Resolver And Router

Production architecture should use two small concepts with separate
responsibilities.

The capability resolver is a policy and availability component. It decides
which complete product configurations and operation capabilities are valid for
the current app build, platform, hardware state, stored metadata, and product
policy. It should be usable by UI and services before an operation starts.

The private-key operation router is an execution component. Given a resolved
operation request, it routes the private operation to either:

- the existing software secret-certificate path;
- a Secure Enclave external signer path;
- a Secure Enclave external ECDH/decryptor path;
- an explicit unsupported result.

The resolver should not perform private-key operations. The router should not
own product workflows or UI policy.

## Dependency Direction

Workflow services should continue to own workflows. They should ask the
resolver what is available and should ask the router for the private-operation
route when execution begins. Custody switches should not be scattered through
every workflow service.

The Security layer should own Apple platform primitives:

- Secure Enclave key generation and loading;
- Keychain handle storage and deletion;
- access-control enforcement;
- role and public-key binding checks;
- hardware availability checks;
- cleanup and local reset participation.

The Rust/OpenPGP layer should own OpenPGP semantics:

- certificate construction and parsing;
- packet construction;
- ECDH KDF and AES Key Wrap handling;
- session-key validation;
- payload decrypt and MDC/AEAD hard-fail behavior;
- signature and certification verification.

The Swift service layer should own user-visible workflows:

- key generation and catalog updates;
- message signing and decryption;
- encryption and sign-plus-encrypt;
- password-message optional signing;
- key detail actions;
- revocation artifact export;
- expiry modification;
- selective revocation;
- contact certification.

## Rust And UniFFI Direction

The current production FFI accepts complete secret certificate bytes for private
operations. Secure Enclave custody needs a different external
private-operation boundary. Production work should add a route that lets Rust
and Sequoia keep OpenPGP semantics while delegating only the private signing or
ECDH operation to Apple platform code.

The Phase 4 POC proved the conceptual shape using Sequoia external signer and
decryptor seams. Production design must remove the POC raw shared-secret JSON
bridge and replace it with a narrower boundary that does not expose shared
secrets through temporary files.

The production boundary must not introduce:

- software fallback for a Secure Enclave custody key;
- secret-cert unwrap fallback;
- partial plaintext acceptance;
- secret logging;
- network or keyserver behavior.

## Workflow Architecture Target

First-version product planning targets all private operations that can be
expressed through Secure Enclave signing or ECDH without exporting private
scalars:

- message signing and verification context integration;
- message and streaming-file decryption;
- sign-plus-encrypt and streaming encrypt-plus-sign;
- password-message signing;
- expiry modification;
- selective revocation;
- contact certification;
- key-level revocation artifact generation and export.

Private-key export, importing existing private keys into Secure Enclave, and
device-loss decrypt recovery remain unsupported. Public-key export and contact
import remain custody-agnostic public-certificate workflows.

## Migration Direction

Production implementation should migrate existing software-key metadata without
changing current key behavior. Existing Profile A/B keys remain software
custody unless the user creates a new Secure Enclave custody key.

There is no migration path that converts an existing software private key into
Secure Enclave custody. Apple Secure Enclave private keys must be generated in
the Secure Enclave.

Metadata migration must be fail-closed and follow ProtectedData migration
rules:

- preserve readable source state until the protected destination is validated;
- never silently reset unreadable committed state;
- make corrupt committed protected state a recovery surface;
- avoid pre-auth key-list reads or empty-key-list flashes;
- keep private-key material and handle material outside plaintext app storage.
