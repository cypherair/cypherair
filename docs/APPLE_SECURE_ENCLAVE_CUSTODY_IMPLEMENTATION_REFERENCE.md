# Apple Secure Enclave Custody Implementation Reference

> Status: Active implementation planning reference. This document describes
> proposed future work and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Provide implementation-facing guidance that is not already owned by
> the product, architecture, security, or feasibility documents.
> Audience: Swift/Rust implementers, reviewers, security reviewers, test owners,
> and AI coding tools.
> Related: [Implementation Roadmap](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_ROADMAP.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Role Of This Document

This reference is a companion for future implementation plans. It does not
replace the active source documents:

| Source | Owns |
| --- | --- |
| [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md) | Product semantics, user commitments, MVP scope, and compatibility language. |
| [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md) | Model separation, layer ownership, resolver/router architecture, and Rust/Swift boundary direction. |
| [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md) | Red lines, access policy, security gates, validation categories, and release readiness. |
| [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md) | POC evidence, caveats, and remaining feasibility gaps. |

This document adds the practical implementation view: which current code paths
future work is expected to replace or route around, how the new model pieces
fit together, and which details should be decided in the later PRs that touch
code.

## Current Baseline To Route Around

The current app is a software-secret-certificate implementation. That baseline
is valid shipped behavior, but it is not the target for Secure Enclave custody:

- Key identity state still uses `PGPKeyProfile` and `PGPKeyIdentity` without a
  separate custody dimension.
- Private workflows unwrap a complete secret certificate through
  [`KeyManagementService.unwrapPrivateKey`](../Sources/Services/KeyManagementService.swift).
- Message and certificate FFI adapters pass complete secret certificate bytes
  through fields such as `signingKey`, `signerCert`, and `secretKeys`.
- The generated UniFFI surface in
  [`Sources/PgpMobile/pgp_mobile.swift`](../Sources/PgpMobile/pgp_mobile.swift)
  mirrors that secret-certificate-centered interface.
- The current Secure Enclave manager protects software secret certificate bytes;
  it is not a store for native private-operation handles.

Future Secure Enclave custody work should treat these as the migration target:
software custody continues to use the existing unwrap route, while Secure
Enclave custody uses explicit private-operation routes and never asks a service
to unwrap a complete secret certificate.

## Consuming The Model Separation

The implementation should consume the Architecture Plan's separation of
OpenPGP configuration, private-key custody, and operation capability.

At a practical level, future PRs should introduce these concepts in a way that
existing Profile A/B keys can still be read as software-custody keys:

- a configuration concept for OpenPGP version, algorithm family, message-format
  preference, and interoperability target;
- a custody concept that distinguishes software secret-certificate custody from
  Secure Enclave custody;
- an operation-capability projection that workflow services can ask before
  offering signing, decryption, certification, mutation, or export operations.

This reference intentionally does not define final type names, Codable schema,
database keys, or migration version numbers. The first PR that changes
persisted state must define those details and update the persisted-state
inventory in the same change.

## Metadata And Handle Store Relationship

Protected key metadata and Security-layer handle storage should stay separate:

- protected metadata records the non-secret app projection needed to list keys,
  display custody state, associate the OpenPGP public certificate, and classify
  recovery or reset states;
- the Security layer owns Secure Enclave key creation, lookup, deletion, local
  reset participation, role checks, and public-key binding checks;
- Rust receives OpenPGP material and private-operation access through the
  service boundary; it should not persist Apple handle locators as OpenPGP
  private-key material.

The later handle-store PR should define exact local identifiers, lookup
contracts, and cleanup behavior. Those details should not be guessed in this
reference document.

## Resolver And Router Use

The resolver and router are the intended way to keep custody branching out of
individual workflows:

- the resolver answers whether a key or product configuration can support a
  requested operation;
- the router chooses the execution route after a workflow service asks for an
  operation;
- workflow services still own product flows, progress reporting, cancellation,
  file cleanup, and user-visible error mapping.

The software route may continue to unwrap a complete secret certificate. The
Secure Enclave route should expose only the private operations needed for the
requested OpenPGP task. If a route has not been implemented for Secure Enclave
custody, the router should return an explicit unsupported result for that
operation.

## Rust And Swift Handoff

Rust/Sequoia should keep ownership of OpenPGP semantics:

- certificate construction and parsing;
- signature packet, context, and hash semantics;
- recipient selection and PKESK handling;
- OpenPGP ECDH KDF and AES Key Wrap processing;
- session-key validation and lifetime;
- streaming decrypt, MDC/AEAD authentication, and success-only plaintext
  release.

Swift/Security should keep ownership of Apple platform private-key operations:

- Secure Enclave key generation and loading;
- authentication and access enforcement;
- role and public-key binding checks;
- the Secure Enclave signing operation;
- the Secure Enclave key-agreement operation;
- handle cleanup and local reset participation.

For signing, Rust prepares the OpenPGP signing work and Swift/Security performs
the Secure Enclave private operation through the future agreed API. The external
signer path must not hash the same message again.

For decryption, Rust parses the OpenPGP recipient material and owns the
OpenPGP KDF, AES Key Wrap unwrap, session-key checks, and payload
authentication. If the final API requires Rust to perform those OpenPGP steps,
Swift/Security may provide only the transient key-agreement output needed for
that Rust-owned work. That output must stay in memory, be cleared when no
longer needed, and never be written to metadata, logs, diagnostics, UI, or the
old POC response-file bridge.

The exact function signatures, call pattern, memory-clearing strategy,
and test doubles belong to the implementation PRs that add the Rust/UniFFI and
Swift Security code.

## Operation Inventory For Later Plans

The Product Design owns MVP scope and the Security Requirements own release
gates. The inventory below is only a planning aid for future PR plans:

| Operation family | Implementation planning note |
| --- | --- |
| New software-key generation | Preserve current behavior unless a specific product migration PR changes presentation. |
| New Secure Enclave key generation | Create OpenPGP public certificate state and Security-owned handles together, then commit non-secret metadata only after both sides validate. |
| Private-key import | Continue as software custody only. It should not create Secure Enclave custody records. |
| Private-key export | Continue for eligible software custody only. Secure Enclave custody surfaces should offer public certificate and revocation exports, not private-key export. |
| Message signing and certification-style signing | Route through the Secure Enclave signing operation when the key is Secure Enclave custody. |
| Message decrypt and streaming file decrypt | Route recipient private work through the Secure Enclave key-agreement path, then keep payload processing in Rust/Sequoia. |
| Expiry updates, revocation, and binding refresh | Treat as signing-class workflows that need the same resolver/router support before they become available for Secure Enclave custody. |
| Contact certification | Treat as a signing-class workflow owned by contact/certificate services, with private work routed centrally. |
| Availability, cancellation, and missing local state | Map resolver/router and Security-layer results into product errors; do not make workflow-local custody branches invent their own states. |

Each implementation PR should decide its exact API, persistence, test fixtures,
and UI behavior in that PR plan. This reference is not approval to implement an
operation by bypassing the active source documents.

## Follow-On Plan Inputs

Before a future PR touches code, its plan should name:

- which active source document owns the behavior being implemented;
- whether the change is model, metadata, Security handle storage, Rust/UniFFI,
  workflow routing, UI, or evidence work;
- which existing secret-certificate route remains in place for software custody;
- how Secure Enclave custody avoids that route;
- what new persisted state, if any, is introduced;
- what tests are added beyond the source documents' validation categories;
- whether the feature remains hidden, test-only, or product-visible after the
  PR lands.

If a future implementation discovers that the architecture cannot safely support
an operation, the correct outcome is to keep that operation unavailable for
Secure Enclave custody and update the planning documents before continuing.
