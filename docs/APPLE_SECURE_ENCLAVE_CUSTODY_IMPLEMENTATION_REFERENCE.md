# Apple Secure Enclave Custody Implementation Reference

> Status: Active implementation reference proposal. This document describes
> proposed future implementation contracts and does not describe shipped
> behavior.
> Date: 2026-05-25.
> Purpose: Translate the active Apple Secure Enclave Custody planning set into
> implementation-facing contracts without defining exact APIs, schemas, or
> storage names.
> Audience: Swift/Rust implementers, security reviewers, architecture
> reviewers, product owners, test owners, reviewers, and AI coding tools.
> Related: [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Implementation Roadmap](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_ROADMAP.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Role And Source Authorities

This document is the implementation companion for the active Secure Enclave
custody planning set. It is not a second Product Design, Architecture Plan, or
Security Requirements document.

| Source | Owns |
| --- | --- |
| [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md) | Product families, user commitments, MVP private-operation scope, compatibility language, and UI semantics. |
| [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md) | Model separation, layer boundaries, resolver/router ownership, metadata/handle split, and Rust/Swift ownership direction. |
| [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md) | Red lines, access policy, private-operation security rules, validation categories, and release gates. |
| [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md) | POC evidence, caveats, and the difference between feasibility proof and production readiness. |
| This document | Implementation-facing contracts that future PR plans consume before choosing exact code APIs, schemas, or storage names. |

When this document repeats a rule from an owning source, the repetition is only
to show how an implementation step consumes that rule. The owning document
remains authoritative.

## Implementation Decision And Baseline

Secure Enclave custody should be implemented as operation-level custody, not as
another way to unwrap complete OpenPGP secret certificate bytes.

The current shipped app remains a software-secret-certificate architecture:

- existing Profile A/B records are software custody;
- `PGPKeyIdentity` does not record Secure Enclave custody state;
- private workflows call `unwrapPrivateKey` and receive complete secret
  certificate bytes;
- Swift FFI adapters pass complete secret certificate bytes into Rust for
  signing, decryption, certification, revocation, and expiry mutation;
- the current Secure Enclave manager protects software secret certificate
  bytes, not native private-operation handles.

That baseline should continue for software custody. Secure Enclave custody work
must route around the secret-certificate path for Secure Enclave keys.

The implementation ownership split is:

- Rust/Sequoia owns OpenPGP packet construction, parsing, signature semantics,
  recipient matching, PKESK processing, OpenPGP ECDH KDF, AES Key Wrap,
  session-key handling, streaming decrypt, MDC/AEAD authentication, and
  success-only plaintext release.
- Swift workflow services own product orchestration, progress, cancellation,
  file cleanup, user-visible errors, and calls into resolver/router APIs.
- The Security layer owns Secure Enclave key generation/loading/deletion,
  Keychain-backed handle lookup, authentication enforcement, role binding,
  public-key binding, and private P-256 operations.

Future implementation PRs should preserve this split even when exact type names
or call patterns change.

## Configuration, Custody, And Capability Contracts

Implementation work should consume the Architecture Plan's three-part model:
OpenPGP configuration, private-key custody, and operation capability.

The configuration contract answers what OpenPGP behavior a key advertises or
uses. It must be able to distinguish at least the current compatible software
configuration, the current modern software configuration, and the future P-256
Secure Enclave-compatible and Secure Enclave-modern candidates. It should not
answer whether private material lives in software or Secure Enclave.

The custody contract answers how private operations are reached. At minimum it
must distinguish software secret-certificate custody from Secure Enclave P-256
operation custody. It should not define packet version, algorithm suite, S2K,
message-format preference, or compatibility claim.

The capability contract answers what product operations are available now. It
should be derived from product policy, configuration, custody, non-secret
metadata, public certificate association, handle association, local state, and
feature-gate state. It should express product operations, not low-level
cryptographic switches.

Implementation PRs may choose final type names later. They must not:

- add Secure Enclave as another `PGPKeyProfile` case;
- store custody only in display strings;
- let custody determine OpenPGP packet behavior;
- let OpenPGP configuration imply private-key exportability;
- trigger authentication or private operations while computing capabilities.

## Metadata And Migration Contracts

Secure Enclave custody requires a versioned protected metadata migration or an
equivalent versioned read/write layer. This reference does not define the final
schema. It defines the state that must be representable.

The metadata model must be able to represent:

- existing Profile A/B keys as configuration plus software custody;
- newly generated Secure Enclave custody keys as configuration plus
  Secure Enclave custody;
- non-secret public certificate association and a way to detect stale or
  mismatched public material;
- public signing-key and key-agreement-key binding information needed to check
  Security-layer handles;
- operation availability and recovery states that UI and workflow services can
  consume;
- revocation artifact presence;
- private-key exportability or non-exportability;
- missing handle, local reset, corrupted committed metadata, and
  metadata/public-material mismatch states.

Metadata must not become a second Security-layer storage policy. It must not
record the Secure Enclave access-control policy as user-owned key data, and it
must not store Apple handle locators as OpenPGP secret-key material.

Migration PRs must keep existing software-key behavior unchanged. They should
preserve readable source state until migrated output is validated, fail closed
on corrupt committed protected state, and update
[Persisted State Inventory](PERSISTED_STATE_INVENTORY.md) when new persisted
state is introduced.

Exact field names, version numbers, migration mechanics, and recovery UI copy
belong to the implementation PR that changes persisted state.

## Secure Enclave Handle Store Contracts

The Secure Enclave handle store must be separate from the current
`se-key` / `salt` / `sealed-key` software-secret wrapping bundle. The current
bundle may continue to serve software custody, but it must not become the
native Secure Enclave custody handle model.

The handle store contract must support:

- distinct signing and key-agreement private-operation handles;
- creation, lookup, deletion, local reset, and key deletion participation;
- role binding for each handle;
- public-key binding for each handle;
- association with the expected OpenPGP public certificate state;
- mismatch and missing-state classification that the resolver/router can expose
  as stable product states.

Every private operation must first validate that the loaded handle matches the
requested role and expected public key. Missing handles, wrong roles, wrong
public bindings, unavailable platform support, authentication cancellation, and
authentication lockout should surface through the stable error taxonomy in this
document.

The Phase 3 implementation plan must include a handle-creation checklist that
ties Apple Security attributes back to
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#access-control-requirement).
That checklist should cover Secure Enclave token use,
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` by default unless Security
Requirements or an explicit security review chooses a stricter compatible
accessibility class, private-key-use authorization, biometric policy,
unsupported passcode fallback, and why the selected policy is not stored as
mutable key metadata.

This document intentionally does not define concrete Keychain item naming or
lookup formats. The first PR that creates real handle rows must document those
choices and cleanup behavior.

## Resolver And Router Contracts

The resolver is a policy and projection component. It computes valid product
choices and operation availability before a workflow starts.

Resolver inputs should be conceptual app state:

- product policy and feature gate state;
- OpenPGP configuration;
- custody kind;
- non-secret migrated metadata;
- public certificate and handle association state;
- local availability state reduced to safe display categories.

Resolver outputs should be product-level decisions:

- valid key-generation choices;
- operation capabilities for a key;
- unavailable states for UI and workflow services;
- impossible configuration/custody combinations.

The resolver must not prompt for biometrics, load Secure Enclave private keys,
perform private operations, mutate Keychain rows, unwrap software secret
certificates, call OpenPGP packet processing, or own workflow side effects.

The router is the execution dispatch point after a workflow service has a
resolved operation. It must choose one of these route families:

- software secret-certificate route for software custody;
- Secure Enclave signing route for signing-class operations;
- Secure Enclave key-agreement/session-key route for recipient private work;
- explicit unsupported route.

The router must prevent software fallback for Secure Enclave custody. It must
not turn unsupported Secure Enclave operations into software routes, and it must
not let individual workflow services grow their own custody switches.

Workflow services still own user-visible orchestration: progress reporting,
cancellation, file cleanup, result mapping, and UI errors. The router only owns
custody-specific dispatch.

## Rust/Swift Handoff Contracts

Rust/Sequoia should keep OpenPGP semantics. Swift/Security should perform only
the Secure Enclave private-key operations needed by those OpenPGP workflows.

The Rust boundary must support Secure Enclave custody without forcing those
keys through APIs that require complete secret certificate bytes. The boundary
should provide conceptual support for:

- constructing OpenPGP public certificate material from Secure Enclave public
  keys;
- asking Swift/Security to perform a signing private operation after Rust has
  prepared the OpenPGP signing work;
- asking Swift/Security to perform a key-agreement private operation after Rust
  has parsed recipient material;
- mapping platform, binding, authentication, unsupported-operation, malformed
  input, and internal failures into stable sanitized errors.

The exact function signatures, callback style, returned representation,
generated UniFFI details, and test double mechanics belong to the Rust/UniFFI
implementation PRs.

For signing-class work:

- Rust owns OpenPGP signature packet semantics, signature context, hash
  selection, digest preparation, and verification behavior.
- Swift/Security owns loading the expected signing handle, validating role and
  public binding, checking platform algorithm support, and performing the
  Secure Enclave signing operation.
- The external signer path must not hash the message again.

For decryption:

- Rust owns recipient matching, OpenPGP ECDH parameters, OpenPGP KDF, AES Key
  Wrap unwrap, session-key validation, streaming payload decrypt, MDC/AEAD
  authentication, read-to-completion semantics, and success-only output commit.
- Swift/Security owns loading the expected key-agreement handle, validating role
  and public binding, and performing the Secure Enclave key-agreement
  operation.
- Swift/Security may provide only transient key-agreement output needed for
  Rust-owned OpenPGP KDF and unwrap work. That output must stay in memory, be
  cleared when no longer needed, and never be written to metadata, logs,
  diagnostics, UI, or the old POC response-file bridge.

Any alternative decrypt helper considered by a future PR must preserve
recipient binding, OpenPGP authentication, and success-only plaintext release.

## Operation Semantics Inventory

This inventory is a planning aid. Product Design owns MVP scope, and Security
Requirements owns release gates.

| Operation family | Implementation contract |
| --- | --- |
| Software key generation | Preserve current behavior unless a dedicated product/model PR changes presentation. |
| Secure Enclave key generation | Generate Secure Enclave signing/key-agreement handles and OpenPGP public certificate state together; commit non-secret metadata only after association checks pass. |
| Private-key import | Remains software custody only. It cannot create Secure Enclave custody records. |
| Public certificate export/share | Remains public-material workflow. Custody must not be presented as private-key backup. |
| Private-key export/backup | Software custody may use existing eligible export routes. Secure Enclave custody must surface non-exportability. |
| Message signing and sign-plus-encrypt | Secure Enclave custody must route private signing through the central router and external signing path. |
| Password-message optional signing | Optional signing must use the same custody routing as other signing-class workflows. |
| Message decrypt | Secure Enclave custody must route recipient private work through key-agreement/session-key acquisition; payload processing stays Rust/Sequoia-owned. |
| Streaming file operations | Preserve existing success-only output behavior; Secure Enclave custody changes private-operation acquisition, not final plaintext release policy. |
| Expiry update, revocation, binding refresh | Treat as signing-class workflows; unsupported until they use external signing without secret-certificate fallback. |
| Contact certification | Treat as a signing-class workflow owned by contact/certificate services, with private work routed centrally. |
| Mode switching | The Standard/High Security rewrap model remains software-custody behavior unless a later Security-approved design changes that model. |

Each future phase plan should turn the relevant rows into exact code changes,
tests, and UI behavior for that phase.

## Error Taxonomy

Secure Enclave custody needs stable error categories so Security, workflow
services, UI, and tests can agree on behavior without exposing sensitive
details.

Recommended implementation categories:

- unsupported platform;
- Secure Enclave unavailable;
- required biometric capability unavailable;
- authentication canceled;
- authentication failed;
- authentication locked out;
- handle missing;
- handle role mismatch;
- handle public-key mismatch;
- metadata/public certificate mismatch;
- operation unsupported for custody;
- malformed OpenPGP input;
- private operation failed;
- payload authentication failed;
- local reset or deletion completed;
- internal implementation failure.

The exact Swift/Rust enum names and localized UI copy belong to future
implementation PRs. The taxonomy should remain stable enough for resolver
output, router errors, workflow mapping, and tests to use the same concepts.

Logging and secret-output restrictions are owned by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#required-red-lines)
and [Security](SECURITY.md). Implementation PRs should reference those sources
instead of maintaining a second copy here.

## Implementation Test Contracts

Future PRs should add mockable tests before hardware-dependent evidence.
Security Requirements owns the full validation categories and release gates;
this section records implementation-specific contracts that should not be lost
when phases are split.

Swift/mockable contracts:

- existing Profile A/B metadata migrates to configuration plus software custody
  without behavior changes;
- resolver covers valid, invalid, supported, unsupported, missing, and
  unavailable states;
- router dispatch covers software custody, Secure Enclave signing,
  Secure Enclave key-agreement/session-key acquisition, and unsupported routes;
- Secure Enclave custody does not use software fallback or secret-certificate
  unwrap fallback;
- mock handle store covers missing handle, wrong role, wrong public binding,
  metadata/handle mismatch, deletion, and local reset cleanup classification;
- export surfaces reject private-key export for Secure Enclave custody while
  keeping public certificate and revocation artifact behavior separate.

Rust/mockable contracts:

- fake external signer receives the digest prepared by Rust and does not request
  another hash of the message;
- fake external signing paths cover the signing-class workflows that Product
  keeps in MVP scope;
- fake external key-agreement/session-key acquisition covers wrong recipient,
  tampered ephemeral public point, tampered wrapped session key, malformed
  packets, and v4/v6 recipient behavior;
- tampered SEIPDv1/MDC and SEIPDv2/AEAD payloads return no plaintext;
- streaming failures do not leave the final output file;
- mixed-recipient behavior remains consistent with the project's message-format
  policy.

Hardware and interop evidence should be referenced from Security Requirements
and Testing. This document should only record additional implementation gaps
that a future phase discovers.

## Documentation Update Triggers

Update this reference when later PRs change:

- configuration/custody/capability modeling;
- metadata migration or persisted-state classification;
- Secure Enclave handle storage or cleanup behavior;
- Security-owned access policy assumptions;
- resolver or router ownership;
- Rust/UniFFI private-operation boundary;
- operation support or unsupported-operation behavior;
- error taxonomy;
- hardware or interop evidence expectations;
- release gates or product availability.

If a future phase chooses an exact API, schema, storage name, or UI copy, update
the implementation PR plan and the owning source document as appropriate. Do
not turn this reference into a dumping ground for every low-level choice.
