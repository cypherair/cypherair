# Apple Secure Enclave Custody Implementation Reference

> Status: Active implementation-preparation reference. This document describes
> proposed future implementation contracts and does not describe shipped
> behavior.
> Date: 2026-05-25.
> Purpose: Give future Secure Enclave Custody implementation plans a shared
> middle-contract reference for ownership, routing, state, failures, and
> validation.
> Audience: Swift/Rust implementers, security reviewers, architecture reviewers,
> product owners, test owners, reviewers, and AI coding tools.
> Related: [Implementation Docs Guidance](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_DOCS_GUIDANCE.md),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Role And Source Authorities

This reference is a planning aid for later per-PR implementation plans. It does
not approve code changes, define final APIs, define final persisted schemas,
choose Keychain item names, choose generated UniFFI shapes, choose localized UI
copy, or replace phase-specific implementation plans.

The active source documents own the requirements behind this reference:

| Source | Owns |
| --- | --- |
| [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md) | Product semantics, user commitments, MVP private-operation scope, compatibility language, and user-facing consequences. |
| [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md) | Configuration/custody/capability separation, metadata and handle ownership, resolver/router architecture, dependency direction, and Swift/Rust ownership direction. |
| [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md) | Security red lines, access-control policy, private-operation requirements, validation categories, evidence gates, and release gates. |
| [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md) | POC evidence, caveats, non-production boundaries, and remaining production-readiness gaps. |

Repository-wide current-state rules remain governed by
[Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
[Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
[Testing](TESTING.md). If this reference conflicts with those documents or with
the active source documents above, the source document owns the decision and
this reference must be updated.

## Baseline And Target Model

Current CypherAir private-key workflows use software secret certificates. The
Security layer wraps complete OpenPGP secret certificate bytes, Swift workflow
services unwrap those bytes when private operations are authorized, and Rust /
Sequoia perform OpenPGP signing, decryption, certification, revocation, and
expiry mutation from those secret certificates.

Apple Secure Enclave Custody is a proposed future custody model, not a new
OpenPGP profile case and not a mutation of existing software keys. Its target
model is:

- OpenPGP public certificates are constructed around P-256 public signing and
  key-agreement keys.
- Long-term private signing and key-agreement keys are generated as distinct
  Secure Enclave keys and are never exported to CypherAir as private scalars or
  complete secret certificates.
- Rust / Sequoia continue to own OpenPGP packet semantics, ECDH KDF / AES Key
  Wrap processing, session-key validation, signature construction context,
  payload decrypt, MDC / AEAD hard-fail behavior, and verification.
- Swift Services own user-visible workflows and orchestration across the
  resolver, router, Security handle layer, and Rust/OpenPGP layer.
- Swift Security owns Apple platform private-operation handles, Keychain /
  Secure Enclave lifecycle, access-control enforcement, role binding, public-key
  binding, cleanup, and local reset participation.

The current `se-key` / `salt` / `sealed-key` model protects portable software
secret certificate bytes. Secure Enclave Custody must use a separate
private-operation handle model, as required by
[Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md#secure-enclave-handle-storage).

## Configuration, Custody, And Capability

Implementation plans must keep three concepts separate:

| Concept | Meaning | Must not own |
| --- | --- | --- |
| OpenPGP configuration | Key version, algorithms, packet and message-format preferences, interoperability target, software export/S2K behavior where software custody supports export. | Secure Enclave handle state, biometric policy, current operation availability. |
| Private-key custody | Whether private operations use portable software secret certificates or Apple Secure Enclave private-operation handles. | OpenPGP packet semantics, product compatibility target, localized copy. |
| Operation capability | What a key can do now for generation, signing, decryption, certification, revocation, expiry changes, public export, revocation export, private export, or explicit unsupported states. | Keychain row details, Rust packet parsing, workflow side effects. |

`PGPKeyProfile` must not gain a Secure Enclave case. A future implementation may
introduce a successor configuration model or equivalent adapter, but the
implementation plan that does so must preserve old Profile A/B behavior and
must normalize existing software keys into configuration plus software custody.

Capability answers should be complete workflow-facing answers. For example, a
generation surface should receive valid product families, not a loose menu of
algorithm, custody, and access-control pieces. A signing workflow should receive
an available route, an authentication-needed status, or an unsupported status,
not enough low-level state to rebuild policy locally.

## Persistent State And Public Binding

Secure Enclave Custody needs versioned protected key metadata, or an equivalent
migration, that can represent old software keys and new Secure Enclave custody
keys. The exact field names and schema shape belong to the future metadata PR,
but the state must be able to express:

- OpenPGP configuration identity and migration provenance for old Profile A/B
  records;
- custody kind;
- public certificate association and validation digest;
- public signing-key and key-agreement-key association needed to bind metadata
  to Security-layer handles;
- operation availability projection suitable for UI and workflow services;
- revocation artifact presence;
- private-key export state, including non-exportability for Secure Enclave
  custody;
- recovery classification when metadata, public certificate state, and handle
  state disagree.

Protected metadata may hold non-secret public association and app-behavior
state. It must not store Secure Enclave access-control policy as user-owned key
metadata, and it must not store Keychain locators or handle details in a way
that Rust or product workflows treat as private-key material.

Any PR that adds or migrates persisted state must update
[Persisted State Inventory](PERSISTED_STATE_INVENTORY.md) and companion current
state documentation in the same change. Migration must fail closed: keep readable
source state until the destination validates, do not silently reset corrupt
committed protected state to empty, and do not show pre-auth empty-key-list
flashes.

## Secure Enclave Handle Store Contract

The Security layer handle store owns the Apple platform private-operation
boundary. The final type names, storage labels, and Keychain queries belong to a
future implementation plan, but the contract must cover:

- distinct signing and key-agreement handles;
- role binding for each handle;
- public-key binding for each handle against the stored OpenPGP public
  association;
- access-control creation using the security-approved policy;
- load/authenticate/use operations that fail closed on missing handles,
  cancelled authentication, role mismatch, public-key mismatch, invalid
  Keychain state, or unavailable Secure Enclave support;
- deletion, cleanup, and local reset participation;
- recovery classification when protected metadata refers to missing or invalid
  handles;
- test doubles that can exercise policy, role, binding, cancellation, and
  recovery behavior without real hardware.

The planned Secure Enclave private-operation access-control policy is
`privateKeyUsage` plus `biometryAny` with no device-passcode fallback, as owned
by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#access-control-requirement).
`biometryCurrentSet` is not a user-selectable first-version or later product
option under the active requirements.

Keychain item accessibility should be chosen in the handle-store implementation
plan and reviewed with Security. If that plan intends a concrete default, it
must name it explicitly rather than saying only "secure accessibility." It must
also explain why the choice fits the current app's protected-data and
private-key-material boundaries.

## Resolver And Router Contracts

The capability resolver is policy-facing. It answers what complete
configurations and operations are valid before a workflow starts. It may
consider product policy, OpenPGP configuration, custody kind, protected
metadata, public certificate association, recorded handle association, and
runtime availability reduced to user-displayable status.

The resolver must not perform private-key operations, call Sequoia packet
decrypt, mutate Keychain rows, write metadata, or own workflow side effects.

The private-key operation router is execution-facing. It receives a resolved
operation request from a workflow service and returns one of these route
classes:

- software secret-certificate route for existing portable keys;
- Secure Enclave signing route for signing, certification, revocation, and
  binding-signature operations;
- Secure Enclave ECDH/session-key route for recipient-key decryption;
- explicit unsupported route.

Workflow services must not grow independent custody switches. A workflow may
branch on route result, availability, cancellation, or unsupported operation,
but the custody-specific dispatch should remain centralized so signing,
decryption, encryption, key-management, and certificate services cannot drift
into inconsistent policy.

## Rust, Swift, And Payload Boundaries

Secure Enclave Custody must not be forced through APIs that require complete
secret certificate bytes. Future Rust/UniFFI work must introduce an external
private-operation boundary that delegates only the private signing or ECDH
operation to Apple platform code while Rust keeps OpenPGP semantics.

Signing responsibilities:

- Rust builds the OpenPGP signature context and packet semantics.
- Swift Security performs the Secure Enclave ECDSA private-key operation after
  handle load, authentication, role validation, and public binding checks.
- Rust validates and encodes the resulting OpenPGP signature according to the
  selected configuration.

Decrypt responsibilities:

- Rust identifies candidate recipients and owns OpenPGP ECDH KDF, AES Key Wrap
  unwrap, session-key validation, and packet semantics.
- Swift Security performs only the Secure Enclave P-256 key-agreement private
  operation after handle load, authentication, role validation, and public
  binding checks.
- Rust consumes the recovered session key through the normal payload decrypt
  pipeline and preserves the message-processing contract.

Streaming responsibilities:

- Recipient/session-key acquisition is not the same as payload authentication.
- Payload plaintext release remains gated by Sequoia streaming decrypt,
  read-to-completion / message-processed behavior, and MDC / AEAD success.
- File decrypt must keep a success-only output contract; cancellation,
  authentication failure, MDC failure, and AEAD failure must not expose partial
  plaintext.
- Progress, cancellation, temporary artifacts, and cleanup remain workflow
  responsibilities and must not bypass payload authentication.

The Phase 4 POC raw shared-secret response-file bridge is non-production. A
production plan must remove or narrow that boundary so shared secrets, session
keys, KEKs, and plaintext are not written to files, diagnostics, stdout, or
persistent logs.

## Operation Semantics

The first-version product operation scope is owned by
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#mvp-private-operation-scope),
and the full-surface release gate is owned by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#mvp-security-gate).
Implementation plans should use the following operation contracts when deciding
route ownership and tests.

| Operation area | Implementation contract |
| --- | --- |
| Key generation | Software key generation remains available through existing software custody. Secure Enclave generation creates public certificate state plus distinct signing and agreement private-operation handles. The feature remains hidden or test-only until product, architecture, security, implementation, hardware, interop, and release gates pass. |
| Existing private-key import | May create software-custody keys only. It must not import a software private key into Secure Enclave custody or present conversion as possible. |
| Public certificate import/share | Public-material workflows remain independent of private-key custody except where they display custody-related metadata for local keys. |
| Private-key export/backup | Supported only where software custody supports export. Secure Enclave private-key export and backup are unsupported and must not be represented as recoverable handle export. |
| Revocation artifact export | Public/revocation artifacts can be exported without treating them as private-key backup. Secure Enclave key-level revocation generation must use the Secure Enclave signing route when private signing is needed. |
| Message signing and sign plus encrypt | Use the Secure Enclave signing route for Secure Enclave custody. Software fallback is forbidden for Secure Enclave custody. |
| Message decryption | Use the Secure Enclave ECDH/session-key route for Secure Enclave custody and Rust payload decrypt for final authentication. Software secret-cert unwrap fallback is forbidden. |
| Password-message optional signing | Password-message decrypt remains a password/SKESK workflow. Optional signing for Secure Enclave custody must use the Secure Enclave signing route or be unavailable. |
| Streaming file workflows | Signing and ECDH use the same route classes as message workflows. Temporary artifacts must preserve success-only plaintext release and cleanup on cancellation or failure. |
| Expiry modification and binding refresh | Any private signing needed for certificate mutation must use the Secure Enclave signing route. If an operation requires complete secret certificate mutation, it is unsupported until redesigned. |
| Key-level and selective revocation | Any revocation signature for Secure Enclave custody must use the Secure Enclave signing route and must preserve role/public binding checks. |
| Contact certification | Certification signatures for Secure Enclave custody must use the Secure Enclave signing route. Contact/public-certificate inspection remains public-material workflow. |
| Unsupported operations | Unsupported must be explicit and testable. Do not route unsupported Secure Enclave custody work through software unwrap, partial secret certificate reconstruction, or hidden fallback. |

## Stable Failure Categories

Future implementation plans may choose exact Swift/Rust error types, but the
cross-layer taxonomy should remain stable enough for UI, workflow services,
tests, and security review:

| Category | Meaning |
| --- | --- |
| Unsupported configuration | The requested OpenPGP configuration plus custody combination is invalid or not product-enabled. |
| Unsupported operation | The key exists, but the operation is unavailable for this custody mode until redesigned or enabled. |
| Authentication cancelled or unavailable | The user cancels biometric authentication, the device cannot satisfy the policy, or authentication is locked out. |
| Secure Enclave unavailable | The device or platform cannot create or use the required Secure Enclave private-operation handle. |
| Missing handle | Metadata or workflow state refers to a Secure Enclave custody key, but the required handle cannot be loaded. |
| Role mismatch | A signing handle is presented for key agreement, or a key-agreement handle is presented for signing. |
| Public binding mismatch | The loaded handle public key does not match the stored OpenPGP public association. |
| Metadata/certificate mismatch | Protected metadata, public certificate bytes, and recorded public association disagree. |
| Protected metadata recovery | Protected metadata migration or committed protected state is corrupt, pending, or requires recovery. |
| Payload authentication failure | MDC or AEAD authentication fails after session-key acquisition. This must fail closed without partial plaintext. |
| Secret-output policy violation | A path would expose plaintext, private-key material, session keys, ECDH shared secrets, KEKs, Keychain locators, stable fingerprints, or temporary capability paths. The implementation must stop and return to security review. |

Errors returned to users should be product-appropriate and localized in a
future UI plan. This taxonomy is not final UI copy.

## Implementation Test Contracts

Mockable tests should prove policy and boundary behavior before hardware
evidence runs. They should cover:

- legal and illegal OpenPGP configuration plus custody combinations;
- Profile A/B metadata migration into successor configuration plus software
  custody;
- Secure Enclave custody metadata state without exposing access-control policy
  or handle internals as user-owned metadata;
- resolver output for supported, unsupported, unavailable, and recovery states;
- router dispatch to software, Secure Enclave signing, Secure Enclave
  ECDH/session-key, or explicit unsupported routes without workflow-local
  custody switches;
- no software fallback and no complete secret certificate unwrap fallback for
  Secure Enclave custody;
- missing handle, wrong role, wrong public binding, metadata/certificate
  mismatch, and metadata/handle mismatch;
- authentication cancellation and lockout as fail-closed operation failures;
- v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD tamper failures with no partial plaintext;
- no secret material in logs, errors, diagnostics, persisted state, temporary
  paths, stdout, or test failure messages.

Hardware evidence should remain outside mandatory default CI unless
[Testing](TESTING.md) later says otherwise. Before product exposure, release
evidence must cover real Secure Enclave generation and persistence of distinct
handles, signing, ECDH/session-key recovery, decrypt, cancellation, biometric
failure/lockout, missing handle, wrong role, wrong public binding, local reset
cleanup, and sanitized outputs on supported Apple platform families.

Interop evidence is required for the device-bound compatible v4 claim. The
source of truth is
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#interop-evidence-requirements):
GnuPG must import the public certificate, verify Secure Enclave-generated
signatures, encrypt to the Secure Enclave custody public certificate, and round
trip bidirectional sign-plus-encrypt through the production boundary. The v4
path must assert PKESK v3 ECDH plus SEIPDv1/MDC for GnuPG output. The v6 path
must validate RFC 9580 / AEAD behavior and must not claim GnuPG compatibility
unless a later product decision adds that claim.

## Documentation Update Triggers

Update this reference when a production PR or accepted planning change:

- changes the configuration/custody/capability model;
- adds or migrates Secure Enclave custody metadata;
- changes Security-layer handle storage, role binding, public binding,
  accessibility, access-control policy, cleanup, or local reset behavior;
- changes resolver or router responsibility;
- changes the Rust/Swift private-operation boundary;
- enables, disables, or reclassifies an MVP private operation;
- changes stable failure categories or user-visible availability projection;
- changes mockable, hardware, interop, or release evidence expectations;
- changes source authority in Product Design, Architecture Plan, Security
  Requirements, Feasibility Summary, Testing, Security, Architecture, or
  Persisted State Inventory.
