# Apple Secure Enclave Custody Implementation Reference

> Status: Active implementation-preparation reference. This document describes
> proposed future work and does not describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Define middle-level implementation contracts for Apple Secure
> Enclave-backed OpenPGP private-key custody.
> Audience: Swift/Rust implementers, security reviewers, architecture
> reviewers, product owners, test owners, reviewers, and AI coding tools.
> Related: [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Role And Source Authority

This reference prepares later per-PR implementation plans. It records the
contracts those plans must preserve, without choosing final code interfaces,
persisted field names, Keychain item names, generated UniFFI shapes, localized
copy, fixture names, or hardware-runner details.

Source ownership is:

| Source | Owns |
| --- | --- |
| [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md) | Product semantics, user commitments, first-version scope, compatibility language, and user-facing consequences. |
| [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md) | Concept separation, layer ownership, metadata/handle split, resolver/router architecture, and Swift/Rust boundary direction. |
| [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md) | Red lines, access policy, private-operation rules, validation categories, evidence gates, and release gates. |
| [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md) | POC evidence, caveats, residual risks, and non-production boundaries. |
| [Architecture](ARCHITECTURE.md), [Security](SECURITY.md), [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), [Testing](TESTING.md) | Current shipped architecture, security, persisted-state, and validation rules. |

If this document appears to conflict with a source owner, the source owner wins.
Update this reference after updating the owning source document.

## Baseline And Target Model

The shipped app is a software-secret-certificate system. Private workflows
currently obtain complete OpenPGP secret certificate bytes through the
Security/Keychain wrapping boundary, pass those bytes through Swift service and
FFI adapters, and let Rust/Sequoia extract private keypairs for signing,
decryption, certification, revocation, and expiry mutation. That is valid
shipped behavior and remains the baseline for portable software custody.

Apple Secure Enclave Custody is a different future custody model. Secure
Enclave owns distinct P-256 private signing and key-agreement operations.
CypherAir software may orchestrate OpenPGP workflows, but it must not receive a
complete Secure Enclave custody secret certificate, store a software fallback,
or treat a handle, locator, or public key as a recoverable private-key backup.

The implementation contract is:

- existing Profile A and Profile B keys remain software custody;
- `PGPKeyProfile` must not gain a Secure Enclave case;
- Secure Enclave custody is generated as new device-bound P-256 material only;
- existing software private keys cannot be converted into Secure Enclave
  custody;
- any operation that cannot use the approved Secure Enclave private-operation
  boundary must be unsupported for this custody mode until redesigned.

## Configuration, Custody, And Capability

Future implementation work must keep these concepts separate:

- OpenPGP configuration: key version, P-256/v4 or P-256/v6 shape, advertised
  features, message-format preference, compatibility target, and software
  export/S2K behavior where software custody supports it.
- Private-key custody: software secret certificate or Secure Enclave
  private-operation handles.
- Operation capability: what this key can do now for generation, signing,
  decryption, streaming, export, mutation, certification, revocation, or an
  explicit unsupported/unavailable state.

Product-facing names are planning labels in
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#product-decision),
not final enum names. Implementation plans should introduce a successor
configuration model, or equivalent representation, that can express at least
the current Profile A/B mappings plus the two Secure Enclave P-256 candidates.

Capability decisions must be complete outcomes. A caller should not have to
combine scattered flags such as key version, custody kind, handle presence,
authentication status, and product policy to infer whether an operation is
available.

## Metadata, Handles, And Public Binding

Protected key metadata owns non-secret app behavior state. It must be versioned
or migrated so existing software keys normalize to configuration plus software
custody, while newly generated Secure Enclave custody keys can record the
non-secret projection needed by the app.

Protected metadata may represent:

- configuration identity;
- custody kind;
- public certificate association and validation digest;
- public signing and agreement key association needed to bind metadata to
  Security-layer handles;
- operation availability projection for UI and workflow services;
- revocation artifact presence;
- private-key export state, including non-exportability for Secure Enclave
  custody.

Protected metadata must not store Secure Enclave access-control policy, private
scalars, secret certificate bytes, raw session keys, ECDH shared secrets, KEKs,
Keychain locators, or temporary capability paths. Final field names and schema
shape belong to the implementation plan that performs the migration.

Security-layer handle storage owns Secure Enclave private-operation handles.
The handle boundary must provide separate lifecycle for:

- signing private-operation handle;
- key-agreement private-operation handle;
- role binding for each handle;
- public-key binding for each handle;
- creation, loading, deletion, local reset, and cleanup;
- recovery classification when metadata and handles disagree.

The current `se-key` / `salt` / `sealed-key` bundle protects complete software
secret certificate bytes and must not be reused as the Secure Enclave custody
handle model. Future handle-storage work must define Keychain accessibility,
access-control flags, cleanup, reset, and recovery behavior in its own plan and
security review. The private-operation policy is owned by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#access-control-requirement):
`privateKeyUsage`, `biometryAny`, and no device-passcode fallback.

Role and public binding are mandatory. A signing handle must never satisfy an
ECDH request, an ECDH handle must never satisfy a signing request, and a handle
whose public key does not match the stored OpenPGP public association must fail
closed.

## Availability, Recovery, And Reset

Secure Enclave custody introduces availability states that software custody
does not have. Later implementation plans must make these states representable
without exposing private implementation details:

- product or platform does not support this custody mode;
- operation not implemented for this custody mode;
- authentication cancelled, failed, or locked out;
- required handle missing or unusable;
- role binding or public binding mismatch;
- metadata corrupt, stale, or in recovery;
- local reset removed device-bound private-operation capability.

These are not configuration choices. The configuration surface should show only
valid generation choices; runtime failures should surface as status or
operation errors.

Persistent-state rules are inherited from
[Persisted State Inventory](PERSISTED_STATE_INVENTORY.md) and
[Security](SECURITY.md#5-protected-app-data). Any PR that adds Secure Enclave
custody state must classify every new persisted item in the same change,
including migration, cleanup, local reset, and recovery behavior. Corrupt
committed protected state is a recovery surface, not a silent reset to empty
data.

## Resolver Contract

The capability resolver is a policy component. It answers which complete key
configurations and operations are valid before a workflow starts.

Allowed inputs include product policy, OpenPGP configuration, custody kind,
migrated metadata, recorded public certificate and handle association, and
runtime availability reduced to user-displayable status.

The resolver may return complete capabilities such as:

- valid generation families for the current platform and product policy;
- supported software-custody operations;
- supported Secure Enclave signer operations;
- supported Secure Enclave ECDH/session-key operations;
- explicitly unsupported operations;
- unavailable operations with stable reason categories.

The resolver must not perform private-key operations, call Sequoia packet
decrypt, mutate Keychain rows, open protected domains, own UI wording, or hide
workflow-specific side effects. Workflow services and UI models consume resolver
output; they do not rebuild resolver policy locally.

## Private-Operation Router Contract

The private-key operation router is an execution component. It receives a
resolved operation request from a workflow service and dispatches to one of the
approved routes:

- software secret-certificate route for existing portable keys;
- Secure Enclave signer route for signing, certification, binding refresh,
  expiry modification, and revocation signatures;
- Secure Enclave ECDH/session-key route for recipient-key decryption;
- explicit unsupported route.

The router centralizes custody-specific dispatch. Signing, decryption,
encryption, password-message, certificate-signature, key-management, and
streaming services should not grow independent custody switches.

The router must not own product workflows, UI copy, metadata migration, OpenPGP
packet semantics, Keychain row details, or Secure Enclave access-control flag
construction. It may request Security-layer private operations and Rust-layer
OpenPGP operations through the implementation interfaces chosen by later PRs.

## Rust, Swift, And Security Handoff

The layer split is:

- Security owns Apple platform primitives: Secure Enclave key creation/loading,
  Keychain handle storage/deletion, access control, role/public binding checks,
  cleanup, and local reset participation.
- Rust/Sequoia owns OpenPGP semantics: certificate construction/parsing, packet
  construction, ECDH KDF, AES Key Wrap unwrap, session-key validation, payload
  decrypt, MDC/AEAD verification, and signature/certification/revocation
  verification.
- Swift services own user-visible workflows, orchestration, progress,
  cancellation, temporary-artifact cleanup, and error presentation.

The signing path should use a Sequoia `crypto::Signer`-style external operation
boundary. Rust builds the OpenPGP signature context and delegates only the
private ECDSA operation to Apple platform code.

The decrypt path has two distinct responsibilities:

- recipient/session-key acquisition delegates P-256 ECDH to the Security layer,
  then Rust performs the OpenPGP ECDH KDF, AES Key Wrap unwrap, and session-key
  validation;
- streaming payload decrypt remains in Sequoia's parse/decrypt pipeline, which
  consumes the recovered session key, decrypts payload bytes, verifies MDC/AEAD,
  and only succeeds when the caller satisfies the read-to-completion /
  message-processed contract.

`parse::stream::DecryptionHelper` belongs to session-key acquisition. It must
not be treated as a replacement for the streaming payload decryptor or as the
owner of payload authentication.

No production boundary may write shared secrets, session keys, KEKs, plaintext,
Keychain locators, stable fingerprints, or temporary capability paths to
temporary files, diagnostics, stdout, persistent logs, or user-visible errors.
The Phase 4 POC response-file bridge is historical evidence only and is not a
production boundary.

## Business Operation Semantics

Generation:
Secure Enclave custody generation must be explicit, opt-in, and hidden or
test-only until product, architecture, security, implementation, hardware,
interop, and release gates allow exposure. Successful generation should create
an OpenPGP public certificate, distinct signing and key-agreement
private-operation capability, metadata sufficient for product family and
custody state, and a revocation artifact. Software-custody generation remains
the default product path unless Product Design changes that decision.

Import and export:
Existing private-key import creates software-custody keys only. Secure Enclave
custody cannot import existing OpenPGP private keys and cannot export private
key material or private-operation handles. Public certificates, revocation
artifacts, and public inspection workflows remain public-material operations.

Signing and sign-plus-encrypt:
All Secure Enclave custody signing must route through the signer boundary and
the signing handle. Sign-plus-encrypt uses the signing route for the private
signing operation and ordinary public-recipient encryption semantics for
recipients.

Decryption:
Recipient-key decryption for Secure Enclave custody must route through the
ECDH/session-key path. Payload plaintext release remains gated by Sequoia
MDC/AEAD authentication and the caller's success-only output contract.
Authentication cancellation, handle failures, malformed metadata, or payload
tampering must not expose partial plaintext.

Streaming workflows:
Streaming sign, decrypt, and encrypt-plus-sign must preserve existing progress,
cancellation, temporary-artifact cleanup, and success-only plaintext release.
The streaming implementation may acquire private-operation capability through
the router, but it must not bypass the payload authentication contract or write
unauthenticated plaintext as a successful output.

Password-message optional signing:
Password/SKESK encryption and decryption remain separate from recipient-key
decrypt. Optional signing for password-message workflows may use Secure Enclave
custody only through the signer route. Password-based decrypt does not become a
Secure Enclave recipient-key operation.

Expiry, binding refresh, revocation, and certification:
Any operation that creates OpenPGP signatures on behalf of the key must use the
Secure Enclave signer route for Secure Enclave custody. This includes expiry
modification, binding refresh, key-level revocation artifacts, selective subkey
or User ID revocation, and contact certification. If a specific mutation cannot
be built without complete secret certificate bytes, that operation is
unsupported for Secure Enclave custody until redesigned.

Unsupported operations:
Private-key backup, private-key export, importing existing keys into Secure
Enclave custody, device-loss decrypt recovery, software fallback, and access
policy rewrap are unsupported for Secure Enclave custody. They must fail
explicitly and must not silently choose a software route.

## Stable Error Categories

Later code may choose final type names, but UI, workflow services, tests, and
security review should share stable categories:

| Category | Meaning |
| --- | --- |
| Unsupported configuration | The requested OpenPGP configuration plus custody combination is invalid by product, platform, or security policy. |
| Unsupported operation | The operation is valid for some keys but unavailable for this custody mode until redesigned or released. |
| Capability unavailable | The operation would be supported, but runtime state prevents it, such as unavailable hardware or missing local capability. |
| Authentication unavailable | Biometric cancellation, failure, lockout, or unavailable biometric state prevented private-key use. |
| Handle missing or unusable | Required Security-layer handle cannot be loaded or used. |
| Role binding mismatch | A signing handle was offered for ECDH, an ECDH handle was offered for signing, or the role cannot be proven. |
| Public binding mismatch | The handle public key does not match the stored OpenPGP public association. |
| Metadata recovery required | Protected metadata is missing, corrupt, stale, or inconsistent with committed state. |
| OpenPGP authentication failure | MDC or AEAD authentication failed and plaintext release must fail closed. |
| No-fallback violation prevented | A path attempted to unwrap, store, or substitute software private material for Secure Enclave custody and was rejected. |

Errors may include user-actionable recovery hints, but they must not include
plaintext, private-key material, session keys, ECDH shared secrets, KEKs,
Keychain locators, stable fingerprints, or temporary capability paths.

## Implementation Test Contracts

Mockable tests should prove architecture contracts before hardware evidence:

- legal and illegal configuration plus custody combinations;
- migration of Profile A/B metadata into successor configuration plus software
  custody;
- metadata corruption, stale association, and recovery behavior;
- resolver output for supported, unsupported, and unavailable operations;
- router dispatch without workflow-local custody switches;
- no software fallback and no secret-cert unwrap fallback for Secure Enclave
  custody;
- wrong role, wrong public key, missing handle, and metadata/handle mismatch;
- cancellation and authentication errors without partial plaintext release;
- v4 MDC and v6 AEAD tamper hard-fail behavior;
- no secret material in logs, errors, diagnostics, persisted state, or temp
  artifacts.

Hardware evidence must prove real Secure Enclave private operations on the
supported Apple platform families before product release, as required by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#hardware-evidence-requirements).
Those tests belong in manual or release-validation lanes, not mandatory default
CI, unless Testing later changes that policy.

Interop evidence must prove the v4 GnuPG-compatible claim and the v6 RFC 9580 /
AEAD claim according to
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#interop-evidence-requirements).

Documentation-only changes may use the documentation-only validation path in
[Testing](TESTING.md#2-test-plans). Functional PRs must follow the relevant
Rust, Swift, device, hardware, and interop validation rules in
[Testing](TESTING.md).

## Documentation Update Triggers

Update this reference when a later accepted implementation plan changes:

- configuration/custody/capability modeling;
- metadata migration or persisted-state classification;
- Secure Enclave handle ownership, access policy, lifecycle, or recovery;
- resolver or router responsibilities;
- Rust/UniFFI external private-operation boundaries;
- supported or unsupported Secure Enclave custody operations;
- stable error categories;
- mockable, hardware, interop, or release evidence expectations.

The same implementation change must update the source authority that owns the
changed rule, rather than only updating this reference.
