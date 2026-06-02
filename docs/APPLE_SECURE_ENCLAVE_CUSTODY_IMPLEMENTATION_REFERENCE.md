# Apple Secure Enclave Custody Implementation Reference

> Status: Draft implementation reference. This document describes proposed
> future work and does not describe shipped behavior.
> Date: 2026-05-26.
> Purpose: Provide middle-level implementation contracts for future Apple
> Secure Enclave-backed OpenPGP private-key custody implementation plans.
> Audience: Swift/Rust implementers, security reviewers, architecture
> reviewers, product owners, test owners, reviewers, and AI coding tools.
> Source authorities: [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> and [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md).
> Related: [Implementation Roadmap](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_ROADMAP.md).
> Companion current-state references: [Architecture](ARCHITECTURE.md),
> [Security](SECURITY.md), [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md),
> and [Testing](TESTING.md).
> Update triggers: Any implementation plan or completed PR that changes Secure
> Enclave custody model boundaries, metadata or handle-state representation,
> private-operation routing, Rust/UniFFI handoff, validation gates, or release
> exposure posture.

## 1. Role And Source-Of-Truth Rules

This reference translates the active Apple Secure Enclave Custody planning set
into implementation-facing contracts. It is not an approval to ship the feature,
not a statement of current app behavior, and not a substitute for a later
phase-specific implementation plan.

Use this document to decide what a later implementation plan must design,
preserve, and verify. Do not use it to override the source authorities:

- [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md) owns product
  semantics, user commitments, MVP private-operation scope, compatibility
  language, and user-facing consequences.
- [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md) owns
  model separation, metadata/handle split, resolver and router ownership, and
  Rust/Swift/Security dependency direction.
- [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md)
  owns red lines, access-control policy, private-operation security,
  persistent-state security, evidence categories, and release gates.
- [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md)
  owns the Phase 0-5 evidence summary, caveats, POC limits, and residual
  production-readiness gaps.
- [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
  [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
  [Testing](TESTING.md) own current shipped architecture, current security
  invariants, persisted-state classification, and validation workflow.

Archived POC documents are historical evidence roots through the Feasibility
Summary. They should not be treated as current production design authority.

## 2. Current Baseline And Target Model

Current CypherAir private-key workflows are software secret-certificate
workflows. Existing key metadata records Profile A/Profile B software-key
behavior, Swift services unwrap complete OpenPGP secret certificate bytes for
private workflows, and Rust/Sequoia extracts keypairs from those secret
certificates for signing, decrypting, certification, revocation, and expiry
mutation. The current Secure Enclave wrapping scheme protects complete software
secret certificate bytes; it is not a Secure Enclave private-operation custody
model.

The target Secure Enclave custody model is different: Apple Secure Enclave owns
non-exportable P-256 private signing and key-agreement operations. Software
still owns OpenPGP certificate construction, packet construction, ECDH KDF and
AES Key Wrap processing, session-key validation, payload processing, signature
verification, workflow orchestration, and user-visible state.

Existing software keys remain software custody. There is no implementation
route that converts an existing OpenPGP software private key into Secure
Enclave custody, imports a private key into Secure Enclave custody, exports
Secure Enclave private-key material, or stores a software fallback for a Secure
Enclave custody key.

## 3. Configuration, Custody, And Capability Separation

Future implementation plans must keep these concepts separate:

| Concept | Implementation contract | Must not own |
| --- | --- | --- |
| OpenPGP configuration | Key version, algorithm family, packet/message-format preference, advertised features, interoperability target, and software export/S2K behavior where applicable. | Apple handle storage, authentication policy, or current operation availability. |
| Private-key custody | Whether private operations use software secret certificates or Secure Enclave private-operation handles. | Packet format, compatibility target, or UI wording. |
| Operation capability | Whether a specific key can currently generate, sign, decrypt, certify, revoke, mutate binding material, export public material, export private material, or report unsupported/unavailable state. | Keychain row details, Sequoia packet semantics, or product-copy decisions. |

The [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md#configuration-model)
explicitly requires that `PGPKeyProfile` not grow a Secure Enclave case. A
future plan may introduce a profile successor or equivalent app-owned
configuration model, but that plan must preserve current Profile A/Profile B
cryptographic behavior by normalizing existing records into software custody
plus the matching OpenPGP configuration.

The planned product families from Product Design are reference labels, not final
UI strings or type names:

- portable compatible software custody;
- portable modern software custody;
- device-bound compatible Secure Enclave custody;
- device-bound modern Secure Enclave custody.

The resolver contract in Section 6 is responsible for exposing only complete,
valid combinations. Invalid matrices, such as Secure Enclave custody for an
algorithm that cannot be backed by Secure Enclave P-256 private operations, must
not leak as user-selectable choices.

## 4. Protected Metadata, Handle State, And Availability

Secure Enclave custody needs a versioned metadata migration, or equivalent
versioned state transition, that can represent existing software keys and newly
generated Secure Enclave custody keys. Future implementation plans own the exact
schema, field names, and migration mechanics.

The middle-contract requirement is that protected key metadata can represent
non-secret app behavior state such as:

- OpenPGP configuration identity;
- custody kind;
- public certificate association and validation digest;
- public signing and key-agreement association needed to bind metadata to
  Security-layer handles;
- operation availability projection for workflow services and UI;
- revocation artifact presence;
- private-key export state, including Secure Enclave non-exportability.

Protected metadata must not store complete private-key material, Secure Enclave
private keys, shared secrets, session keys, KEKs, plaintext, or the Secure
Enclave access-control policy. The final representation must also avoid turning
local handle references into recoverable private-key backups. Rust must not own
or persist Apple handle locators.

Operation availability should be stable enough for UI, services, tests, and
security review to agree on failure class without agreeing on final enum names.
At minimum, implementation plans should represent these categories:

- operation supported and local state present;
- authentication required, canceled, failed, or locked out;
- required local handle missing or inaccessible;
- metadata and handle association mismatch;
- public certificate association mismatch;
- operation unsupported for the custody kind or configuration;
- operation not implemented yet for Secure Enclave custody;
- metadata migration or recovery required;
- hardware or platform capability unavailable.

Migration must fail closed: readable source state stays intact until the
migrated destination is validated, corrupt committed protected state becomes a
recovery surface, and unreadable state must not be silently reset to empty data.

Future implementation plans must also assign recovery ownership and outcomes for
metadata/handle disagreement without choosing final schemas or UI copy:

- unreadable source metadata before migration preserves the source and reports a
  migration/recovery state;
- corrupt committed protected metadata is treated as recovery state, not an
  empty key list;
- missing or inaccessible handles make private operations unavailable while
  preserving public certificate and revocation-artifact surfaces where possible;
- role mismatch and public-binding mismatch fail closed and must not attempt a
  different handle;
- platform Secure Enclave unavailability makes private operations unavailable
  without changing the key's persisted custody kind;
- local reset deletes Security-owned handles and protected metadata projections
  consistently, with mismatches left discoverable and cleanable by recovery
  logic.

## 5. Security-Layer Handle Store Contract

Secure Enclave handle storage is a Security-layer boundary. It must be separate
from the existing `se-key` / `salt` / `sealed-key` bundle because that bundle
wraps complete software secret certificate bytes.

Future implementation plans must provide distinct lifecycle handling for:

- a signing private-operation handle;
- a key-agreement private-operation handle;
- the expected OpenPGP role for each handle;
- the expected public key association for each handle;
- cleanup when generation, migration, reset, or local recovery fails;
- local reset participation;
- recovery classification when metadata and handles disagree.

Reference access-control material for later planning, owned by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#access-control-requirement):

- Secure Enclave custody private operations default to `privateKeyUsage` plus
  `biometryAny`.
- Device-passcode fallback is not part of the planned policy.
- `biometryCurrentSet` is not a user-selectable first-version or later option
  because biometric enrollment changes can permanently invalidate a
  non-exportable key.
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` is the reference accessibility
  value to evaluate for Secure Enclave custody handle-related Keychain items.

These values are implementation guardrails from Security Requirements, not final
Keychain item names or storage schemas. Any function that creates, loads,
validates, or deletes handles remains inside the repository's security-sensitive
review boundary.

Handle loading must fail closed when the required handle cannot be loaded,
authenticated, role-validated, or public-key-bound. A signing handle must never
be accepted for ECDH, an ECDH handle must never be accepted for signing, and a
handle whose public key does not match the stored OpenPGP public association
must not be used.

## 6. Resolver And Router Contracts

The capability resolver is a policy component. It decides which complete product
configurations and operations are valid before a workflow starts. It may consume
product policy, OpenPGP configuration, custody kind, migrated metadata, public
certificate association, handle association state reduced to displayable status,
and runtime availability signals.

The resolver must not perform private operations, call Sequoia packet decrypt,
mutate Keychain rows, or own workflow side effects. UI surfaces should use
resolver output to show valid generation choices and key operation availability.
Workflow services should use resolver output to avoid offering impossible
operations.

The private-key operation router is an execution component. It receives a
resolved operation request from a workflow service and returns one of these
routes:

- software secret-certificate route for existing portable software keys;
- Secure Enclave signer route for signing, certification, revocation, and
  binding-signature operations;
- Secure Enclave ECDH/session-key route for recipient-key decryption;
- explicit unsupported route.

Phase 5A implements the router foundation only. The shared Swift vocabulary is
`PGPPrivateOperationKind`: `sign`, `decrypt`, `certify`, `revoke`,
`modifyExpiry`, and `refreshBinding`, with role mapping to signing or
key-agreement handles. The implemented route outcomes are software
secret-certificate route, Secure Enclave signer route, and blocked
`PGPKeyOperationResolution`; the successful Secure Enclave key-agreement route
remains future Phase 6 work. The Phase 5A router resolves local identity by
fingerprint, consults resolver policy before Security handle lookup, validates
stored public-certificate bindings and key-version/fingerprint association, and
loads only the signing handle by public bindings. Production policy still blocks
Secure Enclave private operations, and no product workflow consumes the router
in this foundation PR.

Phase 5B is the first workflow consumer and is intentionally narrow. The Rust
runtime cleartext signing API accepts only public certificate bytes, an expected
signing-key fingerprint, and the existing external P-256 signing provider. Rust
selects a policy-valid P-256 signing key matching that fingerprint, builds an
external signer, and asks Sequoia to construct the cleartext signature without
extracting a secret keypair. Swift routes only `SigningService.signCleartext`:
software routes keep the existing unwrap-and-zeroize behavior, Secure Enclave
signer routes pass the stored public certificate and loaded signing handle to
the external signer API, and blocked routes map to sanitized unavailable
categories. Sign-plus-encrypt, password-message signing, detached file signing,
certification, revocation, expiry/binding refresh, and decrypt remain outside
PR 5B.

Phase 5C is the second narrow workflow consumer. The Rust runtime text encrypt
API accepts recipient certificates, optional encrypt-to-self certificate, a
public signing certificate, expected signing-key fingerprint, and the existing
external P-256 signing provider. Rust rejects secret signing certificates,
non-P-256 or wrong-role signing certificates, fingerprint mismatches, malformed
callback signatures, wrong digests, and wrong public-key signatures without
falling back to secret-certificate signing. Swift routes only optional signing
for `EncryptionService.encryptText`: unsigned text encryption does not route,
software routes keep the existing unwrap-and-zeroize behavior, Secure Enclave
signer routes pass public signing certificate material and the loaded signing
handle to the external signer encrypt API, and blocked routes map to sanitized
unavailable categories. Password-message signing, streaming file
encryption/signing, detached signing, certification, revocation,
expiry/binding refresh, and decrypt remain outside PR 5C.

Phase 5D is the third narrow workflow consumer. The Rust runtime password
encrypt APIs support both armored text and binary password/SKESK outputs with
optional external P-256 signing. They accept a public signing certificate,
expected signing-key fingerprint, and the existing external P-256 signing
provider, while continuing to let the password-message path own SKESK handling,
format selection, password decrypt, and verification semantics. Rust rejects
secret signing certificates, non-P-256 or wrong-role signing certificates,
fingerprint mismatches, malformed callback signatures, wrong digests, and wrong
public-key signatures without falling back to secret-certificate signing. Swift
routes only optional signing for `PasswordMessageService.encryptText` and
`encryptBinary`: unsigned password encryption does not route, software routes
keep the existing unwrap-and-zeroize behavior, Secure Enclave signer routes pass
public signing certificate material and the loaded signing handle to the
external signer password APIs, and blocked routes map to sanitized unavailable
categories. Streaming file encryption/signing, certification, revocation,
expiry/binding refresh, and decrypt remain outside PR 5D.

Phase 5E is the fourth narrow workflow consumer. The Rust runtime detached file
signing API streams file bytes through the existing detached-signature path
while accepting a public signing certificate, expected signing-key fingerprint,
and the existing external P-256 signing provider. Rust rejects secret signing
certificates, non-P-256 or wrong-role signing certificates, fingerprint
mismatches, malformed callback signatures, wrong digests, and wrong public-key
signatures without falling back to secret-certificate signing. Swift routes only
`SigningService.signDetachedStreaming`: software routes keep the existing
unwrap-and-zeroize behavior, Secure Enclave signer routes pass public signing
certificate material, the loaded signing handle, and existing progress
cancellation through the external signer detached-file API, and blocked routes
map to sanitized unavailable categories. Streaming encrypt-plus-sign,
certification, revocation, expiry/binding refresh, and decrypt remain outside
PR 5E.

Phase 5F is the fifth narrow workflow consumer. The Rust runtime streaming file
encrypt API preserves the binary file-encryption path while accepting a public
signing certificate, expected signing-key fingerprint, and the existing external
P-256 signing provider. Recipient collection, encryptor setup, progress reading,
zeroizing copy, output cleanup, and finalize behavior stay shared with software
streaming file encryption. Rust rejects secret signing certificates, non-P-256
or wrong-role signing certificates, fingerprint mismatches, malformed callback
signatures, wrong digests, and wrong public-key signatures without falling back
to secret-certificate signing. Swift routes only optional signing for
`EncryptionService.encryptFileStreaming`: unsigned file encryption does not
route, software routes keep the existing unwrap-and-zeroize behavior, Secure
Enclave signer routes pass public signing certificate material, the loaded
signing handle, optional encrypt-to-self material, and existing progress
cancellation through the external signer file-encryption API, and blocked routes
map to sanitized unavailable categories. Certification, revocation,
expiry/binding refresh, and decrypt remain outside PR 5F.

Phase 5G is the sixth narrow workflow consumer. The Rust runtime expiry
mutation API accepts only public certificate bytes, an expected signing-key
fingerprint, and the existing external P-256 signing provider, then emits
updated public certificate bytes and key metadata after Sequoia binding
signature construction. Rust rejects secret certificates, non-P-256 or
wrong-role signing certificates, fingerprint mismatches, malformed callback
signatures, wrong digests, wrong public-key signatures, cancellation, and
external failures without falling back to secret-certificate signing. Swift
routes only `KeyMutationService.modifyExpiry`: software routes keep the
existing unwrap-and-zeroize, Rust `modifyExpiry`, rewrap/promotion, pending
bundle, recovery journal, and catalog behavior, while Secure Enclave signer
routes pass stored public certificate material and the loaded signing handle to
the external signer expiry API and update only public metadata/catalog state.
Standalone `refreshBinding` remains explicitly not implemented for Secure
Enclave custody because there is no current product or software workflow to
route. Certification, revocation, and decrypt remain outside PR 5G.
The Phase 5G follow-up refreshes explicit transport/ECDH subkey validity
bindings in the shared Rust expiry helper instead of relying on primary
direct-key/User ID expiry updates alone, and the public-only external API
requires the expected signer fingerprint to match the primary key. A second
follow-up keeps modify-expiry usable after a local key has already expired by
using an expiry-specific primary signer selector that does not require `.alive()`
while ordinary signing workflows still do, and makes Secure Enclave catalog
writeback merge against the current identity so late results preserve local flags
and cannot recreate deleted metadata.

The router centralizes custody-specific dispatch. Signing, decryption,
encryption, password-message, certificate-signature, and key-management services
must not grow separate custody switches that bypass the router. The router must
not own product workflows, UI copy, metadata migration, handle storage details,
or OpenPGP packet semantics.

## 7. Rust, Swift, And Security Handoff

The service layer owns workflow orchestration. It asks the resolver whether an
operation should be available and asks the router for the private-operation
route. It must not force Secure Enclave custody through code paths that require
complete OpenPGP secret certificate bytes.

The Security layer owns Apple platform primitives: Secure Enclave key creation
and loading, Keychain handle storage and deletion, access-control enforcement,
authentication context handling, role checks, public-key binding checks, cleanup,
and local reset participation.

The Rust/OpenPGP layer owns OpenPGP semantics: certificate parsing and
construction, packet construction, ECDH KDF and AES Key Wrap processing,
session-key validation, payload decrypt and verification, message-format
selection, and signature/revocation/certification verification.

Signing-class operations should use an external signer boundary. Rust builds the
OpenPGP signing context and delegates only the private ECDSA operation to Apple
platform code. Future implementation plans own the exact callback, result, and
UniFFI representation.

Decrypt-class operations have two separate contracts:

- Recipient/session-key acquisition delegates the P-256 private ECDH operation
  to Apple platform code while Rust performs OpenPGP ECDH KDF, AES Key Wrap
  unwrap, and session-key validation.
- Payload processing remains a Sequoia parse/decrypt pipeline responsibility.
  Plaintext release is valid only after the caller satisfies the existing
  read-to-completion and message-processed contract.

The POC response-file bridge that moved raw shared secrets through JSON was
evidence-only and is not production acceptable. Production plans must keep
private-operation intermediate values inside the approved in-process boundary
and follow the no-secret diagnostics rule in Section 9.

Streaming workflows must preserve progress reporting, cancellation behavior,
temporary-artifact cleanup, success-only plaintext release, and MDC/AEAD
hard-fail behavior.

## 8. Business Operation Semantics

Future implementation plans should classify Secure Enclave custody operation
work by business behavior, not by whichever service currently reaches the Rust
engine.

| Operation family | Middle-contract requirement |
| --- | --- |
| Generation | Generate distinct Secure Enclave signing and key-agreement handles, build an OpenPGP public certificate around their public keys, record non-secret metadata, and prepare key-level revocation artifact export. Partial failure must clean up local handles and avoid committing a usable-looking key. |
| Private-key import | Existing private-key import can create software-custody keys only. Import into Secure Enclave custody is unsupported. |
| Private-key export or backup | Software custody keeps current export behavior. Secure Enclave custody private-key export, backup, and device-loss decrypt recovery are unsupported. |
| Public export and inspection | Public certificate sharing, public inspection, contact import, and revocation artifact export remain public-material workflows. They should not require private custody capability unless the operation also creates new signed material. |
| Message signing and verify-adjacent workflows | Secure Enclave custody signing must use the signer route. Verification remains public/OpenPGP semantic work and should not depend on private custody. |
| Sign plus encrypt and password-message optional signing | Encryption remains recipient/message-format work. Optional signing must use the signer route when the selected signing key uses Secure Enclave custody. |
| Message and file decryption | Recipient-key decryption must use the ECDH/session-key route. Payload decrypt must preserve Sequoia authentication and success-only plaintext release. |
| Streaming sign, decrypt, and encrypt-plus-sign | Streaming variants must use the same private-operation routes as non-streaming operations while preserving cancellation, progress, cleanup, and hard-fail contracts. |
| Expiry modification and binding refresh | Any operation that emits new binding or certification signatures for a Secure Enclave custody key must use the signer route. |
| Revocation | Key-level, subkey, and User ID revocation artifacts requiring private signing must use the signer route. Exporting already-created public revocation artifacts remains public-material export. |
| Contact certification | Certification signatures made by a Secure Enclave custody key must use the signer route and must not unwrap or synthesize a secret certificate. |
| Unsupported operations | Unsupported states must be explicit resolver/router outcomes. They must not fall back to software private keys or silently hide a failed private route behind public-only behavior. |

The first-version operation scope is owned by
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#mvp-private-operation-scope).
If any product scope item cannot satisfy
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#mvp-security-gate),
the implementation must keep that operation unavailable for Secure Enclave
custody until redesigned.

## 9. Stable Error Taxonomy

Future plans may choose exact Swift/Rust error types later, but the behavior
must map to stable categories that UI, services, tests, and security review can
share:

- invalid or unsupported configuration/custody combination;
- operation unsupported for Secure Enclave custody;
- operation not yet implemented for Secure Enclave custody;
- authentication canceled, failed, unavailable, or locked out;
- required Secure Enclave handle missing, inaccessible, or not authorized;
- signing/ECDH role mismatch;
- handle public-key binding mismatch;
- protected metadata or public certificate association mismatch;
- migration or recovery required before operation;
- prohibited secret-certificate fallback or software fallback attempted;
- Rust/OpenPGP semantic failure, including malformed packets, no matching
  recipient, invalid signature context, session-key validation failure, or
  unsupported algorithm/format;
- payload authentication failure for SEIPDv1/MDC or SEIPDv2/AEAD;
- cleanup or rollback failure that leaves local state requiring recovery.

Errors and diagnostics must not include plaintext, private-key material, shared
secrets, session keys, KEKs, Keychain locators, stable fingerprints, temporary
capability paths, or other secret-bearing values. User-facing wording belongs
to later product/UI implementation plans and the String Catalog workflow.

## 10. Implementation Test Contracts

Mockable tests should prove architecture contracts before hardware evidence is
required. They should cover:

- legal and illegal OpenPGP configuration plus custody combinations;
- migration of existing Profile A/Profile B metadata into successor
  configuration plus software custody;
- metadata corruption and recovery behavior;
- resolver output for supported, unsupported, unavailable, and not-yet-
  implemented operations;
- operation-router dispatch without workflow-local custody switches;
- no software fallback and no secret-certificate unwrap fallback;
- wrong role, wrong public key, missing handle, inaccessible handle, and
  metadata/handle mismatch;
- no partial plaintext after MDC/AEAD failure;
- no secret material in errors, logs, diagnostics, or persisted state.

Rust tests should prove the external private-operation boundary with test
substitutes before relying on device hardware. They should cover v4 and v6
signing-class operations, ECDH/session-key acquisition, packet shape expectations
where relevant, session-key validation failures, and payload authentication
failure behavior.

Swift tests should prove resolver/router behavior, metadata migration,
Security-layer handle-store behavior through mocks, workflow-service
orchestration, cancellation, cleanup, and error mapping. Device-only tests must
be guarded for real hardware availability.

Phase 5A Swift coverage should remain workflow-local: software custody routes
without Secure Enclave handle lookup; production policy blocks; hidden/test
signing policy returns signer routes for signing-class operations; decrypt and
key agreement remain blocked; missing identity, invalid custody/configuration,
public-certificate mismatch, fingerprint mismatch, missing handle, wrong role,
wrong public binding, local-authentication cancellation/failure, and no software
fallback all resolve to sanitized blocked outcomes. Source-audit coverage should
continue to catch new workflow-local custody switches outside the resolver,
router, and established key-management/security boundaries.

Phase 5B coverage adds the runtime cleartext signing path. Rust tests should
verify v4/v6 public-only P-256 cleartext signatures, callback cancellation and
sanitized failure categories, malformed `r/s`, wrong digest, wrong public key,
non-P-256 or wrong-role certificates, fingerprint mismatch, and no fallback to
secret-certificate signing. Swift tests should verify software cleartext signing
stays unchanged, Secure Enclave cleartext signing does not unwrap a software
secret certificate, production policy blocks, hidden/test signing policy can
sign and verify, missing/wrong handles and auth failures surface stable
categories, and blocked routes do not call FFI signing.

Phase 5C coverage adds text sign-plus-encrypt optional signing through the same
external signer route. Rust tests should verify v4/v6 public-only P-256 signed
encrypted messages decrypt and verify, callback cancellation and sanitized typed
categories survive finalization, secret signing certificates, wrong
fingerprints, non-P-256 or wrong-role certificates, malformed signatures, wrong
digests, wrong public keys, and external failures all fail closed, and no
secret-certificate fallback occurs. Swift tests should verify software signed
text encryption remains behavior-compatible and zeroizes unwrapped material,
unsigned text encryption does not route, production policy blocks Secure
Enclave signing, hidden/test policy can sign plus encrypt through a real
catalog/router/public-binding inspector/shared mock handle store, handle/auth
failures surface stable unavailable categories, blocked routes do not call FFI,
and Phase 5C itself does not route streaming file encryption.

Phase 5D coverage adds password-message optional signing through the same
external signer route. Rust tests should verify v4/v6 public-only P-256 signed
password messages decrypt and verify for both armored and binary outputs,
callback cancellation and sanitized typed categories survive finalization,
secret signing certificates, wrong fingerprints, non-P-256 or wrong-role
certificates, malformed signatures, wrong digests, wrong public keys, and
external failures all fail closed, and no secret-certificate fallback occurs.
Swift tests should verify unsigned password encryption does not route, software
signed password encryption remains behavior-compatible and zeroizes unwrapped
material, production policy blocks Secure Enclave signing, hidden/test policy can
sign password messages through a real catalog/router/public-binding
inspector/shared mock handle store, handle/auth failures surface stable
unavailable categories, blocked routes do not call FFI, and password decrypt,
tamper, `noSkesk`, and `passwordRejected` coverage remains unchanged.

Phase 5E coverage adds streaming detached file signing through the same external
signer route. Rust tests should verify v4/v6 public-only P-256 detached file
signatures verify, progress and callback cancellation are preserved, sanitized
typed categories survive finalization, secret signing certificates, wrong
fingerprints, non-P-256 or wrong-role certificates, malformed signatures, wrong
digests, wrong public keys, and external failures all fail closed, and no
secret-certificate fallback occurs. Swift tests should verify software detached
file signing remains behavior-compatible and zeroizes unwrapped material,
production policy blocks Secure Enclave signing, hidden/test policy can sign
through a real catalog/router/public-binding inspector/shared mock handle store,
handle/auth/progress/callback failures surface stable categories, blocked routes
do not call FFI, and Phase 5E itself does not route streaming file encryption.

Phase 5F coverage adds streaming file encrypt-plus-sign optional signing through
the same external signer route. Rust tests should verify v4/v6 public-only P-256
signed streaming file messages decrypt and verify, SEIPDv1/SEIPDv2 packet-format
selection honors recipient and encrypt-to-self downgrade rules, progress and
callback cancellation survive finalization, sanitized typed categories are
preserved, secret signing certificates, wrong fingerprints, non-P-256 or
wrong-role certificates, malformed signatures, wrong digests, wrong public keys,
and external failures all fail closed, and no secret-certificate fallback
occurs. Swift tests should verify unsigned file encryption does not route,
software signed file encryption remains behavior-compatible and zeroizes
unwrapped material, production policy blocks Secure Enclave signing, hidden/test
policy can sign streaming files through a real catalog/router/public-binding
inspector/shared mock handle store, explicit/default encrypt-to-self paths
decrypt and verify, handle/auth/progress/callback failures surface stable
categories, blocked routes do not call FFI, output cleanup occurs on failure,
and text/password/detached/decrypt streaming coverage remains unchanged.

Phase 5G coverage adds modify-expiry binding signatures through the same
external signer route. Rust tests should verify v4/v6 public-only P-256 expiry
set/remove mutations preserve fingerprint and key version, update expiry
metadata, and emit verifiable public certificate binding signatures. Rust
tests should also cover extending and removing expiry after the local key has
already expired. Rust negative tests should cover callback cancellation, typed
callback failure categories, malformed or zero `r/s`, wrong digest, wrong public
key, wrong fingerprint, secret certificate input, non-P-256 or wrong-role
certificates, external failures, and no fallback to secret-certificate signing.
Swift tests should verify software modify-expiry remains behavior-compatible and
preserves zeroization plus pending-bundle recovery behavior, production policy
blocks Secure Enclave modify-expiry, hidden/test policy can modify expiry
through a real catalog/router/public-binding inspector/shared mock handle store
for v4 and v6 fixtures including after expiry has passed, Secure Enclave
writeback preserves current catalog flags and does not resurrect deleted
metadata, no software unwrap or recovery journal path runs on Secure Enclave
routes, handle/auth/callback failures surface stable categories, blocked routes
do not call FFI, and `refreshBinding` remains explicitly not implemented without
touching Security handles or FFI.

Hardware evidence requirements are owned by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#hardware-evidence-requirements)
and should run through manual or release-validation lanes rather than mandatory
default CI. As reference examples, later plans should map real-device evidence
to handle generation/persistence, private signing, ECDH/session-key recovery,
authentication and binding failures, local reset cleanup, and sanitized output.
This reference is not the exhaustive hardware evidence gate.

Interop evidence requirements are owned by
[Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md#interop-evidence-requirements)
and product compatibility claims are owned by
[Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#compatibility-language).
As reference examples, later plans should preserve the v4 GnuPG-compatible claim
only when import, signature verification, GnuPG-originated encryption,
production-boundary decrypt/verify, bidirectional sign-plus-encrypt, and packet
shape evidence remain valid. The v6 modern path needs RFC 9580 / AEAD evidence
and should not gain a GnuPG claim without a later product decision.

Validation commands and test-plan ownership remain governed by
[Testing](TESTING.md) and [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md).

## 11. Documentation Update Triggers

Update this reference when a later planning or implementation PR changes:

- configuration/custody/capability separation;
- protected metadata state categories or migration behavior;
- Secure Enclave handle-store ownership or access-control guardrails;
- resolver or private-operation router responsibilities;
- Rust/UniFFI handoff boundaries;
- supported or unsupported operation classes;
- stable error categories;
- mock, hardware, interop, or release evidence expectations.

When shipped behavior, storage classification, security boundaries, or
validation workflow changes, update the current-state companion documents in
the same implementation change.
