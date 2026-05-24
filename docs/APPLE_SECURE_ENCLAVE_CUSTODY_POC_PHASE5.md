# Apple Secure Enclave Custody POC Phase 5 Evidence

Status: passed as an architecture compatibility audit. This phase did not
implement production Secure Enclave custody, change entitlements, change UniFFI
APIs, or make the custody mode product-selectable.

## Scope

Phase 5 evaluates whether the Secure Enclave custody concept proven by Phases 1
through 4 can fit CypherAir's existing architecture without collapsing service,
security, Rust, and product boundaries.

This is a documentation-only POC phase. It records the future integration shape,
required architecture adjustments, unsupported workflows, and Phase 6 decision
inputs. It does not add production code, a new crate, or a new app target.

## Research And Audit Basis

The audit used the existing custody planning documents, current Swift service
code, current Rust/UniFFI code, Phase 4/4.5 POC evidence, Apple Secure Enclave
documentation, Sequoia's external private-key traits, and OpenPGP standards.

Relevant external references:

- Apple: [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- Apple: [kSecAttrTokenIDSecureEnclave](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- Sequoia: [crypto::Signer](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/crypto/trait.Signer.html)
- Sequoia: [crypto::Decryptor](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/crypto/trait.Decryptor.html)
- Sequoia: [DecryptionHelper](https://docs.rs/sequoia_openpgp/latest/sequoia_openpgp/parse/stream/trait.DecryptionHelper.html)
- OpenPGP: [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html)
- OpenPGP ECC: [RFC 6637](https://www.rfc-editor.org/rfc/rfc6637.html)

Local audit entry points:

- `Sources/Models/PGPKeyProfile.swift`
- `Sources/Models/PGPKeyIdentity.swift`
- `Sources/Security/SecureEnclaveManageable.swift`
- `Sources/Security/KeychainManageable.swift`
- `Sources/Security/ProtectedData/KeyMetadataDomainStore.swift`
- `Sources/Services/KeyManagementService.swift`
- `Sources/Services/KeyManagement/PrivateKeyAccessService.swift`
- `Sources/Services/FFI/PGPMessageOperationAdapter.swift`
- `Sources/Services/FFI/PGPKeyOperationAdapter.swift`
- `Sources/Services/FFI/PGPCertificateOperationAdapter.swift`
- `pgp-mobile/src/sign.rs`
- `pgp-mobile/src/decrypt.rs`
- `pgp-mobile/src/encrypt.rs`
- `pgp-mobile/src/lib.rs`

## Current Architecture Findings

### Profile And Custody Are Currently Conflated By Absence

`PGPKeyProfile` is intentionally only an algorithm/profile vocabulary:

- `universal`: v4 OpenPGP key behavior.
- `advanced`: v6 OpenPGP key behavior.

It has no private-key custody meaning, and Phase 5 should preserve that. Secure
Enclave custody is not a third profile and should not be modeled by adding a
new `PGPKeyProfile` case.

`PGPKeyIdentity` records fingerprint, OpenPGP key version, profile, public
certificate, revocation artifact, algorithm names, expiry, and backup state. It
does not record private-key custody kind or Secure Enclave handle state.
`KeyMetadataDomainStore.Payload.currentSchemaVersion` is currently `1`, so a
production custody mode needs a metadata schema migration or equivalent
versioned extension before any SE custody identity can be persisted.

### Current Private-Key Access Assumes A Complete Secret Certificate

`KeyManagementService.unwrapPrivateKey(fingerprint:)` and
`PrivateKeyAccessService.unwrapPrivateKey(fingerprint:)` expose one private-key
operation shape: authenticate, reconstruct the existing Secure Enclave wrapping
key, unwrap complete OpenPGP secret certificate bytes, return `Data`, and
require the caller to zeroize it.

That shape is used by:

- `SigningService` for cleartext, detached, and streaming signatures.
- `EncryptionService` for optional signing during encryption and file
  encryption.
- `PasswordMessageService` for optional password-message signing.
- `DecryptionService` for message and streaming file decryption after recipient
  matching.
- `CertificateSignatureService` for user-id certifications.
- `KeyExportService` for secret-key export and lazy revocation backfill.
- `SelectiveRevocationService` for subkey and user-id revocation exports.
- `KeyMutationService` for expiry modification and rewrap recovery.

This is the main integration pressure point. Secure Enclave custody cannot use
that access shape without violating the central requirement that long-term
P-256 private keys remain non-exportable and never appear as a complete
software secret certificate.

### Current Keychain Bundle Is A Wrapping Bundle, Not A Custody Handle

The current Keychain/Secure Enclave private-key material boundary stores:

- `se-key`: data representation of the Secure Enclave wrapping key.
- `salt`: HKDF salt.
- `sealed-key`: AES-GCM sealed OpenPGP secret certificate bytes.
- pending variants used by auth-mode rewrap recovery.

That bundle represents "Secure Enclave wraps a software OpenPGP secret cert."
It cannot safely represent "Secure Enclave owns OpenPGP P-256 private
operations." Production Secure Enclave custody needs a separate storage model
for signing and key-agreement handles, public-key role binding, access group,
availability state, and cleanup/recovery behavior.

### Rust And UniFFI Currently Accept Secret Cert Bytes

The production UniFFI API accepts `signing_key: Option<Vec<u8>>`,
`secret_keys: Vec<Vec<u8>>`, or `signer_cert: Vec<u8>` for message operations.
The Rust implementation then extracts Sequoia `KeyPair` values from secret
certificates using `into_keypair()`.

Phase 4 proved a different boundary is feasible: Sequoia `Signer` and
`Decryptor` implementations can delegate the private operation to Secure
Enclave while Rust keeps OpenPGP packet handling, ECDH KDF, AES Key Wrap
unwrap, payload decrypt, verification, and tamper hard-fail behavior.

Production integration should therefore add an external private-operation path
instead of reusing the complete-secret-cert API for Secure Enclave custody.

## Recommended Future Boundary

Phase 5 recommends a small private-key operation routing layer, not broad app
navigation routing and not custody switches scattered across every workflow.

The future layer should be named narrowly, for example
`PrivateKeyOperationRouter` or `CustodyOperationRouter`. Its job is to resolve a
fingerprint and requested operation into an operation capability:

- software secret cert route for existing Profile A/B software custody;
- Secure Enclave external signer route for signing-capable SE custody;
- Secure Enclave external decryptor route for ECDH decrypt-capable SE custody;
- unsupported route for private-key export, unavailable hardware, missing
  handles, unsupported profile/custody combinations, or deferred lifecycle
  operations.

The router should not own OpenPGP workflows. Workflow ownership should remain
with the current services:

- `SigningService` owns user-visible signing workflows.
- `DecryptionService` owns Phase 1 recipient matching and Phase 2 decrypt
  workflows.
- `EncryptionService` owns recipient selection, signing option handling, and
  encrypt-to-self behavior.
- `PasswordMessageService` owns password-message workflows.
- `CertificateSignatureService` owns contact certification workflows.
- Key management services own generation, import/export, revocation, expiry,
  and metadata lifecycle.

The Security layer should continue to own Apple platform primitives: Secure
Enclave key generation/loading, access-control policy, Keychain access groups,
role binding, delete/cleanup, and availability checks. It should not own
OpenPGP packet semantics, KDF policy, session-key validation, or message
verification.

The Rust layer should continue to own OpenPGP semantics. New Rust integration
should prefer Sequoia `crypto::Signer`, `crypto::Decryptor`, and
`DecryptionHelper`-style boundaries. A production callback or handle design
must not introduce software fallback, secret-cert unwrap fallback, partial
plaintext acceptance, or secret logging.

## Workflow Compatibility Matrix

| Workflow | Phase 5 assessment | Future architecture note |
| --- | --- | --- |
| Public certificate export/share | Compatible | Uses `PGPKeyIdentity.publicKeyData`; no private operation required. |
| QR/contact import and validation | Compatible | Public-certificate paths remain custody-agnostic. |
| Recipient matching | Compatible | Phase 1 decrypt matching already uses public certs only. |
| SE signing | Compatible with routing/API work | Route to external signer; Rust/Sequoia still builds signature packets. |
| SE decrypt | Compatible with routing/API work | Route to external decryptor; Rust/Sequoia still owns PKESK, KDF, unwrap, decrypt, and verification. |
| Sign plus encrypt | Compatible with routing/API work | Encryption service should request a signing capability, not raw secret cert bytes. |
| GnuPG v4 interop | Compatible for the tested P-256 v4 shape | Phase 4.5 supports a v4 PKESK v3 ECDH plus SEIPDv1/MDC product candidate. |
| Streaming sign/decrypt | Needs API redesign | Current streaming UniFFI functions take secret cert bytes; future callbacks must preserve progress/cancel and hard-fail semantics. |
| Password-message optional signing | Needs API redesign | Password encryption is not recipient-key custody, but optional signing needs external signer support. |
| Contact certification | Needs API redesign or deferral | Current path takes a signer secret cert; external signer certification APIs are required. |
| Selective revocation | Needs API redesign or deferral | Current subkey/user-id revocation generation takes a secret cert. |
| Expiry modification / binding refresh | Needs API redesign or deferral | Current mutation signs new bindings from a secret cert and rewraps modified secret material. |
| Secret private-key export/backup | Unsupported for SE custody | Must be shown as non-exportable; no software recovery key fallback. |
| Import existing private key into SE | Unsupported | Apple Secure Enclave private keys must be generated in the Secure Enclave. |
| Device-loss decrypt recovery | Unsupported | Product copy must not imply decryptability after device/Keychain/SE-handle loss. |
| Auth-mode switching rewrap | Needs product decision | SE custody should not use in-place rewrap; any future access-policy change should be a new key or lifecycle design. |

## Secure Enclave Access-Control Direction

Production planning should keep the existing Standard/High Security mode and
rewrap model for software custody only. Secure Enclave custody v1 should default
to a biometrics-only private-key policy equivalent to `privateKeyUsage +
biometryAny`, without device-passcode fallback.

## Future Code Organization Rules

If production work proceeds after Phase 6, new Secure Enclave custody code
should be added as separate files and types in the correct layers:

- `Sources/Models`: custody metadata vocabulary and user-visible availability
  state.
- `Sources/Services/KeyManagement`: operation router, capability resolver, and
  key lifecycle orchestration.
- `Sources/Security`: Secure Enclave custody key provider, Keychain handle
  storage, access-control checks, and cleanup.
- `pgp-mobile/src`: external signer/decryptor integration and OpenPGP packet
  contract tests.

Existing files should receive only the necessary wiring. The implementation
should avoid scattering `switch custodyKind` logic through existing workflow
services. This preserves the current architecture where services own product
workflows, Security owns Apple platform primitives, and Rust owns OpenPGP
semantics.

## Test Ownership Recommendation

Production planning should split tests into three groups:

- Hardware evidence: manual or hardware-lane tests that exercise real Secure
  Enclave signing and ECDH operations.
- Contract tests: mock signer/decryptor tests that run without Secure Enclave
  and prove routing, failure mapping, no-fallback behavior, and OpenPGP packet
  handling.
- Regression tests: existing Profile A/B Rust and Swift tests that prove the
  software-custody paths remain unchanged.

Secure Enclave hardware availability should not become a default CI
requirement.

## No-Go Conditions

The following outcomes should stop production integration rather than be worked
around:

- modeling Secure Enclave custody as a new `PGPKeyProfile` case;
- using a software private-key fallback for an SE custody key;
- unwrapping or storing a complete secret certificate for the SE custody path;
- importing an existing OpenPGP private key into Secure Enclave;
- claiming private-key backup/export for SE custody;
- exposing partial plaintext after MDC/AEAD authentication failure;
- logging or printing shared secrets, session keys, KEKs, plaintext, Keychain
  locators, or stable fingerprints;
- reusing the existing `se-key`/`salt`/`sealed-key` wrapped-secret bundle as if
  it were an SE custody handle model.

## Phase 6 Inputs

Phase 6 should make product and production-readiness decisions using this
architecture audit plus Phase 1-4 evidence. The key decisions are:

- Whether the first product candidate is v4 P-256/GnuPG-compatible SE custody
  only, or whether v6/AEAD remains in scope.
- Which private-key operations are supported in the first version.
- Which workflows are shown as unavailable or deferred for SE custody.
- How key generation communicates non-exportability, device binding, revocation
  artifact timing, and device-loss recovery limits.
- How auth-mode switching, lockout, missing handles, Keychain loss, and Secure
  Enclave unavailability appear in product UI.
- Whether production should proceed to a detailed implementation plan or remain
  a POC/no-go.

## Conclusion

Phase 5 finds no architecture blocker that invalidates the Secure Enclave
custody concept. The concept can fit CypherAir if production work keeps
algorithm/profile and custody as separate dimensions, adds a small private-key
operation routing layer, stores SE custody handles separately from the current
wrapped-secret bundle, and extends Rust/UniFFI through external
signer/decryptor boundaries.

The main remaining risk is not cryptographic feasibility; it is product and
lifecycle scope. Phase 6 should decide the first supported product surface and
which lifecycle operations are explicitly deferred.
