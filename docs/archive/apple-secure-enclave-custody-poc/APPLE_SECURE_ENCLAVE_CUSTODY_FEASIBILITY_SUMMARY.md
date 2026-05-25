# Apple Secure Enclave Custody Feasibility Summary

> Status: Archived historical Secure Enclave Custody POC material.
> Archived: 2026-05-25.
> Archive reason: Secure Enclave Custody POC closeout; future product, architecture, and security docs will be rewritten separately.
> Successor: None yet.
> Current-state note: Current code and active docs outrank this archived file; use it only as historical evidence and context.


> Status: Active proposal summary / POC feasibility summary. This document
> summarizes completed validation work and does not describe shipped behavior.
> Date: 2026-05-24.
> Purpose: Summarize Apple Secure Enclave Custody Phase 0-5 evidence before
> product design and production architecture planning.
> Audience: Product, design, security reviewers, Swift/Rust implementers, test
> owners, reviewers, and AI coding tools.
> Current-state note: This is not shipped behavior, not production
> implementation approval, not a current app behavior statement, and not
> authorization to change
> security-sensitive code without a later implementation plan.
> Evidence roots: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md),
> [Validation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md),
> [Phase 0](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE0.md),
> [Phase 1](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE1.md),
> [Phase 2](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE2.md),
> [Phase 3](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE3.md),
> [Phase 4](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE4.md), and
> [Phase 5](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE5.md).

## Executive Decision

Phase 1 through Phase 5 provide enough evidence to move Apple Secure Enclave
Custody from technical feasibility validation into product design and production
architecture planning.

The evidence supports this narrow conclusion:

- Apple Secure Enclave can hold distinct P-256 signing and key-agreement
  private keys without importing or exporting private scalars.
- Valid OpenPGP P-256 public certificate candidates can be built around Secure
  Enclave public keys.
- Secure Enclave ECDSA private-key operations can produce OpenPGP signatures
  through Sequoia's external signer seam.
- Secure Enclave ECDH private-key operations can recover OpenPGP session keys
  through Sequoia's external decryptor seam.
- v4 and v6 P-256 OpenPGP candidates both worked in the POC.
- The v4 P-256 candidate interoperated with local isolated GnuPG for the tested
  public certificate, signing, encryption, decryption, and bidirectional
  sign+encrypt scenarios.
- The current app architecture can accommodate the concept if custody and
  algorithm profile remain separate dimensions and private-key operation
  routing is centralized.

The evidence does not support shipping the feature yet. Production design still
needs product scope, user-visible recovery semantics, metadata migration,
Keychain handle storage, cross-platform device validation, Rust/UniFFI callback
design, and durable test ownership.

## Evidence Matrix

| Phase | What the POC proved | Key caveat |
| --- | --- | --- |
| Phase 0: Baseline | Existing architecture, security invariants, branch policy, and POC evidence rules were recorded before experiments. | Phase 0 is an orientation snapshot only. |
| Phase 1: Apple primitive validation | Secure Enclave P-256 signing and ECDH keys can be generated, persisted, reconstructed, and used on the tested macOS hardware; role-substitution risk was identified. | Role and expected-public-key binding must be a production requirement. |
| Phase 2: OpenPGP public certificate feasibility | P-256 v4 and v6 public certificate candidates can be built and parsed; recipient selection and capability-resolver controls are feasible. | Public-only evidence was not sufficient for custody-bound acceptance. |
| Phase 3: External signing feasibility | SE-backed P-256 ECDSA signing works through a Sequoia `Signer`-style seam for v4 and v6 candidates; failure paths reject wrong or missing handles without fallback. | Production must preserve distinct signing and key-agreement handles. |
| Phase 4: ECDH and decrypt feasibility | SE-backed P-256 ECDH recovered OpenPGP session keys and decrypted v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD messages while preserving tamper hard-fail behavior. | The POC passed raw shared secrets through a private `0600` JSON response file; that boundary is not production acceptable. |
| Phase 4.5: GnuPG v4 interop | A v4 P-256 SE-shaped certificate imported into GnuPG; SE-shaped signatures verified; GnuPG encryption produced PKESK v3 ECDH plus SEIPDv1/MDC; bidirectional sign+encrypt scenarios passed. | This strengthens v4 as the recommended device-bound compatible candidate, not as the only possible technical format. |
| Phase 5: Architecture compatibility | The concept can fit the app if custody is separated from algorithm/profile configuration, metadata gains custody state, private-key operation routing is centralized, and Rust uses external signer/decryptor seams. | The main remaining risk is product and lifecycle scope, not the core cryptographic operation. |

Remaining gaps after Phase 0-5:

- Production Rust/UniFFI external private-operation APIs are not designed.
- Production metadata migration and Keychain handle schema are not designed.
- iPhone, iPadOS, and visionOS hardware validation has not been run.
- Product UX for configuration choice, generation, key detail, recovery copy,
  unavailable states, and error surfaces is not designed.
- Production security validation, mock/hardware test ownership, and release
  gates are not defined.
- The POC raw shared-secret response-file bridge remains non-production.

## Format Recommendation

Both v4 and v6 remain technically viable candidates after the POC:

- v4 P-256 Secure Enclave Custody: recommended device-bound compatible
  candidate because Phase 4.5 showed GnuPG interoperability with PKESK v3 ECDH
  and SEIPDv1/MDC.
- v6 P-256 Secure Enclave Custody: technically feasible in the POC for
  SEIPDv2/AEAD decrypt and signing, but not a GnuPG compatibility path.

The next product-design documents should plan both formats as first-version
product candidates. v4 P-256 / GnuPG-compatible Secure Enclave Custody should
be the recommended device-bound compatible option; v6 P-256 / AEAD Secure
Enclave Custody should remain a device-bound modern option that does not claim
GnuPG compatibility.

This recommendation does not change existing Profile A or Profile B
cryptographic behavior. The current software-key profiles remain:

- Profile A: v4 Ed25519/X25519 software custody for broad GnuPG compatibility.
- Profile B: v6 Ed448/X448 software custody for RFC 9580 behavior.

Future UI naming may still change to make the profile and custody model clearer
for users. Any naming redesign must not imply that Apple Secure Enclave Custody
is a third `PGPKeyProfile` or a migration path for existing software private
keys.

## Core Technical Findings

Apple's Secure Enclave documentation matches the POC design constraints: Secure
Enclave-backed keys are generated by the Secure Enclave, are P-256 elliptic
curve private keys, and cannot import pre-existing private-key material. Apple
also documents `privateKeyUsage` as necessary for private-key operations and
`kSecAttrTokenIDSecureEnclave` as the Secure Enclave storage token.

The tested macOS path used Security framework `SecKey` operations for signing
and key agreement. Phase 4 confirmed that the signed probe could load the
Secure Enclave key-agreement `SecKey` and use `SecKeyCopyKeyExchangeResult`
with the standard ECDH algorithm to obtain a 32-byte raw P-256 shared secret.
Rust, not Swift, then performed OpenPGP ECDH KDF, AES Key Wrap unwrap,
session-key validation, payload decrypt, and signature verification.

Sequoia 2.3.0 provides the right conceptual seams:

- `crypto::Signer` lets software build OpenPGP signatures while delegating
  private signing operations.
- `crypto::Decryptor` lets software decrypt OpenPGP session keys while
  delegating private decrypt/ECDH operations.
- `parse::stream::DecryptionHelper` is the recipient/session-key acquisition
  seam used by Sequoia's streaming decryptor.

Payload decryption and MDC/AEAD authentication remain owned by Sequoia's
streaming `Decryptor` and by the caller's read-to-completion /
`message_processed` policy, not by the Secure Enclave bridge.

These seams are consistent with the desired production boundary: Security owns
Apple platform private-key operations, Rust/Sequoia owns OpenPGP semantics, and
Swift services own product workflows.

## Architecture Implications

Production planning should preserve these architecture decisions:

- Secure Enclave custody must not be modeled as a `PGPKeyProfile` case. P-256
  v4/v6 may require a successor algorithm/format configuration concept, but
  custody must remain a separate dimension.
- `PGPKeyIdentity` and the `key-metadata` protected domain need a versioned way
  to record custody kind, Secure Enclave availability state, and public
  certificate association.
- The existing `se-key` / `salt` / `sealed-key` Keychain bundle represents
  Secure Enclave wrapping of a complete software secret certificate. It must
  not be reused as the Secure Enclave custody handle model.
- A small `PrivateKeyOperationRouter` or `CustodyOperationRouter` should
  resolve requested private-key operations to software secret-cert routes,
  Secure Enclave external signer/decryptor routes, or explicit unsupported
  routes.
- Workflow services such as signing, decryption, encryption, password-message,
  certificate-signature, and key-management services should keep owning product
  workflows. They should request capabilities from the router rather than
  scatter custody switches throughout workflow code.
- Future Rust/UniFFI work should add external private-operation routes instead
  of forcing Secure Enclave custody through existing APIs that accept complete
  secret certificate bytes.
- Phase 5 records an access-control planning direction: the current
  Standard/High Security rewrap model should remain a software-custody concept,
  while Secure Enclave custody v1 should default to a biometrics-only
  `privateKeyUsage + biometryAny` private-key policy without device-passcode
  fallback. `biometryAny` keeps the key usable after biometric enrollment
  changes. `biometryCurrentSet` binds access to the currently enrolled
  biometrics and is invalidated when Touch ID fingers are added or removed, or
  Face ID is re-enrolled; because that creates high permanent-loss risk, it is
  not planned as a user-selectable option. The final policy belongs in the
  later product-design and security-requirements documents.

## Product Implications

The feature should be designed as an explicit opt-in custody choice at key
generation time. It must not silently replace Profile A or Profile B, and it
must not be presented as a way to upgrade or migrate existing keys.

Product design must communicate these facts before key creation:

- The private key is generated on this device and is not exportable.
- Losing the device, Secure Enclave state, Keychain handle, or required
  authentication factor may permanently lose signing and decrypt capability.
- Private-key backup/export is unavailable for this custody mode.
- Revocation artifacts and recovery instructions are separate from private-key
  backup and should be handled while the key is still usable.

Current Profile A/B cryptographic behavior remains unaffected by the POC. Future
UI display naming may still be redesigned for consistency, for example by
separating "message compatibility/profile" from "private-key custody" in the
generation and key-detail surfaces.

## Residual Risks And Non-Production Boundaries

The following items must remain explicit in later product and architecture
documents:

- Hardware evidence is macOS-first. iPhone, iPadOS, and visionOS Secure Enclave
  validation remain later production-readiness gates.
- The current POC target and hardware evidence runner are macOS-only; they
  cannot be treated as iPhone device evidence.
- The Phase 4 response-file bridge passed raw shared secret bytes from Swift to
  Rust through a private `0700` directory and `0600` JSON file. This was
  acceptable POC evidence only and must be removed or narrowed for production.
- Swift `Data`, JSON, and hex intermediates in the POC were not a production
  memory-zeroization design.
- Production Rust/UniFFI callback or handle APIs are not designed yet.
- Production metadata migration, Keychain handle schema, access-control
  lifecycle, UI availability states, and recovery copy are not implemented.
- Real Secure Enclave tests should not become default CI requirements; mockable
  contract tests and hardware evidence lanes need separate ownership.

## Security Red Lines

Production planning must stop or return to design review if it requires any of
the following:

- storing a software private-key fallback for a Secure Enclave custody key;
- unwrapping or storing a complete secret certificate for the Secure Enclave
  custody path;
- importing an existing OpenPGP private key into Secure Enclave;
- exporting Secure Enclave private-key material or presenting a key handle as a
  recoverable private-key backup;
- reusing a single Secure Enclave key for both signing and ECDH;
- modeling Secure Enclave custody as a `PGPKeyProfile` case;
- accepting partial plaintext after MDC or AEAD authentication failure;
- logging plaintext, private-key material, session keys, ECDH shared secrets,
  KEKs, Keychain locators, stable fingerprints, or temp capability paths;
- weakening current Profile A or Profile B behavior to make the custody mode
  easier to integrate.

## Next Planning Documents

This summary is the first of five active planning documents intended to replace
the current POC evidence documents as day-to-day guidance. Until all five are
written, the existing POC documents remain active evidence roots and should be
cited when they support a decision.

The next documents are:

- [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md): high-level
  product direction, user-visible semantics, configuration presentation,
  recovery language, backup/export semantics, availability states, and
  first-version workflow scope.
- [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md):
  high-level Swift/Rust/Security integration direction, algorithm/configuration
  separation, custody metadata, capability resolver, operation router, handle
  storage boundary, and future API migration constraints.
- [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md):
  production security requirements, access-control policy, hardware/mock test
  split, no-fallback tests, tamper tests, full private-operation validation, and
  platform validation gates.
- `APPLE_SECURE_ENCLAVE_CUSTODY_ROADMAP.md`: staged path from POC closeout to
  production implementation, including when to archive the old POC documents
  and close the POC PR.

After these documents are complete, the current POC documents should move under
`docs/archive/` with archive banners and successor links. They should remain
historical evidence, not current implementation guidance.

> Status: Archived historical Secure Enclave Custody POC material.
> Archived: 2026-05-25.
> Archive reason: Secure Enclave Custody POC closeout; future product, architecture, and security docs will be rewritten separately.
> Successor: None yet.
> Current-state note: Current code and active docs outrank this archived file; use it only as historical evidence and context.

