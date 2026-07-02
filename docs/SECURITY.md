# Security Model

> Status: Canonical current-state.
> Purpose: Complete description of the encryption scheme, key lifecycle, authentication flows,
> security invariants, and AI coding boundaries for CypherAir.
> Audience: Human developers, security auditors, and AI coding tools.
> Update triggers: Changes to crypto/profile behavior, key lifecycle, Secure Enclave wrapping,
> authentication modes, the ProtectedData model, tutorial isolation, MIE posture, or the
> Section 10 red lines.
> Last reviewed: 2026-06-12.

## 1. Encryption Scheme

All cryptographic operations use Sequoia PGP 2.3.0. Two profiles with different algorithm suites:

### Profile A (Universal Compatible)

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Primary key (sign/certify) | Ed25519 (legacy EdDSA) | v4 key format |
| Encryption subkey | X25519 (legacy ECDH) | v4 key format |
| Symmetric encryption | AES-256 | 256-bit key |
| Message format | SEIPDv1 (MDC) | Non-AEAD; GnuPG compatible |
| Hash | SHA-512 | Accepts SHA-256 for legacy verification |
| S2K (key export) | Iterated+Salted (mode 3) | GnuPG compatible |
| Compression | DEFLATE (read-only) | Enabled for reading compatibility; outgoing messages must not use compression |
| Random | SecRandomCopyBytes | Via `getrandom` crate on Apple platforms |

### Profile B (Advanced Security)

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Primary key (sign/certify) | Ed448 | v6 key format; ~224-bit security |
| Encryption subkey | X448 | v6 key format; inherent AES-256 key wrap |
| Symmetric encryption | AES-256 | 256-bit key |
| AEAD | OCB (primary), GCM (secondary) | SEIPDv2; OCB mandatory per RFC 9580 |
| Hash | SHA-512 | |
| S2K (key export) | Argon2id (512 MB / p=4 / ~3s) | Memory-hard |
| Compression | DEFLATE (read-only) | Enabled for reading compatibility; outgoing messages must not use compression |
| Random | SecRandomCopyBytes | Via `getrandom` crate on Apple platforms |

**Interoperability:** Profile A output compatible with GnuPG 2.1+ and all PGP tools. Profile B output compatible with Sequoia 2.0+, OpenPGP.js 6.0+, GopenPGP 3.0+, Bouncy Castle 1.82+. The App reads v4 keys, v6 keys, SEIPDv1, SEIPDv2 (OCB/GCM), Iterated+Salted S2K, and Argon2id S2K. Compression (`deflate`) read-only for compatibility; outgoing messages never compressed. Bzip2 excluded (extra C dependency).

## 2. Key Lifecycle

```
Generate (Profile A: Ed25519+X25519 v4 / Profile B: Ed448+X448 v6)
    │
    ├──→ SE Wrap (P-256 ephemeral-static ECDH + HKDF + AES-GCM, AAD-bound)
    │       │
    │       └──→ Store private-key material in Keychain (single envelope row per identity)
    │
    ├──→ Store PGPKeyIdentity metadata in ProtectedData `key-metadata`
    │       └──→ Opened after app-session authentication; no private-key material
    │
    ├──→ Auto-generate revocation certificate
    │       └──→ Prompt user to export separately
    │
    └──→ Prompt user to back up private key + share public key

Use (decrypt / sign):
    Keychain retrieve → decode envelope → SE reconstruct (biometric auth)
    → ECDH(SE priv × envelope ephemeral pub) → HKDF → AES-GCM unseal (AAD-checked)
    → Perform PGP operation → Zeroize private key from memory

Export (backup):
    Authenticate → User enters strong passphrase
    → Profile A: Iterated+Salted S2K protect → .asc file via Share Sheet
    → Profile B: Argon2id protect → .asc file via Share Sheet

Import (restore):
    .asc file → User enters passphrase → S2K derive (detect mode automatically) → Recover key
    → Generate key-level revocation signature for imported key
    → Generate new SE wrapping key → SE wrap → Store in Keychain

Revocation:
    Export ASCII-armored revocation signature → Distribute to contacts → They import → Key marked revoked

Deletion:
    Double-confirm → Delete the private-key envelope row from Keychain
    → Delete protected key-metadata entry
    → Key permanently inaccessible
```

**Metadata storage note:** `PGPKeyIdentity` metadata is non-sensitive indexing data, but it lives in the ProtectedData `key-metadata` domain so key-list loading happens only after app-session authentication opens protected app data. The sealed private-key envelope (which carries the SE key handle, ephemeral public key, salt, and AES-GCM sealed bytes in one row) remains in the protected private-key namespace.

**Revocation storage/export note:** CypherAir stores revocation signatures internally as binary OpenPGP signature packets. Export converts those bytes to ASCII armor on demand. Keys receive key-level revocation material at generation or import; export uses only the stored revocation artifact and fails closed when it is missing.

**Selective revocation note:** Subkey and User ID selective revocations are generated and exported on demand. They do not write back into `PGPKeyIdentity.revocationCert`, and they do not introduce an implicit persisted selective-revocation history alongside the key-level revocation slot.

**Certificate-signature workflow note:** Generated User ID certification signatures are saved in the protected `contacts` domain only when the user explicitly runs `Certify This Contact` and the generated signature verifies against the selected contact key and exact User ID selector. Saved certification artifacts are stored as canonical binary OpenPGP signature bytes with validation metadata and are armored only for explicit export/share. Raw text/file verify/import preview remains non-mutating until the user chooses `Save Signature`. Certification persistence does not insert signatures into a stored contact certificate, change per-key manual fingerprint verification state, or introduce trust / web-of-trust policy semantics.

**Profile-specific behavior:**
- **Generation:** Profile A → `CipherSuite::Cv25519` + `Profile::RFC4880`. Profile B → `CipherSuite::Cv448` + `Profile::RFC9580`.
- **Export:** Profile A → Iterated+Salted S2K. Profile B → Argon2id S2K.
- **Encryption format:** Determined by recipient key version, not sender profile. See [TDD](TDD.md) Section 1.4.

## 3. Secure Enclave Wrapping Scheme

The Secure Enclave supports only P-256. Private keys (Ed25519, X25519, Ed448, or X448) are protected via an indirect wrapping scheme. The wrapping scheme is identical for all key algorithms — the SE wraps raw private key bytes regardless of algorithm.

### Secure Enclave Custody (device-bound private-key model)

This wrapping scheme is the model for **software-custody** keys. A second,
**implemented** custody model — Apple Secure Enclave Custody, presented in the
product as the **Device-Bound key families** — performs private-key operations
inside the Secure Enclave and **never exports long-term private scalars**,
instead of unwrapping a complete OpenPGP secret certificate into app memory. It
is a custody model, not a third OpenPGP profile. Since Phase 7D (issue #501,
decision 3) the production capability-resolver policy exposes device-bound
generation and the implemented private-operation classes, and the production
container wires the generation service (hardware-guarded; only the custody
authorization and handle-load window runs inside an operation-prompt session
per §4). Phase 8 hardware and
GnuPG-interop evidence is captured and the Phase 9 release gate is satisfied
(2026-06-14); the families ship with the next tag-first stable release. The
custody model, security contract, operation surface, and evidence record live in
[Secure Enclave Custody](SECURE_ENCLAVE_CUSTODY.md).
The boundaries below are the durable security red lines this model must hold; code
under `Sources/Security/SecureEnclaveCustody*` and `pgp-mobile` is bound by them.
Mode switching is custody-aware: device-bound keys have no SE-wrapped software
bundle, so the re-wrap workflow and its crash recovery enumerate
software-custody fingerprints only, and the High Security backup expectation
applies to software-custody keys only (device-bound keys cannot be backed up).

- **Handles & access control.** Two distinct, role-tagged Secure Enclave P-256
  `SecKey` rows per identity — one `.signing`, one `.keyAgreement` — created with
  `kSecAttrTokenIDSecureEnclave` and `kSecAttrAccessControl` =
  `WhenUnlockedThisDeviceOnly + .privateKeyUsage + .biometryAny`. No
  `.devicePasscode`, no `.or`, and not the
  `AuthenticationMode.createAccessControl()` helper. Creation sets no
  `kSecAttrCanSign`/`kSecAttrCanDerive` usage flags; role trust comes from the
  separate role tag, public-key binding, and router policy. Application tags are a
  random local handle-set id plus role and never contain a fingerprint.
  Load/inspect fail closed unless the stored role and the 65-byte uncompressed
  X9.63 public key both match the expected values.

- **External operation boundary.** Rust/Sequoia owns all OpenPGP semantics; the
  Secure Enclave performs only the private scalar operation through a narrow
  callback. Signing: the callback receives the public key and a SHA-256 digest and
  returns a fixed-width ECDSA `r/s` that Rust verifies against that public key and
  digest. Key agreement (ECDH): the callback receives the recipient and ephemeral
  P-256 public keys and returns only a raw 32-byte shared secret; Rust owns ECDH
  KDF, AES Key Wrap unwrap, session-key validation, payload authentication, and
  verification folding. Swift zeroizes the shared-secret buffers it owns across the
  FFI handoff, and Rust hard-aborts a malformed or zero shared secret before trying
  any later PKESK. The callback never receives or returns secret certificate
  material.

- **Dispatch & fail-closed.** `PGPKeyCapabilityResolver` gates Secure Enclave
  generation, signing-class operations, and key-agreement operations
  independently. `PrivateKeyOperationRouter` consults the resolver before any
  Security handle lookup, returns software routes without unwrapping a secret
  certificate, and returns a Secure Enclave route only after the stored public
  certificate, fingerprint, key version, role, and public-key bindings agree with
  the Security-owned handle pair. A Secure Enclave route **never falls back** to
  software secret-certificate material; blocked routes surface sanitized
  unavailable categories. Recipient-key decrypt preserves the security-critical
  **Phase 1 / Phase 2 boundary** in `DecryptionService`: Phase 1 recipient parsing
  is unauthenticated and the matched-key guard runs before any private-key access.
  (This decrypt Phase 1/Phase 2 boundary is a permanent property of the decrypt
  flow, unrelated to the custody rollout phases.)

- **Sanitized failure mapping.** All custody error paths expose only stable,
  app-owned categories. Logs, errors, UI, ProtectedData, and Rust must never carry
  fingerprints, application tags, handle-set identifiers, public-binding bytes,
  Keychain locators, plaintext, private material, shared secrets, session keys,
  KEKs, digests, signatures, or temporary capability paths.

- **Storage, export & hard-fail.** Generation stores only the public certificate,
  the key-level revocation packet, and `.appleSecureEnclavePrivateOperations`
  custody in `key-metadata` schema v2 — never private material, application tags,
  handle locators, access-control policy, digests, or signatures. Public-key and
  revocation export use stored public artifacts only; a missing revocation artifact
  fails closed and is never regenerated; Secure Enclave private-key backup/export is
  unsupported and must not touch the `privkey-envelope` row.
  Payload authentication is unchanged: v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD hard-fail
  with no partial plaintext, and streaming file decrypt releases output only through
  the success-only `.tmp`-then-rename contract.

- **Reset & recovery.** Reset All Local Data inventories and deletes only app-owned
  custody `kSecClassKey` rows, including malformed app-owned tags identified by raw
  prefix bytes; startup/load classification never deletes orphan handles and
  produces only an in-memory sanitized metadata/handle report. List, delete, and
  remaining-row failures map to sanitized cleanup or recovery categories.

### ProtectedData Device-Binding Note

ProtectedData uses a separate app-data root-secret model and must not be
conflated with private-key envelope wrapping. The current ProtectedData v3 model
keeps the Keychain / `SecAccessControl` / authenticated `LAContext` gate, but
stores the root-secret Keychain payload as a single self-contained Secure Enclave
device-bound envelope instead of raw root-secret bytes.

The device-binding key is a ProtectedData-only P-256 Secure Enclave key with
`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and `.privateKeyUsage`. It
must not include `.userPresence`, `.biometryAny`, or `.devicePasscode`, because
the user authentication prompt remains the existing app-session Keychain gate.
The SE layer is a silent second factor that makes copied Keychain payloads and
ProtectedData files unusable away from the original device. The v3 envelope is a
single self-contained row: the device-binding key's Secure Enclave
`dataRepresentation` is folded into the envelope (there is no separate
persisted device-binding key item), and the handle is reconstructed from that folded blob at
open time — exactly as the private-key envelope folds its own SE key. The folded
blob is SE-encrypted and useless off-device. If the Secure Enclave cannot
reconstruct or use the folded key, or the reconstructed public key does not match
the envelope's bound public key, ProtectedData fails closed and requires framework
recovery/reset; there is no production fallback that opens ProtectedData without
the SE factor.

The v3 root-secret envelope is a binary-plist `CAPDSEV3` payload with
`algorithmID = p256-ecdh-hkdf-sha256-aes-gcm-v1`. It uses a software-ephemeral
P-256 ECDH exchange with the persistent ProtectedData SE public key. The
private-key envelope (`CAPKEV1`) uses the same ephemeral-static ECDH primitive,
but the two are deliberately domain-separated — distinct `magic` values and
distinct HKDF/AAD prefixes (`CAPDSEKI`/`CAPDSEAD` vs `CAPKKI`/`CAPKAD`) — and use
different persistent keys (one singleton device-binding key bound to a shared-right
identifier; one per-fingerprint SE key bound to the key fingerprint), so neither
blob can be misread as the other. The root-secret HKDF sharedInfo and AES-GCM AAD
bind the AAD version plus hashes of the folded device-binding key data and both
persistent SE and ephemeral public keys. The envelope is the only supported
root-secret payload: any payload that does not decode as a current `CAPDSEV3`
envelope fails closed as ordinary undecodable input.

ProtectedData domain payloads must open only after the app privacy gate has
produced an authenticated `LAContext` or an already-authorized ProtectedData
session. The post-unlock domain coordinator may reuse that context for
registered committed domains, but it must skip pending-mutation, missing
context, and no-domain states without fetching the root secret or starting a
second interactive prompt.

The private-key envelope is a binary-plist `CAPKEV1` payload with
`algorithmID = p256-ecdh-hkdf-sha256-aes-gcm-v1` (`PrivateKeyEnvelope` /
`PrivateKeyEnvelopeCodec`). It mirrors the ProtectedData root-secret envelope's
ephemeral-static ECDH construction but is domain-separated from it (distinct
`magic`, distinct HKDF/AAD prefixes `CAPKKI` / `CAPKAD`) so neither blob can be
misread as the other. The per-key Secure Enclave key is the persistent
key-agreement authority; a fresh software ephemeral P-256 key is generated per
seal. The SE key `dataRepresentation` is folded into the envelope so a single
Keychain row reconstructs the handle and reopens the material.

### Wrapping (on key generation or import)

1. Generate `SecureEnclave.P256.KeyAgreement.PrivateKey()` with access control flags matching the current auth mode.
2. Generate a software-ephemeral `P256.KeyAgreement.PrivateKey()` and compute the shared secret `ECDH(ephemeral private × persistent SE public)`.
3. Derive AES-256 key: `sharedSecret.hkdfDerivedSymmetricKey(using: SHA256, salt: randomSalt, sharedInfo: bindingData, outputByteCount: 32)`, where `bindingData` (prefix `CAPKKI`) binds the magic, algorithmID, lowercase hex fingerprint, and SHA-256 hashes of the SE key blob, persistent SE public key, and ephemeral public key, plus the plaintext length.
4. Seal: `AES.GCM.seal(privateKeyBytes, using: symmetricKey, nonce:, authenticating: aad)`, where `aad` is the same binding under prefix `CAPKAD` (domain-separated from the HKDF info).
5. Store one Keychain item: the encoded `CAPKEV1` envelope (SE key blob, persistent SE + ephemeral public keys, salt, nonce, ciphertext, tag). **Confirm the write succeeds.**
6. Only after successful storage: zeroize the raw private key bytes from memory (the `SymmetricKey` and `SharedSecret` are opaque CryptoKit values that clear their own storage).

**Public-parameter binding:** The fingerprint and both public keys are bound through HKDF `sharedInfo` and the AES-GCM AAD, so no public field can be substituted without breaking authentication. **The envelope is the only supported private-key payload: any row that does not decode as a current `CAPKEV1` envelope fails closed as ordinary undecodable input.** There is no supported legacy private-key wrapping local data to migrate.

**Ordering rationale (steps 5–6):** Storage is performed before zeroization. If storage fails or the process crashes before step 5 completes, the raw key bytes are still in memory and the operation can be retried. If zeroization happened first and storage then failed, the key would be permanently lost.

### Unwrapping (on decrypt or sign)

1. Retrieve the encoded envelope row from Keychain and decode + validate it (magic / version / algorithm / lengths / fingerprint binding; both public keys parse as P-256 points).
2. Reconstruct the SE key from the envelope's `seKeyData` — this triggers device authentication (Face ID / Touch ID, with or without passcode fallback depending on auth mode).
3. Fail closed if the envelope's bound SE public key does not match the reconstructed handle, then compute `ECDH(SE private × envelope ephemeral public)` and re-derive the symmetric key + AAD from the envelope's public fields.
4. `AES.GCM.open` (AAD-checked) → raw private key bytes in application memory; any tamper, wrong binding, or wrong fingerprint aborts here with no plaintext.
5. Perform the PGP operation.
6. Zeroize the private key bytes immediately.

### Security Properties

- Keychain data extraction without the SE hardware yields an encrypted blob that cannot be decrypted.
- The SE key's `dataRepresentation` is bound to the SoC UID (fused at manufacturing, never exposed to software).
- The raw private key exists in application memory briefly during use. This is an inherent tradeoff of the P-256-only SE constraint.
- SE ECDH latency: ~2–5ms. Imperceptible to users.

## 4. Authentication Modes

> **Auth-lifecycle redesign (landed).** Authentication presentation is the **system authentication
> sheet** for both subsystems on every platform, and both private-key modes (this section) and both
> app-session policies (§5) are permanent, user-selectable product features everywhere. App lock is
> an explicit state machine (`AppLockController`: `.locked` / `.authenticating` / `.unlocked`) with
> per-platform away events, and **each system authentication prompt runs inside a short
> operation-prompt session that covers the prompt and the immediately following Keychain /
> Secure Enclave call that consumes that same `LAContext`**. Longer user-action work such as
> PGP generation, import parsing, journaling, commits, reset I/O, and UI state updates stays
> outside the session, so prompt lifecycle resigns are deferred while genuine macOS away
> events under grace=0 still relock as soon as they occur. Key-expiry modification authenticates
> **once** per action with a subsystem-B `LAContext` confined to that action. The previously
> planned in-window (`LAAuthenticationView`) cutover and the macOS
> passcode-fallback removals were **retired**: macOS 27 denies embedded LocalAuthentication UI to
> non-Apple-signed processes (LA -1007).

### Standard Mode (default)

```swift
let accessControl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryAny, .or, .devicePasscode],
    &error
)
```

Face ID / Touch ID with device passcode fallback. Equivalent to `LAPolicy.deviceOwnerAuthentication`. Suitable for most users.

### High Security Mode

```swift
let accessControl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryAny],
    &error
)
```

Face ID / Touch ID only. No passcode fallback. If biometrics are unavailable (sensor damaged, face obscured, biometry locked out after 5 failures), all private-key operations (decrypt, sign, export) are blocked until biometric auth is restored.

High Security protects private-key operations by requiring biometric authorization and denying device-passcode fallback. The current policy uses `.biometryAny`, so it does not invalidate keys merely because biometric enrollment changes.

### Mode Switching Procedure

When the user changes mode in Settings:

1. Display warning. If switching to High Security and no backup exists, show a stronger warning requiring explicit acknowledgment.
2. Record the rewrap target and phase in the post-unlock `private-key-control.recoveryJournal`.
3. Authenticate under the **current** mode (proves the user has authority to change).
4. For each private key:
   a. Unwrap using the current SE key.
   b. Generate a new SE key with the **new** access control flags.
   c. Re-wrap the private key with the new SE key.
   d. Store the new envelope under the **temporary (pending) row** `com.cypherair.v1.pending-privkey-envelope.<fingerprint>`.
   e. Zeroize the raw key bytes from memory.
5. **Verify all new pending rows are successfully stored.**
6. Delete the **old** permanent row (`com.cypherair.v1.privkey-envelope.<fingerprint>`).
7. Promote each pending row to its permanent name.
8. Persist the new mode to `private-key-control.settings.authMode`.
9. Clear the `private-key-control.recoveryJournal` rewrap entry.

**Atomicity:** Old Keychain items are kept intact until ALL new items are confirmed stored (step 5). If any step fails before step 6, the original keys are unaffected — delete the temporary items and report the error.

**Crash recovery:** After app-session authentication opens `private-key-control`, check the rewrap recovery journal. If an entry is present:
- If the permanent envelope row exists and a pending row exists, the permanent row is treated as authoritative. Delete the pending row and keep the original mode.
- If the permanent envelope row is absent or invalid but the pending row is complete, promote the pending row to the permanent service name.
- If neither namespace contains a complete envelope row, recovery is **unrecoverable**. Clear the journal entry, surface a generic post-unlock warning, and require the user to restore from backup if private-key operations fail.
- If deletion or promotion fails for a retryable reason (for example, transient Keychain write/delete failure), preserve the recovery journal so the app retries recovery after the next successful unlock.
- Recovery diagnostics are surfaced through the app's existing post-unlock warning path and must remain generic — never include fingerprints or other key identifiers.
- Persist the new auth mode only after a full successful promotion of complete pending envelope rows. Cleaning stale pending rows alone must not change auth mode.
- This ensures the app prefers an existing permanent row over a pending one and avoids silently finalizing an inconsistent state.

### LAPolicy Selection

| Mode | LAPolicy | Fallback Button |
|------|----------|-----------------|
| Standard | `.deviceOwnerAuthentication` | Passcode shown |
| High Security | `.deviceOwnerAuthenticationWithBiometrics` | `context.localizedFallbackTitle = ""` (hidden) |

## 5. Protected App Data

Protected app data is a separate security domain for CypherAir-owned local state outside private-key material. It must not be conflated with the Secure Enclave wrapping path that protects OpenPGP secret key bytes.

Protected app-data scope and per-surface classification live in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md). This security model records the rules and invariants; the inventory records the row-level domains, paths, current support cutoffs, and export/temp exceptions.

Security invariants for protected app data:

- Protected domains open only after app privacy authentication and the shared ProtectedData authorization path.
- ProtectedData is separate from the private-key material domain; permanent and pending SE-wrapped private-key envelope rows remain under the Keychain / Secure Enclave private-key-material boundary.
- `appSessionAuthenticationPolicy` remains the documented early-readable boot-authentication exception.
- Legacy flat Contacts files under `Documents/contacts` are outside the supported app-state model. CypherAir no longer reads, migrates, quarantines, or reset-cleans them.
- Contacts production state stays inside the protected `contacts` domain. Certification-signature export/share is an explicit artifact export boundary, not a Contacts backup, package, or social-graph export.
- Manual Contacts verification is a local fingerprint-check assertion and is not OpenPGP certification. Saved certification artifacts stay under app custody until the user explicitly exports or shares a certification signature.
- Contacts does not provide multi-contact package exchange or social-graph export. Any future complete Contacts backup or device migration must be mandatory encrypted.
- Self-test, decrypted, streaming, export handoff, and tutorial artifacts keep the inventory's ephemeral-with-cleanup behavior; files exported to user-selected destinations are outside app custody after handoff.

UserDefaults is allowed only for documented boot, test, and tutorial exceptions. Personal or sensitive app data must not be newly introduced there; post-auth settings use `protected-settings` unless they are explicit boot-authentication exceptions.

Protected app-data authorization uses `AppSessionAuthenticationPolicy`, not private-key `AuthenticationMode`. `AppLockController` owns the explicit lock state and the away/grace lifecycle; `AppSessionOrchestrator` owns the authentication record and the authorization-handoff custody. When app authentication succeeds, the controller hands the authenticated `LAContext` to `ProtectedDataSessionCoordinator`, which reads the shared app-data root secret through Keychain with `kSecUseAuthenticationContext`. That same authenticated handoff is reused by post-unlock domain openers so committed registered domains can open without a second Face ID / Touch ID prompt.

`ProtectedOrdinarySettingsCoordinator` owns ordinary-settings availability. It loads grace period, onboarding completion, encrypt-to-self, and guided tutorial completion from `protected-settings` schema v2 only after app privacy authentication and an unlocked protected-settings handoff. Schema v2 payloads are strict: missing or corrupt ordinary settings enter protected-settings recovery instead of resetting to defaults. If the setting snapshot is unavailable, the resume grace window fails closed to immediate authentication, startup/onboarding routing waits for a loaded snapshot, and encryption does not silently use the app-default encrypt-to-self value for real work.

`KeyMetadataDomainStore` owns key metadata availability. It stores `key-metadata` schema v2 payloads with `PGPKeyIdentity` records that explicitly include app-owned OpenPGP configuration identity and private-key custody kind. The domain remains metadata-only: it must not store Apple Secure Enclave handle locators, access-control policy, salts, sealed boxes, secret certificate bytes, or any other private material. Corrupt, missing, or bootstrap-mismatched current committed metadata enters recovery.

Key operation failure categories are app-owned sanitized classifications for resolver, future router, Security, Rust/UniFFI, workflow-service, and UI mapping boundaries. Local-authentication categories are explicitly separate from payload-authentication failure. They must not contain plaintext, private-key material, shared secrets, session keys, KEKs, Keychain locators, stable fingerprints, temporary capability paths, or other secret-bearing values. They do not persist Secure Enclave handle state and do not replace payload-authentication hard-fail behavior.

The shared root secret is not stored as raw bytes in the current format. Keychain stores a single self-contained v3 `CAPDSEV3` envelope that reconstructs its folded ProtectedData-only Secure Enclave device-binding key and unwraps through it, as described in Section 3. The raw root secret is used only to derive the wrapping root key and is immediately zeroized. Each protected domain has its own random domain master key, persisted only as a Keychain-backed self-describing `CADMKV2` wrapped-DMK envelope under the derived wrapping root key. Unwrapped domain keys and decrypted payloads are session-local and must be cleared on relock.

Contacts uses the stable `contacts` ProtectedData domain identity with SQLCipher as the authoritative Contacts payload. The unwrapped `contacts` domain master key is handed directly to SQLCipher through raw-key syntax for `contacts.sqlite`; CypherAir does not create a second Contacts database-key Keychain row. The raw-key buffer is short-lived and zeroized after keying, and the open SQLCipher connection is treated as sensitive runtime state that must be closed on relock and before reset/recovery deletion. Legacy Contacts snapshot-envelope artifacts are not a fallback source of truth.

`ProtectedDataRegistry` is the only authority for committed protected-domain membership and pending create/delete work. Cold start may read the registry and per-domain bootstrap metadata before app authentication, but it must not retrieve the root secret, unwrap any DMK, open domain payloads, or infer committed membership by directory enumeration. Invalid registry state enters framework recovery. Domain corruption enters the domain's recovery state; no protected domain may silently reset unreadable state to empty data.

Relock is fail-closed. `ProtectedDataSessionCoordinator` blocks new protected-domain access, fans out to all registered `ProtectedDataRelockParticipant`s, zeroizes the wrapping root key, clears unwrapped DMKs, and returns to `sessionLocked` only if teardown succeeds. The ordinary-settings coordinator also clears its loaded snapshot on relock/content clear. Any relock participant failure latches runtime-only `restartRequired`, blocking further protected-domain access until process restart.

ProtectedData files live under the protected app-data storage root documented in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md). Registry files, bootstrap metadata, scratch writes, committed domain files, and managed Contacts SQLCipher database sidecars use explicit file-protection verification where the platform supports it. Wrapped-DMK custody lives in app-owned Keychain staged/committed rows. Storage outside the app-owned container is not an allowed fallback for protected-domain files.

## 6. Guided Tutorial Sandbox Isolation

The guided tutorial is allowed to run real app services and real OpenPGP operations only inside an isolated tutorial dependency graph. It must not read or mutate the user's real keys, contacts, settings, files, exports, or private-key security assets.

Tutorial isolation boundaries:

- `TutorialSandboxContainer` uses the fixed `com.cypherair.tutorial.sandbox` `UserDefaults` suite and a temporary contacts directory with verified complete file protection instead of the app's real preferences and real Contacts storage. The product flow owns a single active tutorial sandbox at a time; container creation and current tutorial cleanup clear the fixed suite and directory, and startup and Reset All Local Data also remove the fixed suite plist.
- Tutorial key management, encryption, decryption, signing, certificate, QR, and self-test services are constructed against tutorial-local storage and the same Rust engine API shape used by the real app.
- Tutorial private-key protection currently uses mock Secure Enclave and mock Keychain primitives behind a real `AuthenticationManager` instance, so auth-mode behavior is exercised without touching real Secure Enclave-wrapped private keys or real Keychain rows. This is temporary SR-FIX-18 debt: tutorial/UI-test mocks must remain visibly named `Mock*`, stay under `Sources/Security/Mocks`, and keep mock-owned errors instead of impersonating production `KeychainError`.
- `OutputInterceptionPolicy` and page-level configuration must block or intercept real file import/export, clipboard writes, share-sheet export, URL handoff, app icon changes, onboarding management actions, and other real-workspace side effects.
- Tutorial completion state is the only tutorial fact that persists across app restarts. Tutorial keys, contacts, messages, settings, and unfinished module progress are ephemeral and are cleaned up when the tutorial is reset or finished.

Changes to tutorial isolation, output interception, or tutorial security simulation must be reviewed with the same care as other auth and local-data boundaries. A tutorial regression must never weaken the app's zero-network, minimal-permission, no-secret-logging, or real-workspace isolation guarantees. The long-term direction is to replace tutorial mocks with tutorial-specific isolated Protected Data domains and real hardware-backed processing that never reads or mutates user security assets.

## 7. Argon2id Parameters (Profile B Only)

Used only for private key export (backup) and for importing/unlocking passphrase-protected private key files. **Not used for routine message decryption or signing** — those operations use the SE-unwrapped private key directly.

**Not used by Profile A.** Profile A uses Iterated+Salted S2K (mode 3).

| Parameter | Value | RFC 9580 Encoding |
|-----------|-------|-------------------|
| Memory | 512 MB (524,288 KiB) | `encoded_m = 19` (2^19 KiB) |
| Parallelism | 4 lanes | `p = 4` |
| Time | Fixed at 3 passes (~3s target on contemporary hardware) | `t = 3` |

### iOS Memory Safety Guard

Before Argon2id derivation **when importing or unlocking a passphrase-protected private key file** (this guard does NOT apply to routine message decryption):

1. Parse the S2K specifier from the key file.
2. Calculate required memory: `2^encoded_m` KiB.
3. Query `os_proc_available_memory()`.
4. If required > 75% of available memory: **refuse** with error message: _"This key uses memory-intensive protection that exceeds this device's capacity."_
5. Return a user-facing refusal error before Argon2id derivation begins.

This prevents iOS Jetsam from killing the app. The 75% threshold provides a safety margin.

## 8. Memory Integrity Enforcement (MIE)

### What It Protects

MIE is built into supported Apple hardware and software, including current A19/A19 Pro devices such as iPhone 17 and iPhone Air. It provides hardware-level defense against buffer overflows and use-after-free in all C/C++ code, including vendored OpenSSL. The system allocator assigns 4-bit tags to heap allocations. Every memory access is checked by hardware in real time. Tag mismatch = immediate process termination.

### Enablement

Enhanced Security is enabled via Signing & Capabilities → Add Capability → Enhanced Security → enable Hardware Memory Tagging. When this capability is added, Xcode writes the required entitlement keys into `CypherAir.entitlements`:

- `com.apple.security.hardened-process` → `true`
- `com.apple.security.hardened-process.enhanced-security-version-string` → `1`
- `com.apple.security.hardened-process.hardened-heap` → `true`
- `com.apple.security.hardened-process.platform-restrictions-string` → `2`
- `com.apple.security.hardened-process.dyld-ro` → `true`
- `com.apple.security.hardened-process.checked-allocations` → `true` (Hardware Memory Tagging)
- `com.apple.security.hardened-process.checked-allocations.enable-pure-data` → `true`
- `com.apple.security.hardened-process.checked-allocations.no-tagged-receive` → `true`

**These entitlement keys must be committed to source control.** Xcode reads the `.entitlements` file to determine which protections are enabled. Removing the keys disables the corresponding protections.

Additionally, verify `ENABLE_ENHANCED_SECURITY = YES` in both Debug and Release build settings in `project.pbxproj`.

### Testing Workflow

1. **Xcode diagnostics:** Enable Hardware Memory Tagging in Scheme → Run → Diagnostics. Run full test suite on supported A19/A19 Pro-or-newer hardware. Any tag mismatch surfaces as a crash with exact location.
2. **Production:** Tag mismatches terminate the process immediately. This is the desired behavior — it converts silent corruption into a detectable, non-exploitable crash.

### Impact on Vendored OpenSSL

The `openssl-src` crate compiles OpenSSL from C source. Any undiscovered buffer overflow or use-after-free in OpenSSL will cause an immediate crash under MIE. This is the desired behavior — it converts silent corruption into a detectable, non-exploitable crash. Test all Sequoia + OpenSSL code paths (AES-256, SHA-512, Ed25519, X25519, Ed448, X448, Argon2id) under Hardware Memory Tagging diagnostics.

### Compatibility

| Device | MIE Behavior |
|--------|-------------|
| Supported A19/A19 Pro-or-newer devices, including current iPhone 17 and iPhone Air models | Full hardware memory tagging active |
| Older unsupported devices | Software-only typed allocator. No hardware tagging. |

The Enhanced Security capability is additive. It never breaks compatibility with older devices.

## 9. Known Limitations

### 9.1 Passphrase `String` Cannot Be Reliably Zeroized

**Scope:** Affects passphrase-based flows that originate in Swift `String`, specifically private key import/export and password-message encrypt/decrypt operations. It does **not** affect routine recipient-key decryption or signing, which use SE-unwrapped key bytes (`Data`) that are properly zeroized.

**Issue:** Swift `String` is a value type with copy-on-write semantics. There is no supported API to overwrite a `String`'s internal buffer in place. When the user enters a passphrase for key export (S2K protection), key import (S2K unlock), or password-message encrypt/decrypt (`SKESK`), the passphrase exists as a `String` in memory until ARC deallocates it. The exact lifetime depends on the Swift runtime and is not deterministic.

**Why this is not fixed:**

1. **SwiftUI constraint:** `SecureField` — the only system-provided secure text input — binds to `String`. There is no `Data`-backed alternative.
2. **FFI boundary:** UniFFI transfers `String` by copying through `RustBuffer`. Even if the Swift side could zeroize its copy, the Rust side receives an independent copy (which Sequoia consumes and the Rust `zeroize` crate handles on its side).
3. **Platform-wide pattern:** No shipping iOS app (including Apple's own Keychain prompts) can zeroize `String` passphrases. This is an accepted platform limitation.

**Mitigations:**

- **Short lifetime:** The passphrase `String` is only alive for the duration of the active import/export or password-message call. It is not stored in any persistent state, UserDefaults, or Keychain.
- **Rust-side zeroize:** The `zeroize` crate ensures the Rust copy of the passphrase is overwritten after use.
- **iOS memory protections:** ASLR, sandboxing, and MIE (on supported A19/A19 Pro-or-newer devices) make memory scanning attacks significantly harder.
- **Immediate Rust conversion:** Password-message APIs convert the Swift `String` into Sequoia `Password` at the FFI boundary so the Rust-side representation is encrypted in memory and only decrypted on demand.

**Rejected alternatives:**

- `UnsafeMutableBufferPointer<UInt8>` with manual zeroing: Would require forking `SecureField` or building a custom UIKit text field, bypassing system-provided secure input. The security loss from a custom input field (no system-level screen recording protection, no secure text entry mode) would outweigh the benefit of zeroizable memory.
- `Data`-based passphrase: UniFFI does not support `Data` ↔ `String` conversion at the FFI boundary without an intermediate `String` allocation, negating the benefit.

## 10. AI Coding Red Lines

The following files and functions are security-critical. Coding agents may edit them directly, but every security-sensitive edit must be **explicitly called out — file, what changed, and why — in the task summary and PR description**, must include the testing requirements at the end of this section, and requires human review before merge (see [CODE_REVIEW.md](CODE_REVIEW.md)). Never merge such a change autonomously.

### Absolute Coding Invariants

These hold for every change, independent of which file is touched:

- **Secure random only.** Use `SecRandomCopyBytes` or CryptoKit (Swift) and the `getrandom` crate (Rust) for all security-relevant randomness. Never `arc4random` or `Int.random`.
- **No secret logging — not even in DEBUG.** Never `print()`, `os_log()`, or `NSLog()` key material, passphrases, or decrypted content, including in DEBUG builds.
- **Zero network, but local IPC is allowed.** The custom `cypherair://` URL scheme is local inter-process communication, not network access, and does not violate the zero-network rule.

### Files Requiring Human Review

| File | Reason |
|------|--------|
| `Sources/Security/SecureEnclaveManager.swift` | SE wrapping/unwrapping logic. Error = keys lost or insecure. |
| `Sources/Security/PrivateKeyEnvelope.swift` | `CAPKEV1` private-key envelope (ephemeral-static ECDH, HKDF/AAD binding, contract validation). Error = keys lost, tamper accepted, or domain separation broken. |
| `Sources/Security/KeyBundleStore.swift` | Single-row private-key envelope persistence, pending/permanent promotion, interrupted-rewrap state. Error = key material lost or recovery fails open. |
| `Sources/Security/SecureEnclaveCustody*` | Secure Enclave custody handle lifecycle, access-control policy, role/public-key binding, and sanitized failure mapping. |
| `Sources/Security/KeychainManager.swift` | Access control flags. Wrong flags = wrong auth behavior. |
| `Sources/Security/AuthenticationManager.swift` | Mode switching re-wrap. Error = keys permanently lost. |
| `Sources/Security/ProtectedData/` | App-data root-secret authorization, SE device-binding envelope, domain master-key wrapping, reset semantics. Error = protected app data lost or opened under the wrong gate. |
| `Sources/Security/MemoryZeroingUtility.swift` | Removing a zeroize call = key material leaks. |
| `Sources/Extensions/Data+Zeroing.swift` | Contains `@_optimize(none)` zeroing barrier. Weakening = compiler may eliminate all memory zeroing app-wide. |
| `Sources/Services/DecryptionService.swift` | Phase 1/Phase 2 auth boundary. Skipping Phase 2 auth check = biometric bypass. |
| `Sources/Services/QRService.swift` | Parses untrusted external input (`cypherair://` URLs). Bugs here may trigger Sequoia parser on malicious data. |
| `pgp-mobile/src/decrypt.rs` | AEAD hard-fail enforcement. Weakening = plaintext leaks. |
| `pgp-mobile/src/streaming.rs` | Streaming file encrypt/decrypt with buffer zeroing. Error in temp file handling = plaintext leaks to disk. |
| `pgp-mobile/src/error.rs` | PgpError enum. Must stay 1:1 with Swift. |
| `Sources/Services/DiskSpaceChecker.swift` | Disk space validation threshold. Wrong threshold = Jetsam termination during file operations. |
| `CypherAir.entitlements` | MIE, Enhanced Security entitlements. |
| `CypherAir-Info.plist` | Only `NSFaceIDUsageDescription` permitted. No other usage descriptions. |

### Functions Requiring Human Review

- Any function that calls `SecAccessControlCreateWithFlags`
- Any function that calls `SecKeyCreateRandomKey`, `SecItemCopyMatching`, or `SecItemDelete` for `kSecClassKey`
- Any function that calls `SecureEnclave.P256.KeyAgreement.PrivateKey()`
- Any function that calls `AES.GCM.seal()` or `AES.GCM.open()` on key material
- Any function that calls `HKDF<SHA256>.deriveKey()`
- Any function that writes to or deletes from Keychain
- The `os_proc_available_memory()` guard in Argon2id handling
- Any Rust function marked `pub` in `pgp-mobile/src/lib.rs`
- URL parsing logic in `QRService` that handles `cypherair://` scheme input
- Profile/CipherSuite selection in key generation

### Testing Requirements for Security Changes

Every change to a file listed above must include:

1. **Positive test:** The operation succeeds with correct inputs and proper authentication.
2. **Negative test:** The operation fails gracefully with wrong inputs (wrong key, wrong passphrase, tampered data, unavailable biometrics).
3. **Round-trip test:** For crypto operations — encrypt then decrypt, sign then verify, wrap then unwrap.
4. **No-leak test:** For memory-sensitive changes — verify that sensitive data is zeroized after use (inspect with Xcode Memory Graph Debugger or Instruments).
