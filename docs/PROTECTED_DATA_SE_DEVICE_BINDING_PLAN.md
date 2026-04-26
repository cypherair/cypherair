# ProtectedData Secure Enclave Device-Binding Plan

> Superseded implementation guide. The Secure Enclave device-binding layer is
> now implemented; the permanent architecture/security/testing docs are the
> source of truth. Keep this file only as a short-term implementation audit
> record until it is archived.

## 1. Apple Documentation Baseline

This design was checked against Apple Developer Documentation in Chrome, not
from search-result summaries:

- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [kSecAttrTokenIDSecureEnclave](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly)
- [CryptoKit SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave)
- [SecureEnclave.P256.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey)
- [P256.KeyAgreement.PublicKey](https://developer.apple.com/documentation/cryptokit/p256/keyagreement/publickey)
- [SharedSecret.hkdfDerivedSymmetricKey(using:salt:sharedInfo:outputByteCount:)](https://developer.apple.com/documentation/cryptokit/sharedsecret/hkdfderivedsymmetrickey(using:salt:sharedinfo:outputbytecount:))
- [SecAccessControlCreateFlags.privateKeyUsage](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage)

Relevant constraints:

- Secure Enclave keys must be generated on the Secure Enclave; pre-existing
  private keys cannot be imported.
- Secure Enclave supports P-256 key agreement/signing keys for this use case,
  and CryptoKit exposes `SecureEnclave.P256.KeyAgreement.PrivateKey` plus
  `sharedSecretFromKeyAgreement(with:)`.
- `.privateKeyUsage` enables private-key operations. Adding user-presence or
  biometric flags is optional and would add a second authentication
  requirement, which this design intentionally avoids.
- `ThisDeviceOnly` accessibility means the item is not portable to another
  device. `WhenPasscodeSetThisDeviceOnly` additionally ties availability to a
  configured device passcode and can make data unrecoverable if that condition
  is lost.
- P-256 public keys can be represented and reconstructed with X9.63 bytes;
  the v2 envelope uses that representation for both SE and ephemeral public
  keys.

## 2. Design Goal

ProtectedData v1 currently uses one shared app-data root secret stored in the
data-protection Keychain and released only after app-session authentication via
`LAContext` / `kSecUseAuthenticationContext`.

The v2 implementation keeps that authentication gate and adds a second device-bound
factor:

```text
App privacy Face ID / Touch ID / passcode
    -> authenticated LAContext
    -> LA-gated root-secret Keychain row returns v2 envelope
    -> silent Secure Enclave P-256 key agreement unwraps envelope
    -> raw root secret exists briefly in memory
    -> HKDF derives AppDataWrappingRootKey
    -> per-domain DMKs unwrap as they do today
```

This is not a replacement for app-session authentication. It is an additional
device-binding layer that makes copied Keychain payloads and ProtectedData files
useless without the original Secure Enclave key.

The existing private-key Secure Enclave wrapping implementation is useful as a
local reference for coding style, tracing, and mock coverage only. It is not
the ProtectedData v2 specification. ProtectedData v2 must not copy the existing
private-key self-ECDH wrapping scheme; the root-secret envelope uses a normal
one-time software ephemeral P-256 key agreement with the persistent
ProtectedData SE public key.

## 3. Root-Secret Envelope v2

The root-secret Keychain row remains under
`ProtectedDataRightIdentifiers.productionSharedRightIdentifier` and remains
protected by `AppSessionAuthenticationPolicy`.

The row payload changes from legacy v1 raw root-secret bytes to a v2 envelope.
The canonical storage encoding is a binary property list. The encoded Swift
model must be deterministic in field meaning, but decoding must validate every
field before cryptographic use.

Required fields:

- `magic = CAPDSEV2`
- `formatVersion = 2`
- `algorithmID = p256-ecdh-hkdf-sha256-aes-gcm-v1`
- `aadVersion = 1`
- `sharedRightIdentifier`
- `deviceBindingKeyIdentifier`
- `deviceBindingPublicKeyX963`
- `ephemeralPublicKeyX963`
- `hkdfSalt`
- `nonce`
- `ciphertext`
- `tag`

Required field contracts:

- `deviceBindingPublicKeyX963` and `ephemeralPublicKeyX963` are P-256 X9.63
  public key representations, produced and parsed with CryptoKit
  `x963Representation` APIs.
- `hkdfSalt` is 32 bytes generated with secure randomness.
- `nonce` is 12 bytes generated with secure randomness.
- `tag` is 16 bytes.
- `ciphertext` is exactly the raw root-secret length, currently 32 bytes.
- AES-GCM `nonce`, `ciphertext`, and `tag` are stored as separate fields, not
  as CryptoKit's combined representation.
- Unsupported `magic`, `formatVersion`, `algorithmID`, field lengths, or public
  key encodings fail closed before attempting to unwrap.

HKDF and AAD:

- Derive the envelope wrapping key with
  `SharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: hkdfSalt,
  sharedInfo: rootSecretEnvelopeSharedInfoV1, outputByteCount: 32)`.
- `rootSecretEnvelopeSharedInfoV1` must include at least `magic`,
  `formatVersion`, `algorithmID`, `aadVersion`, `sharedRightIdentifier`,
  `deviceBindingKeyIdentifier`, `SHA256(deviceBindingPublicKeyX963)`,
  `ephemeralPublicKeyX963.count`, and `ciphertext.count`.
- AES-GCM AAD must include the same version/algorithm/key-identity binding and
  field-length binding. Its purpose is to make field substitution, envelope
  confusion, and downgrade-shaped payloads fail authentication.

Seal flow:

1. Generate or load a ProtectedData-only Secure Enclave P-256 key.
2. The SE key uses `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and
   `.privateKeyUsage`; it must not include `.userPresence`, `.biometryAny`, or
   `.devicePasscode`.
3. Generate a software ephemeral P-256 key pair for this seal operation.
4. Derive ECDH shared secret from ephemeral private key and SE public key.
5. HKDF-SHA256 derives a 32-byte root-secret wrapping key using the versioned
   ProtectedData-specific salt and sharedInfo described above.
6. AES-GCM seals the raw root secret with the versioned AAD described above.
7. Store only the envelope in the LA-gated Keychain row.

Open flow:

1. App-session authentication provides the `LAContext`.
2. Keychain returns the v2 envelope through `kSecUseAuthenticationContext`.
3. Reconstruct/load the ProtectedData SE device-binding key.
4. Derive ECDH shared secret from SE private key and stored ephemeral public key.
5. HKDF derives the same wrapping key.
6. AES-GCM opens the envelope and returns raw root-secret bytes.
7. Immediately derive `AppDataWrappingRootKey`; zeroize raw root-secret bytes.

## 4. Migration And Failure Semantics

Migration from v1 raw payload is allowed only during an already-authenticated
ProtectedData authorization:

- If the loaded root-secret payload is v2, open it through SE and continue.
- If the loaded payload is legacy v1 raw bytes, immediately seal it into v2,
  write the v2 Keychain payload, verify v2 can be reopened, then continue.
- If SE generation, SE reconstruction, v2 seal, Keychain update, or v2 verify
  fails, authorization fails closed and the framework enters recovery/reset
  required state.
- After v2 verifies, normal authorization must use only v2. If implementation
  needs to preserve the v1 raw value for one restart as a migration safety net,
  it must move that value into an explicit `legacy-cleanup` / staging row and
  must never read that row as an authorization fallback.
- On the next successful app start that opens the v2 envelope, the migration
  cleanup path must delete any `legacy-cleanup` row and record that cleanup in
  AuthTrace. Missing cleanup rows are success.

Downgrade prevention:

- Successful v2 verification must write both a registry state marker and a
  ThisDeviceOnly Keychain `format-floor` marker saying this installation has
  reached root-secret envelope v2.
- If either marker indicates v2 and the root-secret row later decodes as v1 raw
  bytes, authorization must fail closed as a downgrade/corruption condition.
- The `format-floor` marker is not a secret and does not authorize access, but
  it must be ThisDeviceOnly so copied older app data cannot erase the local v2
  floor during restore-style rollback.

There must be no production fallback that decrypts ProtectedData without the
Secure Enclave after the device-binding layer is introduced. This is the point of
the new layer, and a fallback would defeat the threat model.

Data-loss semantics must be explicit:

- deleting the ProtectedData SE key makes existing v2 ProtectedData
  unrecoverable
- disabling/removing the device passcode may make the SE binding key unusable
- device restore/migration cannot carry the SE factor to another device
- Reset All Local Data must remove the root-secret row, the SE device-binding
  key row, ProtectedData files, and in-memory derived keys

## 5. Trace Rules

AuthTrace may record:

- envelope version
- algorithm ID
- device-binding stage name
- presence/absence of the SE key
- presence/absence of the registry and Keychain `format-floor` markers
- OSStatus / NSError domain and code
- migration result
- legacy cleanup result
- whether the operation used a handoff or interactive context

AuthTrace must not record:

- raw root secret
- ECDH shared secret
- HKDF output
- AES-GCM plaintext
- private key dataRepresentation
- full envelope payload
- X9.63 public key bytes
- ProtectedData domain plaintext

Salt and nonce values should not be logged by default; record lengths and
versions instead.

## 6. Implementation Checklist

- Add a mockable ProtectedData device-binding protocol separate from the
  private-key `SecureEnclaveManageable` protocol.
- Add production Secure Enclave implementation and software mock.
- Add `ProtectedDataRootSecretEnvelope` encode/decode/validate helpers.
- Update `KeychainProtectedDataRootSecretStore` or a wrapper layer so callers
  continue to ask for root-secret bytes while storage can hold v1 or v2.
- Add migration from v1 raw root secret to v2 envelope during authorization.
- Add `format-floor` downgrade prevention through registry state and a
  ThisDeviceOnly Keychain marker.
- Add `legacy-cleanup` staging and next-successful-v2-open cleanup if the
  implementation keeps a one-restart v1 safety copy.
- Update root-secret reprotection so it changes Keychain access control without
  changing the v2 envelope or requiring an extra prompt.
- Update Reset All Local Data to delete and verify the ProtectedData SE
  device-binding key.
- Keep all private-key bundle behavior unchanged.

## 7. Test Matrix

macOS unit tests:

These must run in the normal macOS unit-test lane with mock device-binding
providers:

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
```

- v2 envelope seal/open round trip with the mock device-binding provider
- exact envelope field-length validation for salt, nonce, tag, public keys, and
  32-byte root-secret ciphertext
- unsupported magic, envelope version, algorithm ID, and malformed AAD fail
- HKDF sharedInfo mismatch fails
- tampered ciphertext, tag, nonce, salt, device-binding public key, and
  ephemeral public key fail
- legacy v1 raw root secret migrates to v2 after authorization
- registry + Keychain `format-floor` markers reject a later v1 raw payload
- `legacy-cleanup` row is deleted after the next successful v2 open and is not
  used as a fallback
- migration failure fails closed and does not continue authorization
- root-secret reprotection preserves the v2 envelope payload
- reset deletes root secret and device-binding key, and item-not-found remains
  success
- AuthTrace includes stage/result/error metadata but no secret material

Device-only tests:

- create ProtectedData on real Secure Enclave hardware, restart, authenticate
  once, and reopen protected settings
- delete the device-binding key while keeping the root-secret row and confirm
  ProtectedData enters recovery/reset required
- verify no additional Face ID prompt is introduced by the SE layer

Manual validation:

- normal launch still shows one app privacy authentication
- Settings protected section can reuse the authenticated app-session handoff
- Reset + restart returns to clean first-install state
