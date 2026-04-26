# ProtectedData Secure Enclave Device-Binding Plan

> Temporary implementation guide. Archive or delete this file after the
> Secure Enclave device-binding layer is implemented and the permanent
> architecture/security/testing docs become the source of truth.

## 1. Apple Documentation Baseline

This design was checked against Apple Developer Documentation in Chrome, not
from search-result summaries:

- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [kSecAttrTokenIDSecureEnclave](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly)
- [CryptoKit SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave)

Relevant constraints:

- Secure Enclave keys must be generated on the Secure Enclave; pre-existing
  private keys cannot be imported.
- Secure Enclave supports P-256 key agreement/signing keys for this use case.
- `.privateKeyUsage` enables private-key operations; adding user-presence or
  biometric flags is optional and would add an authentication requirement.
- `ThisDeviceOnly` accessibility means the item is not portable to another
  device. `WhenPasscodeSetThisDeviceOnly` additionally ties availability to a
  configured device passcode and can make data unrecoverable if that condition
  is lost.

## 2. Design Goal

ProtectedData v1 currently uses one shared app-data root secret stored in the
data-protection Keychain and released only after app-session authentication via
`LAContext` / `kSecUseAuthenticationContext`.

The v2 target keeps that authentication gate and adds a second device-bound
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

## 3. Root-Secret Envelope v2

The root-secret Keychain row remains under
`ProtectedDataRightIdentifiers.productionSharedRightIdentifier` and remains
protected by `AppSessionAuthenticationPolicy`.

The row payload changes from legacy v1 raw root-secret bytes to a v2 envelope:

- `formatVersion = 2`
- `algorithm = p256-ecdh-hkdf-sha256-aesgcm`
- `deviceBindingKeyIdentifier`
- `ephemeralPublicKey`
- `hkdfSalt`
- `nonce`
- `ciphertext`
- `tag`
- `aadVersion`

Seal flow:

1. Generate or load a ProtectedData-only Secure Enclave P-256 key.
2. The SE key uses `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and
   `.privateKeyUsage`; it must not include `.userPresence`, `.biometryAny`, or
   `.devicePasscode`.
3. Generate a software ephemeral P-256 key pair for this seal operation.
4. Derive ECDH shared secret from ephemeral private key and SE public key.
5. HKDF-SHA256 derives a 32-byte root-secret wrapping key using versioned
   ProtectedData-specific salt/info bytes.
6. AES-GCM seals the raw root secret with AAD binding version, algorithm,
   key identifier, and envelope field lengths.
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
  overwrite the same Keychain row, verify v2 can be reopened, then continue.
- If SE generation, SE reconstruction, v2 seal, Keychain update, or v2 verify
  fails, authorization fails closed and the framework enters recovery/reset
  required state.

There must be no production fallback that decrypts ProtectedData without the
Secure Enclave once the device-binding layer is introduced. This is the point of
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
- device-binding stage name
- presence/absence of the SE key
- OSStatus / NSError domain and code
- migration result
- whether the operation used a handoff or interactive context

AuthTrace must not record:

- raw root secret
- ECDH shared secret
- HKDF output
- AES-GCM plaintext
- private key dataRepresentation
- full envelope payload
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
- Update root-secret reprotection so it changes Keychain access control without
  changing the v2 envelope or requiring an extra prompt.
- Update Reset All Local Data to delete and verify the ProtectedData SE
  device-binding key.
- Keep all private-key bundle behavior unchanged.

## 7. Test Matrix

Unit tests:

- v2 envelope seal/open round trip with the mock device-binding provider
- unsupported envelope version and malformed AAD fail
- tampered ciphertext, tag, nonce, salt, and ephemeral public key fail
- legacy v1 raw root secret migrates to v2 after authorization
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
