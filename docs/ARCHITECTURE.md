# Architecture

The structure of CypherAir 2.0. Every piece of the 2.0 plan is built against this document and reviewed against it. Numbers such as #1046 are the issues of those pieces.

## 1. The four parts

| Part | Where | Owns | Exposes |
|---|---|---|---|
| **App** | the Xcode app target | Screens, navigation, the lock surface, the privacy cover, texts, and small platform adapters (clipboard, file pickers) | Nothing |
| **Core** | `Packages/CypherCore` | Keys, contacts, messages, settings, the lock, the only path to a private key, every stored shape | Observable objects, operations, one error type |
| **Engine** | `engine/` (Rust), reached through `Packages/CypherEngine` | All OpenPGP | 28 functions, one key-handle object, two callbacks, one error type |
| **Vault** | `Packages/CypherVault` (kept) | The sealed root, unlock, sealed files, Keychain rows, Secure Enclave keys | As today, with the changes in section 3 |

The directions are one-way: App → Core → Engine and Vault. What enforces it:

- The app target links only `CypherCore`.
- The core imports the engine and the vault with `internal import`. So no engine or vault type can appear in the core's public interface. The compiler checks this.
- One small script in CI fails if the core imports a UI framework, or if the app imports the engine or the vault. A clean build refuses such an import, but an incremental build may not.
- The engine's Swift module also exposes the raw C functions. The core calls only the generated functions of section 2.1. This is a review rule.

**The structural rules**

- One function per operation. It takes a key handle, and only the handle knows the custody.
- Two error types, one in the engine and one in the core. Neither can carry text.
- A stored fact lives in one sealed file. What can be computed from a certificate is never stored.
- Content screens can only be built from the unlocked workspace. At lock it is gone.
- One root object, used by the app and by the tests.
- Each rule in section 6 has a strict test: exactly one allowed outcome.

## 2. The engine

A new Rust crate on `sequoia-openpgp` with the OpenSSL backend, exposed through UniFFI. Everything is written new, except nine modules that are brought in through review.

**The key handle.** `PrivateKey` is a UniFFI object, made in one of two ways:

- *portable:* from the certificate and the secret key that the vault unsealed;
- *device-bound:* from the certificate, a callback object that Swift implements (`DeviceKey`), and, for the post-quantum families, the classical halves that the vault unsealed.

Every operation that needs a private key takes a `PrivateKey`. No function has a variant per custody.

**The certificate is the authority.** A portable handle is built from the *public certificate* in the key list and the *secret key* in the vault. The engine joins them and refuses if they are not the same key. An expiry change or a revocation changes only the certificate. So the sealed secret is written once and never rewritten.

**No text in errors.** `EngineError` is a `Copy` type, so it cannot hold a string. Where an error must point at a recipient, it carries the position in the list the caller passed, never a fingerprint.

**Which error a failed decryption gives.** The engine decides by where the failure happened, never by reading error text. The first line that applies wins:

| Case | Error |
|---|---|
| A bound on hostile input fires, at any stage, also after a key was unwrapped | `LimitsExceeded` |
| The user cancels at the device. The device refuses or fails | `Cancelled`. `DeviceNotAuthenticated` or `DeviceFailed` |
| The input does not parse | `Malformed` |
| The container has no authentication (the old tag-9 packet) | `Unsupported` |
| A recipient packet names this key and does not unwrap | `Tampered` |
| No recipient packet names this key, and no hidden one unwraps | `NoMatchingKey` |
| A session key was unwrapped, and the container then fails | `Tampered` |

One accepted limit: an RSA unwrap has only a 16-bit check. For a hidden-recipient RSA message meant for someone else, about 1 try in 65,536 is reported as `Tampered` instead of `NoMatchingKey`.

### 2.1 Interface

Conventions:

- Bytes are `Vec<u8>`, paths are `String`, times are Unix seconds. Every input may be armored or binary. Stored certificates are binary.
- Lists of certificates are in the caller's order, and results point into them by position.
- A signer is *named* by its certificate. A signature is *made* with the certificate's signing key, which is a subkey where there is one.
- The engine has no state, no logging and no expiry policy of its own.

```rust
enum KeyShape {               // the certificate shapes that this app makes
    V4Curve25519,             // Portable Legacy
    V4P256,                   // Device-Bound Legacy
    V6Curve25519,             // Portable Modern
    V6P256,                   // Device-Bound Modern
    V6Curve448,               // Portable Modern · High
    V6MlDsa65,                // both Post-Quantum families
    V6MlDsa87,                // both Post-Quantum · High families
}
enum AlgorithmKind { Rsa, Dsa, ElGamal, EdDsaLegacy, Ecdsa, Ecdh, Ed25519, X25519, Ed448, X448,
                     MlDsa65Ed25519, MlDsa87Ed448, MlKem768X25519, MlKem1024X448, Unknown }
enum Curve { None, Ed25519, Curve25519, NistP256, NistP384, NistP521,
             BrainpoolP256, BrainpoolP384, BrainpoolP512, Unknown }
struct Algorithm { kind: AlgorithmKind, curve: Curve, bits: u32 }   // bits: 0 where a size says nothing

enum Expiry    { Never, At { unix_seconds: u64 } }
struct UserId  { name: String, email: Option<String> }
enum KeyStatus { Valid, Expired, Revoked, Unusable }

struct CertificateInfo {
    fingerprint: String,          // lowercase hex
    version: u8,                  // 4 or 6
    primary: Algorithm,           // the real algorithm and size, for every key
    encryption: Option<Algorithm>,
    shape: Option<KeyShape>,      // only when version, primary key and encryption key all match one of ours
    name: Option<String>,         // only from a User ID with a valid binding
    email: Option<String>,
    created: u64,
    expires: Option<u64>,
    status: KeyStatus,
    can_encrypt: bool,
    quantum_safe: bool,
    has_secret: bool,
}

struct NewKey {
    certificate: Vec<u8>,
    secret: Option<Vec<u8>>,      // what the vault must seal: the secret key (portable), the classical
                                  // halves (device-bound post-quantum), nothing (device-bound P-256)
    revocation: Vec<u8>,
}
struct DeviceKeySlots { signing_public_key: Vec<u8>, agreement_public_key: Vec<u8> }

enum InputKind { EncryptedMessage, SignedMessage, DetachedSignature, Certificate, PrivateKey, Revocation, Unknown }
enum ArmorKind { Certificate, Revocation }

struct OutgoingFormat { modern: bool, held_back_by: Vec<u32> }   // recipients that force the older format
struct Encrypted      { message: Vec<u8>, quantum_safe: bool }
struct MessageHeader  { openable_by: Vec<u32>, quantum_safe: bool }

enum Verdict     { NotSigned, Verified, Invalid, SignerRevoked, SignerExpired, UnknownSigner, Unverifiable }
struct Signature { verdict: Verdict, signer: Option<u32> }

struct Decrypted  { plaintext: Vec<u8>, signature: Signature, quantum_safe: bool }
struct Verified   { content: Vec<u8>, signature: Signature }
struct FileResult { signature: Signature, quantum_safe: bool }
struct Merged     { certificate: Vec<u8>, changed: bool }

#[derive(uniffi::Object)]
struct PrivateKey { /* certificate and custody; private */ }
impl PrivateKey {
    fn portable(certificate: Vec<u8>, secret: Vec<u8>) -> Result<Arc<Self>, EngineError>;
    fn device(certificate: Vec<u8>, secret: Option<Vec<u8>>, device: Arc<dyn DeviceKey>) -> Result<Arc<Self>, EngineError>;
}

#[uniffi::export(foreign)]
trait DeviceKey: Send + Sync {
    // P-256: a SHA-256 digest in, r‖s (64 bytes) out.  ML-DSA: the signature digest in, the raw signature out.
    fn sign(&self, input: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError>;
    // P-256: the sender's ephemeral point in.  ML-KEM: the ciphertext in.  Both: the 32-byte shared secret out.
    fn agree(&self, input: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError>;
}
enum DeviceKeyError { Cancelled, NotAuthenticated, Failed }

#[uniffi::export(foreign)]
trait Progress: Send + Sync {
    fn report(&self, bytes_read: u64, bytes_total: u64) -> bool;   // false cancels
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error, uniffi::Error)]
enum EngineError {
    Malformed,          // not OpenPGP data, or damaged before any key was tried
    WrongKind,          // valid, but not what this function takes
    Unsupported,        // valid OpenPGP that this engine refuses or cannot handle
    LimitsExceeded,     // a bound on hostile input fired
    KeyExpired, KeyRevoked,
    KeyUnusable,        // no key in the certificate can do this
    KeyMismatch,        // the secret key or the classical halves do not belong to the certificate
    NotExportable,
    WrongPassphrase,
    KdfOutOfRange,      // a backup asks for more than the format allows
    RecipientUnusable { position: u32 },
    NoMatchingKey,
    Tampered,
    Cancelled,
    DeviceNotAuthenticated, DeviceFailed,
    OutOfSpace, FileFailed,
    Internal,
}
```

| Function | Returns | Piece |
|---|---|---|
| `stretch_unlock_passphrase(passphrase, salt, memory_kib, iterations, parallelism)` | 32 bytes | #1046 |
| `inspect_certificate(certificate)` | `CertificateInfo` | #1046 |
| `armor(kind, data)` | text | #1046 |
| `generate_portable_key(shape, user, expiry)` | `NewKey` | #1046 |
| `PrivateKey::portable(certificate, secret)` | handle | #1046 |
| `outgoing_format(recipients)` | `OutgoingFormat` | #1046 |
| `encrypt(plaintext, recipients, signer?)` | `Encrypted`, armored | #1046 |
| `decrypt(message, key, verifiers)` | `Decrypted` | #1046 |
| `device_key_slots(certificate)` | `DeviceKeySlots` | #1047 |
| `generate_device_key(shape, user, expiry, signing_public_key, agreement_public_key, device)` | `NewKey` | #1047 |
| `PrivateKey::device(certificate, secret?, device)` | handle | #1047 |
| `recognise(input)` | `InputKind` | #1048 |
| `message_header(message, candidates)` | `MessageHeader` | #1048 |
| `message_header_of_file(path, candidates)` | `MessageHeader` | #1048 |
| `sign_cleartext(text, key)` | signed text | #1048 |
| `verify_signed(signed, verifiers)` | `Verified` | #1048 |
| `encrypt_file(input, output, recipients, signer?, progress?)` | quantum-safe flag | #1048 |
| `decrypt_file(input, output, key, verifiers, progress?)` | `FileResult` | #1048 |
| `sign_file(input, key, progress?)` | detached signature, armored | #1048 |
| `verify_file(input, signature, verifiers, progress?)` | `Signature` | #1048 |
| `erase_file(path)` | — | #1048 |
| `change_expiry(key, expiry)` | certificate | #1049 |
| `apply_revocation(certificate, revocation)` | certificate | #1049 |
| `merge_certificate(current, update)` | `Merged` | #1049 |
| `backup_memory_for_export(certificate)` | KiB needed | #1049 |
| `backup_memory_of(backup)` | KiB needed | #1049 |
| `export_backup(key, passphrase)` | armored secret key | #1049 |
| `import_backup(backup, passphrase?)` | `NewKey` | #1049 |

Notes:

- **Shapes.** `generate_portable_key` makes the three Curve shapes and the two post-quantum shapes. `generate_device_key` makes the two P-256 shapes and the two post-quantum shapes. Each refuses the others as `Unsupported`.
- **Encrypt to self** is not a parameter. The core adds the user's own certificate to `recipients`.
- **`outgoing_format`** answers from the same code that `encrypt` uses, so the preview cannot disagree with the message.
- **The quantum-safe flag** is read from the produced or received message, never from the list of recipients.
- **`verify_signed`** takes a cleartext-signed text and also an inline-signed message, as `gpg --sign` makes. It returns the content.
- **Several signatures.** The summary is `Verified` if any signature is verified, and it names that signer. Else it is the first that applies of: `Invalid`, `SignerRevoked`, `SignerExpired`, `UnknownSigner`, `Unverifiable`.
- **Revocation.** A revocation certificate made by the app states no reason. OpenPGP treats that as final: from then on no signature by the key verifies, whatever its date. `apply_revocation` serves two features: revoking your own key (with the stored certificate; no private key is needed) and accepting a revocation for a contact.
- **`import_backup`** also takes a key without passphrase protection. It refuses a file where the primary secret key is missing, as `gpg --export-secret-subkeys` makes, with `Unsupported`: without it there is no expiry change and no revocation. It makes a new revocation certificate for the key.
- **Key material has bounds too.** Every certificate, revocation or backup that the engine parses is limited in size and in packet count. The numbers are set in #1046.
- **File functions** write beside `output` and rename on success. On a failure or a cancel they erase what they wrote. `erase_file` is the one erase policy, used by the engine and the core.
- **`DeviceKeyError`** is a rich UniFFI error, not a flat one, and it converts from UniFFI's unexpected-callback error to `Failed`. Without that, an unexpected Swift error becomes a Rust panic.
- **A wrong device key.** `PrivateKey::device` cannot see whether the device key belongs to the certificate. It is caught elsewhere: the vault compares the public keys when it loads the handle; every signature is verified before release; a wrong shared secret cannot unwrap a session key.
- **Panics.** The crate keeps `panic = unwind`, so UniFFI can catch a panic inside a dependency. The core maps one to `internalFailure`. A fixture pins it.

### 2.2 Modules

```
engine/src/
  lib.rs        UniFFI setup, the exported types, the one Sequoia policy
  error.rs      EngineError; the only place where a Sequoia error becomes one
  key/          the handle (the only code that branches on custody), DeviceKey, inspect,
                generate, expiry, revocation and update, backup
  message/      recipients and format, encrypt, decrypt, sign and verify, verdict, header, files
  custody/      the six modules brought in
  bounded_walk.rs   unlock_stretch.rs   backup_s2k.rs        brought in
engine/tests/   common/ (the harness), fixtures/, and the tests for the rules in section 6
```

An exported function lives in the module that does the work. There is no separate interface layer. Its dependencies are those of `pgp-mobile`, without `base64`.

### 2.3 Brought in from the 1.x engine

Each module enters through a line-by-line review that ends in keep, fix or rewrite. Its unit tests come with it only if the review keeps them.

| 1.x file | Piece | What must change when it enters |
|---|---|---|
| `unlock_stretch.rs` | #1046 | Its error becomes typed |
| `bounded_walk.rs` | #1046 | Its error carried a sentence; it becomes `LimitsExceeded`. It gains the check for a container without authentication |
| `external_signer/core.rs`, `external_decryptor/core.rs` | #1047 | Their error and request types are re-pointed. **The decryptor checks that a point is on the curve before the device is asked** |
| `external_composite_signer/core.rs`, `external_composite_decryptor/core.rs` | #1047 | One callback returns bytes, so the carrier types per tier go. **The signer accepts only hashes of 256 bits or more**, as RFC 9980 §5.3.1 requires |
| `composite_kem.rs`, `composite_classical.rs` | #1047 | **The combiner gets a known-answer test** from the vectors in RFC 9980, appendix A |
| `keys/s2k.rs` | #1049 | It decides by key version, not by a family name |

The three parts in bold are known defects, and fixing them is required in #1047. The first one matters most. As it stands, the P-256 decryptor checks only the shape of a point, so a crafted packet with an off-curve point reaches the device. The device call is expected to fail then, and a device failure stops the whole decryption. So one bad packet placed before the real one would block a valid message. With the check, a bad point in a hidden packet is skipped, and a bad point in a packet that names the key is `Tampered`.

### 2.4 Behaviour that exists only in the 1.x code

The new code must keep these. A session that writes the module reads the 1.x file first.

- Sequoia's parser has two limits of its own: 16 levels of nesting and 1 MiB per packet that is not a container. Its decryptor and verifier have no limit on the number of packets or on expansion. The only hook for those is `VerificationHelper::inspect`. While plaintext is being read, a limit raised there must travel as an `io::Error` to survive. During setup it comes back unchanged.
- Sequoia swallows the error of a custom decryptor. The custody decryptors keep it in a side channel.
- A message with a hidden recipient is tried against the key. A packet that is clearly for someone else is skipped. A real failure of the device, or a cancel, stops the operation.
- Plaintext is released only after the whole message was authenticated. Sequoia alone releases some of it early when a message is larger than its buffer.
- Decryption does not check whether the key is expired or revoked, so old messages stay readable.
- For an expiry change, the new self-signature must be strictly later than the last one. The engine waits up to two seconds for this.
- Device-bound certificates are built by hand. Sequoia's native secret-key type for composite keys is never built for a device-bound key.
- A backup of a v6 key uses Argon2id with 2 GiB, one pass and four lanes, with AES-256 and OCB, once per secret-key packet. A v4 key uses the iterated and salted method, so that GnuPG can read it.
- Cargo's `lto` and `strip` stay off. Either breaks the link with the vendored OpenSSL.

Two places where the new engine must not follow the 1.x code:

- An expired or revoked key does not sign, for every custody (rule E8). The 1.x code signs with an expired portable key.
- To tell a revoked or expired signer from a bad signature, the engine asks the signer's key itself. The 1.x code reads error text.

## 3. The core

**What screens see.** One root object, `AppCore`, with one observable property, `phase`. A `Workspace` exists only while the app is unlocked. Everything public is on the main actor. Operations are `async throws(CoreError)`. Screens read the observable properties directly. Every type here is the core's own; none is an engine or vault type.

```swift
public final class AppCore {                       // @Observable
    public private(set) var phase: Phase
    public static func live(prompts: PromptTexts) -> AppCore   // hardware and Keychain; software and memory on the simulator
    public static func preview() -> AppCore        // software, memory only, unlocked, with sample data: for SwiftUI previews
    public func start() async
    public func report(_ event: PresenceEvent)     // .wentAway, .cameBack, .deviceLocked
}
public enum Phase {
    case starting, firstRun(FirstRun), locked(Unlock), unlocked(Workspace), damaged(Recovery), restartRequired
}
public final class FirstRun { func create(passphrase: String) async throws(CoreError) }
public final class Unlock {
    func submit(passphrase: String) async throws(CoreError)     // a typo costs no second prompt
    func resetAllLocalData() async throws(CoreError)             // "forgot passphrase"
}
public final class Recovery {
    let report: DamageReport                                     // per file: intact, missing, damaged, or made by another version
    let recoverableKeys: [Key]                                   // empty when the key list itself cannot be read
    func exportBackup(of: Key.ID, passphrase: String) async throws(CoreError) -> TemporaryFile
    func resetAllLocalData() async throws(CoreError)
}
public final class Workspace {
    let keys: Keys, contacts: Contacts, messages: Messages, settings: Settings
    func lock()
    func changePassphrase(current: String, new: String) async throws(CoreError)
    func resetAllLocalData() async throws(CoreError)
}
public final class Keys {
    private(set) var all: [Key]
    func generate(_ request: NewKeyRequest) async throws(CoreError) -> Key      // name, email, family, expiry
    func importBackup(_ data: Data, passphrase: String?) async throws(CoreError) -> Key
    func exportBackup(of: Key.ID, passphrase: String) async throws(CoreError) -> TemporaryFile
    func publicKey(of: Key.ID) async throws(CoreError) -> String
    func revocationCertificate(of: Key.ID) async throws(CoreError) -> String
    func setExpiry(of: Key.ID, to: Expiry) async throws(CoreError)
    func revoke(_ id: Key.ID) async throws(CoreError)
    func setDefault(_ id: Key.ID) async throws(CoreError)
    func delete(_ id: Key.ID) async throws(CoreError)
}
public final class Contacts {
    private(set) var all: [Contact]
    func read(_ data: Data) async throws(CoreError) -> ContactCandidate         // nothing is stored yet
    func add(_ candidate: ContactCandidate, verified: Bool) async throws(CoreError) -> Contact
    func setVerified(_ id: Contact.ID, _ verified: Bool) async throws(CoreError)
    func delete(_ id: Contact.ID) async throws(CoreError)
}
public final class Messages {
    func recognise(_ input: Data) async -> InputKind
    func outgoingFormat(to: [Contact.ID], toSelf: Key.ID?) async throws(CoreError) -> OutgoingFormat
    func encrypt(_ text: String, to: [Contact.ID], toSelf: Key.ID?, signWith: Key.ID?) async throws(CoreError) -> EncryptedText
    func encryptFile(_ file: URL, to: [Contact.ID], toSelf: Key.ID?, signWith: Key.ID?, progress: ProgressHandler?) async throws(CoreError) -> EncryptedFile
    func decrypt(_ message: Data) async throws(CoreError) -> DecryptedMessage
    func decryptFile(_ file: URL, progress: ProgressHandler?) async throws(CoreError) -> DecryptedFile
    func sign(_ text: String, with: Key.ID) async throws(CoreError) -> String
    func signFile(_ file: URL, with: Key.ID, progress: ProgressHandler?) async throws(CoreError) -> TemporaryFile
    func verify(_ signed: Data) async throws(CoreError) -> VerifiedMessage
    func verifyFile(_ file: URL, signature: Data, progress: ProgressHandler?) async throws(CoreError) -> SignatureResult
}
public final class Settings {
    private(set) var values: SettingsValues
    func update(_ change: (inout SettingsValues) -> Void) async throws(CoreError)
}
public enum Passphrase {                            // for the unlock passphrase and for every backup
    static func problems(in: String) -> [PassphraseProblem]      // shorter than 12; a character three times in a row
    static func suggestion() -> String
}

public enum Recipient: Sendable, Hashable { case contact(Contact.ID), ownKey(Key.ID) }
public enum Expiry: Sendable { case never, at(Date) }
public struct OutgoingFormat: Sendable { let modern: Bool; let heldBackBy: [Recipient] }
public enum InputKind: Sendable { case encryptedMessage, signedMessage, detachedSignature, certificate, privateKey, revocation, unknown }

public enum CoreError: Error, Sendable, Equatable {
    case locked, cancelled, restartRequired
    case authenticationFailed, authenticationUnavailable, wrongPassphrase
    case notOpenPGP, wrongKindOfData, unsupported, tooComplex
    case tampered, noMatchingKey
    case keyExpired, keyRevoked, keyUnusable, recipientUnusable(Recipient)
    case notExportable, keyMaterialMissing, deviceKeyFailed
    case notEnoughMemory, outOfSpace, fileFailed
    case alreadyPresent, storageDamaged, storageFailed, internalFailure
}
```

- **A `Key`** has: id, name, email, fingerprint, custody, shape, version, the real algorithm and size of its primary and its encryption key, created, expires, status, default, backed up, quantum-safe. **A `Contact`** has the same without custody, default and backed up, and with can-encrypt and verified.
- **The family name** is a label for a pair of shape and custody that the app can make. There are nine such pairs. A key outside them, for example an imported P-256 or RSA key, has no family name and shows only its real details. For a contact the custody is unknown, so only the shape gives a label.
- **A `ContactCandidate`** says what adding it does (new, update, revocation, already present) and lists look-alikes: contacts with the same email or the same User ID but another key. A bare revocation does not name its contact, so the core tries it against each contact's certificate.
- **A `DecryptedMessage`** holds text or, when the bytes are not UTF-8, data. Every result names its signer as one of the user's keys or a contact.
- **A `TemporaryFile`** is a file in the app's protected temporary folder, with the name to offer when saving. The name exists only in memory. Lock erases every one.
- **`PromptTexts`** holds the sentences for the Face ID sheets. The app owns every text, so it hands them to the core once.
- **Status is computed at unlock.** A key that expires while the app stays unlocked shows as valid until the next unlock. That is accepted: the engine refuses at use. No timer is added for it.
- No `CoreError` case carries text, a fingerprint or a path. The app turns each case into one sentence.

*This serves all three UI directions of #1042.* They need the same things: recognise an input, run one operation per kind, and say who signed. "Open and Write" calls `recognise` first. "Tools" calls the operations directly. "People first" uses the signer that every result carries.

**One path to a private key.** One function, `PrivateKeyAccess.use`, is the only code that touches private-key material. Its steps never change:

1. Find the key in the key list.
2. Find its stored material **without any prompt**. If something is missing, stop. The user never sees a Face ID sheet for an operation that cannot work.
3. For a backup, check that there is enough memory.
4. Ask for **one approval**. A portable key: Face ID or Touch ID, with the device passcode as the system's fallback. A device-bound key: Face ID or Touch ID only.
5. Load the material, build the engine handle, run the engine function.
6. Drop the handle, erase the buffers, end the approval.

| | Portable | Device-bound P-256 | Device-bound post-quantum |
|---|---|---|---|
| Found by | its sealed row, by the name in the key list | its two key blobs in the key list | its two key blobs and its sealed halves in the key list |
| Loaded | the secret key | the handle for the needed role | that handle and the classical halves |

Operations with private keys run one at a time. `DeviceKeyBridge` is the Swift object behind the engine's `DeviceKey`: it holds the loaded handle and calls it. `device_key_slots` gives the public keys that a loaded handle must match.

**Decisions inside the operations**

- The engine says which of the user's keys can open a message. The core takes the default key if it is among them, else the first. The user is not asked. A message whose recipients are all hidden is `noMatchingKey`.
- The first key becomes the default. Deleting the default makes the first remaining key the default.
- Deleting a portable key saves the list first and then deletes its row. A leftover row is harmless. A list entry without its row would fail only at use. A device-bound key is deleted with its entry, because its material is in the list.
- Revoking needs no approval and cannot be undone. The screens treat it like a delete, with an explicit confirmation.
- Adding a contact with a known fingerprint updates that contact. It keeps its id and its verified mark.
- A backup needs up to 2 GiB. The core refuses above 75% of the memory the process may use, before the prompt. Weaker parameters are never used instead.
- Making a device-bound key: the vault creates the two Secure Enclave keys, the engine signs through them, the classical halves are sealed, and everything is saved with the key list in one write. If a step fails, nothing was stored. Making a portable key seals its row first and saves the list second; if saving fails, the row is deleted.
- The engine writes file results itself. The core creates the folder with complete file protection and checks the protection of the file after the call.

**Stored data.** Three sealed files, at schema version 3. Versions 1 and 2 belong to 1.x. The vault refuses a file of another version before it decrypts it, so no 1.x file is ever decoded.

```swift
struct KeysPayload     { var keys: [StoredKey]; var defaultKey: String? }
struct StoredKey       {
    let fingerprint: String        // the key's identity inside the sealed list; never the name of a row
    var certificate: Data          // the authority for expiry and revocation
    let material: KeyMaterial      // where the private part lives; it also says the custody
    let revocation: Data           // made with the key
    var backedUp: Bool
}
enum KeyMaterial {
    case portable(row: String)     // the random name of the Keychain row that holds the sealed secret key
    case deviceBound(signing: Data, agreement: Data, classicalHalves: Data?)
                                   // the two Secure Enclave key blobs; for a post-quantum key also the sealed halves
}
struct ContactsPayload { var contacts: [StoredContact] }
struct StoredContact   { let id: UUID; var certificate: Data; var verified: Bool; let added: Date }
struct SettingsPayload {
    var signByDefault: Bool            // first value: true
    var encryptToSelfByDefault: Bool   // true
    var clipboardNotice: Bool          // true
    var relockAfter: RelockDelay       // immediately, 1, 3 or 5 minutes; first value: 3
}
```

- Names, expiry dates, shapes and "revoked" are not stored. The engine computes them from the certificate at unlock, so they cannot disagree with it.
- A store changes its value in memory only after the file was written. If saving fails, nothing changes and the caller gets an error.
- At unlock, a file that is missing, damaged or made by another version leads to the `damaged` phase, never to default values. Only keys from a key list that can be read can be backed up there.

**Nothing readable in the Keychain identifies a key.** Keychain rows have no access control, so their names, their attributes and the public fields of their values can be read without unlocking the app. None of these may come from a key's fingerprint or public key.

- *A portable key:* its sealed secret sits in a Keychain row with a random name. The envelope's authenticated data is that name too. The key list holds the name.
- *A device-bound key:* its two Secure Enclave key blobs, and for a post-quantum key its sealed classical halves, sit inside the sealed key list. It has no Keychain row. So no public key is readable anywhere, also not inside a blob.
- *Why two ways:* a portable secret is a whole key, and in its own row it survives a damaged key list. Device-bound material is useless without its certificate, which is in the key list.
- *What the Keychain still shows:* how many portable keys exist, and the size of each sealed secret. Not which keys they are.

**The changes to the vault package**

*1. The vault gives the approval.* As the package stands, its caller builds an authentication context and reaches into the vault's authenticator. The change:

- `UnlockedSession` gets the authenticator when the vault creates it, and one new function: `approve(_ kind:, reason:) async throws(VaultError) -> OperationApproval`.
- The kind is `.presence` for a portable key (the device passcode is the fallback) or `.biometrics` for a device-bound key. This follows the constraint that the key already has.
- After a successful approval the context disallows interaction, so the Secure Enclave can never show a sheet of its own. The approval invalidates its context when the operation ends.
- Five public calls take an `LAContext` today. `IdentityEnvelopeStore.open`, `CustodyKeyStore.loadHandle` and `CustodyKeyStore.createPair` take the `OperationApproval` instead. `UnlockedSession.openIdentityEnvelope` takes it too and becomes visible to the package only. `UnlockedSession.operationContext` goes.
- So the core never imports LocalAuthentication, also not for making a device-bound key.

*2. A file made by another version is reported as such,* apart from "damaged". The sealing layer already refuses such a file with an error of its own, and the store folds that error into "damaged". The change keeps the two apart.

*3. Nothing readable in a Keychain row identifies a key.*

- `IdentityEnvelopeStore` holds the portable secrets only. It makes a random name when it seals a secret and returns it. The envelope's authenticated data is that name, not the fingerprint.
- The classical halves are sealed and opened as values, with the session's two functions for that. They have no row.
- `CustodyKeyStore` has no rows. `createPair` returns the two handles with their blobs. `loadHandle` takes a blob and the expected public key, and still compares the Secure Enclave key's own public key with it. `locatePair`, `inventory`, `deletePair` and `deleteAll` go. `RowStore` loses its readable attribute.
- Reset deletes every Keychain item of the app, whatever its service or name, and then the files. So a row that nothing names, or that an earlier version left, goes too.

Not changed: the core composes the vault and its stores itself, in one file, with the constructors the package already has. Swift does not look inside the classical halves. The engine makes that value and checks it.

## 4. The lock

- **One place.** The core decides when to lock and does the locking. The app reports three events: the app went away, it came back, the device was locked.
- **By construction.** At lock, the root view is replaced by the lock surface. Content screens are built from the `Workspace`, and it is gone. A screen that kept an old reference gets `CoreError.locked`.
- **What lock does:** set the phase to `locked`; erase the session values in the vault; tell running file operations to stop; drop every decoded value; erase the plaintext files that were waiting to be saved. Only the last step can fail. Then the phase is `restartRequired`, and the sweep at the next launch erases the files.
- **Running operations.** An engine call cannot be interrupted from outside. So three rules hold. The core always passes a `Progress` to a file function, and it answers "stop" once lock has begun. An operation on text has no `Progress` and runs to its end. A result that arrives after lock is erased and never delivered. Lock applies in the `damaged` phase too, because that phase also holds an open session.
- **Timing.** The time counts from the moment the app goes away. A setting of 0 locks at once. Otherwise the Mac locks when the time is over, even while the app is away. iPhone, iPad and Vision Pro decide when the app comes back, because a suspended app cannot run a timer. A locked Mac screen locks the app at once.
- **A Face ID sheet is not "away".** Every approval starts in the core, so the core knows. Going inactive during that time does not count.
- **The privacy cover is not the lock.** It belongs to the app's shell and decides nothing.

## 5. Concurrency

- **Main actor:** `AppCore`, `Workspace`, the four feature objects and the stores' values in memory.
- **Off the main actor:** every engine call and every vault call that can block, through one helper. The helper runs them on a thread of its own, not on Swift's shared pool: a backup derivation or a large file blocks for seconds or longer.
- **The engine is synchronous.** Its callbacks run on the thread of the call that triggered them.
- **One `@unchecked Sendable` type in the core:** `DeviceKeyBridge`. It is used by one operation on one thread.

## 6. Tests

**The rules.** Each rule below gets one strict test. Strict means: exactly one allowed outcome. These are the rules that a later change could quietly break. Beyond them, each piece's issue says what its tests cover.

**Engine rules** (Rust tests)

| # | Rule | Piece |
|---|---|---|
| E1 | When authentication fails, no plaintext is returned | #1046 |
| E2 | A failed decryption gives exactly the error of the table in section 2. A tampered container is `Tampered`, in both containers, in the first block and in a later one. A recipient packet that names the key and does not unwrap is `Tampered`. A message for someone else is `NoMatchingKey`. The fixtures tamper where no bound can fire | #1046 |
| E3 | Hostile input is refused, each kind with one error. Too many packets, too deep nesting, too much expansion: `LimitsExceeded`, also after a key was unwrapped. A container without authentication: `Unsupported`. A certificate, revocation or backup beyond its bounds: `LimitsExceeded`. A panic inside a dependency becomes an internal failure and does not crash the app | #1046, and each piece for its own inputs |
| E4 | An outgoing message is never compressed, uses AES-256, and uses the new container only if every recipient supports it. The preview equals the message | #1046 |
| E5 | The quantum-safe flag comes from the message. A cut-off message is an error | #1046 |
| E6 | An expired or revoked recipient is refused, by position | #1046 |
| E7 | An expired or revoked key still decrypts | #1046 |
| E8 | An expired or revoked key does not sign | #1046 |
| E9 | Each verdict has its own case: verified, invalid, signer revoked, signer expired, unknown signer, not signed. A single invalid signature is never reported as something milder. One verified and one invalid signature together are `Verified`, with the verified signer | #1046 |
| E10 | A secret that belongs to another certificate is refused | #1046 |
| E11 | A name never comes from a User ID without a valid binding | #1046 |
| E12 | A certificate's shape is reported exactly. A P-256 key and a Curve25519 key never share a shape. A key that matches none of ours has no shape, and still reports its real algorithm and size | #1046 |
| E13 | The unlock stretch gives its pinned answer and refuses parameters out of range | #1046 |
| E14 | No error carries text (a compile-time check that `EngineError` is `Copy`) | #1046 |
| E15 | Every operation runs through the same function for every kind of custody. Each later piece adds its functions to this one test | #1047 |
| E16 | Custody fails closed: a device signature is verified before release; a wrong classical half fails before the device is asked; the hidden-recipient rule, with a point off the curve; a cancel stays a cancel. The combiner gives the answer of the RFC's vector | #1047 |
| E17 | A file is written only on success | #1048 |
| E18 | An expiry change takes effect, also right after generation | #1049 |
| E19 | A revocation revokes only its own key. An update must be the same key and never removes a revocation | #1049 |
| E20 | A backup file that asks for too much is refused before any derivation. A wrong passphrase is told apart from a file that is no backup. A device-bound key is not exportable | #1049 |
| E21 | `gpg` reads what the Legacy families write, and the engine reads what `gpg` writes. The same with `sq` for the v6 and post-quantum families | every piece |

**Core rules** (Swift tests in the core package, on the vault's software enclave and the real engine)

| # | Rule | Piece |
|---|---|---|
| C1 | While locked, no workspace exists. An old reference throws `locked` | #1062 |
| C2 | A file that is missing, damaged or from another version leads to the damaged phase, never to default values | #1062 |
| C3 | A save that fails changes nothing in memory | #1062 |
| C4 | A key whose stored material is missing never shows a prompt | #1063 |
| C5 | One operation takes one approval | #1063 |
| C6 | A device-bound key is never exported or backed up | #1063 |
| C7 | A family name is given only to a pair of shape and custody that the app can make. An imported P-256 key has none | #1063 |
| C8 | After a reset nothing is left: no row, no file, no Secure Enclave key | #1065 |
| C9 | A wrong passphrase, a failed approval and a tampered message are three errors | #1066 |
| C10 | No plaintext file remains after an operation ends or fails, or when the app locks in the middle of a file operation | #1066 |
| C11 | Nothing readable in a Keychain row identifies a key. After one key of every family is made, no row's name or value holds a fingerprint or a public key of the user | #1063 |

**The harness and the fixtures** are copied from `pgp-mobile/tests/` into `engine/tests/` in #1046, because the 1.x engine stays untouched until #1049 removes it with its own copy. Five harness files do not depend on the engine and are copied unchanged. `sq.rs` and the two stand-ins for the Secure Enclave are tied to the old engine. The stand-ins become one software `DeviceKey` that can also cancel, fail and answer wrongly. With `CYPHERAIR_REQUIRE_GPG=1` and `CYPHERAIR_REQUIRE_SQ=1` a missing tool fails instead of skipping. A `sq` without post-quantum support fails as well. CI sets both. The tests of #1046 need expired and revoked keys before #1049 exists; they build them with Sequoia directly.

**The test suites**

| Suite | What it covers | Needs |
|---|---|---|
| Engine tests (Rust) | The engine rules. Interoperability with `gpg` and `sq` in both directions. Every operation over every custody, on the software stand-in | A Mac |
| Package tests (Swift) | The vault's tests, as today. The core's tests: the core rules, and the core's operations through the real engine and the vault's software enclave | No hardware and no prompt. They can run on a Mac, a simulator or a connected iPhone |
| Device bench (#1067) | The real Secure Enclave, Face ID and the real Keychain, from the plain debug screen | A device and a person |
| App build | The app links against every slice of its platform | — |

**Which suite runs on which slice.** The app ships the engine in six slices: iPhone, Mac and Vision Pro, each for arm64 and arm64e. The three arm64e slices come from the patched compiler, so they need tests of their own.

| Slice | Engine tests | Package tests | Device bench | Where |
|---|---|---|---|---|
| Mac, arm64 | Yes | Yes (`swift test`) | — | The Mac and CI |
| Mac, arm64e | Yes, built with the patched compiler ¹ | Yes (`swift test --arch arm64e`) ² | Yes | The Mac. CI, if a hosted runner can run it |
| iPhone, arm64e | — ³ | Yes, on a connected iPhone | Yes | The owner's iPhone |
| iPhone simulator, Vision Pro simulator | — | Yes ⁴ | — | The Mac and CI |
| Vision Pro, arm64 and arm64e | — | — | — | Built and linked only. There is no hardware; `CUSTODY.md` §7 accepts this |
| iPhone, arm64 | — | — | — | Built and linked only ⁵ |

¹ Not yet known: whether the Mac runs a Rust test binary built for arm64e. #1046 tries it and reports.
² `swift test --arch arm64e` links the arm64e slice and passes on the Mac (#1045).
³ `cargo test` cannot run on an iPhone. The engine's iPhone slices are tested through the package tests and the bench.
⁴ The simulator slices link (#1045). The engine has not yet run on a simulator.
⁵ This slice exists because distribution requires it. Every device that 2.0 supports is assumed to run the arm64e slice.

**Who runs what**

| When | Runs |
|---|---|
| A session that changed the engine, before its pull request | The engine tests. Then the full library build, the package tests on both Mac slices and on one simulator, and the app build |
| A session that changed the core | The package tests on both Mac slices and on one simulator |
| CI, on every pull request (#1052) | The engine tests, with `gpg` and `sq` required. The package tests on the Mac and the simulators. The app build for iPhone, Mac and Vision Pro, so that every shipping slice is compiled and linked before a merge |
| The owner, at the device bench and before a release | The package tests on a connected iPhone, and the bench on an iPhone and a Mac |

A few engine tests need 2 GiB of memory or large files. They sit behind a second command. A session runs them when it touched what they test, and CI always runs them. Nothing in CI can replace the device bench for the Secure Enclave.

## 7. Build and packaging

**Build.** One script, `scripts/build-engine.sh`, builds the library for the eight targets of today: iPhone, Mac and Vision Pro, each for arm64 and arm64e, and the two simulators. Stock Rust builds the arm64 slices. The pinned patched compiler builds the three arm64e slices. The script builds one target after another, makes the XCFramework and generates the Swift bindings. It writes both straight into `Packages/CypherEngine/`. Neither is committed. It can also build a list of targets, for a quick loop.

- *Where it runs:* on the Mac, by the session that changed the engine. In CI, when the engine changed.
- *Reuse.* The build compiles OpenSSL once per target. A new worktree starts with a copy of the main checkout's built library, through `.worktreeinclude`, which lists both output paths. If the build proves slow, CI can also publish its build for download; that is for #1052 to decide.
- *A stale library is found by a machine.* The script stores a hash of the engine's source, its lock file, the compiler pin and itself beside the library. The app build compares that hash with the checkout first, and fails with the command that fixes it.

**Packaging.** This layout is shown to work on every platform and slice (#1045).

```
Packages/CypherEngine/
  Package.swift
  CypherEngineFFI.xcframework/                built, not committed; a binary target
  Sources/CypherEngine/cypher_engine.swift    generated, not committed
```

- The package has no hand-written code. Its product is `CypherEngine`. Only the core depends on it.
- The XCFramework must lie inside the package, and the generated Swift file must lie in the target's sources. The C header comes with the XCFramework.
- The package states the platforms as the app's exact deployment target, `27.2`. With `.v27` the linker warns for every object file. The core and the vault package use the same versions.
- The package repeats the project's Swift settings: Swift 6 mode, `InferIsolatedConformances`, `NonisolatedNonsendingByDefault`, `MemberImportVisibility`. Strict memory safety stays off for the bindings; the generated code does not pass it.
- The committed workspace setting `iOSPackagesShouldBuildARM64e` is required, for Vision Pro too. Without it the iPhone device build fails.
- The app's arm64e.x1 slice takes the arm64e objects of the library, as it does for the vault package.

## 8. Layout and parallel work

```
App/                    the app target
  Shell/                root view on AppCore.phase, lock surface, privacy cover, event forwarding
  Platform/             clipboard, file pickers
  Bench/                the device bench (#1067); debug builds only
  one folder and one string table per feature; the names follow the UI design
Packages/
  CypherVault/          kept
  CypherEngine/         the built library and the generated bindings
  CypherCore/Sources/CypherCore/
    Root/               AppCore, Phase, Workspace, CoreError and its two mappings, the composition
    Protection/         first run, unlock, lock, passphrase, reset, recovery
    PrivateKeys/        PrivateKeyAccess, DeviceKeyBridge, the memory guard
    Keys/  Contacts/  Messages/  Settings/
    Storage/            the store, the three payloads, temporary files
engine/                 the Rust crate
scripts/                build-engine.sh, the layer check
```

- A session edits only the folder of its piece.
- #1062 creates every shared file: `CoreError` with all its cases, the public value types, the payloads, `Workspace` with the four feature objects (empty), `AppCore.preview()`, the package manifest.
- The core has one target and the app uses synchronized folders. Adding a file edits neither a manifest nor the project file.
- One string table per feature. A screen never shows a string that the core or the engine produced, except content.
- The engine is built in one place. Engine pieces run one after another.

## 9. The pieces

The engine lands in four pieces and the core in five. The device bench (#1067) is a plain debug screen.

**Where the engine pieces differ from their issue texts.** A function's types do not change after the piece that adds it, so three things land earlier than the issues say.

- The bounds on hostile input move from #1048 to #1046. #1046 decrypts text, and without the bounds it would break rule E3 on its first day.
- Making the revocation certificate moves from #1049 to #1046 and #1047. A key is born with it. #1049 keeps `apply_revocation`.
- The grading of signatures, the quantum-safe flag and `outgoing_format` land in #1046, because `encrypt` and `decrypt` return or share them.

**Two clarifications.** #1062 detects damaged data and shows the phase; #1065 adds what the user can do there. #1046 copies the harness and the fixtures; #1049 deletes the old copies with `pgp-mobile/`.

| Piece | Adds |
|---|---|
| #1046 | The crate, the portable handle, the first eight functions of the table, the bounded walk and the unlock stretch (brought in), the harness and fixtures, the build script and the engine package |
| #1047 | The six custody modules (brought in, with the three required fixes of section 2.3), `DeviceKey`, the device handle, the two device functions, the software stand-in |
| #1048 | Signatures, files, `recognise`, the header functions, `erase_file` |
| #1049 | Expiry, revocation, update, backup with `backup_s2k` (brought in). Then the 1.x engine is removed |
| #1062 | The core package, `AppCore` and its phases, first run, unlock, `lock()`, damage detection, the store and the payloads, settings, the three vault changes, `CoreError` with every case, `preview()` |
| #1063 | `PrivateKeyAccess`, `DeviceKeyBridge`, the memory guard, everything in `Keys` |
| #1064 | Everything in `Contacts` |
| #1065 | The timing rules of the lock, passphrase change, reset, and what `Recovery` can do |
| #1066 | Everything in `Messages`, temporary files |
| #1067 | The debug screen in `App/Bench/`, which runs the real path on the owner's devices |

One thing to know about the order: #1063 and #1064 need #1049, the last engine piece. So only #1062 can start before the engine is complete. If the core should start earlier, #1063 can be split: the private-key path, generate, delete and default after #1047; backup, expiry and revoke after #1049. This is a choice for the plan, not for the design.
