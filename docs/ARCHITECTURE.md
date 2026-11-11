# Architecture

The structure of CypherAir 2.0. Every piece of the 2.0 plan is built against this document and reviewed against it. Numbers such as #1046 are the issues of those pieces.

## 1. The four parts

| Part | Where | Owns | Exposes |
|---|---|---|---|
| **App** | the Xcode app target | Screens, navigation, the lock surface, the privacy cover, texts, and small platform adapters (clipboard, file pickers) | Nothing |
| **Core** | `Packages/CypherCore` | Keys, contacts, messages, settings, the lock, the only path to a private key, every stored shape | Observable objects, operations, one error type |
| **Engine** | `engine/` (Rust), reached through `Packages/CypherEngine` | All OpenPGP | 28 functions, one key-handle object, two callbacks, one error type |
| **Vault** | `Packages/CypherVault` (kept) | The sealed root, unlock, sealed files, the sealing of secrets, Secure Enclave keys | The interface in section 3 |

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

- *portable:* from the certificate and the secret key packets that the vault unsealed;
- *device-bound:* from the certificate, a callback object that Swift implements (`DeviceKey`), and, for the post-quantum families, the classical halves that the vault unsealed.

Every operation that needs a private key takes a `PrivateKey`. No function has a variant per custody.

**A failure of the device takes its own way.** Sequoia turns a decryptor's error into "did not unwrap", and it reports a signer's error as one failure among others. So the handle unwraps a session key itself and answers one of three things: unwrapped, not this key, or an error. An error stops the operation. A signer's failure crosses Sequoia as a typed error, the way a bound does. `error.rs` turns both into `Cancelled`, `DeviceNotAuthenticated` or `DeviceFailed`. No operation looks at the custody to do this.

**The certificate is the authority.** A portable handle is built from the *public certificate* and the *secret key packets* that the vault unsealed. The secret holds the primary key and the subkeys alone, without User IDs or signatures. The engine joins the two and refuses a secret key that is not a key of the certificate. An expiry change or a revocation changes only the certificate. So the secret is sealed once and never sealed again.

**No text in errors.** `EngineError` is a `Copy` type, so it cannot hold a string. Where an error must point at a recipient, it carries the position in the list the caller passed, never a fingerprint.

**Which error a failed decryption gives.** The engine decides by where the failure happened, never by reading error text. The first line that applies wins:

| Case | Error |
|---|---|
| A bound on hostile input fires. In the old container (SEIPDv1) this line applies only before a session key is unwrapped | `LimitsExceeded` |
| The user cancels at the device. The device refuses or fails | `Cancelled`. `DeviceNotAuthenticated` or `DeviceFailed` |
| The input does not parse | `Malformed` |
| The message is one the engine does not open: a container without authentication (the old tag-9 packet), the withdrawn tag-20 packet, an unknown version of the container or of a session-key packet, or a cipher or mode that the engine refuses | `Unsupported` |
| A recipient packet names this key and unwraps to a cipher that the engine refuses. Only the old container keeps its cipher there | `Unsupported` |
| A recipient packet names this key and does not unwrap | `Tampered` |
| No recipient packet names this key, and no hidden one unwraps | `NoMatchingKey` |
| A session key was unwrapped, and the container then fails. In the old container this includes a bound that fires | `Tampered` |

The old container proves that it is genuine only at its end. Until then its content may have been changed. So after the unwrap, nothing that the content decides is reported: every failure of the message there is `Tampered`.

Two accepted limits, both because an RSA unwrap has only a 16-bit check. For a hidden-recipient RSA message meant for someone else, about 1 try in 65,536 is reported as `Tampered` instead of `NoMatchingKey`. And for an RSA packet that names this key, `Unsupported` shows that the unwrap succeeded, which `Tampered` would not show.

### 2.1 Interface

Conventions:

- Bytes are `Vec<u8>`, paths are `String`, times are Unix seconds. Every input may be armored or binary. Stored certificates are binary. A secret argument is `&[u8]`: UniFFI passes it without a copy. UniFFI lends only a top-level `&[u8]`, so a secret that may be absent is empty when it is.
- Lists of certificates are in the caller's order, and results point into them by position.
- A signer is *named* by its certificate. A signature is *made* with the certificate's signing key, which is a subkey where there is one.
- The engine has no state, no logging and no expiry policy of its own. For the times inside a key it reads no clock and draws no random number: the caller gives them (section 2.5). Its one piece of state is a panic hook, set at the first call, that keeps a caught panic off standard error.

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

enum Expiry    { Never, After { days: u32 } }   // a period counted from a stamp (section 2.5)
struct UserId  { name: String, email: Option<String> }
enum KeyStatus { Valid, Expired, Revoked, Unusable }

struct CertificateInfo {
    fingerprint: String,          // lowercase hex
    version: u8,                  // 4 or 6
    primary: Algorithm,           // the real algorithm and size, for every key
    encryption: Option<Algorithm>,
    shape: Option<KeyShape>,      // only when the version, the primary key and every encryption key match one of ours
    name: Option<String>,         // only from a User ID with a valid binding
    email: Option<String>,
    created: u64,
    newest_self_signature: u64,   // the latest creation time among its verified self-signatures and self-revocations (section 2.5)
    expires: Option<u64>,
    status: KeyStatus,
    can_encrypt: bool,
    quantum_safe: bool,
    has_secret: bool,
}

struct NewKey {
    certificate: Vec<u8>,
    secret: Option<Vec<u8>>,      // what the vault must seal: the secret key packets alone (portable), the
                                  // classical halves (device-bound post-quantum), nothing (device-bound P-256)
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
    fn portable(certificate: Vec<u8>, secret: &[u8]) -> Result<Arc<Self>, EngineError>;
    fn device(certificate: Vec<u8>, secret: &[u8], device: Arc<dyn DeviceKey>) -> Result<Arc<Self>, EngineError>;
                                  // secret: the classical halves; empty for P-256
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
    TimeOutOfRange,     // a later stamp that is not strictly later, or a time beyond OpenPGP's range (section 2.5)
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
| `generate_portable_key(shape, user, expiry, stamp)` | `NewKey` | #1046; the stamp in #1047 |
| `PrivateKey::portable(certificate, secret)` | handle | #1046 |
| `outgoing_format(recipients)` | `OutgoingFormat` | #1046 |
| `encrypt(plaintext, recipients, signer?)` | `Encrypted`, armored | #1046 |
| `decrypt(message, key, verifiers)` | `Decrypted` | #1046 |
| `device_key_slots(certificate)` | `DeviceKeySlots` | #1047 |
| `generate_device_key(shape, user, expiry, stamp, signing_public_key, agreement_public_key, device)` | `NewKey` | #1047 |
| `PrivateKey::device(certificate, secret, device)` | handle | #1047 |
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
| `change_expiry(key, expiry, stamp)` | certificate | #1049 |
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
- **A signature outside its own time.** A correct signature that is past its own expiry, or dated more than 30 minutes after this device's clock, is `Unverifiable`. `Invalid` means that the signature does not match the content, or that the key may not sign.
- **Several signatures.** The summary is `Verified` if any signature is verified, and it names that signer. Else it is the first that applies of: `Invalid`, `SignerRevoked`, `SignerExpired`, `UnknownSigner`, `Unverifiable`.
- **Revocation.** A revocation certificate made by the app states the reason "no reason specified". OpenPGP treats that as final: from then on no signature by the key verifies, whatever its date. It carries the key's creation time (section 2.5). `apply_revocation` serves two features: revoking your own key (with the stored certificate; no private key is needed) and accepting a revocation for a contact.
- **`import_backup`** also takes a key without passphrase protection. It refuses a file where the primary secret key is missing, as `gpg --export-secret-subkeys` makes, with `Unsupported`: without it there is no expiry change and no revocation. It makes a new revocation certificate for the key.
- **Key material has bounds too.** Every certificate, revocation or backup that the engine parses is limited to 1 MiB and to 1,024 packets. Beyond that it is `LimitsExceeded`.
- **Certifications by other people** are dropped when a certificate is read. The app has no web of trust, so it does not read them, does not keep them and does not pass them on. They do not count towards the 1,024 packets, so a key that many people have certified can still be added. A certificate of more than 1 MiB is still refused; that takes thousands of certifications, or a large photo.
- **File functions** write beside `output` and rename on success. On a failure or a cancel they erase what they wrote. `erase_file` is the one erase policy, used by the engine and the core.
- **`DeviceKeyError`** is a rich UniFFI error, not a flat one, and it converts from UniFFI's unexpected-callback error to `Failed`. Without that, an unexpected Swift error becomes a Rust panic.
- **A device-bound certificate** is what `generate_device_key` makes: a primary key that certifies and signs, and exactly one subkey, for key agreement. `device_key_slots` and `PrivateKey::device` take only such a certificate of the four device-bound shapes; any other is `Unsupported`. Classical halves that do not belong to the certificate are `KeyMismatch`, before the device is asked. `generate_device_key` refuses public keys that are not what the Secure Enclave makes as `Internal`. The device signs four times per new key: the direct-key signature, the User ID binding, the subkey binding and the revocation.
- **A wrong device key.** `PrivateKey::device` cannot see whether the device key belongs to the certificate. It is caught elsewhere: the vault compares the public keys when it loads the handle; every signature is verified before release; a wrong shared secret cannot unwrap a session key.
- **Panics.** Every exported function runs its body through one function in `error.rs`, which catches a panic and returns `Internal`. Nothing checks that a new function does this, so a review keeps it. The crate refuses to build with `panic = abort`. The core maps `Internal` to `internalFailure`. A deliberate panic in test-only code pins it.

### 2.2 Modules

```
engine/src/
  lib.rs        UniFFI setup, the exported types, the one Sequoia policy
  error.rs      EngineError, the containment of panics, and the classification of a failed
                decryption or stream. Elsewhere a Sequoia error is replaced by the error its place
                implies; no code reads an error's text
  key/          the handle (the only code that branches on custody), DeviceKey, inspect,
                generate, expiry, revocation and update, backup
  message/      recipients and format, encrypt, decrypt, sign and verify, verdict, header, files
  custody/      the six modules brought in: the P-256 signer and decryptor, the composite
                signer and decryptor, the combiner, the classical curve operations
  bounded_walk.rs   unlock_stretch.rs   backup_s2k.rs        brought in
engine/tests/   common/ (the harness), fixtures/, and the tests for the rules in section 6
```

An exported function lives in the module that does the work. There is no separate interface layer. Its dependencies are those of the 1.x engine, without `base64`.

### 2.3 Brought in from the 1.x engine

Each module enters through a line-by-line review that ends in keep, fix or rewrite. Its unit tests come with it only if the review keeps them. The 1.x engine is no longer in the tree. Its files are read from git history at commit `bdfb0149`, under `pgp-mobile/`: for example `git show bdfb0149:pgp-mobile/src/keys/s2k.rs`.

| 1.x file | Piece | What must change when it enters |
|---|---|---|
| `unlock_stretch.rs` | #1046 | Its error becomes typed |
| `bounded_walk.rs` | #1046 | Its error carried a sentence; it becomes `LimitsExceeded`. It gains the check for a container without authentication |
| `external_signer/core.rs`, `external_decryptor/core.rs` | #1047 | Their error and request types are re-pointed. **The decryptor checks that a point is on the curve before the device is asked** |
| `external_composite_signer/core.rs`, `external_composite_decryptor/core.rs` | #1047 | One callback returns bytes, so the carrier types per tier go. **The signer accepts only hashes of 256 bits or more**, as RFC 9980 §5.3.1 requires |
| `composite_kem.rs`, `composite_classical.rs` | #1047 | **The combiner gets a known-answer test** from the vectors in RFC 9980, appendix A |
| `keys/s2k.rs` | #1049 | It decides by key version, not by a family name |

The three parts in bold were known defects of the 1.x modules. The first one matters most. A device call with an off-curve point fails, and a device failure stops the whole decryption, so one bad packet placed before the real one would block a valid message. So the point is checked before the device is asked: a bad point in a hidden packet is skipped, and a bad point in a packet that names the key is `Tampered`.

### 2.4 Behaviour that exists only in the 1.x code

The new code must keep these. A session that writes the module reads the 1.x file first, from git history as section 2.3 says.

- Sequoia's parser has two limits of its own: 16 levels of nesting and 1 MiB per packet that is not a container. Its decryptor and verifier have no limit on the number of packets or on expansion. The only hook for those is `VerificationHelper::inspect`. While plaintext is being read, a limit raised there must travel as an `io::Error` to survive. During setup it comes back unchanged.
- Sequoia swallows the error of a custom decryptor. The custody decryptors keep it in a side channel.
- A message with a hidden recipient is tried against the key. A packet that is clearly for someone else is skipped. A real failure of the device, or a cancel, stops the operation.
- Plaintext is released only after the whole message was authenticated. Sequoia alone releases some of it early when a message is larger than its buffer.
- Decryption does not check whether the key is expired or revoked, so old messages stay readable.
- For an expiry change, the new self-signature must be strictly later than the last one. Section 2.5 says how its time is chosen. The engine takes that time and no longer waits for one.
- Device-bound certificates are built by hand. Sequoia's native secret-key type for composite keys is never built for a device-bound key.
- A backup of a v6 key uses Argon2id with 2 GiB, one pass and four lanes, with AES-256 and OCB, once per secret-key packet. A v4 key uses the iterated and salted method, so that GnuPG can read it.
- Cargo's `lto` and `strip` stay off. Either breaks the link with the vendored OpenSSL.

Two places where the new engine must not follow the 1.x code:

- An expired or revoked key does not sign, for every custody (rule E8). The 1.x code signs with an expired portable key.
- To tell a revoked or expired signer from a bad signature, the engine asks the signer's key itself. The 1.x code reads error text.

### 2.5 The time inside a key

A key's creation time is public: it is in every copy of the certificate. Two times on the device can be read without unlocking the app: when the key list last changed, and when the vault was made. If a key carried the real moment it was made, either time could single it out. So that moment is never written into a key.

| Constant | Value | |
|---|---|---|
| `STAMP_WINDOW` | 45 days | The owner's number |
| `STAMP_MIN_AGE` | 60 seconds | So that a slow clock elsewhere never sees a time in the future |
| `MIN_EXPIRY_DAYS` | 365 | The shortest expiry a user can choose: one year |

The three constants live in the core, in the one file that makes stamps. A test checks that `MIN_EXPIRY_DAYS` is at least four windows, so that a key keeps at least three quarters of the period that was chosen. With a window of 45 days, a key with the shortest expiry lasts between 320 and 365 days from the day it was really made.

**The stamp.** When the app makes a key, the core takes the clock's time and goes back by a random number of seconds, drawn between `STAMP_MIN_AGE` and `STAMP_WINDOW`. The result is the key's stamp. The core gives it to the engine, and the engine writes it into everything made with the key: the primary key, the subkeys, every self-signature and the prepared revocation. The stamp is not rounded. With such a shift, nothing finer than about a day in it carries meaning, and those digits stay random, so that the key carries no further mark of this app.

**The draw comes from the system's secure random generator, and from nothing else.** This is essential. With a weak generator, or one that depends on the time, someone could try every possible moment, find the one that gives the stamp, and so undo the shift.

- *The call.* The core draws with Swift's `SystemRandomNumberGenerator`. On Apple's platforms that is `arc4random_buf`, the system's generator. Swift documents it as cryptographically secure, and it cannot fail. The engine and its OpenSSL generator take no part.
- *The range.* The draw is `UInt64.random(in:using:)` over the seconds from `STAMP_MIN_AGE` to `STAMP_WINDOW`, both ends included. The standard library makes it uniform, without bias. The core writes no sampling code of its own.
- *One draw per stamp.* A draw is used for one stamp and never again.
- *What a test can show.* A test passes its own generator. It cannot show that the app's own one is the system's. That is one line of code, and a review keeps it.

**The engine reads no clock and draws nothing for a key.** It takes the stamp as an argument of `generate_portable_key`, `generate_device_key` and `change_expiry`. So the engine's tests state every time exactly, and the core's tests fix the clock and the generator.

- The engine sets the creation time of every signature it makes for a key itself, to the stamp. It uses no function of Sequoia that reads the clock. Sequoia's own expiry functions sign with the current time, and a signature that is built from an older one picks a time of its own when none is set. So `change_expiry` builds each signature by hand, as the 1.x `keys/expiry.rs` does: the direct-key signature, one for each User ID that is not revoked, one for each subkey, and each new back-signature.
- The device-bound generation writes the stamp into both keys and sets it on every signature, where the 1.x code reads the system time or lets Sequoia read it.
- The engine refuses, as `TimeOutOfRange`, a later stamp that is not strictly later than the newest self-signature, and a stamp or an expiry that does not fit OpenPGP's 32-bit time. It cannot check that a stamp lies in the past. That is the core's part. The core's own rule never gives such a stamp, so the core reports this error as `internalFailure`: it means a mistake in the core, or a time after the year 2106.

**Expiry is a period counted from the stamp.** `Expiry` is `Never` or a number of days, and the key expires at the stamp plus the period. For an expiry change, that is the stamp of the change. OpenPGP stores an expiry in each key packet's signature as a period from that packet's own creation time, so the engine converts it for each key packet. A key that is older than the period is therefore valid again after a change. A period of zero days would read as "never" in OpenPGP; the engine refuses it as `Internal`, and the core never offers it.

An expiry on a day counted from today would undo the shift: the expiry date is public, and "expiry minus two years" would be the real day. Because the engine takes a period and not a date, the core cannot pass the real day by mistake. The core offers no period below `MIN_EXPIRY_DAYS`, so an expiry always lies in the future.

*What a user can no longer do.* There is no exact expiry date, and no expiry sooner than about 320 days from now. So a user cannot let a key run out soon instead of revoking it, and cannot match a date that was set elsewhere. A key expires up to one window before the day the user counted on. The app shows the real expiry date once it is set.

**A later self-signature,** made for an expiry change, gets a stamp of its own. The *newest self-signature* is the latest creation time among all verified self-signatures of the certificate, its revocations by itself included, whatever their date. A certificate with none gives its key's creation time. The engine reports it in `CertificateInfo`, and the core reads it from the certificate it is about to change.

- If the newest self-signature lies inside the window, that is, not earlier than the clock minus `STAMP_WINDOW`, the new stamp is the second after it. Nothing is drawn.
- Otherwise the new stamp is drawn like a new key's stamp.
- If the second after the newest self-signature is less than `STAMP_MIN_AGE` old, the change is refused as `tooSoon`. For a key the app made, this does not happen in practice. It concerns a key from elsewhere that was signed within the last minute, or one that carries a self-signature dated in the future. In the first case a minute's wait ends it. In the second it lasts until that date has passed, so the screen must not promise a short wait.

A fresh draw at every change would be wrong. The previous stamp would cut its range short, so each quick change would move the newest stamp closer to the real moment: after five changes it would lie within a day of it four times out of five. With the rule above, a stamp says that its real moment lies within one window after it, however many changes are made. A drawn later stamp says one thing more: the change came more than one window after the stamp before it. That can narrow the range, but rarely to less than a day.

**A revocation needs no new time.** The prepared revocation states the reason "no reason specified", which makes it final, and it carries the key's creation time. Revoking applies it and signs nothing, so the moment of a revocation appears nowhere. Other tools then show the key as revoked since its creation. The revocation that `import_backup` makes for a key from elsewhere carries that key's own creation time too. No revocation whose meaning depends on its time is ever made.

**Not touched.** A signature on a message carries the real time. A key made elsewhere keeps its own times, and so does a contact's key.

**Nothing else the app writes dates a key.** The name that the app offers when a public key, a revocation or a backup is saved carries no date, and the armor carries no header with one.

**The guarantee, and where it ends.** For a key that the app made: whoever knows the real moment exactly learns only that the stamp lies within one window before it. This holds for the two times above, and for any other record of when the app was used.

- That does not point at one key among all the keys that are published in such a window. For a key of a rare kind the list can still be short.
- A key made elsewhere is outside the guarantee. If it was made shortly before it was imported, its creation time is close to the key list's time. The same holds for a contact's key and the time of the contact list.
- The shift hides the times inside a key, not the moment a key first shows up elsewhere: when it is published, sent, or first used to sign. If that moment is close to a readable time, the two can still be matched.

## 3. The core

**What screens see.** One root object, `AppCore`, with one observable property, `phase`. A `Workspace` exists only while the app is unlocked. Everything public is on the main actor. Operations are `async throws(CoreError)`. Screens read the observable properties directly. Every type here is the core's own; none is an engine or vault type.

```swift
public final class AppCore {                       // @Observable
    public private(set) var phase: Phase
    public static func live(prompts: PromptTexts) -> AppCore   // hardware and Keychain; software and memory on the simulator
    public static func preview() -> AppCore        // software, memory only, unlocked, with sample data: for SwiftUI previews; debug builds only
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
    func resetAllLocalData() async throws(CoreError)             // the only way on
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
public enum Expiry: Sendable { case never, after(days: Int) }
public struct OutgoingFormat: Sendable { let modern: Bool; let heldBackBy: [Recipient] }
public enum InputKind: Sendable { case encryptedMessage, signedMessage, detachedSignature, certificate, privateKey, revocation, unknown }

public enum CoreError: Error, Sendable, Equatable {
    case locked, cancelled, restartRequired
    case authenticationFailed, authenticationUnavailable, wrongPassphrase, passphraseTooWeak
    case notOpenPGP, wrongKindOfData, unsupported, tooComplex
    case tampered, noMatchingKey
    case keyExpired, keyRevoked, keyUnusable, tooSoon, recipientUnusable(Recipient)
    case notExportable, keyMaterialMissing, deviceKeyFailed
    case notEnoughMemory, outOfSpace, fileFailed
    case alreadyPresent, storageDamaged, storageFailed, internalFailure
}
```

- **A `Key`** has: id, name, email, fingerprint, custody, shape, version, the real algorithm and size of its primary and its encryption key, created, added, expires, status, default, backed up, quantum-safe. `created` is the creation time inside the key. For a key that the app made it is the stamp, which is early on purpose (section 2.5). For a key from elsewhere it is that key's own creation time. `added` is the real moment the key was made or imported on this device. **A `Contact`** has the same without custody, default and backed up, and with can-encrypt and verified.
- **The family name** is a label for a pair of shape and custody that the app can make. There are nine such pairs. A key outside them, for example an imported P-256 or RSA key, has no family name and shows only its real details. For a contact the custody is unknown, so only the shape gives a label.
- **A `ContactCandidate`** says what adding it does (new, update, revocation, already present) and lists look-alikes: contacts with the same email or the same User ID but another key. A bare revocation does not name its contact, so the core tries it against each contact's certificate.
- **A `DecryptedMessage`** holds text or, when the bytes are not UTF-8, data. Every result names its signer as one of the user's keys or a contact.
- **A `TemporaryFile`** is a file in the app's protected temporary folder, with the name to offer when saving. The name exists only in memory. Lock erases every one.
- **`PromptTexts`** holds the sentences for the Face ID sheets. The app owns every text, so it hands them to the core once.
- **Status is computed at unlock.** A key that expires while the app stays unlocked shows as valid until the next unlock. That is accepted: the engine refuses at use. No timer is added for it.
- **The lists exist before the workspace.** Unlock reads the three files and computes the keys and the contacts from their certificates in one call off the main actor, with `Keys.list(of:)` and `Contacts.list(of:)`. Only then does it publish the phase.
- No `CoreError` case carries text, a fingerprint or a path. The app turns each case into one sentence.
- A passphrase that the user chooses and that `Passphrase.problems` faults is refused with `passphraseTooWeak`, before any prompt. So the rule does not depend on a screen.

*This serves all three UI directions of #1042.* They need the same things: recognise an input, run one operation per kind, and say who signed. "Open and Write" calls `recognise` first. "Tools" calls the operations directly. "People first" uses the signer that every result carries.

**One path to a private key.** One function, `PrivateKeyAccess.use`, is the only code that touches private-key material. Its steps never change:

1. Find the key in the key list.
2. Check its stored material **without any prompt**. If something is missing or has the wrong form, stop with `keyMaterialMissing`. The user never sees a Face ID sheet for an operation that cannot work.
3. For a backup, check that there is enough memory.
4. Ask for **one approval**. A portable key: Face ID or Touch ID, with the device passcode as the system's fallback. A device-bound key: Face ID or Touch ID only.
5. Load the material, build the engine handle, run the engine function.
6. Drop the handle, erase the buffers, end the approval.

| | Portable | Device-bound P-256 | Device-bound post-quantum |
|---|---|---|---|
| Checked before the prompt | its sealed secret decodes and has the right kind | both key blobs are there, no halves are there, and the public keys from `device_key_slots` have the right length | both key blobs are there, the sealed halves decode and have the right kind, and the public keys have the right length |
| Loaded | the secret key packets | the handle for the needed role | that handle and the classical halves |

Operations with private keys run one at a time. `DeviceKeyBridge` is the Swift object behind the engine's `DeviceKey`: it holds the loaded handle and calls it. `device_key_slots` gives the public keys that a loaded handle must match.

**Decisions inside the operations**

- The engine says which of the user's keys can open a message. The core takes the default key if it is among them, else the first. The user is not asked. A message whose recipients are all hidden is `noMatchingKey`.
- The first key becomes the default. Deleting the default makes the first remaining key the default.
- Making a key and deleting a key are each one write of the key list, because every key's material is inside it. If the write fails, nothing changed.
- Revoking needs no approval and cannot be undone. The screens treat it like a delete, with an explicit confirmation.
- Adding a contact with a known fingerprint updates that contact. It keeps its id and its verified mark.
- A backup needs up to 2 GiB. The core refuses above 75% of the memory the process may use, before the prompt. Weaker parameters are never used instead.
- Making a device-bound key: the vault creates the two Secure Enclave keys, the engine signs through them, the classical halves are sealed, and everything is saved with the key list in that one write. A Secure Enclave key exists only as its blob, so if a step fails, nothing is left behind.
- The engine writes file results itself. The core creates the folder with complete file protection and checks the protection of the file after the call.

**Stored data.** Three sealed files, at schema version 3. Versions 1 and 2 belong to 1.x. The vault refuses a file of another version before it decrypts it, so no 1.x file is ever decoded.

```swift
struct KeysPayload     { var keys: [StoredKey]; var defaultKey: String? }
struct StoredKey       {
    let fingerprint: String        // the key's identity inside the sealed list
    var certificate: Data          // the authority for expiry and revocation
    let material: KeyMaterial      // the private part; it also says the custody
    let revocation: Data           // made with the key
    let added: Date                // the real moment the key was made or imported here; it never leaves this file
    var backedUp: Bool
}
enum KeyMaterial {
    case portable(sealedSecret: Data)
                                   // the secret key packets, sealed to the identity wrapping key
    case deviceBound(signing: Data, agreement: Data, sealedHalves: Data?)
                                   // the two Secure Enclave key blobs; for a post-quantum key also the sealed classical halves
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
- Each file has one turn that outlives every session. A store holds it while it writes, and unlock and first run hold all three. So a write that began before a lock ends before the next unlock reads the file.
- At unlock, a file that is missing, damaged or made by another version leads to the `damaged` phase, never to default values. Nothing is rescued there: the phase names what is wrong, and the only way on is a reset. A file that exists but cannot be read is none of these: the unlock fails with `storageFailed`, and the app stays locked.
- A device that still holds the data of 1.x lands in the `damaged` phase, with its files named as made by another version. The app says so, and the only way on is a reset. Nothing of 1.x is read, and nothing is rescued.

**Nothing readable identifies a key.** Two things can be read without unlocking the app: its Keychain rows, with their names, attributes, dates and public fields, and its files, with their names, sizes and dates. Nothing in them may point at one of the user's keys.

- *The Keychain holds one row, the sealed root.* Its dates say when the vault was made and when the passphrase last changed. A row per key would carry the date of that key, and a key's creation time is public.
- *All key material is inside the sealed key list:* a portable key's sealed secret, a device-bound key's two Secure Enclave key blobs, and a post-quantum key's sealed classical halves. No name, no public key and no per-key date exists outside it.
- *Every sealed file is padded* to a multiple of 16 KiB before it is sealed. So a file's size does not confirm a guess about which keys or contacts it holds.
- *The sealed files stay out of device backups.* Only the vault that wrote a copy could open it, so a copy in a backup could only serve to put old state back.
- *What still shows:* that the three files exist, their size in steps of 16 KiB, when each last changed, when the vault was made, and when its passphrase last changed. The app cannot hide these times. For a key that the app made, they match no time inside it, because the key carries a stamp that lies a random amount before the real moment (section 2.5). Such a time says only that a key of the user was stamped within one window before it. A key made elsewhere keeps its own times and is outside this.

**The vault interface the core uses**

*1. One approval per operation.* `UnlockedSession.approve(_ kind:, reason:) async throws(VaultError) -> OperationApproval` evaluates a fresh context once: `.presence` for a portable key, with the device passcode as the fallback, or `.biometrics` for a device-bound key. This follows the constraint that the key already has.

- After the approval the context disallows interaction, so the Secure Enclave never shows a sheet of its own. The approval invalidates its context when the operation ends.
- Three public calls take the approval: `SealedSecret.open`, `CustodyKeyStore.loadHandle` and `CustodyKeyStore.createPair`. An approval holds the session that gave it and works only with that session, so these calls take no session. Each refuses an approval that has ended, or whose session is locked, before it does anything.
- No public call of the vault takes an `LAContext`. So the core never imports LocalAuthentication, also not for making a device-bound key.

*2. A file made by another version is reported as such,* apart from "damaged". The sealing layer refuses another schema version before it decrypts anything, and `SealedDomain` reports it as `otherVersion`.

*3. All key material lives in the sealed key list. The Keychain holds only the sealed root.*

- `SealedSecret` in `Stores` has three functions: `seal(_ secret:, kind:, session:) -> Data`, `check(_ sealed:, kind:, session:)` and `open(_ sealed:, kind:, approval:) -> SensitiveBuffer`. They serve the portable secrets and the classical halves. The core stores the sealed value in the key list.
- `check` never prompts. It decodes the value and checks its kind, and that it is sealed to this vault's identity wrapping key. Step 2 of the private-key path uses it, so a value from another vault fails before the prompt.
- The authenticated data of such a value is a constant. The key list binds each value to its entry, and the engine refuses a secret that does not belong to the certificate. The payload kind is `secret-keys`.
- `CustodyKeyStore` has no rows. `createPair(tier:approval:)` returns the two handles with their blobs. `loadHandle(role:tier:blob:expectedPublicKey:approval:)` rebuilds one key and compares the Secure Enclave key's own public key with the expected one. The tier comes from the certificate's shape, and the role from the operation. A loaded handle keeps its role, its tier and that public key.
- `CustodyTier.acceptsPublicKey(_:role:)` is the length check of step 2. `LoadedCustodyHandle.sharedSecret` checks the sender's point with the same code.
- A Keychain row has no readable attribute.

*4. The sealed files are padded and stay out of backups.* `SealedDomain.save` pads the payload to a multiple of 16 KiB before it seals it; the padded form carries the payload's length. `ProtectedDataDirectory` excludes its folder from device backups at every start, and checks that the exclusion stuck, as it does for file protection.

*5. Reset deletes every Keychain item of the app.* `Keychain.deleteEverything()` deletes every item of the app in the data-protection Keychain, whatever its service. So a row that an earlier version left goes too. The software composition has one shared `InMemoryKeychain` behind its row stores, so that a test can plant a row under another service and see it go.

*6. A new vault is stored after its files.* `Vault.bootstrap` returns a `NewVault`: the session, and the sealed root that nothing stores yet. The core writes the three files, then calls `store()`, which writes the root's row. The root marks a finished first run, so a first run stopped at any point leaves a device that starts over.

The core composes the vault and its stores itself, in one file. The software composition keeps the sealed root's row in the shared in-memory Keychain and the sealed files in memory, behind the same interface as `ProtectedDataDirectory`. Previews get a sandbox session that needs no prompt and stores nothing. Swift does not look inside the classical halves. The engine makes that value and checks it.

## 4. The lock

- **One place.** The core decides when to lock and does the locking. The app reports three events: the app went away, it came back, the device was locked.
- **By construction.** At lock, the root view is replaced by the lock surface. Content screens are built from the `Workspace`, and it is gone. A screen that kept an old reference gets `CoreError.locked`.
- **What lock does:** set the phase to `locked`; erase the session values in the vault; tell running file operations to stop; drop the decoded values; erase the plaintext files that were waiting to be saved. Only the last step can fail. Then the phase is `restartRequired`, and the sweep at the next launch erases the files. The settings stay readable on an old reference, because they hold no user content; changing them throws `locked`.
- **`restartRequired` has a second meaning:** the app could not start, because its protected folder or the Keychain could not be reached.
- **A lock voids an unlock or a first run in flight.** It does not publish its result: the app stays locked, and a vault that a first run just made stays locked. Going away during one does not count, because that may be its own Face ID sheet.
- **The presence check of an unlock does not wait on the lock screen.** After a wrong passphrase the next submission needs no prompt, but only until the device locks or the app goes away while no submission runs. Then the attempt ends, and the next submission shows the prompt again.
- **Running operations.** An engine call cannot be interrupted from outside. So three rules hold. The core always passes a `Progress` to a file function, and it answers "stop" once lock has begun. An operation on text has no `Progress` and runs to its end. A result that arrives after lock is erased and never delivered. Lock applies in the `damaged` phase too, because that phase also holds an open session.
- **Timing.** The time counts from the moment the app goes away. A setting of 0 locks at once. Otherwise the Mac locks when the time is over, even while the app is away. iPhone, iPad and Vision Pro decide when the app comes back, because a suspended app cannot run a timer. A locked Mac screen locks the app at once.
- **A Face ID sheet is not "away".** Every approval starts in the core, so the core knows. Going inactive during that time does not count.
- **The privacy cover is not the lock.** It belongs to the app's shell and decides nothing.

## 5. Concurrency

- **Main actor:** `AppCore`, `Workspace`, the four feature objects and the stores' values in memory.
- **Off the main actor:** every engine call and every vault call that can block, through one helper. The helper runs them on a thread of its own, not on Swift's shared pool: a backup derivation or a large file blocks for seconds or longer.
- **Two exceptions, inside the vault.** Unlock and first run stretch the passphrase and use the Secure Enclave on Swift's shared pool, through the vault's own `@concurrent` functions. They read and write the sealed root's Keychain row on the main actor. Both take well under a second; moving them would need a change to the vault.
- **The engine is synchronous.** Its callbacks run on the thread of the call that triggered them.
- **One `@unchecked Sendable` type in the core:** `DeviceKeyBridge`. It is used by one operation on one thread.

## 6. Tests

**The rules.** Each rule below gets one strict test. Strict means: exactly one allowed outcome. These are the rules that a later change could quietly break. Beyond them, each piece's issue says what its tests cover.

**Engine rules** (Rust tests)

| # | Rule | Piece |
|---|---|---|
| E1 | When authentication fails, no plaintext is returned | #1046 |
| E2 | A failed decryption gives exactly the error of the table in section 2. A tampered container is `Tampered`, in both containers, in the first block and in a later one. A recipient packet that names the key and does not unwrap is `Tampered`. A message for someone else is `NoMatchingKey`. The fixtures tamper where no bound can fire | #1046 |
| E3 | Hostile input is refused, each kind with one error. Too many packets, too deep nesting, too much expansion: `LimitsExceeded`. In the new container this holds also after a key was unwrapped. In the old container that case is `Tampered` (section 2). Too many session-key packets to try (256 attempts, across nested containers): `LimitsExceeded`. A container without authentication: `Unsupported`. A certificate, revocation or backup beyond its bounds: `LimitsExceeded`. A panic inside a dependency becomes an internal failure and does not crash the app; a deliberate panic in test-only code shows it | #1046, and each piece for its own inputs |
| E4 | An outgoing message is never compressed, uses AES-256, and uses the new container only if every recipient supports it. The preview equals the message | #1046 |
| E5 | The quantum-safe flag comes from the message. A cut-off message is an error | #1046 |
| E6 | An expired or revoked recipient is refused, by position | #1046 |
| E7 | An expired or revoked key still decrypts | #1046 |
| E8 | An expired or revoked key does not sign | #1046 |
| E9 | Each verdict has its own case: verified, invalid, signer revoked, signer expired, unknown signer, not signed. A single invalid signature is never reported as something milder. One verified and one invalid signature together are `Verified`, with the verified signer. A correct signature outside its own time is `Unverifiable` | #1046 |
| E10 | A secret that belongs to another certificate is refused | #1046 |
| E11 | A name never comes from a User ID without a valid binding | #1046 |
| E12 | A certificate's shape is reported exactly. A P-256 key and a Curve25519 key never share a shape. A key that matches none of ours has no shape, and still reports its real algorithm and size | #1046 |
| E13 | The unlock stretch gives its pinned answer and refuses parameters out of range | #1046 |
| E14 | No error carries text (a compile-time check that `EngineError` is `Copy`) | #1046 |
| E15 | Every operation runs through the same function for every kind of custody. Each later piece adds its functions to this one test | #1047 |
| E16 | Custody fails closed: a device signature is verified before release; a wrong classical half fails before the device is asked; the hidden-recipient rule, with a point off the curve; a cancel or a failure of the device stops the operation and is reported as itself: in decryption for a packet that names the key and for a hidden one, and in signing. The combiner gives the answer of the RFC's vector | #1047 |
| E17 | A file is written only on success | #1048 |
| E18 | An expiry change takes effect, also right after generation | #1049 |
| E19 | A revocation revokes only its own key. An update must be the same key and never removes a revocation | #1049 |
| E20 | A backup file that asks for too much is refused before any derivation. A wrong passphrase is told apart from a file that is no backup. A device-bound key is not exportable | #1049 |
| E21 | `gpg` reads what the Legacy families write, and the engine reads what `gpg` writes. The same with `sq` for the v6 and post-quantum families | every piece |
| E22 | Everything made with a key carries the stamp that the caller gave, for every key shape: the primary key, the subkeys, every signature packet with its back-signature inside, and the prepared revocation. The key expires at the stamp plus the period. An expiry change does the same with its own stamp, also for a key that is older than the period. A stamp that is equal to the newest self-signature, or earlier, is refused, and so is a time beyond OpenPGP's range. The prepared revocation still revokes after a later self-signature. `gpg` and `sq` accept the results | #1047; the expiry change in #1049 |

**Core rules** (Swift tests in the core package, on the vault's software enclave and the real engine)

| # | Rule | Piece |
|---|---|---|
| C1 | While locked, no workspace exists. An old reference throws `locked` | #1062 |
| C2 | A file that is missing, damaged or from another version leads to the damaged phase, never to default values | #1062 |
| C3 | A save that fails changes nothing in memory | #1062 |
| C4 | A key whose stored material is missing or has the wrong form never shows a prompt, for a portable key and for a device-bound key | #1063 |
| C5 | One operation takes one approval | #1063 |
| C6 | A device-bound key is never exported or backed up | #1063 |
| C7 | A family name is given only to a pair of shape and custody that the app can make. An imported P-256 key has none | #1063 |
| C8 | After a reset nothing is left: no file, and no Keychain item under any service, also not one that the test planted under another service | #1065 |
| C9 | A wrong passphrase, a failed approval and a tampered message are three errors | #1066 |
| C10 | No plaintext file remains after an operation ends or fails, or when the app locks in the middle of a file operation | #1066 |
| C11 | After one key of every family is made, the Keychain holds exactly one row, the sealed root. The row has no attribute. Its name and its value hold no fingerprint, key ID, public key or User ID of those keys, as text or as bytes. The test's rows have no dates; with one row there is none to check | #1063 |
| C12 | With a fixed clock and a generator that gives a new value at each call, a new key's stamp is the clock minus its own draw: minus `STAMP_MIN_AGE` for the smallest draw, minus `STAMP_WINDOW` for the largest, both included. Two keys never share a draw. For an expiry change the core reads the newest self-signature from the certificate it changes. Inside the window, the new stamp is the second after it and nothing is drawn. Outside, it is the clock minus a new draw. When that second is less than `STAMP_MIN_AGE` old, the change is `tooSoon`. No period below `MIN_EXPIRY_DAYS` is accepted, and `MIN_EXPIRY_DAYS` is at least four windows | #1063 |

**The harness and the fixtures** are copied from the tests of the 1.x engine into `engine/tests/` in #1046. Five harness files do not depend on the engine and are copied unchanged. `sq.rs` and the two stand-ins for the Secure Enclave are tied to the old engine. The stand-ins become one software `DeviceKey` that can also cancel, fail and answer wrongly. With `CYPHERAIR_REQUIRE_GPG=1` and `CYPHERAIR_REQUIRE_SQ=1` a missing tool fails instead of skipping. A `sq` without post-quantum support fails as well. CI sets both. The tests of #1046 need expired and revoked keys before #1049 exists; they build them with Sequoia directly.

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
| Mac, arm64e | Not yet ¹ | Yes (`swift test --arch arm64e`) ² | Yes | The Mac. CI, if a hosted runner can run it |
| iPhone, arm64e | — ³ | Yes, on a connected iPhone | Yes | The owner's iPhone |
| iPhone simulator, Vision Pro simulator | — | Yes ⁴ | — | The Mac and CI |
| Vision Pro, arm64 and arm64e | — | — | — | Built and linked only. There is no hardware; `CUSTODY.md` §7 accepts this |
| iPhone, arm64 | — | — | — | Built and linked only ⁵ |

¹ An arm64e Rust executable built by the patched compiler runs on the Mac, but a Rust test binary cannot be built for arm64e: the compiler's prebuilt libraries have `std` without `libtest`. Until the compiler adds `library/test`, this slice is covered only by `swift test --arch arm64e`, which the core's package tests (#1062) are the first to run.
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
- *A stale library is found by a machine.* The script stores beside the library a hash of the engine's sources and the bindings generator, its lock file, the package manifest (which states the deployment targets), the compiler pin and itself, and the list of slices it built. The app build compares that hash with the checkout first, checks that the library has the slice it builds, and fails with the command that fixes it. Xcode lets the check read only the files it declares, so the script writes the list of its inputs to `engine/inputs.xcfilelist`. A piece that adds a source file runs the script and commits the list; the check fails until it does.

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
- The app's arm64e.x1 slice takes the arm64e objects of the library. The Swift packages are compiled for arm64e.x1 themselves.

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

**One exception to that rule.** #1046 lands `generate_portable_key` without a stamp and `Expiry` as a moment. #1047 adds the stamp argument, turns `Expiry` into a period, and adds the newest self-signature to `CertificateInfo` and `TimeOutOfRange` to the errors, before any core piece uses them.

**One clarification.** #1062 detects damaged data and shows the phase; #1065 adds the reset there, which is all the user can do.

| Piece | Adds |
|---|---|
| #1046 | The crate, the portable handle, the first eight functions of the table, the bounded walk and the unlock stretch (brought in), the harness and fixtures, the build script and the engine package |
| #1047 | The six custody modules (brought in, with the three required fixes of section 2.3), `DeviceKey`, the device handle, the two device functions, the software stand-in, and the way a device failure reaches the operation's error (section 2), which changes the handle's inner interface, `decrypt` and `encrypt`. For section 2.5: both generation functions take the stamp, `Expiry` is a period, and `CertificateInfo` reports the newest self-signature |
| #1048 | Signatures, files, `recognise`, the header functions, `erase_file` |
| #1049 | Expiry, revocation, update, backup with `backup_s2k` (brought in). For section 2.5: `change_expiry` takes its stamp, and the revocation made at import carries the key's creation time |
| #1062 | The core package, `AppCore` and its phases, first run, unlock, `lock()`, damage detection, the store and the payloads, settings, the vault changes of section 3, `CoreError` with every case, `preview()` |
| #1063 | `PrivateKeyAccess`, `DeviceKeyBridge`, the memory guard, everything in `Keys`, the stamp and its draw (section 2.5) |
| #1064 | Everything in `Contacts` |
| #1065 | The timing rules of the lock, passphrase change, and reset, also the reset in `Recovery` |
| #1066 | Everything in `Messages`, temporary files |
| #1067 | The debug screen in `App/Bench/`, which runs the real path on the owner's devices |

One thing to know about the order: #1063 and #1064 need #1049, the last engine piece. So only #1062 can start before the engine is complete. If the core should start earlier, #1063 can be split: the private-key path, generate, delete and default after #1047; backup, expiry and revoke after #1049. This is a choice for the plan, not for the design.
