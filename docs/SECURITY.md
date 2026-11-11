# Security Model

## 1. Threat model

Three statements an auditor needs that the code cannot make:

1. **A copy of the container and the Keychain decrypts nothing.** Every secret at rest is ciphertext whose key only this device's Secure Enclave can produce, and the enclave produces it only with user presence and the unlock passphrase. Enclave key blobs are bound to the SoC and inert off-device, so neither a dump nor another device can attack them.
2. **The passphrase is the factor an attacker must know.** Presence can be borrowed inside Apple's biometric reuse window or phished with a fake prompt, and a compromised kernel can observe the device passcode. Neither opens anything here, because the enclave folds the stretched passphrase into the wrapping key's protection as an application password — key material the enclave needs, not a constraint it checks. No Keychain row carries an access control; every gate is an enclave key.
3. **Out of scope, stated plainly:** an unlocked session against a kernel-level memory reader, and the passphrase against an implant capturing keystrokes at the moment it is typed. Relock bounds the first; nothing a third-party app can do bounds the second. Device-bound private material stays unextractable even then. Deletion of a sealed file is detected (§5); rollback of a file is not detected and yields older state, never forged state. Older state can include a key that was deleted since, because a key's private part is stored in the key list; the sealed files are not in device backups ([STORAGE.md](STORAGE.md) §2), so an old file has to reach the device some other way.

## 2. Format and interop rules

- The engine reads v4 and v6 keys and opens SEIPDv1 and SEIPDv2 messages. The legacy Symmetrically Encrypted Data packet (tag 9, no MDC) is refused on decrypt.
- **Outgoing messages are never compressed, and always use AES-256.** `deflate` is read-only for compatibility; bzip2 is excluded (a second C dependency).
- **The quantum-safe flag is read from the message itself** — its session-key packets and its container — never from the list of recipients. A message cut off before its container is an error, not a flag.
- **A decryption whose authentication fails returns no plaintext**, in either container.

## 3. The vault

- **One sealed root, one wrapping key, one passphrase.** The wrapping key is an enclave P-256 key-agreement key created with private-key usage, user presence, and the application-password option, with the stretched passphrase as its application password. It seals a random 32-byte root secret. The root secret is never derived from the passphrase, so a passphrase change is a reseal, never a rotation.
- **Two session values, nothing else.** HKDF-SHA256 over the root secret with distinct labels yields the wrapping root key for protected app data and the identity credential for identity keys. The root secret and the stretched passphrase are zeroized the moment both exist; the session values are zeroized at relock.
- **Every enclave key the app creates carries the application-password option**, with exactly one platform exception: enclave ML-KEM keys, which cannot decapsulate under it (§9, [CUSTODY.md](CUSTODY.md) §4). No other code path creates an enclave key without the option, and the vault's tests record every policy the fake enclave is handed to prove it. Identity keys are created only inside an unlocked session, with the identity credential as their password.
- **One identity wrapping key** — an enclave key with the same flags, whose blob lives in the sealed root's metadata — seals every portable private key and every split-custody classical half. Device-bound keys are enclave-resident and carry the identity credential directly.
- **One envelope construction, three payload kinds.** Ephemeral-static ECDH on P-256, HKDF-SHA256 over a random salt and a binding of every public field, AES-256-GCM with the same binding as authenticated data; the sealing key's blob and public key are folded in. The payload kind — root secret, secret keys, split-custody component — rides in both the derivation and the authenticated data, so a blob opens only as what it was sealed as, wherever it is stored.
- **The current envelope is the only supported payload.** Anything else fails closed as ordinary undecodable input.
- **Secure Enclave key loss is permanent.** Device erase, iCloud restore, and backup restore destroy enclave keys, and an enclave key exists only as its stored blob. No detect-and-re-wrap flow exists or can exist.
- **Key metadata is gated, and nothing readable gets around the gate**: every key's certificate and private part live in the protected `keys` domain, so nothing about a key is loaded before unlock, and the Keychain holds the sealed root alone. What a locked app still shows: [STORAGE.md](STORAGE.md) §2.
- **The software composition never holds user data.** A software enclave with rows held in memory serves the simulator, previews, and tests; the production composition is the one place that pairs the hardware enclave with Keychain rows.
- **Sanitized failure mapping.** Failure surfaces expose only stable app-owned categories. Logs, errors, UI, and Rust never carry fingerprints, Keychain row names, enclave key blobs, public-binding bytes, plaintext, private material, shared secrets, session keys, derived keys, digests, or signatures. Three failures must never collapse into one message: a refused application password, a failed local authentication, and a failed payload authentication — "wrong passphrase", "you failed Face ID", and "the ciphertext was tampered with" are different facts.

## 4. Authentication

- **One configuration.** Unlock is the passphrase plus one system presence prompt — biometrics with the device passcode or Mac password as the system's own fallback. There is no mode, no policy, and therefore no re-wrap workflow for changing one.
- **One prompt per unlock.** The unlock context carries the stretched passphrase as its credential and is evaluated once; the wrapping key is the only enclave gate at unlock; the context is invalidated the moment the session values exist. Within the relock delay nothing is asked.
- **A typo costs no second prompt.** A refused passphrase is retried on the same authenticated context; only the credential changes. The context ends when the device locks, or when the app goes away while no submission runs, so a later try shows the prompt again.
- **One approval per private operation.** Each operation evaluates the key's own constraint once — presence with the passcode fallback for a portable key, which the identity wrapping key's policy already allows, and biometrics alone for a device-bound key — on a fresh context with biometric reuse duration zero, then disallows interaction on that context; the enclave loads that follow consume the approval, and the identity credential rides silently.
- **Presentation is the system authentication sheet** on every platform.
- **Passphrase change is one atomic row update.** The same root secret is sealed under a new wrapping key, with a new salt, and the sealed root row's value is replaced in place; the Keychain applies the update atomically, so the old passphrase stays in force until the new value exists. The old wrapping key lived only inside the old envelope and is gone with it. A cancelled prompt leaves no intent behind.

## 5. Protected app data

Protected app data is what the app keeps in its three sealed files. Their contents and the exceptions: [STORAGE.md](STORAGE.md). The invariants:

- **Domains open only after unlock.** Before unlock the app derives no key and opens no sealed file.
- **Domain keys are derived, never stored.** Each domain's key is HKDF over the wrapping root key with the domain label; derived keys and decrypted payloads are session-local.
- **One sealed file per domain** ([STORAGE.md](STORAGE.md) §2). A temporary file that an interrupted save left is swept at launch. The set of domains is fixed by the app, and the sealed root's existence is the marker that onboarding completed.
- **One integrity-failure state, never a silent default.** If the sealed root exists and any domain file is missing or fails to authenticate, unlock opens the damaged phase, whose report names each file as intact, missing or damaged; nothing is exported or rescued from there. A file made by another version of the app is named as such, apart from damage, and nothing in it is read or rescued. Nothing is repaired or re-bootstrapped per domain, and no setting falls back to a default. Reinstalling on iOS lands here too, because the sealed root's row outlives the app's files. Without a sealed root nothing on the device can be opened, so onboarding starts over and first-run setup writes fresh domain files.
- **Relock is fail-closed and happens in one place**: block new access, zeroize both session values, and drop the decoded values. Relock applies to the damaged phase as well, because it also holds an open session.
- **File protection is verified, not assumed** (§9); storage outside the app-owned container is never a fallback.

## 6. Argon2id

**The unlock profile** stretches the unlock passphrase into the wrapping key's application password. Its parameters are fixed in code, with a ceiling of one second on the slowest supported device; its salt is public metadata in the sealed root. It exists to make each on-device guess through the enclave expensive; off-device guessing is impossible regardless, because the enclave key never leaves the device. It is never used for a backup.

**The iOS memory entitlements** (`increased-memory-limit` and `extended-virtual-addressing`) exist for the 2 GiB derivation of a backup (§10); macOS applies no such limit.

**The passphrase is the other half of the cost.** Every passphrase the user chooses meets the same two requirements, a minimum length and no character repeated past a short run; the core refuses one that does not, before any prompt. The requirements are deliberately not a strength score, which would need frequency corpora this app will not ship or download. Entering a passphrase that already protects an artifact is never gated.

## 7. Memory Integrity Enforcement

MIE (hardware memory tagging) protects all C/C++ code — **including vendored OpenSSL, which is why the requirement exists** — on supported hardware; tag mismatches terminate the process, converting silent corruption into a detectable, non-exploitable crash. Unsupported devices run normally. Enablement is the Enhanced Security capability, whose `hardened-process*` keys in the entitlements files are the canonical list and must never be removed. The iOS memory entitlements (§6) are a separate axis and not hardening keys. The hardware-checked pointer arithmetic slice (`arm64e.x1`) covers Swift code only: the app and its Swift packages are compiled for it, while the Rust engine and its vendored OpenSSL run inside it as plain arm64e code until their toolchains can emit the slice.

## 8. Known limitations

- **Passphrase `String` cannot be reliably zeroized.** The core takes each passphrase as a `String`, the type a secure text field binds to, and a `String`'s storage cannot be erased: its lifetime is up to ARC. Every passphrase lives only for the duration of the call and is never persisted.
- **The credential inside an authentication context cannot be zeroized.** The context object holds its own copy of the bytes it was handed; the app invalidates and drops it, and accepts that the copy lives until the object is freed.
- **An unlocked session is readable by a kernel-level attacker.** Memory then holds the wrapping root key, the identity credential, the derived domain keys, and a private key only during the operation that uses it. The identity credential stays useful to such an attacker until the sealed root is deleted by a reset.
- **FFI transit copies.** UniFFI copies what crosses the boundary, on both sides, and frees its copies without zeroization. A value the engine returns is handed to UniFFI as it is and freed the same way. Neither side can reach these copies. So a secret that the engine returns stays in freed heap memory until that memory is reused: the unlock stretch output, the `secret` of a `NewKey` (a portable key's secret key packets or a post-quantum key's classical halves), and decrypted plaintext. The same holds for what a Secure Enclave key returns through the `DeviceKey` callback: a P-256 shared secret or an ML-KEM key share. This is an accepted residual. Each side zeroizes what it keeps: the engine the working copies it makes and does not return, the core the values it receives. A secret that goes into the engine is borrowed and crosses without a copy. ASLR, the app sandbox, and MIE raise the bar for exploiting both residuals; they do not close them.
- **Argon2id's stack state is scrubbed only best effort.** The engine zeroizes the unlock stretch's working memory when the derivation ends, success or failure. The argon2 crate erases one copy of the initial hash and the buffers that fold the final blocks; the rest of its transient state lives on the calling thread's stack, including copies of the passphrase, the initial hash and the derived key, and the blocks that seed the lanes and carry each compression. The unlock stretch overwrites the stack below its frame once the derivation returns, which relies on the compiler keeping the derivation out of line and within the overwritten depth.

## 9. Platform facts

Behaviour the design rests on that Apple does not document, or documents only partially.

- **The application password is enforced by the enclave for P-256 key agreement, P-256 signing, ML-DSA-65, and ML-DSA-87.** A context with no credential and interaction disallowed fails before the enclave with LocalAuthentication error −1004, "user interaction is required", because the system would otherwise show its own password dialog; a wrong credential fails inside the enclave with CryptoTokenKit −3 and an AKS error; the right credential succeeds on a fresh context, so nothing is cached across contexts. Creation with the option and no credential fails the same way. Consequence: the app always sets the credential itself, and a custody operation context has interaction disallowed once its one evaluation has passed.
- **One authenticated context covers every enclave key it is handed, with no second prompt**, and the two factors stay independent on it: with the biometric satisfied, removing the credential fails with −1004 and a wrong credential fails inside the enclave; with the credential set on a fresh context that has no biometric result, the operation fails with −1004 rather than silently passing. Creating a key with the option on an authenticated context still needs the credential. Basis of the one-prompt unlock and of every per-operation context.
- **Enclave ML-KEM-768 and ML-KEM-1024 keys created with the option cannot decapsulate at all**, whatever the context, while the same keys without the option decapsulate normally. Observed on macOS 27. Consequence: §3's single exception and [CUSTODY.md](CUSTODY.md) §4.
- **Enclave reconstruction is a synchronous, blocking call.** With the key's constraint evaluated beforehand on the same context and interaction disallowed, it shows no sheet. On macOS a sheet makes the app look as if it went away.
- **Complete file protection must be verified per volume**: every domain file write re-reads the attribute it set and fails closed when it did not stick. Simulator builds alone accept a missing readback, since the simulator's volume never reports the attribute.

## 10. Not built yet

Rules for pieces that are not built yet. Each names the piece that builds it: a piece of [ARCHITECTURE.md](ARCHITECTURE.md) §9, or a screens piece by its issue.

- **#1048.** Streaming decryption must release output only through the success-only temporary-file-then-rename contract.
- **#1049.** Importing a key must read both Iterated+Salted and Argon2id S2K.
- **#1049.** The backup profile of Argon2id must run only on private-key export and passphrase-protected private-key import of a v6 key, with the parameters of [ARCHITECTURE.md](ARCHITECTURE.md) §2.4; never for decrypt or sign. It runs once per secret-key packet, one after another, so peak memory stays 2 GiB.
- **#1049.** A backup derivation's working memory must be zeroized when it ends, success or failure; Sequoia does this. Its stack is not scrubbed afterwards, as the unlock stretch's is (§8), so that state stays on the thread's stack until later calls overwrite it.
- **#1049, #1063.** After enclave keys are lost, the only recovery must be importing the user's passphrase-protected backup of a portable key; a device-bound key cannot be recovered. The user's own backup is also what protects against damaged files (§5).
- **#1063.** Exporting a revocation certificate must use only the stored one and fail closed when it is missing; it is never made again.
- **#1063.** The memory guard of [ARCHITECTURE.md](ARCHITECTURE.md) §3 must refuse a device that cannot afford the backup derivation, on the export and the import side alike, and never give it weaker parameters.
- **#1063.** A backup must be protected by a passphrase entered for it, which meets the requirements of §6; the app never uses the unlock passphrase for a backup.
- **#1063.** A key the app makes must carry the stamp of [ARCHITECTURE.md](ARCHITECTURE.md) §2.5, drawn from the system's secure random generator and from nothing else, so that none of the readable times of [STORAGE.md](STORAGE.md) §2 is a time inside the key. §2.5 says where this guarantee ends.
- **#1064.** Manual verification of a contact must be a local fingerprint assertion, not an OpenPGP certification.
- **#1065.** Each system prompt must run inside a short window that covers the prompt and the Keychain or Secure Enclave call right after it, so that the app going inactive for its own prompt is not taken for going away, while a real away event with a relock delay of zero still locks at once. Longer work stays outside the window. #1063 opens the window around each approval.
- **#1065.** The new passphrase of a change must meet the requirements of §6.
- **#1065, #1055.** Reset needs no passphrase. Forgot Passphrase on the lock surface leads to Reset All Local Data behind a typed confirmation: anyone holding the device can destroy the vault, and nobody can read it. Destruction without the passphrase is accepted; disclosure is not.
- **#1065, #1055.** The damaged phase must offer Reset All Local Data as its only way on.
- **#1066.** Relock must also stop running file operations and erase staged plaintext files, and treat a failure and a late result as [ARCHITECTURE.md](ARCHITECTURE.md) §4 says.
- **#1066.** Every scratch write must have its file protection verified, as every domain file write does.
- **#1066.** Decrypt's recipient-parsing phase is unauthenticated, so the matched-key guard must run before any private-key access.
- **#1053, #1056.** A copy to the clipboard must be device-only and expire after five minutes. macOS has no per-write expiry, so there the app clears the copy on its own clock, and quitting the app first leaves it on the pasteboard.
- **#1050, #1053, #1055.** Every screen where the user chooses a passphrase must offer a generated one (`Passphrase.suggestion()`).
