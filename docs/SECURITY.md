# Security Model

## 1. Threat model

Four statements an auditor needs that the code cannot make:

1. **A copy of the container and the Keychain decrypts nothing.** Every secret at rest is ciphertext whose key only this device's Secure Enclave can produce, and the enclave produces it only with user presence and the unlock passphrase. Enclave key blobs are bound to the SoC and inert off-device, so neither a dump nor another device can attack them.
2. **The passphrase is the factor an attacker must know.** Presence can be borrowed inside Apple's biometric reuse window or phished with a fake prompt, and a compromised kernel can observe the device passcode. Neither opens anything here, because the enclave folds the stretched passphrase into the wrapping key's protection as an application password — key material the enclave needs, not a constraint it checks. No Keychain row carries an access control; every gate is an enclave key.
3. **Out of scope, stated plainly:** an unlocked session against a kernel-level memory reader, and the passphrase against an implant capturing keystrokes at the moment it is typed. Relock bounds the first; nothing a third-party app can do bounds the second. Device-bound private material stays unextractable even then. Deletion and rollback are detected, never prevented.
4. **Passphrase `String` cannot be reliably zeroized** (§9).

### Screen capture (macOS)

Every window the macOS app puts on screen is excluded from capture (`NSWindowSharingNone`), in every build configuration, so another process holding the Screen Recording grant cannot read plaintext, contact identities, or armored key material out of the app's windows. What it does not cover: window titles and bounds stay readable, so the app's titles are generic and must stay generic; it stops processes, not people looking at the screen, which is what the privacy cover addresses; and UI drawn by other processes is outside it entirely — with Simplified Chinese a first-class locale, text composed through an input method is rendered in the IM's own candidate window. iOS, iPadOS, and visionOS are not addressed here.

The mechanism rests on an API in tension with itself: the SDK header describes `NSWindowSharingNone` as current, while Apple's documentation calls it legacy. Measurement agrees with the header today, on macOS 27. **Re-check it each macOS major** with `scripts/probe_macos_window_capture.sh`, which attempts a real cross-process capture and fails loudly if the system has stopped enforcing the flag; the unit lane guards only that the app still sets it.

## 2. Format and interop rules

- The app reads v4 and v6 keys, SEIPDv1 and SEIPDv2, and on key import both Iterated+Salted and Argon2id S2K. The legacy Symmetrically Encrypted Data packet (tag 9, no MDC) is hard-rejected on decrypt.
- **Outgoing messages are never compressed.** `deflate` is read-only for compatibility; bzip2 is excluded (a second C dependency).
- **Any post-quantum recipient enforces an AES-256 floor**, inside both SEIPDv1 and SEIPDv2 containers.
- **The quantum-safety badge derives from the produced artifact** — the session-key algorithms of the message — never from the live recipient selection. Classification fails closed on a truncated prefix, and callers map the failure to *no badge*, never a misleading one.
- **An AEAD authentication failure during decryption aborts with no partial plaintext.**

## 3. The vault

- **One sealed root, one wrapping key, one passphrase.** The wrapping key is an enclave P-256 key-agreement key created with private-key usage, user presence, and the application-password option, with the stretched passphrase as its application password. It seals a random 32-byte root secret. The root secret is never derived from the passphrase, so a passphrase change is a reseal, never a rotation.
- **Two session values, nothing else.** HKDF-SHA256 over the root secret with distinct labels yields the wrapping root key for protected app data and the identity credential for identity keys. The root secret and the stretched passphrase are zeroized the moment both exist; the session values are zeroized at relock.
- **Every enclave key the app creates carries the application-password option**, with exactly one platform exception: enclave ML-KEM keys, which cannot decapsulate under it (§10, [CUSTODY.md](CUSTODY.md) §4). No code path creates an enclave key without the option, and the fake enclave in the unit lane records every flag set it is handed to prove it. Identity keys are created only inside an unlocked session, with the identity credential as their password.
- **One identity wrapping key** — an enclave key with the same flags, whose blob lives in the sealed root's metadata — seals every portable private key and every split-custody classical half. Device-bound keys are enclave-resident and carry the identity credential directly.
- **One envelope construction, three payload kinds.** Ephemeral-static ECDH on P-256, HKDF-SHA256 over a random salt and a binding of every public field, AES-256-GCM with the same binding as authenticated data; the sealing key's blob and public key are folded in. The payload kind — root secret, secret certificate, split-custody component — rides in both the derivation and the authenticated data, so a blob opens only as what it was sealed as, whichever row it was found in.
- **Storage before zeroization.** A raw private key is zeroized only after the envelope write is confirmed; the reverse order would permanently lose the key.
- **The current envelope is the only supported payload.** Anything else fails closed as ordinary undecodable input. There is no legacy format and no migration path, ever.
- **Secure Enclave key loss is unrecoverable except by re-import.** Device erase, iCloud restore, and backup restore destroy enclave keys; because every enclave key exists only inside the row it protects, the only recovery is re-importing from the user's passphrase-protected backup. No detect-and-re-wrap flow exists or can exist.
- **A Secure Enclave route never falls back to software secret-certificate material.** Decrypt's recipient-parsing phase is unauthenticated, and the matched-key guard runs before any private-key access.
- **Revocation.** Export uses only the stored revocation artifact and **fails closed when it is missing — a missing artifact is never regenerated**. Import generates a key-level revocation for the imported key. Certification persistence never inserts signatures into a stored contact certificate, never changes manual verification state, and introduces no web-of-trust semantics.
- **Key metadata is gated, not secret**: it lives in the protected `key-metadata` domain so key-list loading happens only after unlock, while the sealed envelopes stay in their own Keychain namespaces.
- **Streaming decrypt releases output only through the success-only `.tmp`-then-rename contract.**
- **Sanitized failure mapping.** Failure surfaces expose only stable app-owned categories. Logs, errors, UI, protected data, and Rust never carry fingerprints, handle-set identifiers, public-binding bytes, Keychain locators, plaintext, private material, shared secrets, session keys, KEKs, digests, or signatures. Three failures must never collapse into one message: a refused application password, a failed local authentication, and a failed payload authentication — "wrong passphrase", "you failed Face ID", and "the ciphertext was tampered with" are different facts.

## 4. Authentication

- **One configuration.** Unlock is the passphrase plus one system presence prompt — biometrics with the device passcode or Mac password as the system's own fallback. There is no mode, no policy, and therefore no re-wrap workflow for changing one.
- **One prompt per unlock.** The unlock context carries the stretched passphrase as its credential and is evaluated once; the wrapping key is the only enclave gate at unlock; the same context opens the domains; it is invalidated the moment the session values exist. Within the grace period nothing is asked.
- **A typo costs no second prompt.** A refused passphrase is retried on the same authenticated context; only the credential changes.
- **One approval per private operation.** Each operation uses a fresh context with the identity credential set and biometric reuse duration zero; the enclave prompts for the key's constraint and the credential rides silently. Longer work stays outside the prompt window.
- **Presentation is the system authentication sheet** on every platform. Environment-dependent platform gates (such as the macOS embedded-LA denial) are verified against the **installed app build, never the unit-test host** — test-host probes have passed while the real app was denied.
- **Each system prompt runs inside a short operation-prompt session** covering the prompt plus the immediately following Keychain or Secure Enclave call, so prompt-lifecycle resigns are deferred while genuine away events under grace = 0 still relock immediately.
- **Passphrase change is a staged reseal.** Run the unlock chain, take the new passphrase, draw a new salt, create a new wrapping key under the new stretched value, seal the same root secret into a staged row, promote it, delete the old row. **Crash-recovery invariant:** the committed row stays authoritative until the staged row is confirmed; a cancelled prompt leaves no intent behind.
- **Device-bound keys always require biometrics**, fixed at creation, with no passcode fallback ([CUSTODY.md](CUSTODY.md)).

## 5. Protected app data

Protected app data is the security domain for CypherAir-owned local state outside private-key material. Rows, domains, and exceptions: [STORAGE.md](STORAGE.md). The invariants:

- **Domains open only after unlock.** Pre-unlock startup may classify the registry and bootstrap metadata but must not derive the wrapping root key, derive any domain key, or open protected payloads.
- **Domain keys are derived, never stored.** Each domain's key is HKDF over the wrapping root key with the domain label; unwrapped keys and decrypted payloads are session-local.
- **No silent reset, anywhere.** Missing or corrupt payloads enter recovery instead of resetting to defaults; encryption never silently uses a default encrypt-to-self value; while settings are unavailable, resume grace fails closed to immediate authentication.
- **Anti-rollback watermark, with its honest scope.** Payload generations behind the bootstrap watermark, or more than one ahead, enter recovery; exactly one ahead is the interrupted-commit signature and heals forward only after the envelope authenticates. The watermark defends against *selective* rollback; a coherent whole-container restore is outside its scope by design.
- **The registry is the only authority for committed domain membership**; membership is never inferred from directory listings.
- **Relock is fail-closed**: block new access, fan out to all relock participants, zeroize both session values, clear derived keys and snapshots; any participant failure latches a runtime-only, never persisted, restart-required state.
- **File protection is verified, not assumed** — registry files, bootstrap metadata, scratch writes, and committed domain files; storage outside the app-owned container is never a fallback.
- **Contacts:** manual verification is a local fingerprint assertion, not OpenPGP certification; certification-signature export is an explicit artifact boundary, not a Contacts backup.

## 6. Guided tutorial containment

The guided tutorial may run real app services and real OpenPGP operations only inside an isolated tutorial dependency graph; it must never read or mutate real keys, contacts, settings, files, or exports. Its sandbox vault is the production code path over a random root and a random session credential with real enclave keys; **no software fallback in sandbox custody** — without a Secure Enclave it fails closed. **No impersonation** — the ephemeral stores throw their own error types, never production ones. **Output interception** blocks real file import/export, clipboard writes, URL handoff, app-icon changes, and every other real-workspace side effect; tutorial completion state is the only fact that persists across restarts.

## 7. Argon2id

Two profiles, never interchanged.

**The backup profile** runs on exactly two shipped paths: **private-key export** and **passphrase-protected private-key import**, both for the v6 portable families. It never runs for routine decrypt or sign, and never for Portable Legacy, which uses Iterated+Salted S2K in both directions. The engine can also derive under a foreign message's parameters when opening a password-encrypted message, bounded before the KDF runs; that is engine capability, not a shipped surface. The parameters emitted are RFC 9106's primary recommendation at 2 GiB. **The derivation runs once per secret-key packet, not once per operation:** a v6 certificate carries three, so a single export or import runs the 2 GiB derivation three times in sequence — peak memory stays 2 GiB, wall-clock cost roughly triples. **Memory-safety guard, both key paths.** The app refuses a derivation above 75% of the memory this process was actually granted; the message path is bounded in Rust instead, because there the parameters are untrusted input. **A device that cannot afford the derivation is refused, never given weaker parameters**, on the backup and the restore side alike — which is what makes the 8 GB device floor ([PRODUCT.md](PRODUCT.md)) load-bearing, and why the iOS memory entitlements exist; macOS applies no such limit.

**The unlock profile** stretches the unlock passphrase into the wrapping key's application password. Its parameters are fixed in code, far below the guard's threshold, with a ceiling of one second on the slowest supported device; its salt is public metadata in the sealed root. It exists to make each on-device guess through the enclave expensive; off-device guessing is impossible regardless, because the enclave key never leaves the device. It is never used for a backup, and a backup passphrase never doubles as the unlock passphrase.

**The passphrase is the other half of the cost.** Every screen where the user chooses a passphrase — the unlock passphrase at onboarding and on change, and every backup — applies the same two requirements, a minimum length and no character repeated past a short run, and offers a generated ~116-bit value as the primary path. The requirements are deliberately not a strength score, which would need frequency corpora this app will not ship or download. Entering a passphrase that already protects an artifact is never gated.

## 8. Memory Integrity Enforcement

MIE (hardware memory tagging) protects all C/C++ code — **including vendored OpenSSL, which is why the requirement exists** — on supported hardware; tag mismatches terminate the process, converting silent corruption into a detectable, non-exploitable crash. Unsupported devices run normally. Enablement is the Enhanced Security capability, whose `hardened-process*` keys in the entitlements files are the canonical list and must never be removed. The iOS memory entitlements (§7) are a separate axis and not hardening keys. The hardware-checked pointer arithmetic slice covers Swift code only; the Rust engine and its vendored OpenSSL run inside it as plain arm64e code until their toolchains can emit the slice. Validation: [TESTING.md](TESTING.md).

## 9. Known limitations

- **Passphrase `String` cannot be reliably zeroized.** The secure text field binds to `String` and the FFI copies it, so the Swift-side copy's lifetime is up to ARC. Scope: the unlock passphrase and the import and export passphrases. Key export/import also leaves a Rust-side copy that is dropped without zeroization — an open gap, not a mitigated one. Every passphrase lives only for the duration of the call and is never persisted.
- **The credential inside an authentication context cannot be zeroized.** The context object holds its own copy of the bytes it was handed; the app invalidates and drops it, and accepts that the copy lives until the object is freed.
- **An unlocked session is readable by a kernel-level attacker.** Memory then holds the wrapping root key, the identity credential, the derived domain keys, and a private key only during the operation that uses it. The identity credential stays useful to such an attacker until the sealed root is deleted by a reset.
- **FFI transit copies.** Every buffer crossing the UniFFI boundary is serialized into a transit copy freed without zeroization; both endpoints zeroize the copies they own, and the transit copy's brief lifetime in freed heap memory is an accepted residual. ASLR, the app sandbox, and MIE raise the bar for exploiting both residuals; they do not close them.
- **The macOS clipboard expiry is the app's own clock.** macOS has no per-write expiry, so the five-minute clear runs in-process: quitting the app before a copy expires leaves it on the pasteboard until something else replaces it. The device-only half is a property of the write itself, and on the other platforms the system owns the expiry.

## 10. Platform facts

Behaviour the design rests on that Apple does not document, or documents only partially, each recorded by a probe in the device lane ([TESTING.md](TESTING.md)) so a change surfaces as a failure.

- **The application password is enforced by the enclave for P-256 key agreement, P-256 signing, ML-DSA-65, and ML-DSA-87.** A context with no credential and interaction disallowed fails before the enclave with LocalAuthentication error −1004, "user interaction is required", because the system would otherwise show its own password dialog; a wrong credential fails inside the enclave with CryptoTokenKit −3 and an AKS error; the right credential succeeds on a fresh context, so nothing is cached across contexts. Creation with the option and no credential fails the same way. Consequence: the app always sets the credential itself and disallows interaction on every context except the unlock context.
- **One authenticated context covers every enclave key it is handed, with no second prompt**, and the two factors stay independent on it: with the biometric satisfied, removing the credential fails with −1004 and a wrong credential fails inside the enclave; with the credential set on a fresh context that has no biometric result, the operation fails with −1004 rather than silently passing. Creating a key with the option on an authenticated context still needs the credential. Basis of the one-prompt unlock and of every per-operation context.
- **Enclave ML-KEM-768 and ML-KEM-1024 keys created with the option cannot decapsulate at all**, whatever the context, while the same keys without the option decapsulate normally. Observed on macOS 27. Consequence: §3's single exception and [CUSTODY.md](CUSTODY.md) §4.
- **Enclave reconstruction with a biometric constraint is a synchronous, blocking call** and must run off the main actor, or the biometric sheet's scene transitions are delivered after the operation-prompt session has ended and are mistaken for backgrounding.
- **Access-control creation follows the CF create rule**: the error out-parameter is an owned reference to release on failure.
- **The access-control and accessibility attributes are mutually exclusive on a row, and private-key usage applies only to key items**; rows storing sealed blobs use the accessibility attribute alone. Every query names the data-protection Keychain, and on macOS rows set synchronizable to false explicitly.
- **An authentication context is not Sendable**; it crosses actors inside a carrier, is consumed by exactly one operation, and is invalidated by its owner afterwards.
- **Complete file protection must be verified per volume**: the storage root re-reads the attribute it wrote and fails closed when the volume does not support it, which is what the simulator's volume does.
- **Packages are built for arm64e and x1 only with the shared workspace setting** ([ARCHITECTURE.md](ARCHITECTURE.md)).
