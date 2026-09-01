# Security Model

*Threat model, fail-closed rules, authentication contracts, and storage invariants. Custody promises: [CUSTODY.md](CUSTODY.md). Storage promises and exceptions: [STORAGE.md](STORAGE.md).*

## 1. Threat model

Four statements an auditor needs that the code cannot make:

1. **Secure Enclave-bound blobs are inert off-device.** Keychain extraction without the SE hardware yields ciphertext that cannot be decrypted; SE key blobs are bound to the SoC UID.
2. **Software custody accepts a named tradeoff:** the raw private key exists briefly in app memory during use. Device-bound families avoid it entirely.
3. **ProtectedData has no path that opens without the SE factor.** There is no fallback.
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

## 3. Private-key custody and storage

Every software-custody private key is sealed under a per-key Secure Enclave key and persists as a single self-contained Keychain row with that key's blob folded in. The rules that are not visible in the bytes:

- **Storage before zeroization.** The raw private key is zeroized only after the envelope write is confirmed; the reverse order would permanently lose the key.
- **The envelope is the only supported private-key payload.** Anything else fails closed as ordinary undecodable input. There is no legacy wrapping format and no migration path, ever. The envelope's authenticated payload kind keeps a software secret certificate and a split-custody classical component from ever being opened as one another, whichever row either was found in.
- **Secure Enclave key loss is unrecoverable except by re-import.** SE keys are destroyed by device erase, iCloud restore, or backup restore; because the SE key exists only inside the envelope it seals, the only recovery is re-importing from the user's passphrase-protected backup. No detect-and-re-wrap flow exists or can exist.
- **A Secure Enclave route never falls back to software secret-certificate material.** Decrypt's recipient-parsing phase is unauthenticated, and the matched-key guard runs before any private-key access.
- **Revocation.** Export uses only the stored revocation artifact and **fails closed when it is missing — a missing artifact is never regenerated**. Import generates a key-level revocation for the imported key. Certification persistence never inserts signatures into a stored contact certificate, never changes manual verification state, and introduces no web-of-trust semantics.
- **Key metadata is gated, not secret**: it lives in the protected `key-metadata` domain so key-list loading happens only after app-session authentication, while the sealed envelope stays in the private-key Keychain namespace.
- **Streaming decrypt releases output only through the success-only `.tmp`-then-rename contract.**
- **Sanitized failure mapping.** Failure surfaces expose only stable app-owned categories. Logs, errors, UI, ProtectedData, and Rust never carry fingerprints, handle-set identifiers, public-binding bytes, Keychain locators, plaintext, private material, shared secrets, session keys, KEKs, digests, or signatures. Local-authentication failure stays a separate category from payload-authentication failure — "you failed Face ID" and "the ciphertext was tampered with" must never collapse into one message.

**ProtectedData is a separate root-secret model — do not conflate it with private-key envelope wrapping.** Its root secret folds in a ProtectedData-only SE device-binding key that is reconstructed at open time as a silent second factor, with no user-facing prompt of its own because the app-session Keychain gate is the prompt. The two envelope families share a construction but are domain-separated so neither blob can be misread as the other. If the enclave cannot reconstruct the folded key, ProtectedData fails closed into framework recovery.

## 4. Authentication

**Two independent axes:** the app-session authentication policy gates the app privacy session and root-secret access; the authentication mode (Standard / High Security) governs private-key Secure Enclave flags. Neither implies the other.

- **Presentation is the system authentication sheet** for both subsystems on every platform. Environment-dependent platform gates (such as the macOS embedded-LA denial) are verified against the **installed app build, never the unit-test host** — test-host probes have passed while the real app was denied.
- **Each system prompt runs inside a short operation-prompt session** covering the prompt plus the immediately following Keychain or Secure Enclave call; longer work stays outside it, so prompt-lifecycle resigns are deferred while genuine away events under grace = 0 still relock immediately.
- **Standard Mode keys keep the passcode fallback; High Security Mode keys have none**, and their fallback button is hidden. Keys survive biometric re-enrollment in both modes; in High Security Mode, while biometrics are unavailable, all private-key operations are blocked until restored.

**Mode switching** re-wraps every software-custody key under a single authentication taken under the **current** mode (a cancelled prompt leaves no intent behind); device-bound keys are exempt ([CUSTODY.md](CUSTODY.md)). **Crash-recovery invariant:** old rows stay authoritative until every new row is confirmed, the new mode is persisted only after a full successful promotion, and a no-complete-row-anywhere state is unrecoverable and surfaces a generic warning that never includes fingerprints.

## 5. Protected app data

Protected app data is the security domain for CypherAir-owned local state outside private-key material. Rows, domains, and exceptions: [STORAGE.md](STORAGE.md). The invariants:

- **Domains open only after app privacy authentication.** Pre-auth startup may classify the registry and bootstrap metadata but must not retrieve the root secret, unwrap any domain master key, or open protected payloads.
- **One prompt per unlock.** The post-unlock opener reuses the authenticated context across all registered domains; the handoff-only path never starts a new interactive prompt.
- **The raw root secret exists only to derive the wrapping root key and is immediately zeroized.** Unwrapped domain master keys and decrypted payloads are session-local.
- **No silent reset, anywhere.** Missing or corrupt payloads enter recovery instead of resetting to defaults; encryption never silently uses a default encrypt-to-self value; while settings are unavailable, resume grace fails closed to immediate authentication.
- **Anti-rollback watermark, with its honest scope.** Payload generations behind the bootstrap watermark, or more than one ahead, enter recovery; exactly one ahead is the interrupted-commit signature and heals forward only after the envelope authenticates. The watermark defends against *selective* rollback; a coherent whole-container restore is outside its scope by design.
- **The registry is the only authority for committed domain membership**; membership is never inferred from directory listings.
- **Relock is fail-closed**: block new access, fan out to all relock participants, zeroize the wrapping root key, clear unwrapped keys and snapshots; any participant failure latches a runtime-only, never persisted, restart-required state.
- **File protection is verified, not assumed** — registry files, bootstrap metadata, scratch writes, committed domain files, and SQLCipher sidecars; storage outside the app-owned container is never a fallback.
- **Contacts:** manual verification is a local fingerprint assertion, not OpenPGP certification; certification-signature export is an explicit artifact boundary, not a Contacts backup.

## 6. Guided tutorial containment

The guided tutorial may run real app services and real OpenPGP operations only inside an isolated tutorial dependency graph; it must never read or mutate real keys, contacts, settings, files, or exports. **No software fallback in sandbox custody** — without a Secure Enclave it fails closed. **No impersonation** — the ephemeral stores throw their own error types, never production ones. **Output interception** blocks real file import/export, clipboard writes, URL handoff, app-icon changes, and every other real-workspace side effect; tutorial completion state is the only fact that persists across restarts.

## 7. Argon2id

Argon2id S2K runs on exactly two shipped paths: **private-key export** and **passphrase-protected private-key import**, both for the v6 portable families. It never runs for routine decrypt or sign, and never for Portable Legacy, which uses Iterated+Salted S2K in both directions. The engine can also derive under a foreign message's parameters when opening a password-encrypted message, bounded before the KDF runs; that is engine capability, not a shipped surface.

The parameters emitted are RFC 9106's primary recommendation at 2 GiB. **The derivation runs once per secret-key packet, not once per operation:** a v6 certificate carries three, so a single export or import runs the 2 GiB derivation three times in sequence — peak memory stays 2 GiB, wall-clock cost roughly triples.

**Memory-safety guard, both key paths.** The app refuses a derivation above 75% of the memory this process was actually granted, preventing termination mid-derivation; the message path is bounded in Rust instead, because there the parameters are untrusted input. **A device that cannot afford the derivation is refused, never given weaker parameters**, on the backup and the restore side alike — which is what makes the 8 GB device floor ([PRODUCT.md](PRODUCT.md)) load-bearing. The 2 GiB requirement is why the iOS memory entitlements exist; macOS applies no such limit.

**The passphrase is the other half of the cost.** Every screen where the user chooses a passphrase applies the same two requirements — a minimum length, and no character repeated past a short run — and offers a generated ~116-bit value as the primary path. The requirements are deliberately not a strength score, which would need frequency corpora this app will not ship or download. Entering a passphrase that already protects an artifact is never gated.

## 8. Memory Integrity Enforcement

MIE (hardware memory tagging) protects all C/C++ code — **including vendored OpenSSL, which is why the requirement exists** — on supported hardware; tag mismatches terminate the process, converting silent corruption into a detectable, non-exploitable crash. Unsupported devices run normally. Enablement is the Enhanced Security capability, whose `hardened-process*` keys in the entitlements files are the canonical list and must never be removed. The iOS memory entitlements (§7) are a separate axis and not hardening keys. Validation: [TESTING.md](TESTING.md).

## 9. Known limitations

- **Passphrase `String` cannot be reliably zeroized.** The secure text field binds to `String` and the FFI copies it, so the Swift-side copy's lifetime is up to ARC. Scope: the import and export passphrases, the only passphrases any shipped flow collects. Key export/import also leaves a Rust-side copy that is dropped without zeroization — an open gap, not a mitigated one. The passphrase lives only for the duration of the call and is never persisted.
- **FFI transit copies.** Every buffer crossing the UniFFI boundary is serialized into a transit copy freed without zeroization; both endpoints zeroize the copies they own, and the transit copy's brief lifetime in freed heap memory is an accepted residual. ASLR, the app sandbox, and MIE raise the bar for exploiting both residuals; they do not close them.
- **The macOS clipboard expiry is the app's own clock.** macOS has no per-write expiry, so the five-minute clear runs in-process: quitting the app before a copy expires leaves it on the pasteboard until something else replaces it. The device-only half is a property of the write itself, and on the other platforms the system owns the expiry.
