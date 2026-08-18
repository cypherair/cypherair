# Security Model

*Threat model, fail-closed rules, authentication contracts, and storage invariants. What ships is stated as shipped; decided-but-unshipped work is explicitly marked **roadmap**. Custody promises: [CUSTODY.md](CUSTODY.md). Storage rows and the version map: [STORAGE.md](STORAGE.md).*

## 1. Threat Model

Four statements an auditor needs that the code cannot make:

1. **Secure Enclave-bound blobs are inert off-device.** Keychain extraction without the SE hardware yields ciphertext that cannot be decrypted; SE key blobs are bound to the SoC UID.
2. **Software custody accepts a named tradeoff:** the raw private key exists briefly in app memory during use. Device-bound families avoid it entirely — operations run inside the enclave ([CUSTODY.md](CUSTODY.md)).
3. **ProtectedData has no path that opens without the SE factor.** There is no fallback (§3).
4. **Passphrase `String` cannot be reliably zeroized.** Honest accounting: §9.

### Screen Capture (macOS)

Every window the macOS app puts on screen is `NSWindowSharingNone`, in every build configuration, so another process holding the Screen Recording grant — a conferencing tool, a capture utility, malware that obtained the permission — cannot read plaintext, contact identities or armored key material out of the app's windows. One process-wide rule, because SwiftUI and AppKit create most of the windows, not this app.

What it does not cover:

- **Window titles and bounds stay readable** to any process enumerating windows. The app's titles are generic and must stay generic.
- **It stops processes, not people.** Anyone looking at the screen sees everything. That is the case the lock shield's privacy cover addresses, and why the two are not redundant.
- **UI drawn by other processes is outside it entirely.** The sharpest case is an input method: with Simplified Chinese a first-class locale, a user composing plaintext through the Chinese IME has that text rendered in the input method's own candidate window, owned by the IM process, which this app cannot exclude.
- **iOS, iPadOS and visionOS are not addressed here.** The platform answer there is `EnvironmentValues.isSceneCaptured`, which is `@available(macOS, unavailable)`; the macOS capture surface is the whole of what this covers.

The mechanism rests on an API in tension with itself: the shipped SDK header describes `NSWindowSharingNone` in the present tense with no deprecation, while Apple's documentation calls it a legacy constant and says not to use it for this. Measurement agrees with the header today, on macOS 27. **Re-check it each macOS major** with `scripts/probe_macos_window_capture.sh`, which attempts a real cross-process capture and fails loudly if the system has stopped enforcing the flag. The unit lane guards only that the app still *sets* it; no lane can tell whether macOS still honours it.

## 2. Format & Interop Security Rules

- **Read-support contract:** the app reads v4 keys, v6 keys, SEIPDv1, and SEIPDv2 (OCB/GCM), and on the key-import path both Iterated+Salted S2K and Argon2id S2K. The legacy Symmetrically Encrypted Data packet (tag 9, no MDC) is hard-rejected on decrypt.
- **Outgoing messages are never compressed.** `deflate` is read-only for compatibility; bzip2 is excluded (a second C dependency).
- **Any post-quantum recipient enforces an AES-256 floor**, inside both SEIPDv1 and SEIPDv2 containers.
- **The quantum-safety badge derives from the produced artifact** — the session-key (PKESK) algorithms of the message — never from the live recipient selection. Classification fails closed on a truncated prefix; callers map the failure to *no badge*, never a misleading one.
- Message-format selection is AGENTS.md Hard Constraint 8; AEAD hard-fail with no partial plaintext is Hard Constraint 3.

## 3. Key Custody & Storage

Software-custody private keys are protected by an indirect wrapping scheme that is identical for every software-key algorithm: a per-key Secure Enclave P-256 key wraps the raw private-key bytes (ephemeral-static ECDH → HKDF-SHA256 → AES-GCM), and each key persists as a single self-contained `CAPKEV6` Keychain row with the SE key's blob folded in. The rules that are not visible in the bytes:

- **Ordering: storage before zeroization.** The raw private key is zeroized only after the envelope write is confirmed. If storage fails or the process crashes first, the bytes are still in memory and the operation can retry; the reverse order would permanently lose the key.
- **Binding.** The payload kind, the fingerprint, both public keys, the SE key blob hash, and the plaintext length are bound through both the HKDF `sharedInfo` and the AES-GCM AAD — no public field can be substituted without breaking authentication. The kind is what keeps the two payloads the envelope can seal — a software secret certificate and a split-custody classical component ([CUSTODY.md](CUSTODY.md) §7) — from ever being opened as one another, independently of which row either was found in.
- **The envelope is the only supported private-key payload.** Any row that does not decode as a current `CAPKEV6` envelope of the kind the caller asked for fails closed as ordinary undecodable input. There is no legacy wrapping format and no migration path, ever.
- **Rows carry no per-row access control.** The auth-mode policy is baked into the folded SE key at creation; device authentication triggers when the enclave reconstructs and uses that key.
- **Secure Enclave key loss is unrecoverable except by re-import.** SE keys are destroyed by device erase, iCloud restore, or backup restore; because the SE key exists only inside the envelope it seals, a destroyed SE key can never be re-wrapped — the only recovery is re-importing the key from the user's passphrase-protected backup. No detect-and-re-wrap flow exists or can exist.
- **A Secure Enclave route never falls back to software secret-certificate material** — every non-matching path returns a blocked resolution. The decrypt Phase 1/Phase 2 boundary is preserved: Phase 1 recipient parsing is unauthenticated and the matched-key guard runs before any private-key access.
- **Revocation.** Revocation signatures are stored as binary packets and armored on demand; export uses only the stored artifact and **fails closed when it is missing — a missing artifact is never regenerated**. The import path generates a key-level revocation for the imported key. Subkey and User ID revocations are generated on demand and create no persisted selective-revocation history. Certification persistence never inserts signatures into a stored contact certificate, never changes manual verification state, and introduces no web-of-trust semantics.
- **Key metadata is gated, not secret.** Key metadata lives in the ProtectedData `key-metadata` domain so key-list loading happens only after app-session authentication; the sealed envelope stays in the private-key Keychain namespace.
- **Streaming decrypt releases output only through the success-only `.tmp`-then-rename contract.**
- **Sanitized failure mapping.** Failure surfaces expose only stable app-owned categories. Logs, errors, UI, ProtectedData, and Rust never carry: fingerprints, handle-set identifiers, public-binding bytes, Keychain locators, plaintext, private material, shared secrets, session keys, KEKs, digests, or signatures. Local-authentication failure stays a separate category from payload-authentication failure — "you failed Face ID" and "the ciphertext was tampered with" must never collapse into one message.

Device-bound custody — access policy, split custody, the mode-switch exemption and its mechanism, interop position, and evidence rules — is [CUSTODY.md](CUSTODY.md).

### ProtectedData Device-Binding Note

ProtectedData uses a separate app-data root-secret model — do not conflate it with private-key envelope wrapping. The root secret's `CAPDSEV5` Keychain row (shape: [STORAGE.md](STORAGE.md) §2) folds in a ProtectedData-only P-256 SE device-binding key (`WhenPasscodeSetThisDeviceOnly` + `[.privateKeyUsage]` — never `.userPresence`/`.biometryAny`/`.devicePasscode`, *because* the user-facing prompt remains the app-session Keychain gate), reconstructed at open time as a silent second factor. `CAPDSEV5` and `CAPKEV6` share the ECDH construction but are domain-separated by magic and HKDF/AAD prefixes, so neither blob can be misread as the other (all four envelope magics and their version map: [STORAGE.md](STORAGE.md) §5). If the enclave cannot reconstruct the folded key or its public key mismatches, ProtectedData fails closed into framework recovery — **there is no fallback that opens ProtectedData without the SE factor**.

## 4. Authentication

**Two independent axes:** the app-session authentication policy gates the app privacy session and root-secret access; the authentication mode (Standard / High Security) governs private-key Secure Enclave flags. Neither implies the other.

- **Presentation is the system authentication sheet** for both subsystems on every platform. Environment-dependent platform gates (such as the macOS embedded-LA denial) are verified against the **installed app build, never the unit-test host** — test-host probes have passed while the real app was denied.
- **Each system prompt runs inside a short operation-prompt session** covering the prompt plus the immediately following Keychain/Secure Enclave call that consumes the same `LAContext`; longer work stays outside it, so prompt-lifecycle resigns are deferred while genuine away events under grace = 0 still relock immediately.
- **Access-control shapes, as values:**
  - Standard Mode private keys: `WhenUnlockedThisDeviceOnly` + `[.privateKeyUsage, .biometryAny, .or, .devicePasscode]`.
  - High Security Mode private keys: the same minus `.or, .devicePasscode` — no passcode fallback, hidden fallback button.
  - ProtectedData device-binding key: `WhenPasscodeSetThisDeviceOnly` + `[.privateKeyUsage]`, promptless (§3 note).
  - The root-secret row's own LA gate follows the app-session policy (`.userPresence` or `.biometryAny`).
- **`.biometryAny` means keys survive biometric re-enrollment.** In High Security Mode, if biometrics are unavailable (sensor damage, lockout), all private-key operations are blocked until restored.

### Mode Switching

Switching re-wraps every **software-custody** key under a single authentication: authenticate under the **current** mode (a cancelled prompt leaves no intent behind), record the target in the `private-key-control` recovery journal, re-wrap each key into its pending row, and only after **all** pending rows are verified: delete old rows, promote pending rows, persist the new mode, clear the journal. **Device-bound keys are exempt** ([CUSTODY.md](CUSTODY.md) §4). The High Security backup check applies to software-custody keys only.

**Crash-recovery invariant:** old rows stay authoritative until every new row is confirmed. Recovery (after unlock opens `private-key-control`) prefers an existing permanent row over a pending one; promotes a complete pending row only when the permanent row is absent or invalid; keeps the journal on retryable Keychain failures so recovery re-runs after the next unlock; treats no-complete-row-anywhere as unrecoverable (clear journal, surface a generic warning that never includes fingerprints); and persists the new auth mode only after a full successful promotion — cleaning stale pending rows alone never changes the mode. All four outcomes are test-pinned.

## 5. Protected App Data

Protected app data is the security domain for CypherAir-owned local state outside private-key material. Rows, domains, and exceptions: [STORAGE.md](STORAGE.md). The invariants:

- **Domains open only after app privacy authentication.** The app-session authentication policy setting is the sole **ordinary-settings** boot-authentication exception (the full pre-unlock exception set, including the test-only bypass preference: [STORAGE.md](STORAGE.md) §4). Pre-auth startup may classify the registry and bootstrap metadata but must not retrieve the root secret, unwrap any domain master key, or open protected payloads.
- **Prompt hygiene.** App unlock runs one post-unlock opener pass that reuses the authenticated `LAContext` across all registered committed domains without a second prompt; Contacts joins the session through its own post-auth gate. Settings refresh may auto-open protected settings only by **consuming** an existing app-session context handoff — the handoff-only path never starts a new interactive prompt.
- **The raw root secret exists only to derive the wrapping root key and is immediately zeroized.** Unwrapped domain master keys and decrypted payloads are session-local.
- **No silent reset, anywhere.** Missing or corrupt payloads enter recovery instead of resetting to defaults; no domain ever resets unreadable state to empty; encryption never silently uses a default encrypt-to-self value; while settings are unavailable, resume grace fails closed to immediate authentication.
- **Anti-rollback watermark, with its honest scope.** The bootstrap generation watermark is a floor: payload generations behind it, or more than one ahead, enter recovery; exactly one ahead is the interrupted-commit signature and heals forward only after the envelope AEAD-authenticates under the domain master key. The watermark defends against *selective* rollback of protected payloads; a coherent whole-container restore (e.g. a Time Machine restore that moves watermark and payloads together) is outside its scope by design.
- **The registry is the only authority for committed domain membership.** Membership is never inferred from directory listings. Invalid registry state enters framework recovery; domain corruption enters that domain's recovery.
- **Relock is fail-closed.** Block new access, fan out to all relock participants, zeroize the wrapping root key, clear unwrapped keys and snapshots, and return to the locked session only if teardown succeeds; any participant failure latches a **runtime-only** restart-required state (never persisted).
- **File protection is verified, not assumed** — registry files, bootstrap metadata, scratch writes, committed domain files, and SQLCipher **sidecars** (`-wal`, `-shm`, `-journal`); storage outside the app-owned container is never a fallback.
- **Contacts:** manual verification is a local fingerprint assertion, not OpenPGP certification; certification-signature export is an explicit artifact boundary, not a Contacts backup. The mandatory-encrypted rule for any future Contacts exchange is product law ([PRODUCT.md](PRODUCT.md) §8).

## 6. Guided Tutorial Containment

The guided tutorial may run real app services and real OpenPGP operations only inside an isolated tutorial dependency graph; it must never read or mutate real keys, contacts, settings, files, or exports. The sandbox graph is fully in-memory — RAM domain stores, an in-memory keychain, in-memory preferences, ephemeral Secure Enclave key wrapping — and names no storage root, registry, database, or preferences suite, so it writes zero bytes to disk by construction. **Roadmap:** the sandbox graph and the production graph converge on one composition body.

- **Structural isolation, not guards** — every real-world mutator reaches views only through the single optional `realWorkspace` environment value, which the tutorial mirror shell explicitly injects as nil; the content-clear signal is its own small value each world injects. A sandbox screen cannot name a real mutator.
- **Same validation as production** — the in-memory domain conformances run the same model-level contract validation the production stores run, so the sandbox cannot reach states production rejects.
- **No software fallback in sandbox custody** — without a Secure Enclave it fails closed.
- **No impersonation** — the ephemeral stores throw their own error types and never impersonate production error types.
- **Output interception** blocks real file import/export, clipboard writes, URL handoff, app-icon changes, and every other real-workspace side effect. Tutorial completion state is the only fact that persists across restarts, and persisting it reports success or failure rather than failing silently.

## 7. Argon2id

Argon2id S2K runs on exactly two shipped paths: **private-key export** and **passphrase-protected private-key import**, both for the v6 portable families. It never runs for routine decrypt/sign with your own key, and never for Portable Legacy, which uses Iterated+Salted (mode 3) in both directions.

The engine can also derive under a foreign message's Argon2 parameters when opening a password-encrypted (SKESK) message, where the parameters are the sender's and are bounded before the KDF runs. That is engine capability, not a shipped surface: no app flow reaches it, and the app has made no commitment to one ([PRODUCT.md](PRODUCT.md) §2).

The parameters we emit are RFC 9106's primary recommendation at 2 GiB; a foreign message's parameters are its own. The cost the memory guard checks is the cost the KDF runs under.

**The derivation runs once per secret-key packet, not once per operation.** A v6 certificate carries three — primary, signing subkey, encryption subkey — each protected under its own S2K, so a single export runs the 2 GiB derivation three times and a single import runs it three times. They run one after another: peak memory stays 2 GiB, while wall-clock cost is roughly three times a single derivation.

**Memory-safety guard, both key paths.** Export derives under the same parameters as import and can be terminated mid-derivation just as easily, so both are checked; the message path is bounded in Rust instead, because there the parameters are untrusted input rather than our own. The requirement comes from the engine — parsed from the incoming key on import, declared from the suite on export — and the app refuses above 75% of available memory, preventing Jetsam termination mid-derivation. Answering the export question from the suite alone is what lets the check run before the authentication prompt and before the private key leaves the enclave.

**The passphrase is the other half of the cost.** Argon2id sets what one guess costs; it does nothing about a passphrase that is guessed early. Every screen where the user **chooses** a passphrase applies the same two requirements — a minimum length, and no character repeated past a short run — and offers a generated ~116-bit value as the primary path. The requirements are deliberately not a strength score: a score needs frequency corpora this app will not ship or download, and generation is what actually answers guessability. Entering a passphrase that already protects an artifact (backup import) is never gated: that protection was fixed when the artifact was written, and refusing to open it would only lock the user out.

**A device that cannot afford the derivation is refused, never given weaker parameters.** The 2 GiB requirement fits only where the memory entitlements (§8) are actually granted, and the check reads the limit this process was actually granted rather than what the entitlement asked for. The same figure binds the restore side: a backup produced under these parameters can only be opened on a device that can also afford them, which is what makes the 8 GB device floor ([PRODUCT.md](PRODUCT.md) §1) load-bearing rather than advisory.

## 8. Memory Integrity Enforcement (MIE)

MIE (hardware memory tagging) protects all C/C++ code — **including vendored OpenSSL, which is why the requirement exists** — against buffer overflows and use-after-free on supported hardware; tag mismatches terminate the process, converting silent corruption into a detectable, non-exploitable crash. The capability is additive: unsupported devices run normally.

Enablement is the Enhanced Security capability (`ENABLE_ENHANCED_SECURITY = YES` for Debug and Release via project-level inheritance), which writes the `com.apple.security.hardened-process*` keys into `CypherAir.entitlements` and `CypherAirMacOS.entitlements`. **The entitlements files are the canonical key list.** Validation pass criteria: [TESTING.md](TESTING.md) §6.

### Memory Resource Entitlements

`CypherAir.entitlements` (iOS/iPadOS/visionOS) additionally carries `com.apple.developer.kernel.increased-memory-limit` and `com.apple.developer.kernel.extended-virtual-addressing`. They are a **separate axis from MIE** and neither is a hardening key: removing them weakens no defense, and removing the `hardened-process*` keys is what AGENTS.md Hard Constraint 7 forbids.

They exist for one reason — §7's Argon2id derivation needs 2 GiB, and that does not fit under the default app memory limit. macOS applies no such limit and `CypherAirMacOS.entitlements` carries neither key.

## 9. Known Limitations

- **Passphrase `String` cannot be reliably zeroized.** The secure text field binds to `String` and the FFI copies it, so the Swift-side copy's lifetime is up to ARC — an accepted platform-wide limitation. Scope: the import and export passphrases, which are the only passphrases any shipped flow collects. Key export/import leaves a Rust-side copy that is dropped **without zeroization** — an open gap, not a mitigated one (**roadmap:** the decided byte-passphrase FFI change closes it). The passphrase lives only for the duration of the call and is never persisted.
- **FFI transit copies.** Every buffer crossing the UniFFI boundary is serialized into a transit copy that the FFI layer frees without zeroization. Both endpoints zeroize the copies they own (the SE-unwrapped key material, the P-256 and ML-KEM shared-secret shares); the transit copy's brief lifetime in freed heap memory is an accepted residual.
- ASLR, the app sandbox, and MIE (§8) raise the bar for exploiting both residuals; they do not close them.
- **The macOS clipboard expiry is the app's own clock.** macOS has no per-write expiry, so the five-minute clear ([PRODUCT.md](PRODUCT.md) §5) runs in-process: quitting the app before a copy expires leaves that copy on the pasteboard until something else replaces it. The device-only half is unaffected — it is a property of the write itself (`currentHostOnly`) — and on iOS, iPadOS and visionOS the system owns the expiry, so neither half depends on the app still running.
