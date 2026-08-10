# Security Model

*Threat model, fail-closed rules, authentication contracts, storage invariants, and the §10 coding red lines. What ships is stated as shipped; decided-but-unshipped work is explicitly marked **roadmap**. Custody promises: [CUSTODY.md](CUSTODY.md). Storage rows and the version map: [STORAGE.md](STORAGE.md). Mechanisms restated nowhere: the cited code is the spec.*

## 1. Threat Model

Six statements an auditor needs that the code cannot make:

1. **Secure Enclave-bound blobs are inert off-device.** Keychain extraction without the SE hardware yields ciphertext that cannot be decrypted; SE key `dataRepresentation` is bound to the SoC UID.
2. **Software custody accepts a named tradeoff:** the raw private key exists briefly in app memory during use. Device-bound families avoid it entirely — operations run inside the enclave ([CUSTODY.md](CUSTODY.md)).
3. **ProtectedData has no path that opens without the SE factor.** There is no fallback (§3).
4. **Passphrase `String` cannot be reliably zeroized.** Scope: key import/export passphrases and password-message (SKESK) flows only — it does **not** affect routine recipient-key decryption or signing, which use SE-unwrapped `Data` that is zeroized. Honest accounting: §9.
5. **ASLR, sandboxing, and MIE are the defense-in-depth floor** under the accepted residuals in §9 — they raise the cost of memory scanning; they do not eliminate it.
6. **MIE exists because vendored OpenSSL is C** (§8).

## 2. Format & Interop Security Rules

- **Read-support contract:** the app reads v4 keys, v6 keys, SEIPDv1, SEIPDv2 (OCB/GCM), Iterated+Salted S2K, and Argon2id S2K. The legacy Symmetrically Encrypted Data packet (tag 9, no MDC) is hard-rejected on decrypt.
- **Outgoing messages are never compressed.** `deflate` is read-only for compatibility; bzip2 is excluded (a second C dependency).
- **Any post-quantum recipient enforces an AES-256 floor**, inside both SEIPDv1 and SEIPDv2 containers.
- **The quantum-safety badge derives from the produced artifact** — the session-key (PKESK) algorithms of the message — never from the live recipient selection. Classification fails closed on a truncated prefix (`pgp-mobile/src/decrypt.rs`, `message_quantum_safety`); callers map the failure to *no badge*, never a misleading one.
- Format selection by recipient key version is CLAUDE.md Hard Constraint 8; AEAD hard-fail with no partial plaintext is Hard Constraint 3. This document does not restate them.

## 3. Key Custody & Storage

Software-custody private keys are protected by an indirect wrapping scheme that is identical for every software-key algorithm: a per-key Secure Enclave P-256 key wraps the raw private-key bytes (ephemeral-static ECDH → HKDF-SHA256 → AES-GCM), and each key persists as a single self-contained `CAPKEV6` Keychain row with the SE key's `dataRepresentation` folded in. `Sources/Security/PrivateKeyEnvelope.swift` is the byte-level spec. The rules that are not visible in the bytes:

- **Ordering: storage before zeroization.** The raw private key is zeroized only after the envelope write is confirmed. If storage fails or the process crashes first, the bytes are still in memory and the operation can retry; the reverse order would permanently lose the key.
- **Binding.** The payload kind, the fingerprint, both public keys, the SE key blob hash, and the plaintext length are bound through both the HKDF `sharedInfo` and the AES-GCM AAD — no public field can be substituted without breaking authentication. The kind is what keeps the two payloads the envelope can seal — a software secret certificate and a split-custody classical component ([CUSTODY.md](CUSTODY.md) §7) — from ever being opened as one another, independently of which row either was found in.
- **The envelope is the only supported private-key payload.** Any row that does not decode as a current `CAPKEV6` envelope of the kind the caller asked for fails closed as ordinary undecodable input. There is no legacy wrapping format and no migration path, ever.
- **Rows carry no per-row access control.** The auth-mode policy is baked into the folded SE key at creation; device authentication triggers when the enclave reconstructs and uses that key.
- **Secure Enclave key loss is unrecoverable except by re-import.** SE keys are destroyed by device erase, iCloud restore, or backup restore; because the SE key exists only inside the envelope it seals, a destroyed SE key can never be re-wrapped — the only recovery is re-importing the key from the user's passphrase-protected backup. No detect-and-re-wrap flow exists or can exist.
- **A Secure Enclave route never falls back to software secret-certificate material** (`PrivateKeyOperationRouter` returns a blocked resolution on every non-matching path). The decrypt Phase 1/Phase 2 boundary is preserved: Phase 1 recipient parsing is unauthenticated and the matched-key guard runs before any private-key access (`Sources/Services/Messaging/DecryptionService.swift`).
- **Revocation.** Revocation signatures are stored as binary packets and armored on demand; export uses only the stored artifact and **fails closed when it is missing — a missing artifact is never regenerated**. The import path generates a key-level revocation for the imported key. Subkey and User ID revocations are generated on demand and create no persisted selective-revocation history. Certification persistence never inserts signatures into a stored contact certificate, never changes manual verification state, and introduces no web-of-trust semantics.
- **Key metadata is gated, not secret.** `PGPKeyIdentity` metadata lives in the ProtectedData `key-metadata` domain so key-list loading happens only after app-session authentication; the sealed envelope stays in the private-key Keychain namespace.
- **Streaming decrypt releases output only through the success-only `.tmp`-then-rename contract** (`pgp-mobile/src/streaming.rs`).
- **Sanitized failure mapping.** Failure surfaces expose only stable app-owned categories. Logs, errors, UI, ProtectedData, and Rust never carry: fingerprints, handle-set identifiers, public-binding bytes, Keychain locators, plaintext, private material, shared secrets, session keys, KEKs, digests, or signatures. Local-authentication failure stays a separate category from payload-authentication failure — "you failed Face ID" and "the ciphertext was tampered with" must never collapse into one message.

Device-bound custody — access policy, split custody, the mode-switch exemption and its true mechanism, interop position, and evidence rules — is [CUSTODY.md](CUSTODY.md).

### ProtectedData Device-Binding Note

ProtectedData uses a separate app-data root-secret model — do not conflate it with private-key envelope wrapping. The root secret's `CAPDSEV5` Keychain row (shape: [STORAGE.md](STORAGE.md) §2) folds in a ProtectedData-only P-256 SE device-binding key (`WhenPasscodeSetThisDeviceOnly` + `[.privateKeyUsage]` — never `.userPresence`/`.biometryAny`/`.devicePasscode`, *because* the user-facing prompt remains the app-session Keychain gate), reconstructed at open time as a silent second factor. `CAPDSEV5` and `CAPKEV6` share the ECDH construction but are domain-separated by magic and HKDF/AAD prefixes, so neither blob can be misread as the other (all four envelope magics and their version map: [STORAGE.md](STORAGE.md) §5). If the enclave cannot reconstruct the folded key or its public key mismatches, ProtectedData fails closed into framework recovery — **there is no fallback that opens ProtectedData without the SE factor**.

## 4. Authentication

**Two independent axes — the #1 confusion this section exists to prevent:** `AppSessionAuthenticationPolicy` gates the app privacy session and root-secret access; `AuthenticationMode` (Standard / High Security) governs private-key Secure Enclave flags. Neither implies the other; `Sources/Security/AuthenticationEvaluable.swift` owns both flag sets.

- **Presentation is the system authentication sheet** for both subsystems on every platform. Environment-dependent platform gates (such as the macOS embedded-LA denial) are verified against the **installed app build, never the unit-test host** — test-host probes have passed while the real app was denied. In-window authentication is tracked in issue #724.
- **Each system prompt runs inside a short operation-prompt session** covering the prompt plus the immediately following Keychain/Secure Enclave call that consumes the same `LAContext`; longer work (PGP generation, import parsing, journaling, commits, reset I/O, UI updates) stays outside it, so prompt-lifecycle resigns are deferred while genuine away events under grace = 0 still relock immediately.
- **Access-control shapes, as values** (the code authors them; these are the facts):
  - Standard Mode private keys: `WhenUnlockedThisDeviceOnly` + `[.privateKeyUsage, .biometryAny, .or, .devicePasscode]`.
  - High Security Mode private keys: the same minus `.or, .devicePasscode` — no passcode fallback, hidden fallback button.
  - Device-bound custody keys: **fixed** `[.privateKeyUsage, .biometryAny]` at creation, never mode-dependent ([CUSTODY.md](CUSTODY.md) §3).
  - ProtectedData device-binding key: `WhenPasscodeSetThisDeviceOnly` + `[.privateKeyUsage]`, promptless (§3 note).
  - The root-secret row's own LA gate follows `AppSessionAuthenticationPolicy` (`.userPresence` or `.biometryAny`).
- **`.biometryAny` means keys survive biometric re-enrollment.** In High Security Mode, if biometrics are unavailable (sensor damage, lockout), all private-key operations are blocked until restored.

### Mode Switching

Switching re-wraps every **software-custody** key under a single authentication: authenticate under the **current** mode (a cancelled prompt leaves no intent behind), record the target in the `private-key-control` recovery journal, re-wrap each key into its pending row, and only after **all** pending rows are verified: delete old rows, promote pending rows, persist the new mode, clear the journal. **Device-bound keys are exempt; the exemption is enforced by the caller-side custody-kind filter, not by their fixed access policy** — mechanism and consequences: [CUSTODY.md](CUSTODY.md) §4. The High Security backup check applies to software-custody keys only.

**Crash-recovery invariant:** old rows stay authoritative until every new row is confirmed. Recovery (after unlock opens `private-key-control`) prefers an existing permanent row over a pending one; promotes a complete pending row only when the permanent row is absent or invalid; keeps the journal on retryable Keychain failures so recovery re-runs after the next unlock; treats no-complete-row-anywhere as unrecoverable (clear journal, surface a generic warning that never includes fingerprints); and persists the new auth mode only after a full successful promotion — cleaning stale pending rows alone never changes the mode. All four outcomes are test-pinned ([TESTING.md](TESTING.md) §4).

## 5. Protected App Data

Protected app data is the security domain for CypherAir-owned local state outside private-key material. Rows, domains, and exceptions: [STORAGE.md](STORAGE.md). The invariants:

- **Domains open only after app privacy authentication.** `appSessionAuthenticationPolicy` is the sole **ordinary-settings** boot-authentication exception (the full pre-unlock exception set, including the test-only bypass preference: [STORAGE.md](STORAGE.md) §4). Pre-auth startup may classify the registry and bootstrap metadata but must not retrieve the root secret, unwrap any domain master key, or open protected payloads.
- **Prompt hygiene.** App unlock runs one post-unlock opener pass that reuses the authenticated `LAContext` across all registered committed domains without a second prompt, skipping pending-mutation, missing-context, and no-domain states without fetching the root secret or prompting again; Contacts joins the session through its own post-auth gate. Settings refresh may auto-open protected settings only by **consuming** an existing app-session context handoff — the handoff-only path never starts a new interactive prompt.
- **The raw root secret exists only to derive the wrapping root key and is immediately zeroized.** Unwrapped domain master keys and decrypted payloads are session-local.
- **No silent reset, anywhere.** Missing or corrupt payloads enter recovery instead of resetting to defaults; no domain ever resets unreadable state to empty; encryption never silently uses a default encrypt-to-self value; while settings are unavailable, resume grace fails closed to immediate authentication.
- **Anti-rollback watermark, with its honest scope.** The bootstrap generation watermark is a floor: payload generations behind it, or more than one ahead, enter recovery; exactly one ahead is the interrupted-commit signature and heals forward only after the envelope AEAD-authenticates under the domain master key. The watermark defends against *selective* rollback of protected payloads; a coherent whole-container restore (e.g. a Time Machine restore that moves watermark and payloads together) is outside its scope by design.
- **The registry is the only authority for committed domain membership.** Membership is never inferred from directory listings. Invalid registry state enters framework recovery; domain corruption enters that domain's recovery.
- **Relock is fail-closed.** Block new access, fan out to all relock participants, zeroize the wrapping root key, clear unwrapped keys and snapshots, and return to the locked session only if teardown succeeds; any participant failure latches **runtime-only** `restartRequired` (never persisted).
- **File protection is verified, not assumed** — registry files, bootstrap metadata, scratch writes, committed domain files, and SQLCipher **sidecars** (`-wal`, `-shm`, `-journal`); storage outside the app-owned container is never a fallback.
- **Storage-migration invariant:** any migration preserves readable source state until the protected destination is created, opened, and verified through the normal post-auth path. The full migration contract: [STORAGE.md](STORAGE.md) §6.
- **Contacts:** manual verification is a local fingerprint assertion, not OpenPGP certification; certification-signature export is an explicit artifact boundary, not a Contacts backup. The mandatory-encrypted rule for any future Contacts exchange is product law ([PRODUCT.md](PRODUCT.md) §2).

## 6. Guided Tutorial Containment

The guided tutorial may run real app services and real OpenPGP operations only inside an isolated tutorial dependency graph; it must never read or mutate real keys, contacts, settings, files, or exports. Today the isolation runs on a sandboxed dependency graph (fixed defaults suite, temporary directory, ephemeral Secure Enclave custody); **roadmap:** the tutorial is being rebuilt fully in-memory on a unified composition graph. These rules bind both shapes:

- **No software fallback in sandbox custody** — without a Secure Enclave it fails closed.
- **No impersonation** — the ephemeral stores throw their own error types and never impersonate the production `KeychainError`. The same rule binds the `Mock*` test doubles, which live only in the test target and are never compiled into the app.
- **Output interception** blocks real file import/export, clipboard writes, URL handoff, app-icon changes, and every other real-workspace side effect. Tutorial completion state is the only fact that persists across restarts.
- A tutorial regression must never weaken the zero-network, minimal-permission, no-secret-logging, or workspace-isolation guarantees; tutorial-isolation changes get the same review care as other auth/local-data boundaries.

## 7. Argon2id

Argon2id S2K applies to **private-key export and passphrase-protected import only** (the v6 portable families) — never to routine decrypt/sign, and never to Portable Legacy (Iterated+Salted, mode 3). This scope prevents the recurring "why is decrypt slow" misdiagnosis. The shipped parameter set is `t=3, p=4, m=2^19 KiB (512 MiB)` with RFC 9580 encodings (`pgp-mobile/src/keys/secret_transfer.rs` is the spec).

**Memory-safety guard (import):** before derivation begins, the S2K specifier is parsed, the Rust side computes the KiB requirement, and Swift refuses above 75% of available memory (`os_proc_available_memory()` on iOS/iPadOS/visionOS; total physical memory on macOS, which has no Jetsam) — preventing iOS Jetsam termination mid-derivation (`Sources/Security/Argon2idMemoryGuard.swift`; refusal copy in the String Catalog).

**Roadmap:** the decided target is the RFC 9106 high-memory preset (2 GiB) with an export-side guard as well. The iOS resource entitlements for that headroom (`increased-memory-limit`, `extended-virtual-addressing`) are already committed; the parameter change has not landed — until it does, the 512 MiB set above is the truth.

## 8. Memory Integrity Enforcement (MIE)

MIE (hardware memory tagging) protects all C/C++ code — **including vendored OpenSSL, which is why the requirement exists** — against buffer overflows and use-after-free on supported hardware; tag mismatches terminate the process, converting silent corruption into a detectable, non-exploitable crash. The capability is additive: unsupported devices run normally.

Enablement is the Enhanced Security capability (`ENABLE_ENHANCED_SECURITY = YES` for Debug and Release via project-level inheritance), which writes the `com.apple.security.hardened-process*` keys into `CypherAir.entitlements` and `CypherAirMacOS.entitlements`. **The entitlements files are the canonical key list and must stay committed to source control.** (The iOS file also carries the §7 memory resource entitlements — a separate axis from MIE.) Validation pass criteria: [TESTING.md](TESTING.md) §6.

## 9. Known Limitations

- **Passphrase `String` cannot be reliably zeroized.** `SecureField` binds to `String` and UniFFI copies `String` across the boundary, so the Swift-side copy's lifetime is up to ARC — an accepted platform-wide limitation. Scope: import/export passphrases and SKESK flows only (§1). The honest per-path accounting:
  - **Password-message (SKESK) APIs** convert the Swift `String` into a Sequoia `Password` **by value** at the FFI boundary — the buffer is moved, and the Rust-side representation is encrypted in memory.
  - **Key export/import** forwards the Rust `String` by reference; Sequoia's `Password::from(&str)` **copies**, and the original Rust `String` is dropped **without zeroization**. This is an open gap, not a mitigated one. **Roadmap:** the decided byte-passphrase FFI change closes it; until then this sentence is the truth.
  - The passphrase lives only for the duration of the call and is never persisted.
- **FFI transit copies.** Every buffer crossing the UniFFI boundary is serialized into a transit copy that the FFI layer frees without zeroization. Both endpoints zeroize the copies they own (the SE-unwrapped key material, the P-256 and ML-KEM shared-secret shares); the transit copy's brief lifetime in freed heap memory is an accepted residual.
- ASLR, the app sandbox, and MIE (§8) raise the bar for exploiting both residuals; they do not close them.

## 10. AI Coding Red Lines

Security-critical scope is defined by **grep-able predicates, not file paths** — paths rot silently when code moves; predicates follow the code. A change is security-critical when it touches any predicate below. The process this triggers — the explicit call-out (file, what changed, why) in the task summary and PR description, and the extra-care check in the PR's independent verification — is stated once in [WORKFLOW.md](WORKFLOW.md) §3.

### Absolute Coding Invariants

These hold for every change, independent of which file is touched:

- **Secure random only.** Swift: `SecRandomCopyBytes` or CryptoKit (which uses it internally). Rust: `openpgp::crypto::random` — the Sequoia `crypto-openssl` CSPRNG (the crate has no direct RNG dependency; do not add one). Never `arc4random`, `Int.random`, or any non-CSPRNG source.
- **No secret logging — not even in DEBUG.** Never `print()`, `os_log()`, or `NSLog()` key material, passphrases, or decrypted content, in any build configuration.
- **Zero network, but local IPC is allowed.** The app's custom URL scheme is local inter-process communication, not network access, and does not violate the zero-network rule.

### Security-Critical Predicates

Any function or change matching one of these requires the §10 process:

- Calls `SecAccessControlCreateWithFlags` — every access-control shape in §4 is authored at such a site.
- Calls a `SecureEnclave.P256`, `SecureEnclave.MLDSA*`, or `SecureEnclave.MLKEM*` constructor.
- Calls `AES.GCM.seal`/`AES.GCM.open` or `HKDF<SHA256>.deriveKey` on key material.
- Writes to or deletes from the Keychain.
- Seals, opens, validates, or re-encodes any of the four authenticated envelopes (`CAPKEV6`, `CAPDSEV5`, `CADMKV5`, `CPDENV5`) — magic, payload kind, binding, or AAD changes break domain separation.
- Implements, calls, or removes a function that **overwrites a secret buffer**. Today that is `Data.zeroize()` (`Sources/Extensions/Data+Zeroing.swift`), `Data.protectedDataZeroize()` (`Sources/Security/ProtectedData/Envelopes/ProtectedDataDomain.swift`), the direct `resetBytes(in:)` calls on key material and plaintext, and the `@_optimize(none)` `opaqueZero` in `Sources/Services/Common/SQLCipherRawKey.swift`. The `Data`-based barriers rely on the cross-module Foundation call to defeat dead-store elimination; weakening any of them may let the optimizer eliminate zeroing. (**Roadmap:** the zeroing-constitution work consolidates these into one primitive with one owner.)
- Filters fingerprints by custody kind for mode-switch re-wrap or its recovery (`PGPKeyIdentity.softwareCustodyFingerprints` and its call sites) — this one-line filter decides what the re-wrap enumerates, and a device-bound fingerprint reaching it poisons mode-switch recovery (§4, [CUSTODY.md](CUSTODY.md) §4).
- Touches the decrypt Phase 1/Phase 2 boundary, AEAD hard-fail handling, or the `.tmp`-then-rename output contract (Swift decryption services; `pgp-mobile/src/decrypt.rs`, `streaming.rs`).
- Changes custody routing or capability resolution for private-key operations (`PrivateKeyOperationRouter`, `PGPKeyCapabilityResolver`) — the enforcement points behind §3's never-falls-back rule and [CUSTODY.md](CUSTODY.md)'s operation surface.
- Changes the sanitized failure-category vocabulary or any error surface crossing the FFI boundary — categories must stay stable and lossless through the adapter chokepoint's category translation, and free of the §3 leak-set.
- Is a `pub` function in `pgp-mobile/src/lib.rs` (the FFI surface), or changes the vendored RFC 9980 combiner / external-operation seams (`composite_kem.rs`, `external_*` modules).
- Parses untrusted external input from the URL scheme or QR path (`QRService` and its Rust counterpart).
- Selects key family, `CipherSuite`, or S2K parameters in key generation/export, or changes the Argon2id memory-guard threshold logic (`os_proc_available_memory` path).
- Edits either `.entitlements` file, `ENABLE_ENHANCED_SECURITY`, or adds/changes any usage-description key — usage descriptions are injected as `INFOPLIST_KEY_*` build settings in `project.pbxproj`; `CypherAir-Info.plist` itself carries none, so the pbxproj is the enforcement point to watch.
