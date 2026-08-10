# Product Promises

*The product's promises, deliberate absences, consent gates, and user-facing consequences. What ships is stated as shipped; decided-but-unshipped work is explicitly marked **roadmap**. UI copy is owned by the String Catalog; algorithm and family definitions are owned by the code (`Sources/Models/Keys/PGPKeyFamily.swift`).*

## 1. What CypherAir X is

CypherAir X is a fully offline OpenPGP encryption tool for people who want to communicate securely without cryptographic knowledge — encrypt, decrypt, sign, and verify with keys and contacts managed on device. It never touches the network (CLAUDE.md Hard Constraint 1) and asks for no permissions beyond the Face ID / Touch ID usage description; the additional iOS entitlements (`increased-memory-limit`, `extended-virtual-addressing`) are resource entitlements for Argon2id memory headroom, not privacy permissions. All I/O goes through system pickers, the clipboard, and the app's URL scheme.

The product name is **CypherAir X** (bundle display name, Face ID prompt, About screen); copyright lines keep "CypherAir".

**Minimum device: 8 GB RAM.** Nothing in code enforces this — it is a support promise, and it becomes load-bearing under the decided Argon2id 2 GiB move ([SECURITY.md](SECURITY.md) §7).

## 2. Deliberate non-features

Each of these is an absence a code read cannot prove. They are decisions, not gaps:

- **No messaging, no key-server sync, no custom encryption formats.** CypherAir X produces and consumes standard OpenPGP artifacts; transport is the user's problem by design.
- **No proactive clipboard reading.** Paste areas only; the app writes to the clipboard solely on explicit copy actions.
- **No backup flow and no backup badge for device-bound keys.** Their private material is not exportable in any form ([CUSTODY.md](CUSTODY.md) §2); the revocation certificate is the primary export action for a device-bound key.
- **No global signing off-switch.** Signing defaults on and is toggled per message only.
- **Contacts never store recipient lists**, and contacts-package exchange does not exist. Any future complete Contacts backup or device migration **must** be a mandatory-encrypted export/import — never a plaintext social-graph export. This binds unbuilt work.
- **Password (SKESK) messages exist at the service layer but are deliberately not part of the shipped app surface** (`PrivateKeyPasswordMessageEncryptionService` has zero references from `Sources/App/`).

## 3. Consent gates

Actions that never proceed without an explicit user step:

- **Device-bound key generation** requires passing a commitment sheet (the permanence consequences, §4) before generation starts.
- **URL-scheme key import** always requires user confirmation before a key is added; a second import while one is pending errors rather than auto-adding.
- **High Security Mode activation** requires a warning, a backup check over software-custody keys, and a biometric confirmation of the change.
- **Copy actions** show a clipboard safety notice.
- **Roadmap:** the system Open With handler (file types are declared today but no handler exists) ships with an explicit import confirmation, like the URL scheme's.

## 4. User-facing consequences of the security design

- **Device-bound keys are permanent residents of one device's Secure Enclave.** Device loss, key-handle loss, or loss of biometric access makes the key permanently unusable — there is no recovery. Key family is **immutable** after generation; switching family means generating a new key.
- **Software (portable) keys survive through backups** — export is passphrase-protected, and losing the wrapped copy is recoverable only from such a backup ([SECURITY.md](SECURITY.md) §3).
- **High Security Mode** removes the passcode fallback: while biometrics are unavailable (sensor damage, lockout), decrypt, sign, and export stay blocked. Device-bound keys always require biometrics regardless of this setting — their enforcement is fixed at creation.
- **On macOS, screen lock locks the app immediately**, regardless of the grace-period setting. A biometric prompt's own transient deactivation is never treated as leaving the app.
- **On macOS the re-authentication interval bounds the session, not just the next prompt.** The app keeps running while it is not frontmost, so once the interval passes it relocks itself — decrypted content cleared, protected app data re-protected — rather than waiting for you to come back. iOS, iPadOS, and visionOS suspend the app while it is away, so nothing can run in between and the same check runs on your return.
- **The privacy cover is not the lock.** When the app is not foreground-active it shows an opaque, app-identified cover — purely visual, with no authentication role; the lock surface is a separate state driven by the app-lock state machine ([SECURITY.md](SECURITY.md) §4–§5).

## 5. Product rules

Choices, not mechanisms — each could plausibly be built the other way and deliberately is not:

- **Message format is never a manual choice.** It is selected automatically from recipient key versions (CLAUDE.md Hard Constraint 8).
- **Format downgrade is surfaced before encryption** — as a warning on the recipient chooser — never as a post-hoc error.
- **A message not addressed to you never triggers an authentication prompt.** Decrypt Phase 1 matches recipients against public certificates only and fails without touching any private key ([SECURITY.md](SECURITY.md) §3).
- **Signature verification is graded, not binary** — during decryption a bad or unknown signature is reported alongside the plaintext, never used to suppress it. The standalone Verify surface grades the same way; only its summary verdict is stricter (the first bad or expired signature is decisive).
- **Every key ships with a revocation certificate**, generated at key creation and at import, and exportable from the key detail page. If the stored artifact is missing (e.g. interrupted device-bound generation), export fails closed rather than regenerating ([SECURITY.md](SECURITY.md) §3).
- **Tutorial state never touches the real workspace**, and the tutorial is not a prerequisite for key generation. Isolation rules: [SECURITY.md](SECURITY.md) §6.
- **Self-test report data is export-only and never persisted.**
- **Fingerprints are read segment-by-segment by VoiceOver** — a fingerprint is only useful if it can be verified, including aurally.
- **Error copy is owned by the String Catalog**; the app-owned error taxonomy is `CypherAirError`. The meaning contract that survives any copy edit: authentication failure during decryption aborts with no partial plaintext (CLAUDE.md Hard Constraint 3).

## 6. Compatibility promises (tool families, not version pins)

- **Portable Legacy / Device-Bound Legacy (v4)** — the GnuPG-compatibility story: works with GnuPG and the broad classical OpenPGP ecosystem.
- **Portable Modern, Portable Modern · High, Device-Bound Modern (v6, RFC 9580)** — work with RFC 9580-capable tools (the Sequoia lineage, current OpenPGP.js); **not compatible with GnuPG** (no v6 support). Modern · High's Ed448/X448 is additionally not yet supported by some v6 tools.
- **Post-Quantum families (RFC 9980)** — interop target is the Sequoia lineage; they make **no GnuPG claim**, and product copy must never imply one. Full interop position and red lines: [CUSTODY.md](CUSTODY.md) §8.

## 7. What the current surface actually shows

Honest statements about shipped indicator behavior, recorded so no document or comment re-inflates them:

- The recipient compatibility indicator has exactly **two states**: format-downgrade warning and compatible. There is **no near-expiry warning**, and non-encryptable contacts are filtered out of the chooser rather than shown blocked. A contact key's encryptability is cached at import time, not re-evaluated against the clock.
- Encrypt **tags are a filter** over the recipient list (browse-only); batch selection is the separate "Select All Shown" action scoped to the filtered view.
- The **quantum-safety badge is on the result surface**, derived from the produced artifact's session-key packets — never from the live recipient selection ([SECURITY.md](SECURITY.md) §2). Mixed recipient sets get a visible not-fully-quantum-safe state.
- Revoked/expired keys are retained and shown for signer recognition, but the app does not surface *why* a key was revoked (the revocation reason is not carried past the FFI boundary).
- Save-pending decrypted output files live in the app temp directory until the **next-launch sweep** — there is no termination-time sweep. Cleanup mechanism and the remaining roadmap gap: [STORAGE.md](STORAGE.md) §4.

## 8. Roadmap-class product commitments

Decided but not shipped; nothing here describes current behavior:

- **Unified screen lifecycle rule:** hide keeps everything and operations continue; destroy cancels and cleans; relock clears everything on every screen.
- **Contacts redesign:** person/certificate membership model, reversible merge with undo, detachable keys, withdrawable manual verification, and lifecycle-refresh (which is what would make expiry states re-evaluated and representable).
- **Open With handler** with explicit consent (§3) and the `cypherairx://` scheme rename.
