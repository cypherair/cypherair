# Product Promises

*The product's promises, deliberate absences, consent gates, and user-facing consequences. What ships is stated as shipped; decided-but-unshipped work is explicitly marked **roadmap**. UI copy is owned by the String Catalog; algorithm and family definitions are owned by the code.*

## 1. What CypherAir X is

CypherAir X is a fully offline OpenPGP encryption tool for people who want to communicate securely without cryptographic knowledge — encrypt, decrypt, sign, and verify with keys and contacts managed on device. It never touches the network and asks for no permissions beyond the Face ID / Touch ID usage description; the additional iOS entitlements (`increased-memory-limit`, `extended-virtual-addressing`) are resource entitlements for Argon2id memory headroom, not privacy permissions. All I/O goes through system pickers, the clipboard, and the app's URL scheme.

The product name is **CypherAir X**; copyright lines keep "CypherAir".

**Minimum device: 8 GB RAM.** Nothing in code enforces the floor as a device check — it is a support promise, and it is load-bearing now that key backups derive under Argon2id's 2 GiB parameters ([SECURITY.md](SECURITY.md) §7). What the code does enforce is the consequence: a device without the memory to run that derivation is refused the backup — in both directions — rather than given a weaker one.

## 2. Deliberate non-features

Each of these is an absence a code read cannot prove. They are decisions, not gaps:

- **No messaging, no key-server sync, no custom encryption formats.** CypherAir X produces and consumes standard OpenPGP artifacts; transport is the user's problem by design.
- **No proactive clipboard reading.** Paste areas only; the app writes to the clipboard solely on explicit copy actions.
- **No backup flow and no backup badge for device-bound keys.** Their private material is not exportable in any form ([CUSTODY.md](CUSTODY.md) §2); the revocation certificate is the primary export action for a device-bound key.
- **Contacts never store recipient lists**, and contacts-package exchange does not exist.
- **No password (SKESK) message flow.** The app offers no way to create one and no way to open one. The engine carries the capability ([SECURITY.md](SECURITY.md) §7); exposing it is not a commitment the app has made.

## 3. Consent gates

Actions that never proceed without an explicit user step:

- **Device-bound key generation** requires passing a commitment sheet (the permanence consequences, §4) before generation starts.
- **URL-scheme key import** always requires user confirmation before a key is added; a second import while one is pending errors rather than auto-adding.
- **High Security Mode activation** requires a warning, a backup check over software-custody keys, and a biometric confirmation of the change.

## 4. User-facing consequences of the security design

- **Device-bound keys are permanent residents of one device's Secure Enclave.** Device loss, key-handle loss, or loss of biometric access makes the key permanently unusable — there is no recovery. Key family is **immutable** after generation; switching family means generating a new key.
- **Software (portable) keys survive through backups** — export is passphrase-protected, and losing the wrapped copy is recoverable only from such a backup ([SECURITY.md](SECURITY.md) §3).
- **High Security Mode** removes the passcode fallback: while biometrics are unavailable (sensor damage, lockout), decrypt, sign, and export stay blocked. Device-bound keys always require biometrics regardless of this setting — their enforcement is fixed at creation.
- **On macOS, screen lock locks the app immediately**, regardless of the grace-period setting. A biometric prompt's own transient deactivation is never treated as leaving the app.
- **On macOS the re-authentication interval bounds the session, not just the next prompt.** The app keeps running while it is not frontmost, so once the interval passes it relocks itself — decrypted content cleared, protected app data re-protected — rather than waiting for you to come back. iOS, iPadOS, and visionOS suspend the app while it is away, so nothing can run in between and the same check runs on your return.
- **The privacy cover is not the lock.** When the app is not foreground-active it shows an opaque, app-identified cover — purely visual, with no authentication role; the lock surface is a separate state driven by the app-lock state machine ([SECURITY.md](SECURITY.md) §4–§5).

## 5. Product rules

Choices, not mechanisms — each could plausibly be built the other way and deliberately is not:

- **Message format is never a manual choice.** The engine selects it from what the recipient certificates advertise: AEAD only when every certificate the message is encrypted to advertises SEIPDv2. For every key CypherAir generates that tracks the key version exactly; an imported certificate may advertise otherwise, and the advertised capability is what decides.
- **Format downgrade is surfaced before encryption** — as a warning on the recipient chooser — never as a post-hoc error. The warning comes from the engine's decision for the recipients actually addressed, so it cannot describe a different message than the one that gets sent.
- **A message not addressed to you never triggers an authentication prompt.** Decrypt Phase 1 matches recipients against public certificates only and fails without touching any private key ([SECURITY.md](SECURITY.md) §3).
- **Signing is on by default, and the default is a setting.** Settings › Encryption holds what new messages start with — signing and the self copy alike; the per-message toggles decide the message being written. Signing attaches attribution, so it is stated in both places rather than assumed.
- **Signature verification is graded, not binary** — during decryption a bad or unknown signature is reported alongside the plaintext, never used to suppress it. The standalone Verify surface grades the same way; only its summary verdict is stricter (the first bad or expired signature is decisive).
- **A weak passphrase is refused, not warned about.** Where the user *chooses* a passphrase — today, private-key backup — the app declines rather than letting a warning be dismissed, and offers a generated passphrase as the first option instead of asking for a better invention. What it asks for is two plain requirements shown as they are met, never a strength score to argue with; generation produces uniform characters rather than words, so no wordlist ships and no language is privileged ([SECURITY.md](SECURITY.md) §7).
- **Every key ships with a revocation certificate**, generated at key creation and at import, and exportable from the key detail page. If the stored artifact is missing (e.g. interrupted device-bound generation), export fails closed rather than regenerating ([SECURITY.md](SECURITY.md) §3).
- **Key expiry is the user's choice on both paths, and never expiring is one of the choices.** Creation offers a fixed set of whole-year terms plus Never; the modify sheet reaches the same ceiling but takes any date under it, down to the next day, or drops the expiry outright. Declining an expiry means exactly that — the engine is told the key has none, never handed a distant date — so the key detail page reads Never because the certificate carries no expiration, not because one is far off. What is offered, what is accepted, and the ceiling over both are stated once in code (`Sources/Models/Keys/KeyExpiryPolicy.swift`) and read by both surfaces: the two paths differ in how they ask and how finely, not in what they will set.
- **Tutorial state never touches the real workspace**, and the tutorial is not a prerequisite for key generation. Isolation rules: [SECURITY.md](SECURITY.md) §6.
- **Every copy is device-only and expires after five minutes.** One rule for everything the app copies — ciphertext, signed text, public keys, fingerprints, URLs: the write never reaches another device through Handoff or Universal Clipboard, and the copy leaves the clipboard five minutes later. iPhone, iPad and Vision Pro let the system remove it; on Mac the app clears its own copy, and only while the clipboard still holds it, never something copied elsewhere in the meantime ([SECURITY.md](SECURITY.md) §9). The Encrypt and Sign result copies additionally state this promise in the shared clipboard safety notice — on by default, silenceable as a protected setting. That notice **informs; it does not confirm**: the copy underneath it is confirmed the same way every other copy is, so silencing the notice costs the user the promise, never the acknowledgement.
- **An exported file is offered under exactly one name, fixed where the artifact is produced.** Encryption appends `.gpg` to the name the file already has — `photo.jpg` becomes `photo.jpg.gpg` — and decryption removes that extension to give the original name back. A ciphertext carrying no OpenPGP extension has no original name to recover, so its plaintext is offered with `.decrypted` appended rather than under a name that would propose overwriting the ciphertext being read.
- **Success is confirmed in place, by the control the user just tapped.** It becomes the confirmation for a moment, then returns to rest. One shared control does this for every copy in the app, so no screen invents its own: a checkmark that swaps in with a small symbol animation, a spoken confirmation for VoiceOver, and on iPhone a gentle success haptic. Reduce Motion drops the animation and keeps the haptic, which is not motion. The confirmation waits for the copy to actually land — the Encrypt and Sign copies first consult a protected setting — so it reports what happened rather than what was asked for. Two things are deliberately outside this rule: the clipboard safety notice above, which exists to inform, and a fingerprint copied from a context menu, which confirms nothing at all because the menu — and with it the control that would confirm — is gone before there is anything to show.
- **No pop-up reports a success.** Setting aside the informing notice above, an alert asks a question or reports a failure, and nothing the user succeeded at has to be dismissed: a completed local-data reset restarts into a fresh app rather than announcing itself, and a finished encrypt, decrypt, sign or verify settles its result into place rather than snapping in.
- **Self-test report data is export-only and never persisted** — saving one passes through the same erased temporary staging as every other export ([STORAGE.md](STORAGE.md) §4).
- **Fingerprints are read segment-by-segment by VoiceOver** — a fingerprint is only useful if it can be verified, including aurally.
- **Error copy is owned by the String Catalog**; the app-owned error taxonomy is `CypherAirError`. The meaning contract that survives any copy edit: authentication failure during decryption aborts with no partial plaintext.

## 6. Compatibility promises (tool families, not version pins)

- **Portable Legacy / Device-Bound Legacy (v4)** — the GnuPG-compatibility story: works with GnuPG and the broad classical OpenPGP ecosystem.
- **Portable Modern, Portable Modern · High, Device-Bound Modern (v6, RFC 9580)** — work with RFC 9580-capable tools (the Sequoia lineage, current OpenPGP.js); **not compatible with GnuPG** (no v6 support). Modern · High's Ed448/X448 is additionally not yet supported by some v6 tools.
- **Post-Quantum families (RFC 9980)** — interop target is the Sequoia lineage. Full interop position and red lines: [CUSTODY.md](CUSTODY.md) §8.

## 7. What the current surface shows

- The recipient compatibility indicator has exactly **two states** — holds-the-message-at-SEIPDv1 and compatible. The message-level outcome is stated once below the list.
- The **quantum-safety badge is on the result surface**, derived from the produced artifact — never from the live recipient selection ([SECURITY.md](SECURITY.md) §2). Mixed recipient sets get a visible not-fully-quantum-safe state.
- Revoked/expired keys are retained and shown for signer recognition, but the app does not surface *why* a key was revoked.

## 8. Roadmap-class product commitments

Decided but not shipped; nothing here describes current behavior:

- **Unified screen lifecycle rule:** hide keeps everything and operations continue; destroy cancels and cleans; relock clears everything on every screen.
- **Contacts redesign:** person/certificate membership model, reversible merge with undo, detachable keys, withdrawable manual verification, and lifecycle-refresh (which is what would make expiry states re-evaluated and representable). A complete Contacts backup or device migration **must** be a mandatory-encrypted export/import — never a plaintext social-graph export.
- **Open With handler** with an explicit import confirmation, like the URL scheme's (§3).
