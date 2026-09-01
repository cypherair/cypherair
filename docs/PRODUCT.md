# Product Promises

*The product's promises, deliberate absences, consent gates, and user-facing consequences. UI copy is owned by the String Catalog; algorithm and family definitions are owned by the code.*

## 1. What CypherAir X is

CypherAir X is a fully offline OpenPGP encryption tool for people who want to communicate securely without cryptographic knowledge — encrypt, decrypt, sign, and verify with keys and contacts managed on device. It never touches the network and asks for no permissions beyond the Face ID / Touch ID usage description; the iOS memory entitlements are resource entitlements for Argon2id headroom, not privacy permissions. All I/O goes through system pickers, the clipboard, and the app's URL scheme.

The product name is **CypherAir X**; copyright lines keep "CypherAir".

**Minimum device: 8 GB RAM.** Nothing in code enforces the floor as a device check — it is a support promise, load-bearing because key backups derive under Argon2id's 2 GiB parameters ([SECURITY.md](SECURITY.md)). What the code enforces is the consequence: a device without the memory to run that derivation is refused the backup, in both directions, rather than given a weaker one.

## 2. Deliberate non-features

Each of these is an absence a code read cannot prove. They are decisions, not gaps:

- **No messaging, no key-server sync, no custom encryption formats.** CypherAir X produces and consumes standard OpenPGP artifacts; transport is the user's problem by design.
- **No proactive clipboard reading.** Paste areas only; the app writes to the clipboard solely on explicit copy actions.
- **No backup flow and no backup badge for device-bound keys.** Their private material is not exportable in any form ([CUSTODY.md](CUSTODY.md)); the revocation certificate is the primary export action for a device-bound key.
- **Contacts never store recipient lists**, and contacts-package exchange does not exist. Any future Contacts backup or device migration **must** be a mandatory-encrypted export/import — never a plaintext social-graph export.
- **No password (SKESK) message flow.** The engine carries the capability; exposing it is not a commitment the app has made.

## 3. Consent gates

Actions that never proceed without an explicit user step:

- **Device-bound key generation** requires passing a commitment sheet (the permanence consequences, §4) before generation starts.
- **URL-scheme key import** always requires user confirmation before a key is added; a second import while one is pending errors rather than auto-adding.
- **High Security Mode activation** requires a warning, a backup check over software-custody keys, and a biometric confirmation of the change.

## 4. User-facing consequences of the security design

- **Device-bound keys are permanent residents of one device's Secure Enclave.** Device loss, key-handle loss, or loss of biometric access makes the key permanently unusable — there is no recovery. Key family is **immutable** after generation.
- **Software (portable) keys survive through backups** — export is passphrase-protected, and losing the wrapped copy is recoverable only from such a backup.
- **High Security Mode** removes the passcode fallback: while biometrics are unavailable, decrypt, sign, and export stay blocked. Device-bound keys always require biometrics regardless of this setting.
- **On macOS, screen lock locks the app immediately**, regardless of the grace-period setting, and **the re-authentication interval bounds the session, not just the next prompt**: the app keeps running while not frontmost, so once the interval passes it relocks itself. The other platforms suspend the app while it is away and run the same check on return.
- **The privacy cover is not the lock.** When the app is not foreground-active it shows an opaque, app-identified cover — purely visual, with no authentication role.

## 5. Product rules

Choices, not mechanisms — each could plausibly be built the other way and deliberately is not:

- **Message format is never a manual choice.** The engine selects it from what the recipient certificates advertise: AEAD only when every certificate the message is encrypted to advertises SEIPDv2. **Format downgrade is surfaced before encryption**, as a warning on the recipient chooser derived from the engine's decision for the recipients actually addressed — never as a post-hoc error.
- **A message not addressed to you never triggers an authentication prompt.** Recipient matching runs against public certificates only and fails without touching any private key.
- **Signing is on by default, and the default is a setting**; the per-message toggles decide the message being written.
- **Signature verification is graded, not binary** — a bad or unknown signature is reported alongside the plaintext, never used to suppress it. The standalone Verify surface grades the same way; only its summary verdict is stricter.
- **A weak passphrase is refused, not warned about.** Where the user chooses a passphrase, the app declines rather than letting a warning be dismissed, offers a generated passphrase as the first option, and asks for two plain requirements shown as they are met — never a strength score ([SECURITY.md](SECURITY.md)).
- **Every key ships with a revocation certificate**, generated at creation and at import and exportable from the key detail page. If the stored artifact is missing, export fails closed rather than regenerating.
- **Key expiry is the user's choice on both paths, and never expiring is one of the choices.** Declining an expiry means the certificate carries no expiration — the engine is never handed a distant date. What is offered, what is accepted, and the ceiling over both are stated once in code and read by both surfaces.
- **Tutorial state never touches the real workspace**, and the tutorial is not a prerequisite for key generation ([SECURITY.md](SECURITY.md)).
- **Every copy is device-only and expires after five minutes** — ciphertext, signed text, public keys, fingerprints, URLs alike. The Encrypt and Sign result copies additionally state this in the clipboard safety notice, on by default and silenceable as a protected setting; that notice informs, it does not confirm.
- **An exported file is offered under exactly one name, fixed where the artifact is produced.** Encryption appends `.gpg` to the name the file already has, and decryption removes it; a ciphertext with no OpenPGP extension is offered with `.decrypted` appended rather than under a name that would propose overwriting the ciphertext being read.
- **Success is confirmed in place, by the control the user just tapped**, through one shared control for every copy in the app, and it reports what happened rather than what was asked for. **No pop-up reports a success**: an alert asks a question or reports a failure, and a completed local-data reset restarts into a fresh app rather than announcing itself.
- **Fingerprints are read segment-by-segment by VoiceOver** — a fingerprint is only useful if it can be verified, including aurally.
- **Error copy is owned by the String Catalog**; the app-owned error taxonomy is `CypherAirError`. The meaning contract that survives any copy edit: authentication failure during decryption aborts with no partial plaintext.

## 6. Compatibility promises (tool families, not version pins)

- **Portable Legacy / Device-Bound Legacy (v4)** — the GnuPG-compatibility story: works with GnuPG and the broad classical OpenPGP ecosystem.
- **Portable Modern, Portable Modern · High, Device-Bound Modern (v6, RFC 9580)** — work with RFC 9580-capable tools; **not compatible with GnuPG**. Modern · High's Ed448/X448 is additionally not yet supported by some v6 tools.
- **Post-Quantum families (RFC 9980)** — interop target is the Sequoia lineage ([CUSTODY.md](CUSTODY.md)).

Revoked and expired keys are retained and shown for signer recognition, but the app does not surface *why* a key was revoked.
