# Local Storage

## 1. Posture

**Protect every CypherAir-owned local data surface unless a documented technical or security reason keeps it outside a protected domain.** Default-protect, explicit exceptions (§3) — a new persisted surface either joins a protected domain or names its reason here.

## 2. Promises attached to persisted state

- **No Keychain row carries an access control, anywhere.** Every row is an inert sealed blob in the passcode-set, this-device-only class, and every gate is an enclave key. A row an attacker can read is never a row an attacker can open.
- **One sealed root.** The root secret persists only as ciphertext inside one Keychain row, sealed under the wrapping enclave key whose blob is folded into the same row. The row's public metadata is exactly: the Argon2id salt and parameters of the unlock profile, the wrapping key's blob and public key, the identity wrapping key's blob and public key, the ephemeral public key, the HKDF salt, the nonce, and the tag. All of it is bound into the seal, so an edited field fails the open; the gate itself lives inside the enclave key regardless. The root secret is random and never derived from the passphrase: a passphrase change reseals it under a new wrapping key and changes nothing else on the device.
- **Nothing derived from the root is stored.** The wrapping root key, every per-domain key, and the identity credential are HKDF outputs that exist in memory for one session. There are no domain-key rows and no staged domain-key rows.
- **Domain payloads are sealed snapshots.** One AES-256-GCM envelope per generation under the domain's derived key, with domain, schema, and generation bound as authenticated data, in the current/previous/pending slots the registry governs. Contacts is such a domain like every other: it has no database and no sidecar files.
- **Anti-silent-wipe:** a missing registry combined with a surviving sealed root enters framework recovery — never a bootstrap into empty state.
- **`key-metadata` is the key-list source of truth.** It stores only the non-secret key identity projection plus public certificate bytes and the key-level revocation artifact — never handle locators, sealed boxes, or secret material — and is **never silently rebuilt from private-key envelope rows**; expected Secure Enclave handles are derived from stored public certificate bindings at load time and stay in memory only.
- **Every portable private key is one self-contained envelope row**, sealed against the identity wrapping key's public key with a fresh ephemeral key; the row holds no enclave key of its own. A pending envelope row exists only inside a modify-expiry window and is promoted or cleaned, never trusted over a permanent row.
- **Custody rows are keyed by a random handle-set id, never a fingerprint** — a deliberate unlinkability property between Keychain rows and key identities. Handle-set ids are Security-layer-private locators: never written to `key-metadata`, logs, UI, exports, or Rust.
- **Reset deletion must reach what a default-account sweep cannot see:** the sealed root and the custody handle store's random-account rows have their own deletion paths. Deleting the sealed root is the only root rotation: every identity key is unusable afterwards by construction, which is why the reset flow, not a rotation flow, is what exists.

## 3. Documented exceptions and prohibitions

- **UserDefaults holds nothing security-relevant.** Everything the unlock prompt needs is read from the sealed root's public metadata before any prompt; protected-after-unlock settings must never grow pre-unlock shadow copies.
- **Self-test reports** are held in process memory, export-only, never persisted; saving one transits the same erased `tmp/` staging every export uses.
- **Files exported to user-selected locations** are the custody boundary: past export, CypherAir makes no protection claim.
- **Contacts runtime-only state is a prohibition, not a location:** the search index, screen search/filter values, tag filters, recipient selection, and pending route state must never become persisted.
- **Temporary artifacts** live under verified-file-protection `tmp/` paths and are swept **once per launch, and never at termination**; the sweep erases only what the running session does not own.
- **No `tmp/` path CypherAir creates is named after what it holds** — every one is a UUID or a fixed component; the name a save is offered under is carried on the artifact in memory and never written to a path the app controls. What the system's export machinery stages between the app and the document picker is outside this guarantee.
- **Erasing a temporary artifact is one policy** for app-owned and engine-owned files alike: unlink the name, overwrite the bytes with zeros. The overwrite is best-effort hygiene; what actually makes a discarded plaintext file unreadable is the file protection class it was created under, and above that, not writing plaintext to disk at all.
