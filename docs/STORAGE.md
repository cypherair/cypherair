# Local Storage

## 1. Posture

**Protect every CypherAir-owned local data surface unless a documented technical or security reason keeps it outside a protected domain.** Default-protect, explicit exceptions (§3) — a new persisted surface either joins a protected domain or names its reason here.

## 2. Promises attached to persisted state

- **The Keychain holds one row, the sealed root, and it carries no access control.** The row is an inert sealed blob in the passcode-set, this-device-only class, and every gate is an enclave key. A row an attacker can read is never a row an attacker can open.
- **One sealed root.** The root secret persists only as ciphertext inside one Keychain row, sealed under the wrapping enclave key whose blob is folded into the same row. Every public field of the row, the unlock profile's salt and parameters among them, is bound into the seal, so an edited field fails the open; the gate itself lives inside the enclave key regardless. The root secret is random and never derived from the passphrase: a passphrase change reseals it under a new wrapping key and changes nothing else on the device.
- **Nothing derived from the root is stored.** The wrapping root key, every per-domain key, and the identity credential are HKDF outputs that exist in memory for one session.
- **Domain payloads are sealed snapshots, one file per domain.** One AES-256-GCM envelope under the domain's derived key, with the domain and schema bound as authenticated data, written to a temporary file and renamed into place. The payload is padded to a multiple of 16 KiB before it is sealed, and the directory is excluded from device backups. No generations, no registry, no watermark. Contacts is such a domain like every other: it has no database and no sidecar files.
- **Damage has one destination.** A sealed root without its domain files, or a domain file that is missing or fails to authenticate, is the integrity-failure state ([SECURITY.md](SECURITY.md) §5) — never a bootstrap into empty state and never a default value.
- **`keys` is the key-list source of truth, and it holds every key's private part.** For each key it stores the public certificate bytes, the key-level revocation artifact, and the private part in its stored form: for a portable key the sealed secret, for a device-bound key the Secure Enclave key blobs and, for a post-quantum key, the sealed classical halves. It also stores the real moment each key was made or imported on this device, which never leaves this file. It never stores an opened secret. The public keys a Secure Enclave key must match are not stored; the certificate holds them.
- **Every portable private key is one self-contained envelope**, sealed against the identity wrapping key's public key with a fresh ephemeral key; the envelope holds no enclave key of its own. It holds the secret key packets alone, without User IDs or signatures.
- **Nothing readable identifies a key.** The Keychain row and the files can be read without unlocking the app, so nothing in them may point at one of the user's keys. No Keychain row exists per key, because the system dates every row and a key's creation time is public. The sealed files have fixed names, and their padding keeps a file's size from confirming a guess about its content. What still shows: that the three files exist, their size in steps of 16 KiB, when each last changed, and the two dates of the sealed root's row, which say when the vault was made and when its passphrase last changed. The app cannot hide these times.
- **The sealed files are never in a device backup.** Only the vault that wrote a copy could open it, because the sealed root is never backed up; a copy in a backup could only serve to put old state back.
- **There is no root rotation.** Deleting the sealed root makes every identity key unusable by construction, so a reset, not a rotation, is the only way to a new root.

## 3. Documented exceptions and prohibitions

- **UserDefaults holds nothing security-relevant.** Everything the unlock prompt needs is read from the sealed root's public metadata before any prompt; protected-after-unlock settings must never grow pre-unlock shadow copies.
- **Files exported to user-selected locations** are the custody boundary: past export, CypherAir makes no protection claim.

## 4. Not built yet

Rules for pieces that are not built yet. Each names the piece that builds it: a piece of [ARCHITECTURE.md](ARCHITECTURE.md) §9, or a screens piece by its issue.

- **#1063.** A portable key's envelope must be sealed once, when the key is made or imported: an expiry change or a revocation changes only the certificate, which is the authority for both.
- **#1063.** For a key the app makes, the readable times of §2 must match no time inside the key: the stamp of [SECURITY.md](SECURITY.md) §10.
- **#1065.** Reset must delete every Keychain item of the app, whatever its service or name, so a row that an earlier version left goes with the rest.
- **#1066.** Temporary artifacts must live under verified-file-protection `tmp/` paths and be swept **once per launch, and never at termination**; the sweep erases only what the running session does not own.
- **#1066.** No `tmp/` path CypherAir creates may be named after what it holds — every one is a UUID or a fixed component; the name a save is offered under is carried on the artifact in memory and never written to a path the app controls. What the system's export machinery stages between the app and the document picker is outside this guarantee.
- **#1048, #1066.** Erasing a temporary artifact must be one policy for app-owned and engine-owned files alike: unlink the name, overwrite the bytes with zeros. The overwrite is best-effort hygiene; what actually makes a discarded plaintext file unreadable is the file protection class it was created under, and above that, not writing plaintext to disk at all.
- **#1054, #1056.** Contacts runtime-only state must never become persisted: the search index, screen search and filter values, recipient selection, and pending route state.
