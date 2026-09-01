# Local Storage

*The storage posture, the promises attached to persisted state, and the documented exceptions. Lifecycle and fail-closed invariants: [SECURITY.md](SECURITY.md). Row-name constants: `Sources/Security/KeychainManageable.swift`.*

## 1. Posture

**Protect every CypherAir-owned local data surface unless a documented technical or security reason keeps it outside a protected domain.** Default-protect, explicit exceptions (§3) — a new persisted surface either joins a protected domain or names its reason here.

## 2. Promises attached to persisted state

- **One Secure Enclave-sealed root.** The ProtectedData root secret persists as a single self-contained Keychain row with the SE device-binding key folded in; that key has no row of its own. The raw root secret only ever derives the wrapping root key and is then zeroized; each domain has its own random master key, persisted only wrapped under the wrapping root key, and unwrapped keys are memory-only and session-local.
- **Domain-key rows carry no per-row biometric access control** — deliberately: unwrapping still requires the post-auth wrapping root key, and the user-facing prompt is the app-session gate.
- **Anti-silent-wipe:** a missing registry combined with any surviving app-owned domain-key row enters framework recovery — never a bootstrap into empty state.
- **`key-metadata` is the key-list source of truth.** It stores only the non-secret key identity projection plus public certificate bytes and the key-level revocation artifact — never handle locators, access-control policy, salts, sealed boxes, or secret material — and is **never silently rebuilt from private-key envelope rows**; expected Secure Enclave handles are derived from stored public certificate bindings at load time and stay in memory only.
- **Contacts is SQLCipher keyed directly with the raw domain-master-key bytes** — no second database-key row; the key buffer is zeroized after keying and the connection is closed on relock and before any reset or recovery deletion.
- **Every software-custody private key is one self-contained envelope row, and nothing else lives in that row family.** A pending envelope row exists only inside a mode-switch or modify-expiry window and is promoted or cleaned, never trusted over a permanent row.
- **Custody rows are keyed by a random handle-set id, never a fingerprint** — a deliberate unlinkability property between Keychain rows and key identities. Handle-set ids are Security-layer-private locators: never written to `key-metadata`, logs, UI, exports, or Rust.
- **Reset deletion must reach what a default-account sweep cannot see:** the root-secret row and the custody handle store's random-account rows have their own deletion paths.

## 3. Documented exceptions and prohibitions

- **The app-session authentication policy and its pending-switch journal live in plain `UserDefaults`** because they configure the unlock prompt itself and must be readable before ProtectedData opens. They are the **only** ordinary-settings boot-authentication exceptions; protected-after-unlock settings must never grow pre-unlock shadow copies.
- **Self-test reports** are held in process memory, export-only, never persisted; saving one transits the same erased `tmp/` staging every export uses.
- **Files exported to user-selected locations** are the custody boundary: past export, CypherAir makes no protection claim.
- **Contacts runtime-only state is a prohibition, not a location:** the search index, screen search/filter values, tag filters, recipient selection, and pending route state must never become persisted.
- **Temporary artifacts** live under verified-file-protection `tmp/` paths and are swept **once per launch, and never at termination**; the sweep erases only what the running session does not own.
- **No `tmp/` path CypherAir creates is named after what it holds** — every one is a UUID or a fixed component; the name a save is offered under is carried on the artifact in memory and never written to a path the app controls. What the system's export machinery stages between the app and the document picker is outside this guarantee.
- **Erasing a temporary artifact is one policy** for app-owned and engine-owned files alike: unlink the name, overwrite the bytes with zeros. The overwrite is best-effort hygiene; what actually makes a discarded plaintext file unreadable is the file protection class it was created under, and above that, not writing plaintext to disk at all.
