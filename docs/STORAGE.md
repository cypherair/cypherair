# Local Storage

*The storage posture, the promises attached to persisted state, the documented exceptions, the envelope version map, and the storage target design. What ships is stated as shipped; decided-but-unshipped work is explicitly marked **roadmap**. Lifecycle and fail-closed invariants: [SECURITY.md](SECURITY.md) §3/§5. Row-name constants: `Sources/Security/KeychainManageable.swift`.*

## 1. Posture

**Protect every CypherAir-owned local data surface unless a documented technical or security reason keeps it outside a protected domain.** Default-protect, explicit exceptions (§4) — a new persisted surface either joins a protected domain or names its reason here.

## 2. Protected domains and the key hierarchy

The key hierarchy, as promises:

- One SE-sealed root: the ProtectedData root secret persists as a single self-contained `CAPDSEV5` Keychain row, LA-gated under the app-session policy, with the SE device-binding key folded in ([SECURITY.md](SECURITY.md) §3 note). The device-binding **key** has no row of its own — it exists only inside the envelope.
- The raw root secret only ever derives the wrapping root key (then is zeroized); each domain has its own random master key, persisted **only** as a `CADMKV5` wrapped-DMK Keychain record under the wrapping root key. Unwrapped DMKs are memory-only, session-local.
- **Domain-key rows carry no per-row biometric access control** — deliberately: unwrapping still requires the post-auth wrapping root key, and the user-facing prompt is the app-session gate.
- **Anti-silent-wipe:** a missing registry combined with any surviving app-owned domain-key row enters framework recovery — never a bootstrap into empty state.

Four domains ship today: `contacts`, `key-metadata`, `protected-settings`, `private-key-control`. Domain-level promises:

- **`key-metadata` is the key-list source of truth.** It stores only the non-secret `PGPKeyIdentity` projection plus public certificate bytes and the key-level revocation artifact — never handle locators, access-control policy, salts, sealed boxes, or secret material. It is recoverable after unlock but **never silently rebuilt from private-key envelope rows**; expected Secure Enclave handles are *derived* from stored public certificate bindings at load time and the classification stays in memory only.
- **`contacts` is SQLCipher**, keyed directly with the raw domain-master-key bytes (no second database-key Keychain row); the raw key buffer is zeroized after keying, and the connection is closed on relock and before any reset/recovery deletion. Recovery triggers: missing database authority, wrong key, corrupt database, application-id mismatch, unsupported `user_version`, or integrity failure — this list is the generic per-domain recovery contract the §6 target design adopts for every domain.
- **`private-key-control`** holds the auth mode and the rewrap/modify-expiry recovery journal — the state the [SECURITY.md](SECURITY.md) §4 crash-recovery invariant operates on.

## 3. Keychain rows (private-key side)

Everything app-owned sits under the `com.cypherair.v5.` service prefix. Reset deletion is the default-account prefix sweep **plus two dedicated paths the sweep cannot reach**: an exact delete of the root-secret row (with its own failure key) and the custody handle store's namespace cleanup — the custody rows use random handle-set accounts, which a default-account sweep structurally cannot see. The promises attached to the row families:

- **`privkey-envelope.<fingerprint>`** — one self-contained `CAPKEV6` envelope per software-custody key, sealed as the `software-secret-certificate` payload kind. Nothing else lives here.
- **`pending-privkey-envelope.<fingerprint>`** — the crash-window artifact: it exists only between mode-switch / modify-expiry phases and is owned by the interrupted-rewrap recovery coordinators; it is promoted or cleaned, never trusted over a permanent row ([SECURITY.md](SECURITY.md) §4).
- **`split-custody-classical.<fingerprint>`** — the Device-Bound Post-Quantum classical component, a `CAPKEV6` envelope sealed as the `split-custody-classical-component` payload kind ([CUSTODY.md](CUSTODY.md) §7). Its own row family and its own payload kind: a software-custody consumer handed one of these rows fails closed rather than opening it.
- **`secure-enclave-custody.<tier>.<role>`** — device-bound enclave-key blob rows. **The account is a random handle-set id, never a fingerprint** — a deliberate unlinkability property between Keychain rows and key identities. Handle-set ids are Security-layer-private locators: never written to `key-metadata`, logs, UI, exports, or Rust.
- **`protected-data.shared-right`** and **`protected-data.domain-key.[staged.]<domainID>`** — the §2 hierarchy's rows.

## 4. Documented exceptions and prohibitions

The exceptions, each with the reason that keeps it outside a protected domain:

- **`appSessionAuthenticationPolicy`** (plain `UserDefaults`) — must be readable *before* ProtectedData opens, because it configures the unlock prompt itself. Its pending-switch journal (**`pendingAppSessionAuthenticationPolicySwitch`**, plain `UserDefaults`) shares the exception: it records an in-flight protection-switch intent so launch converges on the stricter policy after an interruption. These two are the **only** ordinary-settings boot-authentication exceptions; protected-after-unlock settings must never grow pre-unlock shadow copies.
- **Self-test reports** — in-memory, export-only, never persisted.
- **Files exported to user-selected locations** — the custody boundary: past export, the data is outside the app-owned container and CypherAir makes no protection claim.
- **Contacts runtime-only state is a prohibition, not a location:** the search index, screen search/filter values, tag filters, recipient selection, and pending route state must never become persisted.
- **Temporary artifacts** live under `tmp/` directories born with the complete-protection class as a creation attribute ([SECURITY.md](SECURITY.md) §5) and are swept **once per launch, and never at termination**; the sweep erases only what the running session does not own. Export handoffs are staged inside an owned `export-` directory rather than loose in the `tmp/` root, and are erased by their owner when the export closes out.
- **Erasing a temporary artifact is one policy** for both the files the app owns and the ones the engine owns: unlink the name, overwrite the bytes with zeros. **The overwrite is best-effort hygiene, not a guarantee that the previous bytes are gone.** What actually makes a discarded plaintext file unreadable is the file protection class it was created under, whose per-file key dies with the file, and above that, not writing plaintext to disk at all.

## 5. The envelope version map

The map below is **ratified**; every *Next* entry is **roadmap-class** — it lands with its named trigger, not before. The four authenticated-envelope magics and the Keychain prefix version are **separate axes** and move on their own triggers, never in lockstep:

| Envelope | Today | Next | Trigger |
|---|---|---|---|
| `CAPKEV6` (private-payload envelope) | v6 — the payload kind rides in the authenticated binding, so one envelope type seals two non-interchangeable payloads (§3) | none | — |
| `CPDENV5` (protected-domain payload envelope) | v5 | **retires — no v6** | the §6 storage move replaces the plist payload container with per-domain SQLCipher |
| `CAPDSEV5` (root-secret envelope) | v5 | stays v5 | its bytes do not change under the §6 storage move |
| `CADMKV5` (wrapped domain master key) | v5 | stays v5 | its bytes do not change under the §6 storage move |

## 6. Storage target design (roadmap)

Decided, not shipped — nothing in this section describes current behavior:

- **All four protected domains move to per-domain SQLCipher databases** (the contacts model generalized, including its §2 recovery-trigger contract). The three-slot plist payload container — and `CPDENV5` with it — retires.
- **Generation-watermark authority moves into the per-domain databases**; the anti-rollback invariant and its scope bound are unchanged ([SECURITY.md](SECURITY.md) §5).
