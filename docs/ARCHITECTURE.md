# Architecture

> Purpose: Module breakdown, dependency relationships, and data flow for CypherAir.
> Audience: Human developers and AI coding tools.

## 1. Layer Overview

CypherAir is a three-layer application: a SwiftUI presentation layer, a Swift services layer, and a Rust cryptographic engine bridged via UniFFI.

```mermaid
graph TB
    subgraph "Swift Application"
        UI["App Layer<br/>SwiftUI Views + Navigation"]
        SVC["Services Layer<br/>Encryption · Signing · Keys · Contacts · QR"]
        SEC["Security Layer<br/>SE Wrapping · Keychain · Auth Modes"]
        MOD["Models<br/>Data Types · Errors"]
    end

    subgraph "FFI Boundary"
        BIND["UniFFI Swift Bindings<br/>pgp_mobile.swift"]
    end

    subgraph "Rust Engine"
        PGP["pgp-mobile crate<br/>Sequoia 2.2.0 + crypto-openssl"]
    end

    UI --> SVC
    SVC --> SEC
    SVC --> BIND
    SEC --> |CryptoKit| SE["Secure Enclave<br/>P-256 Hardware"]
    SEC --> |Security.framework| KC["Keychain"]
    BIND --> PGP
    SVC --> MOD
    SEC --> MOD
```

## 2. Module Breakdown

### App Layer (`Sources/App/`)

SwiftUI views, navigation routing, onboarding, and application composition. Views remain thin and call into the Services layer for all operations. Uses iOS 26 Liquid Glass conventions where applicable and native platform SwiftUI chrome elsewhere. Standard components auto-adopt; custom floating controls apply `.glassEffect()` only where the API is available and platform-appropriate.

Key files:

- `CypherAirApp.swift` — app entry point and scene configuration
- `AppContainer.swift` — centralized dependency construction
- `AppStartupCoordinator.swift` — synchronous pre-auth bootstrap, cold-start loading, crash recovery, temporary file cleanup, startup warning aggregation
- `LocalDataResetService.swift` — destructive reset workflow for CypherAir-owned Keychain items, ProtectedData files, contacts, defaults, temporary files, and in-memory session state
- `ContentView.swift` — root navigation
- `OnboardingView.swift` — first-run flow and guided tutorial decision page
- `Onboarding/Tutorial*` — sandboxed guided tutorial host, session store, shell, and page-configuration seams

### App Common Helpers (`Sources/App/Common/`)

Shared presentation-layer infrastructure used across multiple views.

| Helper | Responsibility |
|--------|---------------|
| `OperationController` | Shared task lifecycle, cancellation, progress state, error presentation, and clipboard notice handling for encrypt/decrypt/sign/verify flows |
| `SecurityScopedFileAccess` | Uniform wrapper around security-scoped file URL access |
| `FileExportController` | Shared `fileExporter` state for exporting generated data or existing files |
| `PrivacyScreenModifier` | Background blur + re-authentication gating as a thin UI adapter over `AppSessionOrchestrator` |

### Services Layer (`Sources/Services/`)

Orchestrates user-facing operations by coordinating the Security layer and the Rust PGP engine.

| Service | Responsibility |
|---------|---------------|
| `EncryptionService` | Text/file encryption with recipient selection, encrypt-to-self, signature toggle, **auto format selection** (SEIPDv1/v2 by recipient key version) |
| `DecryptionService` | Two-phase decryption: header parse (Phase 1, no auth) → decrypt (Phase 2, auth required). Handles both SEIPDv1 and SEIPDv2. **Security-critical: Phase 1/Phase 2 boundary must never be bypassed.** |
| `PasswordMessageService` | Password/SKESK message encryption and decryption with optional signing. Separate from the recipient-key/two-phase decrypt flow; password-based decrypt does not use PKESK matching, while optional signing during password-message encryption may trigger Secure Enclave unwrap. |
| `SigningService` | Cleartext text signatures, detached file signatures, legacy verification summaries, and detailed signature-result service APIs used by the current verify workflows |
| `KeyManagementService` | Key generation (**profile-aware**: Profile A → Cv25519/RFC4880, Profile B → Cv448/RFC9580), import, export, expiry modification, revocation export, selector discovery, and selective revocation export through focused internal key-management helpers |
| `CertificateSignatureService` | Certificate-signature verification and User ID certification generation. Owns selector-validated certificate-signature workflows and signer identity resolution at the service boundary. |
| `ContactService` | Public key storage, same-fingerprint public update absorption, different-fingerprint replacement detection, flat list management |
| `QRService` | QR generation (CIQRCodeGenerator), QR decoding from photo (CIDetector), URL scheme parsing. **Security-critical: parses untrusted external input.** |
| `SelfTestService` | One-tap diagnostic covering **both profiles**: key gen → encrypt/decrypt → sign/verify → tamper test → QR round-trip |
| `FileProgressReporter` | Bridges Rust streaming progress callbacks to SwiftUI `@Observable` state. Implements UniFFI `ProgressReporter` protocol. Thread-safe via `OSAllocatedUnfairLock`. |
| `DiskSpaceChecker` | Runtime disk space validation before streaming file encryption. Uses `volumeAvailableCapacityForImportantUsageKey` to prevent Jetsam termination during large file operations. The legacy in-memory `encryptFile(...)` helper still retains its fixed 100 MB guard. |

### Guided Tutorial Architecture (`Sources/App/Onboarding/`)

The guided tutorial is a host-driven sandbox that teaches the real app workflow without touching real workspace state. `TutorialView` owns the hub, sandbox acknowledgement, workspace, completion, and leave-confirmation surfaces. `TutorialSessionStore` owns the current tutorial session, seven-module progress, replay unlock rules, navigation state, active tutorial modal, output interception policy, and completion-version persistence.

`TutorialSandboxContainer` builds a separate dependency graph for the tutorial using isolated `UserDefaults`, a temporary contacts directory, real app services, and mock Secure Enclave / Keychain primitives behind a real `AuthenticationManager`. The tutorial reuses production pages through `TutorialConfigurationFactory`, `TutorialRouteDestinationView`, and `TutorialShellDefinitionsBuilder`; tutorial behavior is injected through generic page configuration instead of pervasive page-level tutorial branches.

Safety is enforced by narrow host boundaries:

- `TutorialUnsafeRouteBlocklist` blocks only routes that would break isolation or create misleading tutorial behavior.
- `OutputInterceptionPolicy` suppresses clipboard writes and real file/data exports during a live tutorial session.
- Page configuration disables real file import/export, share/copy sinks, onboarding re-entry, app icon changes, selective revocation export, and certificate-signature workflows inside the sandbox while preserving the real page structure where practical.
- Tutorial helper modals keep shell guidance hidden while active, but the tutorial host wraps import, auth-mode, and leave-confirmation modals with module-aware sandbox guidance so the task context does not disappear during an interruption.
- `TutorialAutomationContract` owns tutorial-ready markers and stable UI identifiers for onboarding decision actions, tutorial hub/completion actions, return/close/finish controls, helper modals, and completion prompts.

### Current Rust / FFI Capability Ownership

| Family | Swift service owner | Current app owner | Status |
|--------|---------------------|-------------------|--------|
| Certificate Merge / Update | `ContactService` | `ContactImportWorkflow`, `AddContactView`, `IncomingURLImportCoordinator`, URL import flow in `CypherAirApp` | Shipped |
| Revocation Construction | `KeyManagementService` | `KeyDetailView`, `SelectiveRevocationView`, `SelectiveRevocationScreenModel` | Shipped |
| Password / SKESK Symmetric Messages | `PasswordMessageService` | None | Service-only |
| Certification And Binding Verification | `CertificateSignatureService` | `ContactDetailView`, `ContactCertificateSignaturesView`, `ContactCertificateSignaturesScreenModel` | Shipped |
| Richer Signature Results | `SigningService` and `DecryptionService` | `VerifyView`, `VerifyScreenModel`, `DecryptView`, `DecryptScreenModel`, shared `DetailedSignatureSectionView` | Shipped |

Current app-surface workflows call the owning Swift service rather than `PgpEngine` directly. `PasswordMessageService` remains intentionally service-only until product scope adds a dedicated route and plaintext-handling contract.

### Security Layer (`Sources/Security/`)

Manages all hardware-backed security operations. This is the most sensitive module.

| Component | Responsibility |
|-----------|---------------|
| `SecureEnclaveManager` | P-256 key generation in SE, self-ECDH + HKDF + AES-GCM wrapping/unwrapping, key deletion. Same wrapping scheme for Ed25519/X25519/Ed448/X448. |
| `KeychainManager` | CRUD for Keychain items (SE key blob, salt, sealed box), access control flag configuration |
| `AuthenticationManager` | Standard/High Security mode logic, mode switching with SE key re-wrapping, LAContext evaluation, and auth-mode crash recovery |
| `ProtectedDataSessionCoordinator` | Shared Keychain-protected root-secret retrieval through authenticated `LAContext`, wrapping-root-key derivation, relock, and `restartRequired` latching for protected app-data domains |
| `ProtectedDomainKeyManager` | Per-domain DMK wrapping/unwrapping, staged wrapped-DMK validation/promotion, and unlocked-domain-key zeroization |
| `AppSessionOrchestrator` | App-wide grace-window ownership, content-clear generation, launch/resume privacy-auth sequencing, bootstrap handoff, and protected-data access-gate evaluation |
| `AuthLifecycleTraceStore` / `AuthTraceMetadata` | Passive authentication, Keychain, Secure Enclave, ProtectedData, startup, UI timing, and local reset trace metadata; never records plaintext, keys, salts, sealed payloads, or fingerprints |
| `KeyBundleStore` | Shared storage helper for 3-item wrapped key bundles (permanent/pending namespaces, rollback, replace-from-pending semantics) |
| `KeyMetadataStore` | Shared persistence helper for non-sensitive key metadata items in the dedicated metadata Keychain account, with authenticated legacy migration from the default account |
| `KeyMigrationCoordinator` | Shared migration state machine for pending/permanent recovery, including safe/retryable/unrecoverable outcomes |
| `Argon2idMemoryGuard` | Validates `os_proc_available_memory()` against Argon2id S2K memory requirements before key import. 75% threshold prevents Jetsam termination. No-op for Profile A (Iterated+Salted S2K). |
| `MemoryZeroingUtility` | Extensions on `Data` and `Array<UInt8>` for secure clearing |

### ProtectedData Phase 1 Additions (`Sources/Security/ProtectedData/`)

- `ProtectedDataStorageRoot.swift` — resolves `Application Support/ProtectedData/`, file-protection application, and registry/domain metadata paths
- `ProtectedDataRegistry.swift` / `ProtectedDataRegistryStore.swift` — registry manifest, consistency validation, recovery classification, empty-registry bootstrap, and bootstrap outcome construction
- `KeychainProtectedDataRootSecretStore.swift` — Keychain storage for the shared app-data root secret
- `ProtectedDataRightStoreClient.swift` — legacy right-store migration/cleanup adapter, not the current authorization path
- `ProtectedDomainBootstrapStore.swift` — file-side bootstrap metadata persistence

Current Phase 1 scope:

- the framework exists and is wired into startup/bootstrap and app-session ownership
- `ProtectedSettingsStore` is the first protected-domain adopter for protected settings/control state
- cold-start bootstrap results are only an initial handoff; future protected access re-checks current registry/framework state through an explicit gate
- Settings refresh can auto-open protected settings only by consuming an existing app-session `LAContext` handoff; the handoff-only path must not start a new interactive authentication prompt

### Models (`Sources/Models/`)

Pure data types with no side effects. Includes Swift representations of PGP keys, error enums mapping from `PgpError`, user-facing error messages per PRD Section 4.7, configuration types (auth mode, grace period), and shared identity presentation helpers.

| Helper | Responsibility |
|--------|---------------|
| `IdentityPresentation` | Shared fingerprint formatting, short key ID derivation, user ID parsing, email extraction, and accessibility label generation |

### Rust Engine (`pgp-mobile/`)

The `pgp-mobile` Rust crate wraps `sequoia-openpgp` behind a UniFFI-annotated API. It exposes operations (generate, encrypt, decrypt, sign, verify, export, import) that accept/return `Vec<u8>` and `String`. All Sequoia internal types stay hidden behind this boundary.

```
pgp-mobile/
├── Cargo.toml        # sequoia-openpgp 2.2 + crypto-openssl + uniffi
├── src/
│   ├── lib.rs        # UniFFI proc-macros, public API surface
│   ├── keys.rs       # Profile-aware generation (Cv25519/RFC4880 vs Cv448/RFC9580)
│   ├── encrypt.rs    # Auto format selection by recipient key version
│   ├── decrypt.rs    # SEIPDv1 + SEIPDv2 (OCB/GCM), AEAD hard-fail
│   ├── password.rs   # Password / SKESK message encrypt/decrypt
│   ├── sign.rs       # Signing (cleartext + detached)
│   ├── verify.rs     # Signature verification with graded results
│   ├── streaming.rs  # File-path-based streaming I/O with progress reporting and cancellation
│   ├── armor.rs      # ASCII armor encode/decode
│   └── error.rs      # PgpError enum (maps 1:1 to Swift throwing functions)
├── tests/            # Rust-side unit + integration tests
└── uniffi-bindgen.rs # UniFFI CLI entrypoint used by the build script
bindings/
├── module.modulemap  # Xcode-imported module map alias
├── pgp_mobileFFI.h   # Generated C header
└── pgp_mobile.swift  # Generated Swift bindings synced into Sources/PgpMobile/
```

## 3. Data Flows

### Encrypt (Profile-Aware)

```mermaid
sequenceDiagram
    participant U as User
    participant V as EncryptView
    participant ES as EncryptionService
    participant PGP as pgp-mobile (Rust)

    U->>V: Enter plaintext + select recipients
    V->>ES: encrypt(plaintext, recipients, signWith, encryptToSelf)
    ES->>ES: Collect recipient public keys from ContactService
    ES->>ES: If encryptToSelf: add own public key
    ES->>PGP: pgpEncrypt(plaintext bytes, pubkeys, signingKey?)
    Note over PGP: Inspect recipient key versions
    alt All v4
        PGP->>PGP: SEIPDv1 (MDC)
    else All v6
        PGP->>PGP: SEIPDv2 (AEAD OCB)
    else Mixed v4+v6
        PGP->>PGP: SEIPDv1 (lowest common)
    end
    PGP-->>ES: Result<Vec<u8>> (ASCII armor ciphertext)
    ES-->>V: Ciphertext string
    V-->>U: Copy / Share options
```

### Two-Phase Decrypt

```mermaid
sequenceDiagram
    participant U as User
    participant V as DecryptView
    participant DS as DecryptionService
    participant PGP as pgp-mobile (Rust)
    participant SEC as Security Layer
    participant SE as Secure Enclave

    U->>V: Paste/import ciphertext
    V->>DS: beginDecrypt(ciphertext)

    Note over DS,PGP: Phase 1 — No authentication
    DS->>PGP: matchRecipients(ciphertext, localCerts)
    PGP-->>DS: Matched primary certificate fingerprints
    DS->>DS: Resolve matched local key identity
    alt No match
        DS-->>V: Error: "Not addressed to your identities"
    end

    Note over DS,SE: Phase 2 — Authentication required
    DS->>SEC: requestPrivateKey(matchedKeyID)
    SEC->>SE: Reconstruct SE key (triggers Face ID / passcode)
    SE-->>SEC: ECDH shared secret
    SEC->>SEC: HKDF + AES-GCM unseal → private key bytes
    SEC-->>DS: Private key bytes (temporary)
    DS->>PGP: pgpDecrypt(ciphertext, privateKey)
    Note over PGP: Handles SEIPDv1 + SEIPDv2 (OCB/GCM)
    PGP->>PGP: Decrypt (hard-fail on auth error)
    PGP-->>DS: Result<plaintext>
    DS->>DS: Zeroize private key bytes
    DS-->>V: Plaintext + signature verification result
    V-->>U: Display (memory only, cleared on dismiss)
```

### URL Scheme Public Key Import

```mermaid
sequenceDiagram
    participant Cam as System Camera
    participant iOS as iOS URL Routing
    participant App as CypherAirApp
    participant QR as QRService
    participant CS as ContactService
    participant V as ImportConfirmView

    Cam->>iOS: Scans QR → recognizes cypherair:// URL
    iOS->>App: onOpenURL(cypherair://import/v1/<base64url>)
    App->>QR: parseImportURL(url)
    QR->>QR: Validate /v1/ path segment
    QR->>QR: Base64url decode → binary bytes
    QR->>QR: Parse as OpenPGP public key (v4 or v6, via pgp-mobile)
    alt Invalid data
        QR-->>App: Error: "Not a valid CypherAir public key"
    end
    QR-->>App: Parsed key details (name, email, fingerprint, algorithm, profile)
    App->>V: Show key details confirmation page (includes profile indicator)
    V-->>App: User confirms "Add to Contacts"
    App->>CS: store(publicKey)
    CS-->>App: Success
```

### SE Key Wrapping

```mermaid
sequenceDiagram
    participant App as KeyManagementService
    participant SEM as SecureEnclaveManager
    participant SE as Secure Enclave Hardware
    participant KC as KeychainManager

    App->>SEM: wrapPrivateKey(privateKeyBytes, authMode, fingerprint)
    SEM->>SE: Generate P-256 KeyAgreement key (access control per authMode)
    SE-->>SEM: SE private key handle
    SEM->>SE: Self-ECDH (SE privkey × SE pubkey)
    SE-->>SEM: Shared secret (computed inside SE)
    SEM->>SEM: HKDF(SHA-256, sharedSecret, randomSalt, info="CypherAir-SE-Wrap-v1:"+fingerprint) → AES-256 key
    SEM->>SEM: AES-GCM seal(privateKeyBytes) → sealed box
    SEM->>KC: Store SE key dataRepresentation
    SEM->>KC: Store salt
    SEM->>KC: Store sealed box
    Note over SEM,KC: Confirm all 3 writes succeed
    SEM->>SEM: Zeroize privateKeyBytes + symmetric key (only after storage confirmed)
    SEM-->>App: Success
```

The wrapping scheme is identical for all key algorithms — the SE wraps raw private key bytes regardless of whether they are Ed25519, X25519, Ed448, or X448.

### Auth Mode Switching

```mermaid
sequenceDiagram
    participant U as User
    participant AM as AuthenticationManager
    participant SEM as SecureEnclaveManager
    participant KC as KeychainManager

    U->>AM: switchMode(to: .highSecurity)
    AM->>AM: Verify backup exists (if not: show strong warning)
    AM->>AM: Set rewrapInProgress flag in UserDefaults
    AM->>AM: Authenticate under CURRENT mode

    loop For each private key
        AM->>SEM: unwrapPrivateKey(keyID) [current SE key]
        SEM-->>AM: Raw private key bytes
        AM->>SEM: wrapPrivateKey(bytes, newMode: .highSecurity)
        SEM-->>AM: Success (new SE key with new flags)
        Note over SEM,KC: New items stored under TEMPORARY key names
        AM->>AM: Zeroize raw key bytes
    end

    AM->>AM: Verify all new items stored successfully
    AM->>KC: Delete OLD Keychain items (original keys)
    AM->>KC: Promote temporary items to permanent key names
    AM->>AM: Persist mode preference
    AM->>AM: Clear rewrapInProgress flag
    AM-->>U: Mode switched successfully

    Note over AM: If any step fails before deletion: delete temp items, clear flag, report error. Original keys remain intact.
    Note over AM: On app launch: if rewrapInProgress flag exists, run shared crash recovery via KeyMigrationCoordinator (see SECURITY.md Section 4).
```

## 4. Tightly Coupled Modules

These pairs must be updated together. A change to one without the other will cause build failures or runtime errors.

| Module A | Module B | Coupling Reason |
|----------|----------|----------------|
| `pgp-mobile/src/error.rs` | `Sources/Models/CypherAirError.swift` | PgpError enum variants must match 1:1 across FFI |
| `pgp-mobile/src/lib.rs` (public API) | `Sources/Services/*Service.swift` | Any Rust API change requires Swift call-site updates |
| `SecureEnclaveManager` | `KeychainManager` | SE wrapping writes 3 Keychain items; unwrapping reads them |
| `SecureEnclaveManager` | `AuthenticationManager` | Mode switch re-wraps all keys via SE manager |
| `DecryptionService` | `AuthenticationManager` | Phase 2 auth policy depends on current auth mode |
| `KeyManagementService` | `pgp-mobile/src/keys.rs` | Profile → CipherSuite mapping must stay synchronized |

## 5. Storage Layout

```
Keychain (kSecClassGenericPassword, data-protection Keychain):
├── Default account (`com.cypherair`):
│   ├── com.cypherair.v1.se-key.<fingerprint>         → SE key dataRepresentation
│   ├── com.cypherair.v1.salt.<fingerprint>           → Random HKDF salt
│   ├── com.cypherair.v1.sealed-key.<fingerprint>     → AES-GCM sealed private key
│   ├── com.cypherair.v1.pending-se-key.<fingerprint> → Temporary mode-switch / expiry-recovery row
│   ├── com.cypherair.v1.pending-salt.<fingerprint>   → Temporary mode-switch / expiry-recovery row
│   ├── com.cypherair.v1.pending-sealed-key.<fingerprint>
│   └── com.cypherair.protected-data.shared-right.v1  → Shared app-data root secret
├── Metadata account (`com.cypherair.metadata`):
│   └── com.cypherair.v1.metadata.<fingerprint>       → PGPKeyIdentity JSON cold-launch index

App Sandbox:
├── Documents/
│   ├── contacts/                → Public key files (.gpg binary)
│   │   └── contact-metadata.json → Verification-state manifest for stored contacts
│   └── self-test/               → Self-test reports
├── Application Support/
│   └── ProtectedData/
│       ├── ProtectedDataRegistry.plist
│       └── protected-settings/   → Protected settings envelopes and domain bootstrap metadata
├── Library/Preferences/
│   └── (UserDefaults)
│       ├── com.cypherair.preference.authMode              → "standard" | "highSecurity" (future private-key-control domain)
│       ├── com.cypherair.preference.appSessionAuthenticationPolicy → App-session boot auth profile
│       ├── com.cypherair.preference.gracePeriod            → Int (seconds): 0 / 60 / 180 / 300
│       ├── com.cypherair.preference.encryptToSelf          → Bool (default true)
│       ├── com.cypherair.preference.clipboardNotice        → Bool (default true)
│       ├── com.cypherair.preference.onboardingComplete     → Bool (default false)
│       ├── com.cypherair.preference.guidedTutorialCompletedVersion → Int (default 0)
│       ├── com.cypherair.preference.colorTheme             → String (ColorTheme rawValue, default "systemDefault")
│       ├── com.cypherair.internal.rewrapInProgress         → Bool (future private-key-control.recoveryJournal)
│       ├── com.cypherair.internal.rewrapTargetMode         → String (future private-key-control.recoveryJournal)
│       ├── com.cypherair.internal.modifyExpiryInProgress   → Bool (future private-key-control.recoveryJournal)
│       └── com.cypherair.internal.modifyExpiryFingerprint  → String (future private-key-control.recoveryJournal)
└── tmp/
    ├── decrypted/               → Decrypted file previews (deleted on view exit + app launch)
    ├── streaming/               → Temporary streaming encrypt/decrypt outputs (deleted on app launch)
    ├── export-*                 → Temporary fileExporter handoff files
    └── CypherAirGuidedTutorial-* → Tutorial contacts sandbox
```

**Keychain key naming conventions:**
- All keys prefixed with `com.cypherair.v1.` — the `v1` segment enables future data migration if the wrapping scheme changes.
- `<fingerprint>` is the full key fingerprint in lowercase hexadecimal, no spaces or separators (e.g., `a1b2c3d4...`).
- Metadata items use `metadata.` prefix under the dedicated metadata account and store `PGPKeyIdentity` as JSON. These items have no access control (no SE authentication required) and are the current transitional cold-launch index. The long-term target is a ProtectedData `key metadata` domain opened automatically after app unlock.
- Temporary keys during mode switch and modify-expiry recovery use `pending-` prefix. Permanent and pending private-key bundle rows remain in the existing Keychain / Secure Enclave private-key material domain; future ProtectedData recovery journals may reference these rows but must not store the bundle material.
- The long-term app-data goal is to move every CypherAir-owned local data surface behind ProtectedData after unlock unless it is a documented boot-authentication, private-key-material, framework-bootstrap, ephemeral-cleanup, test-only, legacy-cleanup, or out-of-app-custody exception.
- Future post-unlock orchestration should open required domains such as `private-key-control`, `key metadata`, and protected settings by reusing the app privacy authentication context without extra Face ID prompts.

## 6. Memory Integrity Enforcement

MIE is built right into Apple hardware and software in all models of iPhone 17 and iPhone Air (A19/A19 Pro). It is enabled via the Enhanced Security capability in Xcode, adding hardware memory tagging (EMTE) that protects all C/C++ code — including vendored OpenSSL — against buffer overflows and use-after-free.

The capability is configured in Xcode 26 via Signing & Capabilities → Add Capability → Enhanced Security. Xcode manages this through the `ENABLE_ENHANCED_SECURITY = YES` build setting and writes the required entitlement keys (Hardened Process, Hardened Heap, Enhanced Security version, Platform Restrictions, Read-Only Platform Memory, Hardware Memory Tagging, etc.) into `CypherAir.entitlements`. These entitlement keys must be committed to source control — Xcode reads them to determine which protections are enabled. See [SECURITY.md](SECURITY.md) Section 7.

On older devices without A19/A19 Pro chips, the app runs normally — the capability is additive and never breaks compatibility with older devices. See [SECURITY.md](SECURITY.md) Section 7 for the full testing workflow.
