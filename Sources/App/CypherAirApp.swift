import SwiftUI

@main
struct CypherAirApp: App {

    // MARK: - Shared Dependencies

    /// Security layer (protocols allow mock injection in tests).
    @State private var secureEnclave: HardwareSecureEnclave = HardwareSecureEnclave()
    @State private var keychain: SystemKeychain = SystemKeychain()
    @State private var authManager: AuthenticationManager

    /// App configuration (persisted in UserDefaults).
    @State private var config = AppConfiguration()

    /// PGP engine (shared across services).
    private let engine: PgpEngine

    /// Core services.
    @State private var keyManagement: KeyManagementService
    @State private var contactService: ContactService
    @State private var encryptionService: EncryptionService
    @State private var decryptionService: DecryptionService
    @State private var signingService: SigningService
    @State private var qrService: QRService
    @State private var selfTestService: SelfTestService

    /// Pending public key import awaiting user confirmation (Issue #3).
    @State private var pendingImport: PendingImport?
    @State private var importError: CypherAirError?
    @State private var loadError: String?

    /// Holds parsed key data and info for the import confirmation sheet.
    private struct PendingImport {
        let keyData: Data
        let keyInfo: KeyInfo
        let profile: KeyProfile
    }

    // MARK: - Init

    init() {
        let se = HardwareSecureEnclave()
        let kc = SystemKeychain()
        let auth = AuthenticationManager(secureEnclave: se, keychain: kc)

        let engine = PgpEngine()
        let keyMgmt = KeyManagementService(
            engine: engine,
            secureEnclave: se,
            keychain: kc,
            authenticator: auth
        )
        let contacts = ContactService(engine: engine)
        let encryption = EncryptionService(
            engine: engine,
            keyManagement: keyMgmt,
            contactService: contacts
        )
        let decryption = DecryptionService(
            engine: engine,
            keyManagement: keyMgmt,
            contactService: contacts
        )
        let signing = SigningService(
            engine: engine,
            keyManagement: keyMgmt,
            contactService: contacts
        )
        let qr = QRService(engine: engine)
        let selfTest = SelfTestService(engine: engine)

        self.engine = engine
        _secureEnclave = State(initialValue: se)
        _keychain = State(initialValue: kc)
        _authManager = State(initialValue: auth)
        _keyManagement = State(initialValue: keyMgmt)
        _contactService = State(initialValue: contacts)
        _encryptionService = State(initialValue: encryption)
        _decryptionService = State(initialValue: decryption)
        _signingService = State(initialValue: signing)
        _qrService = State(initialValue: qr)
        _selfTestService = State(initialValue: selfTest)

        // Load stored key identities from Keychain metadata (no SE auth needed).
        do {
            try keyMgmt.loadKeys()
        } catch {
            // Non-fatal: keys will appear empty. Store error for diagnostic display.
            _loadError = State(initialValue: error.localizedDescription)
        }

        // Crash recovery: check for interrupted auth mode switch.
        auth.checkAndRecoverFromInterruptedRewrap(fingerprints: keyMgmt.keys.map(\.fingerprint))

        // Crash recovery: check for interrupted modifyExpiry operation.
        keyMgmt.checkAndRecoverFromInterruptedModifyExpiry()

        // Load contacts from disk.
        do {
            try contacts.loadContacts()
        } catch {
            // Non-fatal: contacts will appear empty. Append to diagnostic info.
            let existing = _loadError.wrappedValue ?? ""
            _loadError = State(initialValue: existing.isEmpty ? error.localizedDescription : "\(existing)\n\(error.localizedDescription)")
        }

        // Clean up any leftover decrypted files from tmp/.
        cleanupTempDecryptedFiles()
    }

    // MARK: - Scene

    var body: some Scene {
        WindowGroup {
            ContentView()
                .privacyScreen()
                .environment(config)
                .environment(keyManagement)
                .environment(contactService)
                .environment(encryptionService)
                .environment(decryptionService)
                .environment(signingService)
                .environment(qrService)
                .environment(selfTestService)
                .environment(authManager)
                .sheet(isPresented: showOnboarding) {
                    OnboardingView()
                        .environment(config)
                        .interactiveDismissDisabled()
                }
                .sheet(isPresented: Binding(
                    get: { pendingImport != nil },
                    set: { if !$0 { pendingImport = nil } }
                )) {
                    if let pending = pendingImport {
                        ImportConfirmView(
                            keyInfo: pending.keyInfo,
                            detectedProfile: pending.profile,
                            onConfirm: {
                                do {
                                    let result = try contactService.addContact(publicKeyData: pending.keyData)
                                    if case .keyUpdateDetected(let newContact, let existingContact, let keyData) = result {
                                        // User confirmed import via ImportConfirmView — proceed with replacement.
                                        try contactService.confirmKeyUpdate(
                                            existingFingerprint: existingContact.fingerprint,
                                            newContact: newContact,
                                            keyData: keyData
                                        )
                                    }
                                } catch {
                                    importError = CypherAirError.from(error) { _ in .invalidQRCode }
                                }
                                pendingImport = nil
                            },
                            onCancel: {
                                pendingImport = nil
                            }
                        )
                    }
                }
                .alert(
                    String(localized: "import.error.alertTitle", defaultValue: "Import Failed"),
                    isPresented: Binding(
                        get: { importError != nil },
                        set: { if !$0 { importError = nil } }
                    )
                ) {
                    Button(String(localized: "import.error.ok", defaultValue: "OK")) {
                        importError = nil
                    }
                } message: {
                    if let importError {
                        Text(importError.localizedDescription)
                    }
                }
                .alert(
                    String(localized: "app.loadError.title", defaultValue: "Load Warning"),
                    isPresented: Binding(
                        get: { loadError != nil },
                        set: { if !$0 { loadError = nil } }
                    )
                ) {
                    Button(String(localized: "error.ok", defaultValue: "OK")) {
                        loadError = nil
                    }
                } message: {
                    if let loadError {
                        Text(loadError)
                    }
                }
                .onOpenURL { url in
                    handleIncomingURL(url)
                }
        }
    }

    private var showOnboarding: Binding<Bool> {
        Binding(
            get: { !config.hasCompletedOnboarding },
            set: { newValue in
                if !newValue {
                    config.hasCompletedOnboarding = true
                }
            }
        )
    }

    // MARK: - URL Scheme Handling

    /// Handle cypherair:// URLs for public key import.
    /// The QRService validates the URL format and parses the OpenPGP key.
    /// The user must confirm before the key is added as a contact.
    private func handleIncomingURL(_ url: URL) {
        guard url.scheme == "cypherair" else { return }

        do {
            let publicKeyData = try qrService.parseImportURL(url)
            let keyInfo = try engine.parseKeyInfo(keyData: publicKeyData)
            let profile = try engine.detectProfile(certData: publicKeyData)
            // Show confirmation sheet — do NOT add directly (PRD Section 4.2).
            pendingImport = PendingImport(keyData: publicKeyData, keyInfo: keyInfo, profile: profile)
        } catch {
            importError = CypherAirError.from(error) { _ in .invalidQRCode }
        }
    }

    // MARK: - Temp File Cleanup

    /// Delete any leftover temporary files on app launch.
    /// Per PRD Section 4.4: decrypted files deleted on exit + app launch.
    /// Also cleans up tmp/share/ used by ShareLink for named file exports.
    private func cleanupTempDecryptedFiles() {
        let fm = FileManager.default
        let tmpDir = fm.temporaryDirectory.appendingPathComponent("decrypted", isDirectory: true)
        if fm.fileExists(atPath: tmpDir.path) {
            try? fm.removeItem(at: tmpDir)
        }
        let shareDir = fm.temporaryDirectory.appendingPathComponent("share", isDirectory: true)
        if fm.fileExists(atPath: shareDir.path) {
            try? fm.removeItem(at: shareDir)
        }
        let streamingDir = fm.temporaryDirectory.appendingPathComponent("streaming", isDirectory: true)
        if fm.fileExists(atPath: streamingDir.path) {
            try? fm.removeItem(at: streamingDir)
        }
    }
}
