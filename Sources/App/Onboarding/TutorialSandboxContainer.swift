import Foundation

enum TutorialSandboxContainerError: LocalizedError {
    case defaultsUnavailable
    case contactsDirectoryCreationFailed

    var errorDescription: String? {
        switch self {
        case .defaultsUnavailable:
            String(localized: "guidedTutorial.error.defaults", defaultValue: "Could not create isolated tutorial preferences.")
        case .contactsDirectoryCreationFailed:
            String(localized: "guidedTutorial.error.contactsDirectory", defaultValue: "Could not create isolated tutorial contacts storage.")
        }
    }
}

/// Isolated dependency graph for the guided tutorial.
/// Uses real app services backed by sandbox storage and mock security primitives.
final class TutorialSandboxContainer {
    let engine: PgpEngine
    let mockSecureEnclave: MockSecureEnclave
    let mockKeychain: MockKeychain
    let mockAuthenticator: MockAuthenticator
    let authManager: AuthenticationManager
    let config: AppConfiguration
    let keyManagement: KeyManagementService
    let contactService: ContactService
    let encryptionService: EncryptionService
    let decryptionService: DecryptionService
    let signingService: SigningService
    let qrService: QRService
    let selfTestService: SelfTestService
    let contactsDirectory: URL
    let defaultsSuiteName: String

    private let defaults: UserDefaults
    private var didCleanup = false

    init() throws {
        self.engine = PgpEngine()
        self.mockSecureEnclave = MockSecureEnclave()
        self.mockKeychain = MockKeychain()
        self.mockAuthenticator = MockAuthenticator()

        let suiteName = "com.cypherair.tutorial.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            throw TutorialSandboxContainerError.defaultsUnavailable
        }
        defaults.removePersistentDomain(forName: suiteName)
        self.defaultsSuiteName = suiteName
        self.defaults = defaults

        let contactsDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirGuidedTutorial-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: contactsDirectory, withIntermediateDirectories: true)
        } catch {
            throw TutorialSandboxContainerError.contactsDirectoryCreationFailed
        }
        self.contactsDirectory = contactsDirectory

        self.authManager = AuthenticationManager(
            secureEnclave: mockSecureEnclave,
            keychain: mockKeychain,
            defaults: defaults
        )
        self.config = AppConfiguration(defaults: defaults)
        self.keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: mockSecureEnclave,
            keychain: mockKeychain,
            authenticator: authManager,
            defaults: defaults
        )
        self.contactService = ContactService(engine: engine, contactsDirectory: contactsDirectory)
        self.encryptionService = EncryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        self.decryptionService = DecryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        self.signingService = SigningService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        self.qrService = QRService(engine: engine)
        self.selfTestService = SelfTestService(engine: engine)

        self.mockAuthenticator.shouldSucceed = true
        self.mockAuthenticator.biometricsAvailable = true
        self.mockSecureEnclave.simulatedAuthMode = authManager.currentMode
        try? self.contactService.loadContacts()
    }

    func cleanup() {
        guard !didCleanup else { return }
        didCleanup = true

        try? FileManager.default.removeItem(at: contactsDirectory)
        defaults.removePersistentDomain(forName: defaultsSuiteName)
    }

    deinit {
        cleanup()
    }
}
