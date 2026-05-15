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
/// The product flow owns a single active tutorial sandbox at a time.
final class TutorialSandboxContainer {
    let engine: PgpEngine
    let mockSecureEnclave: MockSecureEnclave
    let mockKeychain: MockKeychain
    let mockAuthenticator: MockAuthenticator
    let authManager: AuthenticationManager
    let privateKeyControlStore: InMemoryPrivateKeyControlStore
    let securitySimulationStack: TutorialSecuritySimulationStack
    let config: AppConfiguration
    let protectedOrdinarySettingsCoordinator: ProtectedOrdinarySettingsCoordinator
    let keyManagement: KeyManagementService
    let contactService: ContactService
    let encryptionService: EncryptionService
    let decryptionService: DecryptionService
    let signingService: SigningService
    let certificateSignatureService: CertificateSignatureService
    let qrService: QRService
    let selfTestService: SelfTestService
    let contactsDirectory: URL
    let defaultsSuiteName: String

    private let defaults: UserDefaults
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let temporaryArtifactStore: AppTemporaryArtifactStore
    private var didCleanup = false

    init(temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()) throws {
        self.temporaryArtifactStore = temporaryArtifactStore
        self.engine = PgpEngine()
        self.mockSecureEnclave = MockSecureEnclave()
        self.mockKeychain = MockKeychain()
        self.mockAuthenticator = MockAuthenticator()
        self.authenticationPromptCoordinator = AuthenticationPromptCoordinator()

        let suiteName = AppTemporaryArtifactStore.tutorialSandboxDefaultsSuiteName
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            throw TutorialSandboxContainerError.defaultsUnavailable
        }
        defaults.removePersistentDomain(forName: suiteName)
        _ = defaults.synchronize()
        self.defaultsSuiteName = suiteName
        self.defaults = defaults

        do {
            let contactsDirectory = try temporaryArtifactStore.makeTutorialSandboxDirectory()
            self.contactsDirectory = contactsDirectory
        } catch {
            throw TutorialSandboxContainerError.contactsDirectoryCreationFailed
        }

        self.authManager = AuthenticationManager(
            secureEnclave: mockSecureEnclave,
            keychain: mockKeychain,
            defaults: defaults,
            authenticationPromptCoordinator: authenticationPromptCoordinator
        )
        self.privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        self.authManager.configurePrivateKeyControlStore(privateKeyControlStore)
        self.securitySimulationStack = TutorialSecuritySimulationStack(
            authManager: authManager,
            mockSecureEnclave: mockSecureEnclave,
            mockKeychain: mockKeychain,
            mockAuthenticator: mockAuthenticator
        )
        self.config = AppConfiguration(defaults: defaults)
        self.config.privateKeyControlState = .unlocked(.standard)
        let protectedOrdinarySettingsCoordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: LegacyOrdinarySettingsStore(defaults: defaults)
        )
        protectedOrdinarySettingsCoordinator.loadForAuthenticatedTestBypass()
        self.protectedOrdinarySettingsCoordinator = protectedOrdinarySettingsCoordinator
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        self.keyManagement = KeyManagementService(
            engine: engine,
            certificateAdapter: certificateAdapter,
            secureEnclave: mockSecureEnclave,
            keychain: mockKeychain,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore
        )
        try? self.keyManagement.loadKeys()
        self.contactService = ContactService(engine: engine, contactsDirectory: contactsDirectory)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        self.encryptionService = EncryptionService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            temporaryArtifactStore: temporaryArtifactStore
        )
        self.decryptionService = DecryptionService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            temporaryArtifactStore: temporaryArtifactStore
        )
        self.signingService = SigningService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService
        )
        self.certificateSignatureService = CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: keyManagement,
            contactService: contactService
        )
        self.qrService = QRService(engine: engine)
        self.selfTestService = SelfTestService(
            engine: engine,
            messageAdapter: messageAdapter
        )

        self.mockAuthenticator.shouldSucceed = true
        self.mockAuthenticator.biometricsAvailable = true
        self.mockSecureEnclave.simulatedAuthMode = authManager.currentMode ?? .standard
        _ = try? self.contactService.openLegacyCompatibilityForTests()
    }

    func cleanup() {
        guard !didCleanup else { return }
        didCleanup = true

        try? FileManager.default.removeItem(at: contactsDirectory)
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        _ = defaults.synchronize()
    }

    deinit {
        cleanup()
    }
}
