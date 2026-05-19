import Foundation

enum TutorialSandboxContainerError: LocalizedError {
    case defaultsUnavailable
    case contactsDirectoryCreationFailed
    case contactsProtectedDomainOpenFailed

    var errorDescription: String? {
        switch self {
        case .defaultsUnavailable:
            String(localized: "guidedTutorial.error.defaults", defaultValue: "Could not create isolated tutorial preferences.")
        case .contactsDirectoryCreationFailed:
            String(localized: "guidedTutorial.error.contactsDirectory", defaultValue: "Could not create isolated tutorial contacts storage.")
        case .contactsProtectedDomainOpenFailed:
            String(localized: "guidedTutorial.error.contactsProtectedDomain", defaultValue: "Could not open isolated tutorial contacts storage.")
        }
    }
}

private final class TutorialSandboxContactsOpenResultBox: @unchecked Sendable {
    var result: ContactsAvailability?
    var error: Error?
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
        let keyAdapter = PGPKeyOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let selfTestAdapter = PGPSelfTestOperationAdapter(engine: engine)
        self.keyManagement = KeyManagementService(
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            secureEnclave: mockSecureEnclave,
            keychain: mockKeychain,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore
        )
        try? self.keyManagement.loadKeys()
        let contactsWrappingRootKey = Data(repeating: 0x54, count: 32)
        let contactsDomainStore = try Self.makeContactsDomainStore(
            baseDirectory: contactsDirectory.appendingPathComponent("protected-contacts", isDirectory: true),
            contactsDirectory: contactsDirectory,
            contactImportAdapter: contactImportAdapter,
            wrappingRootKey: contactsWrappingRootKey
        )
        self.contactService = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: contactsDomainStore
        )
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
        self.qrService = QRService(contactImportAdapter: contactImportAdapter)
        self.selfTestService = SelfTestService(
            selfTestAdapter: selfTestAdapter,
            messageAdapter: messageAdapter
        )

        self.mockAuthenticator.shouldSucceed = true
        self.mockAuthenticator.biometricsAvailable = true
        self.mockSecureEnclave.simulatedAuthMode = authManager.currentMode ?? .standard
        try Self.openContactsSynchronously(
            contactService: self.contactService,
            wrappingRootKey: contactsWrappingRootKey
        )
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

    private static func makeContactsDomainStore(
        baseDirectory: URL,
        contactsDirectory: URL,
        contactImportAdapter: PGPContactImportAdapter,
        wrappingRootKey: Data
    ) throws -> ContactsDomainStore {
        let storageRoot = ProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = ProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tutorial.contacts.\(UUID().uuidString)"
        )
        _ = try registryStore.performSynchronousBootstrap()
        var registry = try registryStore.loadRegistry()
        if registry.committedMembership.isEmpty,
           registry.sharedResourceLifecycleState == .absent {
            registry.sharedResourceLifecycleState = .ready
            registry.committedMembership = [ProtectedSettingsStore.domainID: .active]
            try registryStore.saveRegistry(registry)
        }

        let repository = ContactRepository(contactsDirectory: contactsDirectory)
        let migrationSource = ContactsLegacyMigrationSource(
            contactImportAdapter: contactImportAdapter,
            repository: repository
        )
        return ContactsDomainStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: ProtectedDomainKeyManager(storageRoot: storageRoot),
            currentWrappingRootKey: { wrappingRootKey },
            initialSnapshotProvider: {
                try migrationSource.makeInitialSnapshot()
            }
        )
    }

    private static func openContactsSynchronously(
        contactService: ContactService,
        wrappingRootKey: Data
    ) throws {
        let semaphore = DispatchSemaphore(value: 0)
        let resultBox = TutorialSandboxContactsOpenResultBox()
        Task.detached {
            let availability = await contactService.openContactsAfterPostUnlock(
                gateDecision: ContactsPostAuthGateDecision(
                    postUnlockOutcome: .opened([ContactsDomainStore.domainID]),
                    frameworkState: .sessionAuthorized
                ),
                wrappingRootKey: { wrappingRootKey }
            )
            resultBox.result = availability
            semaphore.signal()
        }
        semaphore.wait()
        if let error = resultBox.error {
            throw error
        }
        guard resultBox.result == .availableProtectedDomain else {
            throw TutorialSandboxContainerError.contactsProtectedDomainOpenFailed
        }
    }
}
