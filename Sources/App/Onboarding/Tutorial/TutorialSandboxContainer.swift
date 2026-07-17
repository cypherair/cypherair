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
    private let contactsWrappingRootKey: Data
    private var didCleanup = false

    init(temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()) throws {
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
        self.config = AppConfiguration(defaults: defaults)
        self.config.privateKeyControlState = .unlocked(.standard)
        let protectedOrdinarySettingsCoordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: InMemoryOrdinarySettingsStore()
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
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            metadataPersistence: InMemoryKeyMetadataStore()
        )
        try? self.keyManagement.loadKeys()
        let contactsWrappingRootKey = Data(repeating: 0x54, count: 32)
        self.contactsWrappingRootKey = contactsWrappingRootKey
        let contactsDomainStore = try Self.makeContactsDomainStore(
            baseDirectory: contactsDirectory.appendingPathComponent("protected-contacts", isDirectory: true),
            wrappingRootKey: contactsWrappingRootKey,
            keychain: mockKeychain
        )
        self.contactService = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            contactsDomainStore: contactsDomainStore
        )
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let secureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: SystemSecureEnclaveCustodyKeyStore(),
            tier: .classicalP256
        )
        let secureEnclaveDigestSigner = SystemSecureEnclaveCustodyDigestSigner()
        let secureEnclaveCompositeOperations = SystemSecureEnclaveCompositeOperations()
        keyManagement.configurePrivateKeyExpiryMutationService(
            PrivateKeyExpiryMutationService(
                router: keyManagement.makePrivateKeyOperationRouter(
                    publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                    handleStore: secureEnclaveCustodyHandleStore
                ),
                keyAdapter: keyAdapter,
                digestSigner: secureEnclaveDigestSigner,
                compositeSigner: secureEnclaveCompositeOperations
            )
        )
        keyManagement.configurePrivateKeySelectiveRevocationService(
            PrivateKeySelectiveRevocationService(
                router: keyManagement.makePrivateKeyOperationRouter(
                    publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                    handleStore: secureEnclaveCustodyHandleStore
                ),
                certificateAdapter: certificateAdapter,
                digestSigner: secureEnclaveDigestSigner,
                compositeSigner: secureEnclaveCompositeOperations
            )
        )
        let textEncryptor = PrivateKeyTextEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        let fileEncryptor = PrivateKeyStreamingFileEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        self.encryptionService = EncryptionService(
            keyManagement: keyManagement,
            contactService: contactService,
            textEncryptor: textEncryptor,
            fileEncryptor: fileEncryptor,
            temporaryArtifactStore: temporaryArtifactStore
        )
        let messageDecryptor = PrivateKeyMessageDecryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            keyAgreement: SystemSecureEnclaveCustodyKeyAgreement(),
            compositeDecapsulator: secureEnclaveCompositeOperations
        )
        let fileDecryptor = PrivateKeyStreamingFileDecryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            keyAgreement: SystemSecureEnclaveCustodyKeyAgreement(),
            compositeDecapsulator: secureEnclaveCompositeOperations
        )
        self.decryptionService = DecryptionService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            messageDecryptor: messageDecryptor,
            fileDecryptor: fileDecryptor,
            temporaryArtifactStore: temporaryArtifactStore
        )
        let cleartextSigner = PrivateKeyCleartextSigningService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        let detachedFileSigner = PrivateKeyDetachedFileSigningService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        self.signingService = SigningService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            cleartextSigner: cleartextSigner,
            detachedFileSigner: detachedFileSigner
        )
        let contactCertificationSigner = PrivateKeyContactCertificationService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            certificateAdapter: certificateAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        self.certificateSignatureService = CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            certificationSigner: contactCertificationSigner
        )
        self.qrService = QRService(contactImportAdapter: contactImportAdapter)
        self.selfTestService = SelfTestService(
            selfTestAdapter: selfTestAdapter,
            messageAdapter: messageAdapter
        )

        self.mockAuthenticator.shouldSucceed = true
        self.mockAuthenticator.biometricsAvailable = true
        self.mockSecureEnclave.simulatedAuthMode = authManager.currentMode ?? .standard
    }

    func openContactsIfNeeded() async throws {
        guard contactService.contactsAvailability != .availableProtectedDomain else {
            return
        }

        try Task.checkCancellation()
        let contactService = self.contactService
        let wrappingRootKey = contactsWrappingRootKey
        let availability = await Task.detached {
            await contactService.openContactsAfterPostUnlock(
                gateDecision: ContactsPostAuthGateDecision(
                    postUnlockOutcome: .opened([ContactsDomainStore.domainID]),
                    frameworkState: .sessionAuthorized
                ),
                wrappingRootKey: { wrappingRootKey }
            )
        }.value
        try Task.checkCancellation()
        guard availability == .availableProtectedDomain else {
            throw TutorialSandboxContainerError.contactsProtectedDomainOpenFailed
        }
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
        wrappingRootKey: Data,
        keychain: any KeychainManageable
    ) throws -> ContactsDomainStore {
        let storageRoot = ProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let domainKeyManager = ProtectedDomainKeyManager(
            storageRoot: storageRoot,
            keychain: keychain
        )
        let registryStore = ProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tutorial.contacts.\(UUID().uuidString)",
            hasExternalProtectedDataArtifacts: {
                try domainKeyManager.hasAnyPersistedDomainKeyRecord()
            }
        )
        _ = try registryStore.performSynchronousBootstrap()
        var registry = try registryStore.loadRegistry()
        if registry.committedMembership.isEmpty,
           registry.sharedResourceLifecycleState == .absent {
            registry.sharedResourceLifecycleState = .ready
            registry.committedMembership = [ProtectedSettingsStore.domainID: .active]
            try registryStore.saveRegistry(registry)
        }

        return ContactsDomainStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
    }
}
