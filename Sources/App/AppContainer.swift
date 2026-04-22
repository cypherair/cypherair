import Foundation

/// Centralized dependency container for the application.
final class AppContainer {
    let secureEnclave: any SecureEnclaveManageable
    let keychain: any KeychainManageable
    let authManager: AuthenticationManager
    let config: AppConfiguration
    let protectedDataStorageRoot: ProtectedDataStorageRoot
    let protectedDataRegistryStore: ProtectedDataRegistryStore
    let protectedDomainKeyManager: ProtectedDomainKeyManager
    let protectedDomainRecoveryCoordinator: ProtectedDomainRecoveryCoordinator
    let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    let appSessionOrchestrator: AppSessionOrchestrator
    let engine: PgpEngine
    let keyManagement: KeyManagementService
    let contactService: ContactService
    let encryptionService: EncryptionService
    let decryptionService: DecryptionService
    let passwordMessageService: PasswordMessageService
    let signingService: SigningService
    let certificateSignatureService: CertificateSignatureService
    let qrService: QRService
    let selfTestService: SelfTestService
    let contactsDirectory: URL?
    let defaultsSuiteName: String?

    init(
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        authManager: AuthenticationManager,
        config: AppConfiguration,
        protectedDataStorageRoot: ProtectedDataStorageRoot,
        protectedDataRegistryStore: ProtectedDataRegistryStore,
        protectedDomainKeyManager: ProtectedDomainKeyManager,
        protectedDomainRecoveryCoordinator: ProtectedDomainRecoveryCoordinator,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        appSessionOrchestrator: AppSessionOrchestrator,
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        encryptionService: EncryptionService,
        decryptionService: DecryptionService,
        passwordMessageService: PasswordMessageService,
        signingService: SigningService,
        certificateSignatureService: CertificateSignatureService,
        qrService: QRService,
        selfTestService: SelfTestService,
        contactsDirectory: URL? = nil,
        defaultsSuiteName: String? = nil
    ) {
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.authManager = authManager
        self.config = config
        self.protectedDataStorageRoot = protectedDataStorageRoot
        self.protectedDataRegistryStore = protectedDataRegistryStore
        self.protectedDomainKeyManager = protectedDomainKeyManager
        self.protectedDomainRecoveryCoordinator = protectedDomainRecoveryCoordinator
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
        self.appSessionOrchestrator = appSessionOrchestrator
        self.engine = engine
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.encryptionService = encryptionService
        self.decryptionService = decryptionService
        self.passwordMessageService = passwordMessageService
        self.signingService = signingService
        self.certificateSignatureService = certificateSignatureService
        self.qrService = qrService
        self.selfTestService = selfTestService
        self.contactsDirectory = contactsDirectory
        self.defaultsSuiteName = defaultsSuiteName
    }

    static func makeDefault() -> AppContainer {
        let secureEnclave = HardwareSecureEnclave()
        let keychain = SystemKeychain()
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
        let config = AppConfiguration()
        let protectedDataStorageRoot = ProtectedDataStorageRoot()
        let protectedDomainKeyManager = ProtectedDomainKeyManager(storageRoot: protectedDataStorageRoot)
        let protectedDataRegistryStore = ProtectedDataRegistryStore(
            storageRoot: protectedDataStorageRoot,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let protectedDomainRecoveryCoordinator = ProtectedDomainRecoveryCoordinator(
            registryStore: protectedDataRegistryStore
        )
        let protectedDataSessionCoordinator = ProtectedDataSessionCoordinator(
            rightStoreClient: ProtectedDataRightStoreClient(),
            domainKeyManager: protectedDomainKeyManager,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let appSessionOrchestrator = AppSessionOrchestrator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { config.gracePeriod },
            requireAuthOnLaunchProvider: { config.requireAuthOnLaunch },
            evaluateAppAuthentication: { reason in
                try await authManager.evaluate(mode: config.authMode, reason: reason)
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator
        )
        let engine = PgpEngine()

        let keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: .standard
        )
        let contactService = ContactService(engine: engine)
        let encryptionService = EncryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let decryptionService = DecryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let passwordMessageService = PasswordMessageService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let signingService = SigningService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let certificateSignatureService = CertificateSignatureService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let qrService = QRService(engine: engine)
        let selfTestService = SelfTestService(engine: engine)

        return AppContainer(
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedDataStorageRoot: protectedDataStorageRoot,
            protectedDataRegistryStore: protectedDataRegistryStore,
            protectedDomainKeyManager: protectedDomainKeyManager,
            protectedDomainRecoveryCoordinator: protectedDomainRecoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            encryptionService: encryptionService,
            decryptionService: decryptionService,
            passwordMessageService: passwordMessageService,
            signingService: signingService,
            certificateSignatureService: certificateSignatureService,
            qrService: qrService,
            selfTestService: selfTestService
        )
    }

    static func makeUITest(
        requiresManualAuthentication: Bool = false,
        preloadContact: Bool = false
    ) -> AppContainer {
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let suiteName = "com.cypherair.uitests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName) ?? .standard
        defaults.removePersistentDomain(forName: suiteName)
        defaults.set(!requiresManualAuthentication, forKey: "com.cypherair.preference.uiTestBypassAuthentication")

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults
        )
        let config = AppConfiguration(defaults: defaults)
        let engine = PgpEngine()
        let contactsDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirUITests-\(UUID().uuidString)", isDirectory: true)
        let protectedDataBaseDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirUITestProtectedData-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: contactsDirectory,
            withIntermediateDirectories: true
        )
        try? FileManager.default.createDirectory(
            at: protectedDataBaseDirectory,
            withIntermediateDirectories: true
        )
        let protectedDataStorageRoot = ProtectedDataStorageRoot(baseDirectory: protectedDataBaseDirectory)
        let protectedDomainKeyManager = ProtectedDomainKeyManager(storageRoot: protectedDataStorageRoot)
        let protectedDataRegistryStore = ProtectedDataRegistryStore(
            storageRoot: protectedDataStorageRoot,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let protectedDomainRecoveryCoordinator = ProtectedDomainRecoveryCoordinator(
            registryStore: protectedDataRegistryStore
        )
        let protectedDataSessionCoordinator = ProtectedDataSessionCoordinator(
            rightStoreClient: ProtectedDataRightStoreClient(),
            domainKeyManager: protectedDomainKeyManager,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let appSessionOrchestrator = AppSessionOrchestrator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { !requiresManualAuthentication },
            gracePeriodProvider: { config.gracePeriod },
            requireAuthOnLaunchProvider: { config.requireAuthOnLaunch },
            evaluateAppAuthentication: { reason in
                try await authManager.evaluate(mode: config.authMode, reason: reason)
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator
        )

        let keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults
        )
        let contactService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory
        )
        let encryptionService = EncryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let decryptionService = DecryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let passwordMessageService = PasswordMessageService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let signingService = SigningService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let certificateSignatureService = CertificateSignatureService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let qrService = QRService(engine: engine)
        let selfTestService = SelfTestService(engine: engine)

        if preloadContact {
            try? preloadUITestContact(engine: engine, contactService: contactService)
        }

        return AppContainer(
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedDataStorageRoot: protectedDataStorageRoot,
            protectedDataRegistryStore: protectedDataRegistryStore,
            protectedDomainKeyManager: protectedDomainKeyManager,
            protectedDomainRecoveryCoordinator: protectedDomainRecoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            encryptionService: encryptionService,
            decryptionService: decryptionService,
            passwordMessageService: passwordMessageService,
            signingService: signingService,
            certificateSignatureService: certificateSignatureService,
            qrService: qrService,
            selfTestService: selfTestService,
            contactsDirectory: contactsDirectory,
            defaultsSuiteName: suiteName
        )
    }

    private static func preloadUITestContact(
        engine: PgpEngine,
        contactService: ContactService
    ) throws {
        let generated = try engine.generateKey(
            name: "UITest Contact",
            email: "uitest-contact@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
    }
}
