import Foundation

/// Centralized dependency container for the application.
final class AppContainer {
    let secureEnclave: any SecureEnclaveManageable
    let keychain: any KeychainManageable
    let authManager: AuthenticationManager
    let config: AppConfiguration
    let engine: PgpEngine
    let keyManagement: KeyManagementService
    let contactService: ContactService
    let encryptionService: EncryptionService
    let decryptionService: DecryptionService
    let passwordMessageService: PasswordMessageService
    let signingService: SigningService
    let qrService: QRService
    let selfTestService: SelfTestService
    let contactsDirectory: URL?
    let defaultsSuiteName: String?

    init(
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        authManager: AuthenticationManager,
        config: AppConfiguration,
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        encryptionService: EncryptionService,
        decryptionService: DecryptionService,
        passwordMessageService: PasswordMessageService,
        signingService: SigningService,
        qrService: QRService,
        selfTestService: SelfTestService,
        contactsDirectory: URL? = nil,
        defaultsSuiteName: String? = nil
    ) {
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.authManager = authManager
        self.config = config
        self.engine = engine
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.encryptionService = encryptionService
        self.decryptionService = decryptionService
        self.passwordMessageService = passwordMessageService
        self.signingService = signingService
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
        let qrService = QRService(engine: engine)
        let selfTestService = SelfTestService(engine: engine)

        return AppContainer(
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            encryptionService: encryptionService,
            decryptionService: decryptionService,
            passwordMessageService: passwordMessageService,
            signingService: signingService,
            qrService: qrService,
            selfTestService: selfTestService
        )
    }

    static func makeUITest(
        requiresManualAuthentication: Bool = false
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
        try? FileManager.default.createDirectory(
            at: contactsDirectory,
            withIntermediateDirectories: true
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
        let qrService = QRService(engine: engine)
        let selfTestService = SelfTestService(engine: engine)

        return AppContainer(
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            encryptionService: encryptionService,
            decryptionService: decryptionService,
            passwordMessageService: passwordMessageService,
            signingService: signingService,
            qrService: qrService,
            selfTestService: selfTestService,
            contactsDirectory: contactsDirectory,
            defaultsSuiteName: suiteName
        )
    }
}
