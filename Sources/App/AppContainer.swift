import Foundation

/// Centralized dependency container for the application.
final class AppContainer {
    let secureEnclave: HardwareSecureEnclave
    let keychain: SystemKeychain
    let authManager: AuthenticationManager
    let config: AppConfiguration
    let engine: PgpEngine
    let keyManagement: KeyManagementService
    let contactService: ContactService
    let encryptionService: EncryptionService
    let decryptionService: DecryptionService
    let signingService: SigningService
    let qrService: QRService
    let selfTestService: SelfTestService

    init(
        secureEnclave: HardwareSecureEnclave,
        keychain: SystemKeychain,
        authManager: AuthenticationManager,
        config: AppConfiguration,
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        encryptionService: EncryptionService,
        decryptionService: DecryptionService,
        signingService: SigningService,
        qrService: QRService,
        selfTestService: SelfTestService
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
        self.signingService = signingService
        self.qrService = qrService
        self.selfTestService = selfTestService
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
            authenticator: authManager
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
            signingService: signingService,
            qrService: qrService,
            selfTestService: selfTestService
        )
    }
}
