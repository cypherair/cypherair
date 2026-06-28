import Foundation

/// Centralized dependency container for the application.
final class AppContainer: @unchecked Sendable {
    let authLifecycleTraceStore: AuthLifecycleTraceStore?
    let appLockController: AppLockController
    let authPromptCoordinator: AuthenticationPromptCoordinator
    let secureEnclave: any SecureEnclaveManageable
    let keychain: any KeychainManageable
    let authManager: AuthenticationManager
    let config: AppConfiguration
    let protectedOrdinarySettingsCoordinator: ProtectedOrdinarySettingsCoordinator
    let protectedDataStorageRoot: ProtectedDataStorageRoot
    let protectedDataRegistryStore: ProtectedDataRegistryStore
    let protectedDomainKeyManager: ProtectedDomainKeyManager
    let protectedDomainRecoveryCoordinator: ProtectedDomainRecoveryCoordinator
    let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    let privateKeyControlStore: PrivateKeyControlStore
    let keyMetadataDomainStore: KeyMetadataDomainStore?
    let contactsDomainStore: ContactsDomainStore?
    let protectedSettingsStore: ProtectedSettingsStore
    let protectedDataFrameworkSentinelStore: ProtectedDataFrameworkSentinelStore
    let protectedDataPostUnlockCoordinator: ProtectedDataPostUnlockCoordinator
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
    let temporaryArtifactStore: AppTemporaryArtifactStore
    let localDataResetService: LocalDataResetService
    let defaultsSuiteName: String?
    private var uiTestContactsBootstrap: UITestContactsBootstrap?

    init(
        authLifecycleTraceStore: AuthLifecycleTraceStore?,
        appLockController: AppLockController,
        authPromptCoordinator: AuthenticationPromptCoordinator,
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        authManager: AuthenticationManager,
        config: AppConfiguration,
        protectedOrdinarySettingsCoordinator: ProtectedOrdinarySettingsCoordinator,
        protectedDataStorageRoot: ProtectedDataStorageRoot,
        protectedDataRegistryStore: ProtectedDataRegistryStore,
        protectedDomainKeyManager: ProtectedDomainKeyManager,
        protectedDomainRecoveryCoordinator: ProtectedDomainRecoveryCoordinator,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        privateKeyControlStore: PrivateKeyControlStore,
        keyMetadataDomainStore: KeyMetadataDomainStore? = nil,
        contactsDomainStore: ContactsDomainStore? = nil,
        protectedSettingsStore: ProtectedSettingsStore,
        protectedDataFrameworkSentinelStore: ProtectedDataFrameworkSentinelStore,
        protectedDataPostUnlockCoordinator: ProtectedDataPostUnlockCoordinator = .noOp,
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
        temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore(),
        localDataResetService: LocalDataResetService,
        defaultsSuiteName: String? = nil
    ) {
        self.authLifecycleTraceStore = authLifecycleTraceStore
        self.appLockController = appLockController
        self.authPromptCoordinator = authPromptCoordinator
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.authManager = authManager
        self.config = config
        self.protectedOrdinarySettingsCoordinator = protectedOrdinarySettingsCoordinator
        self.protectedDataStorageRoot = protectedDataStorageRoot
        self.protectedDataRegistryStore = protectedDataRegistryStore
        self.protectedDomainKeyManager = protectedDomainKeyManager
        self.protectedDomainRecoveryCoordinator = protectedDomainRecoveryCoordinator
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
        self.privateKeyControlStore = privateKeyControlStore
        self.keyMetadataDomainStore = keyMetadataDomainStore
        self.contactsDomainStore = contactsDomainStore
        self.protectedSettingsStore = protectedSettingsStore
        self.protectedDataFrameworkSentinelStore = protectedDataFrameworkSentinelStore
        self.protectedDataPostUnlockCoordinator = protectedDataPostUnlockCoordinator
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
        self.temporaryArtifactStore = temporaryArtifactStore
        self.localDataResetService = localDataResetService
        self.defaultsSuiteName = defaultsSuiteName
        uiTestContactsBootstrap = nil
    }

    private struct UITestContactsBootstrap {
        let wrappingRootKey: Data
        let preloadContact: Bool
        var didPreloadContact: Bool = false
        var isPreparing: Bool = false
        var cachedAvailability: ContactsAvailability?
        var waiters: [CheckedContinuation<ContactsAvailability, Never>] = []
    }

    private struct AuthenticationPromptStack {
        let authLifecycleTraceStore: AuthLifecycleTraceStore
        let authPromptCoordinator: AuthenticationPromptCoordinator
    }

    private struct PgpServiceGraph {
        let temporaryArtifactStore: AppTemporaryArtifactStore
        let encryptionService: EncryptionService
        let decryptionService: DecryptionService
        let passwordMessageService: PasswordMessageService
        let signingService: SigningService
        let certificateSignatureService: CertificateSignatureService
        let qrService: QRService
        let selfTestService: SelfTestService
    }

    private static func makeAuthenticationPromptStack(authTraceEnabled: Bool) -> AuthenticationPromptStack {
        let authLifecycleTraceStore = AuthLifecycleTraceStore(isEnabled: authTraceEnabled)
        let authPromptCoordinator = AuthenticationPromptCoordinator(
            traceStore: authLifecycleTraceStore
        )
        return AuthenticationPromptStack(
            authLifecycleTraceStore: authLifecycleTraceStore,
            authPromptCoordinator: authPromptCoordinator
        )
    }

    #if os(macOS)
    /// Wire the operation-prompt lifecycle hooks to the lock controller's
    /// main-actor mirror (the `.authenticating` rule). The controller also gets
    /// the coordinator's live depth as an injected closure: live depth catches a
    /// resign that beats the began-hop, while a false live depth prevents a stale
    /// ended-hop mirror from swallowing a real away after the prompt has ended.
    /// The coordinator's hooks are write-once; every `AppLockController`
    /// construction site must call this on macOS.
    @MainActor
    private static func wireOperationPromptLifecycle(
        from coordinator: AuthenticationPromptCoordinator,
        to appLockController: AppLockController
    ) {
        coordinator.onOperationPromptSessionBegan = { [weak appLockController] in
            Task { @MainActor in
                appLockController?.handleOperationPromptSessionBegan()
            }
        }
        coordinator.onOperationPromptsEnded = { [weak appLockController] in
            Task { @MainActor in
                appLockController?.handleOperationPromptsEnded()
            }
        }
    }
    #endif

    /// The production modify-expiry pre-authenticator: one system access-control
    /// authentication whose context is threaded into the short SE unwrap/rewrap
    /// windows. Bypass containers (UI test, tutorial) stay nil.
    static var productionExpiryAuthenticator: KeyMutationService.ExpiryAuthenticator? {
        KeyMutationService.systemAccessControlExpiryAuthenticator
    }

    /// The custody pre-authenticator: one biometric system-sheet evaluation per
    /// Secure Enclave custody private operation, threaded into the handle-loading
    /// keychain query via kSecUseAuthenticationContext.
    /// Bypass containers (UI test, tutorial) stay nil.
    private static var productionSecureEnclaveCustodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator? {
        PrivateKeyOperationRouter.systemBiometricCustodyOperationAuthenticator
    }

    /// Builds the App Access Protection policy-switch workflow over the
    /// container's live dependencies. The workflow enrolls only its authentication
    /// and immediate root-secret re-protection window in an operation-prompt
    /// session.
    @MainActor
    func makeAppAccessPolicySwitchWorkflow() -> AppAccessPolicySwitchWorkflow {
        let config = config
        let protectedDataSessionCoordinator = protectedDataSessionCoordinator
        let authManager = authManager
        let appSessionOrchestrator = appSessionOrchestrator
        return AppAccessPolicySwitchWorkflow(
            currentPolicy: {
                config.appSessionAuthenticationPolicy
            },
            hasPersistedRootSecret: {
                protectedDataSessionCoordinator.hasPersistedRootSecret()
            },
            canEvaluate: { policy in
                authManager.canEvaluate(appSessionPolicy: policy)
            },
            evaluateAppSession: { policy, reason, source in
                try await authManager.evaluateAppSession(
                    policy: policy,
                    reason: reason,
                    source: source
                )
            },
            reprotectPersistedRootSecret: { from, to, context in
                try protectedDataSessionCoordinator.reprotectPersistedRootSecretIfPresent(
                    from: from,
                    to: to,
                    authenticationContext: context
                )
            },
            discardHandoffContextForPolicyChange: {
                appSessionOrchestrator.discardProtectedDataAuthorizationHandoffContextForPolicyChange()
            },
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
    }

    private static func makeProtectedDataSessionCoordinator(
        rootSecretStore: any ProtectedDataRootSecretStoreProtocol,
        domainKeyManager: ProtectedDomainKeyManager,
        config: AppConfiguration,
        authPromptCoordinator: AuthenticationPromptCoordinator,
        traceStore: AuthLifecycleTraceStore?
    ) -> ProtectedDataSessionCoordinator {
        ProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            appSessionPolicyProvider: { config.appSessionAuthenticationPolicy },
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: traceStore
        )
    }

    private static func makeFirstDomainSharedRightCleaner(
        storageRoot: ProtectedDataStorageRoot,
        domainKeyManager: ProtectedDomainKeyManager,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        traceStore: AuthLifecycleTraceStore?
    ) -> ProtectedDataFirstDomainSharedRightCleaner {
        ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { identifier in
                protectedDataSessionCoordinator.hasPersistedRootSecret(identifier: identifier)
            },
            hasExternalProtectedDataArtifacts: {
                try domainKeyManager.hasAnyPersistedDomainKeyRecord()
            },
            removePersistedSharedRight: { identifier in
                try await protectedDataSessionCoordinator.removePersistedSharedRight(identifier: identifier)
            },
            traceStore: traceStore
        )
    }

    private static func makePrivateKeyControlPostUnlockOpener(
        privateKeyControlStore: PrivateKeyControlStore
    ) -> ProtectedDataPostUnlockDomainOpener {
        ProtectedDataPostUnlockDomainOpener(
            domainID: PrivateKeyControlStore.domainID,
            ensureCommittedIfNeeded: { wrappingRootKey in
                try await privateKeyControlStore.ensureCommittedIfNeeded(
                    wrappingRootKey: wrappingRootKey
                )
            },
            open: { wrappingRootKey in
                _ = try await privateKeyControlStore.openDomainIfNeeded(
                    wrappingRootKey: wrappingRootKey
                )
            }
        )
    }

    private static func makeProtectedSettingsPostUnlockOpener(
        protectedSettingsStore: ProtectedSettingsStore,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        firstDomainSharedRightCleaner: ProtectedDataFirstDomainSharedRightCleaner
    ) -> ProtectedDataPostUnlockDomainOpener {
        ProtectedDataPostUnlockDomainOpener(
            domainID: ProtectedSettingsStore.domainID,
            ensureCommittedIfNeeded: { wrappingRootKey in
                try await protectedSettingsStore.ensureCommittedIfNeeded(
                    persistSharedRight: { secret in
                        try await protectedDataSessionCoordinator.persistSharedRight(secretData: secret)
                    },
                    firstDomainSharedRightCleaner: firstDomainSharedRightCleaner,
                    currentWrappingRootKey: {
                        wrappingRootKey
                    }
                )
            },
            open: { wrappingRootKey in
                _ = try await protectedSettingsStore.openDomainIfNeeded(
                    wrappingRootKey: wrappingRootKey
                )
            }
        )
    }

    private static func makeProtectedDataFrameworkSentinelPostUnlockOpener(
        protectedDataFrameworkSentinelStore: ProtectedDataFrameworkSentinelStore
    ) -> ProtectedDataPostUnlockDomainOpener {
        ProtectedDataPostUnlockDomainOpener(
            domainID: ProtectedDataFrameworkSentinelStore.domainID,
            ensureCommittedIfNeeded: { wrappingRootKey in
                try await protectedDataFrameworkSentinelStore.ensureCommittedIfNeeded(
                    wrappingRootKey: wrappingRootKey
                )
            },
            open: { wrappingRootKey in
                _ = try await protectedDataFrameworkSentinelStore.openDomainIfNeeded(
                    wrappingRootKey: wrappingRootKey
                )
            }
        )
    }

    private static func makePgpServiceGraph(
        engine: PgpEngine,
        keyAdapter: PGPKeyOperationAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        contactImportAdapter: PGPContactImportAdapter,
        selfTestAdapter: PGPSelfTestOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore,
        secureEnclaveDigestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> PgpServiceGraph {
        let temporaryArtifactStore = AppTemporaryArtifactStore()
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        keyManagement.configurePrivateKeyExpiryMutationService(
            makePrivateKeyExpiryMutationService(
                engine: engine,
                keyAdapter: keyAdapter,
                keyManagement: keyManagement,
                secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
                secureEnclaveDigestSigner: secureEnclaveDigestSigner
            )
        )
        keyManagement.configurePrivateKeySelectiveRevocationService(
            makePrivateKeySelectiveRevocationService(
                engine: engine,
                certificateAdapter: certificateAdapter,
                keyManagement: keyManagement,
                secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
                secureEnclaveDigestSigner: secureEnclaveDigestSigner
            )
        )
        let textEncryptor = makePrivateKeyTextEncryptionService(
            engine: engine,
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
            secureEnclaveDigestSigner: secureEnclaveDigestSigner
        )
        let fileEncryptor = makePrivateKeyStreamingFileEncryptionService(
            engine: engine,
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
            secureEnclaveDigestSigner: secureEnclaveDigestSigner
        )
        let cleartextSigner = makePrivateKeyCleartextSigningService(
            engine: engine,
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
            secureEnclaveDigestSigner: secureEnclaveDigestSigner
        )
        let detachedFileSigner = makePrivateKeyDetachedFileSigningService(
            engine: engine,
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
            secureEnclaveDigestSigner: secureEnclaveDigestSigner
        )
        let passwordEncryptor = makePrivateKeyPasswordMessageEncryptionService(
            engine: engine,
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
            secureEnclaveDigestSigner: secureEnclaveDigestSigner
        )
        let contactCertificationSigner = makePrivateKeyContactCertificationService(
            engine: engine,
            certificateAdapter: certificateAdapter,
            keyManagement: keyManagement,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
            secureEnclaveDigestSigner: secureEnclaveDigestSigner
        )
        let messageDecryptor = makePrivateKeyMessageDecryptionService(
            engine: engine,
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore
        )
        let fileDecryptor = makePrivateKeyStreamingFileDecryptionService(
            engine: engine,
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore
        )
        return PgpServiceGraph(
            temporaryArtifactStore: temporaryArtifactStore,
            encryptionService: EncryptionService(
                keyManagement: keyManagement,
                contactService: contactService,
                textEncryptor: textEncryptor,
                fileEncryptor: fileEncryptor,
                temporaryArtifactStore: temporaryArtifactStore
            ),
            decryptionService: DecryptionService(
                messageAdapter: messageAdapter,
                keyManagement: keyManagement,
                contactService: contactService,
                messageDecryptor: messageDecryptor,
                fileDecryptor: fileDecryptor,
                temporaryArtifactStore: temporaryArtifactStore
            ),
            passwordMessageService: PasswordMessageService(
                messageAdapter: messageAdapter,
                keyManagement: keyManagement,
                contactService: contactService,
                passwordEncryptor: passwordEncryptor
            ),
            signingService: SigningService(
                messageAdapter: messageAdapter,
                keyManagement: keyManagement,
                contactService: contactService,
                cleartextSigner: cleartextSigner,
                detachedFileSigner: detachedFileSigner
            ),
            certificateSignatureService: CertificateSignatureService(
                certificateAdapter: certificateAdapter,
                keyManagement: keyManagement,
                contactService: contactService,
                certificationSigner: contactCertificationSigner
            ),
            qrService: QRService(contactImportAdapter: contactImportAdapter),
            selfTestService: SelfTestService(
                selfTestAdapter: selfTestAdapter,
                messageAdapter: messageAdapter
            )
        )
    }

    private static func makePrivateKeyTextEncryptionService(
        engine: PgpEngine,
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore,
        secureEnclaveDigestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> PrivateKeyTextEncryptionService {
        PrivateKeyTextEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner
        )
    }

    private static func makePrivateKeyStreamingFileEncryptionService(
        engine: PgpEngine,
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore,
        secureEnclaveDigestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> PrivateKeyStreamingFileEncryptionService {
        PrivateKeyStreamingFileEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner
        )
    }

    private static func makePrivateKeyCleartextSigningService(
        engine: PgpEngine,
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore,
        secureEnclaveDigestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> PrivateKeyCleartextSigningService {
        PrivateKeyCleartextSigningService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner
        )
    }

    private static func makePrivateKeyMessageDecryptionService(
        engine: PgpEngine,
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore
    ) -> PrivateKeyMessageDecryptionService {
        PrivateKeyMessageDecryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            keyAgreement: SystemSecureEnclaveCustodyKeyAgreement()
        )
    }

    private static func makePrivateKeyStreamingFileDecryptionService(
        engine: PgpEngine,
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore
    ) -> PrivateKeyStreamingFileDecryptionService {
        PrivateKeyStreamingFileDecryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            keyAgreement: SystemSecureEnclaveCustodyKeyAgreement()
        )
    }

    private static func makePrivateKeyDetachedFileSigningService(
        engine: PgpEngine,
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore,
        secureEnclaveDigestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> PrivateKeyDetachedFileSigningService {
        PrivateKeyDetachedFileSigningService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner
        )
    }

    private static func makePrivateKeyPasswordMessageEncryptionService(
        engine: PgpEngine,
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore,
        secureEnclaveDigestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> PrivateKeyPasswordMessageEncryptionService {
        PrivateKeyPasswordMessageEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner
        )
    }

    private static func makePrivateKeyExpiryMutationService(
        engine: PgpEngine,
        keyAdapter: PGPKeyOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore,
        secureEnclaveDigestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> PrivateKeyExpiryMutationService {
        PrivateKeyExpiryMutationService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            keyAdapter: keyAdapter,
            digestSigner: secureEnclaveDigestSigner
        )
    }

    private static func makePrivateKeySelectiveRevocationService(
        engine: PgpEngine,
        certificateAdapter: PGPCertificateOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore,
        secureEnclaveDigestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> PrivateKeySelectiveRevocationService {
        PrivateKeySelectiveRevocationService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            certificateAdapter: certificateAdapter,
            digestSigner: secureEnclaveDigestSigner
        )
    }

    private static func makePrivateKeyContactCertificationService(
        engine: PgpEngine,
        certificateAdapter: PGPCertificateOperationAdapter,
        keyManagement: KeyManagementService,
        secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore,
        secureEnclaveDigestSigner: any SecureEnclaveCustodyDigestSigning
    ) -> PrivateKeyContactCertificationService {
        PrivateKeyContactCertificationService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            certificateAdapter: certificateAdapter,
            digestSigner: secureEnclaveDigestSigner
        )
    }

    // `@MainActor`: this composition root constructs `AppSessionOrchestrator`,
    // which is main-actor-isolated. Called from `CypherAirApp.init` (App is
    // main-actor) and from `@MainActor` test cases.
    @MainActor
    static func makeDefault(
        authTraceEnabled: Bool = false
    ) -> AppContainer {
        let authentication = makeAuthenticationPromptStack(authTraceEnabled: authTraceEnabled)
        let authLifecycleTraceStore = authentication.authLifecycleTraceStore
        let authPromptCoordinator = authentication.authPromptCoordinator
        let secureEnclave = HardwareSecureEnclave(traceStore: authLifecycleTraceStore)
        let keychain = SystemKeychain(traceStore: authLifecycleTraceStore)
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let defaults = UserDefaults.standard
        let config = AppConfiguration(defaults: defaults)
        let protectedDataStorageRoot = ProtectedDataStorageRoot(traceStore: authLifecycleTraceStore)
        let protectedDomainKeyManager = ProtectedDomainKeyManager(
            storageRoot: protectedDataStorageRoot,
            keychain: keychain
        )
        let protectedDataRegistryStore = ProtectedDataRegistryStore(
            storageRoot: protectedDataStorageRoot,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            hasExternalProtectedDataArtifacts: {
                try protectedDomainKeyManager.hasAnyPersistedDomainKeyRecord()
            },
            traceStore: authLifecycleTraceStore
        )
        let protectedDomainRecoveryCoordinator = ProtectedDomainRecoveryCoordinator(
            registryStore: protectedDataRegistryStore
        )
        let protectedDataSessionCoordinator = makeProtectedDataSessionCoordinator(
            rootSecretStore: KeychainProtectedDataRootSecretStore(traceStore: authLifecycleTraceStore),
            domainKeyManager: protectedDomainKeyManager,
            config: config,
            authPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let firstDomainSharedRightCleaner = makeFirstDomainSharedRightCleaner(
            storageRoot: protectedDataStorageRoot,
            domainKeyManager: protectedDomainKeyManager,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let privateKeyControlStore = PrivateKeyControlStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let protectedSettingsStore = ProtectedSettingsStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let protectedOrdinarySettingsCoordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: protectedSettingsStore
            )
        )
        let protectedDataFrameworkSentinelStore = ProtectedDataFrameworkSentinelStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let keyMetadataDomainStore = KeyMetadataDomainStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let engine = PgpEngine()
        let keyAdapter = PGPKeyOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let secureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: SystemSecureEnclaveCustodyKeyStore(traceStore: authLifecycleTraceStore)
        )
        let secureEnclaveCustodyPublicBindingInspector = PGPSecureEnclaveCustodyPublicBindingInspector(
            engine: engine
        )
        let secureEnclaveCustodyDigestSigner = SystemSecureEnclaveCustodyDigestSigner()
        let secureEnclaveCustodyRecoveryService = SecureEnclaveCustodyGenerationRecoveryService(
            publicBindingInspector: secureEnclaveCustodyPublicBindingInspector,
            handleStore: secureEnclaveCustodyHandleStore
        )
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let selfTestAdapter = PGPSelfTestOperationAdapter(engine: engine)
        let contactsDomainStore = ContactsDomainStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        authManager.configurePrivateKeyControlStore(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(privateKeyControlStore)
        let keyManagement = KeyManagementService(
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: .standard,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            // Short-window modify-expiry pre-auth: wired in production only.
            // The UI-test container stays nil (mock Secure Enclave under the
            // authentication bypass must not drive real LocalAuthentication).
            expiryAuthenticator: Self.productionExpiryAuthenticator,
            secureEnclaveCustodyOperationAuthenticator: Self.productionSecureEnclaveCustodyOperationAuthenticator,
            secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext(
                publicBindingInspector: secureEnclaveCustodyPublicBindingInspector,
                handleStore: secureEnclaveCustodyHandleStore
            ),
            authLifecycleTraceStore: authLifecycleTraceStore,
            metadataPersistence: keyMetadataDomainStore,
            // Device-bound Secure Enclave custody generation (issue #501 P7D
            // exposure). Hardware-guarded at the composition root; on hardware
            // without a Secure Enclave the factory stays nil and the UI hides
            // the device-bound families. The prompt coordinator enrolls only
            // the custody authorization and immediate handle-load window.
            secureEnclaveCustodyGenerationServiceFactory: HardwareSecureEnclave.isAvailable
                ? { catalogStore, invalidationGate, commitCoordinator in
                    SecureEnclaveCustodyGenerationService(
                        certificateBuilder: PGPSecureEnclaveCustodyGenerationAdapter(engine: engine),
                        handleStore: secureEnclaveCustodyHandleStore,
                        digestSigner: secureEnclaveCustodyDigestSigner,
                        catalogStore: catalogStore,
                        resolver: PGPKeyCapabilityResolver(),
                        invalidationGate: invalidationGate,
                        commitCoordinator: commitCoordinator,
                        authenticationPromptCoordinator: authPromptCoordinator,
                        custodyOperationAuthenticator: Self.productionSecureEnclaveCustodyOperationAuthenticator
                    )
                }
                : nil,
            secureEnclaveCustodyRecoveryService: secureEnclaveCustodyRecoveryService
        )
        protectedDataSessionCoordinator.registerRelockParticipant(keyManagement)
        protectedDataSessionCoordinator.registerRelockParticipant(keyMetadataDomainStore)
        protectedDataSessionCoordinator.registerRelockParticipant(contactsDomainStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedSettingsStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedDataFrameworkSentinelStore)
        let contactService = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            contactsDomainStore: contactsDomainStore
        )
        protectedDataSessionCoordinator.registerRelockParticipant(contactService)
        let protectedDataPostUnlockCoordinator = ProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            domainOpeners: [
                makePrivateKeyControlPostUnlockOpener(
                    privateKeyControlStore: privateKeyControlStore
                ),
                ProtectedDataPostUnlockDomainOpener(
                    domainID: KeyMetadataDomainStore.domainID,
                    ensureCommittedIfNeeded: { wrappingRootKey in
                        keyManagement.beginKeyMetadataLoad()
                        do {
                            try await keyMetadataDomainStore.ensureCommittedIfNeeded(
                                wrappingRootKey: wrappingRootKey
                            )
                        } catch {
                            keyManagement.markKeyMetadataRecoveryNeeded()
                            throw error
                        }
                    },
                    open: { wrappingRootKey in
                        keyManagement.beginKeyMetadataLoad()
                        do {
                            _ = try await keyMetadataDomainStore.openDomainIfNeeded(
                                wrappingRootKey: wrappingRootKey
                            )
                            try keyManagement.completeKeyMetadataLoad(
                                source: "postUnlock"
                            )
                        } catch {
                            keyManagement.markKeyMetadataRecoveryNeeded()
                            throw error
                        }
                    }
                ),
                makeProtectedSettingsPostUnlockOpener(
                    protectedSettingsStore: protectedSettingsStore,
                    protectedDataSessionCoordinator: protectedDataSessionCoordinator,
                    firstDomainSharedRightCleaner: firstDomainSharedRightCleaner
                ),
                makeProtectedDataFrameworkSentinelPostUnlockOpener(
                    protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore
                )
            ],
            traceStore: authLifecycleTraceStore
        )
        let appSessionOrchestrator = AppSessionOrchestrator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let appLockController = AppLockController(
            gracePeriodProvider: {
                protectedOrdinarySettingsCoordinator.gracePeriodForSession
            },
            lastAuthenticationDateProvider: { appSessionOrchestrator.lastAuthenticationDate },
            evaluateAppSessionAuthentication: { reason, source in
                try await authManager.evaluateAppSession(
                    policy: config.appSessionAuthenticationPolicy,
                    reason: reason,
                    source: source
                )
            },
            recordSuccessfulAuthentication: { context in
                appSessionOrchestrator.recordSuccessfulAppSessionAuthentication(context: context)
            },
            discardHandoffContext: { reason in
                appSessionOrchestrator.discardAuthorizationHandoffContext(reason: reason)
            },
            relockProtectedData: {
                await protectedDataSessionCoordinator.relockCurrentSession()
            },
            postAuthenticationHandler: { authenticationContext, source in
                do {
                    _ = try await privateKeyControlStore.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
                        authenticationContext: authenticationContext,
                        persistSharedRight: { secret in
                            try await protectedDataSessionCoordinator.persistSharedRight(secretData: secret)
                        },
                        firstDomainSharedRightCleaner: firstDomainSharedRightCleaner
                    )
                } catch {
                    config.privateKeyControlState = privateKeyControlStore.privateKeyControlState
                }
                let postUnlockOutcome = await protectedDataPostUnlockCoordinator.openRegisteredDomains(
                    authenticationContext: authenticationContext,
                    localizedReason: String(
                        localized: "protectedData.postUnlock.reason",
                        defaultValue: "Authenticate to unlock protected app data."
                    ),
                    source: source
                )
                _ = await contactService.openContactsAfterPostUnlock(
                    gateDecision: ContactsPostAuthGateDecision(
                        postUnlockOutcome: postUnlockOutcome,
                        frameworkState: protectedDataSessionCoordinator.frameworkState
                    ),
                    wrappingRootKey: {
                        try protectedDataSessionCoordinator.wrappingRootKeyData()
                    }
                )
                protectedOrdinarySettingsCoordinator.loadAfterAppAuthentication(
                    availability: Self.protectedOrdinarySettingsAvailability(
                        postUnlockOutcome: postUnlockOutcome,
                        protectedSettingsStore: protectedSettingsStore
                    )
                )
                config.privateKeyControlState = privateKeyControlStore.privateKeyControlState
                Self.recoverPrivateKeyControlJournalsAfterPostUnlock(
                    authManager: authManager,
                    keyManagement: keyManagement,
                    config: config,
                    privateKeyControlStore: privateKeyControlStore
                )
                appSessionOrchestrator.recordPostAuthenticationCompletion()
            },
            contentClearHandler: {
                protectedOrdinarySettingsCoordinator.relock()
                appSessionOrchestrator.requestContentClear()
            },
            shouldBypassAuthentication: { false },
            operationPromptInProgressProvider: {
                authPromptCoordinator.isOperationPromptInProgress
            },
            traceStore: authLifecycleTraceStore
        )
        #if os(macOS)
        wireOperationPromptLifecycle(from: authPromptCoordinator, to: appLockController)
        #endif
        let pgpServices = makePgpServiceGraph(
            engine: engine,
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            contactImportAdapter: contactImportAdapter,
            selfTestAdapter: selfTestAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
            secureEnclaveDigestSigner: secureEnclaveCustodyDigestSigner
        )
        let localDataResetService = LocalDataResetService(
            keychain: keychain,
            protectedDataStorageRoot: protectedDataStorageRoot,
            defaults: defaults,
            defaultsDomainName: Bundle.main.bundleIdentifier,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            authManager: authManager,
            keyManagement: keyManagement,
            contactService: contactService,
            selfTestService: pgpServices.selfTestService,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            appLockController: appLockController,
            temporaryArtifactStore: pgpServices.temporaryArtifactStore,
            protectedDataRootSecretExists: {
                protectedDataSessionCoordinator.hasPersistedRootSecret()
            },
            secureEnclaveCustodyHandleStore: secureEnclaveCustodyHandleStore,
            traceStore: authLifecycleTraceStore
        )

        return AppContainer(
            authLifecycleTraceStore: authLifecycleTraceStore,
            appLockController: appLockController,
            authPromptCoordinator: authPromptCoordinator,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            protectedDataStorageRoot: protectedDataStorageRoot,
            protectedDataRegistryStore: protectedDataRegistryStore,
            protectedDomainKeyManager: protectedDomainKeyManager,
            protectedDomainRecoveryCoordinator: protectedDomainRecoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            keyMetadataDomainStore: keyMetadataDomainStore,
            contactsDomainStore: contactsDomainStore,
            protectedSettingsStore: protectedSettingsStore,
            protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore,
            protectedDataPostUnlockCoordinator: protectedDataPostUnlockCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            encryptionService: pgpServices.encryptionService,
            decryptionService: pgpServices.decryptionService,
            passwordMessageService: pgpServices.passwordMessageService,
            signingService: pgpServices.signingService,
            certificateSignatureService: pgpServices.certificateSignatureService,
            qrService: pgpServices.qrService,
            selfTestService: pgpServices.selfTestService,
            temporaryArtifactStore: pgpServices.temporaryArtifactStore,
            localDataResetService: localDataResetService
        )
    }

    #if DEBUG
    @MainActor
    static func makeUITest(
        requiresManualAuthentication: Bool = false,
        preloadContact: Bool = false,
        authTraceEnabled: Bool = false
    ) -> AppContainer {
        let authentication = makeAuthenticationPromptStack(authTraceEnabled: authTraceEnabled)
        let authLifecycleTraceStore = authentication.authLifecycleTraceStore
        let authPromptCoordinator = authentication.authPromptCoordinator
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let suiteName = "com.cypherair.uitests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName) ?? .standard
        defaults.removePersistentDomain(forName: suiteName)
        defaults.set(!requiresManualAuthentication, forKey: "com.cypherair.preference.uiTestBypassAuthentication")

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults,
            allowsUITestAuthenticationBypass: true,
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let config = AppConfiguration(defaults: defaults)
        let engine = PgpEngine()
        let keyAdapter = PGPKeyOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let selfTestAdapter = PGPSelfTestOperationAdapter(engine: engine)
        let documentDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirUITestDocuments-\(UUID().uuidString)", isDirectory: true)
        let applicationSupportDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let protectedDataBaseDirectory = applicationSupportDirectory
            .appendingPathComponent("CypherAirUITestProtectedData-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: documentDirectory,
            withIntermediateDirectories: true
        )
        try? FileManager.default.createDirectory(
            at: protectedDataBaseDirectory,
            withIntermediateDirectories: true
        )
        let protectedDataStorageRoot = ProtectedDataStorageRoot(
            baseDirectory: protectedDataBaseDirectory,
            validationMode: .enforceAppSupportContainment,
            traceStore: authLifecycleTraceStore
        )
        let protectedDomainKeyManager = ProtectedDomainKeyManager(
            storageRoot: protectedDataStorageRoot,
            keychain: keychain
        )
        let protectedDataRegistryStore = ProtectedDataRegistryStore(
            storageRoot: protectedDataStorageRoot,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            hasExternalProtectedDataArtifacts: {
                try protectedDomainKeyManager.hasAnyPersistedDomainKeyRecord()
            },
            traceStore: authLifecycleTraceStore
        )
        let protectedDomainRecoveryCoordinator = ProtectedDomainRecoveryCoordinator(
            registryStore: protectedDataRegistryStore
        )
        let protectedDataSessionCoordinator = makeProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRootSecretStore(),
            domainKeyManager: protectedDomainKeyManager,
            config: config,
            authPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let firstDomainSharedRightCleaner = makeFirstDomainSharedRightCleaner(
            storageRoot: protectedDataStorageRoot,
            domainKeyManager: protectedDomainKeyManager,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let privateKeyControlStore = PrivateKeyControlStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        privateKeyControlStore.seedUnlockedForTesting(.standard)
        config.privateKeyControlState = .unlocked(.standard)
        let protectedSettingsStore = ProtectedSettingsStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let protectedOrdinarySettingsCoordinator: ProtectedOrdinarySettingsCoordinator
        if requiresManualAuthentication {
            protectedOrdinarySettingsCoordinator = ProtectedOrdinarySettingsCoordinator(
                persistence: ProtectedSettingsOrdinarySettingsPersistence(
                    protectedSettingsStore: protectedSettingsStore
                )
            )
        } else {
            protectedOrdinarySettingsCoordinator = ProtectedOrdinarySettingsCoordinator(
                persistence: InMemoryOrdinarySettingsStore()
            )
            protectedOrdinarySettingsCoordinator.loadForAuthenticatedTestBypass()
        }
        let protectedDataFrameworkSentinelStore = ProtectedDataFrameworkSentinelStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let contactsWrappingRootKey = Data(repeating: 0xCA, count: 32)
        let contactsDomainStore: ContactsDomainStore
        do {
            contactsDomainStore = try makeSandboxContactsDomainStore(
                baseDirectory: protectedDataBaseDirectory.appendingPathComponent(
                    "contacts-sandbox",
                    isDirectory: true
                ),
                wrappingRootKey: contactsWrappingRootKey,
                keychain: keychain
            )
        } catch {
            fatalError("Failed to create UI-test Contacts protected domain: \(error)")
        }
        authManager.configurePrivateKeyControlStore(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedSettingsStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedDataFrameworkSentinelStore)
        let protectedDataPostUnlockCoordinator = ProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            domainOpeners: [
                makePrivateKeyControlPostUnlockOpener(
                    privateKeyControlStore: privateKeyControlStore
                ),
                makeProtectedSettingsPostUnlockOpener(
                    protectedSettingsStore: protectedSettingsStore,
                    protectedDataSessionCoordinator: protectedDataSessionCoordinator,
                    firstDomainSharedRightCleaner: firstDomainSharedRightCleaner
                ),
                makeProtectedDataFrameworkSentinelPostUnlockOpener(
                    protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore
                )
            ],
            traceStore: authLifecycleTraceStore
        )
        let keyManagement = KeyManagementService(
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            authLifecycleTraceStore: authLifecycleTraceStore,
            metadataPersistence: InMemoryKeyMetadataStore()
        )
        try? keyManagement.loadKeys()
        let contactService = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            contactsDomainStore: contactsDomainStore
        )
        protectedDataSessionCoordinator.registerRelockParticipant(contactService)
        let appSessionOrchestrator = AppSessionOrchestrator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let appLockController = AppLockController(
            gracePeriodProvider: {
                protectedOrdinarySettingsCoordinator.gracePeriodForSession
            },
            lastAuthenticationDateProvider: { appSessionOrchestrator.lastAuthenticationDate },
            evaluateAppSessionAuthentication: { reason, source in
                try await authManager.evaluateAppSession(
                    policy: config.appSessionAuthenticationPolicy,
                    reason: reason,
                    source: source
                )
            },
            recordSuccessfulAuthentication: { context in
                appSessionOrchestrator.recordSuccessfulAppSessionAuthentication(context: context)
            },
            discardHandoffContext: { reason in
                appSessionOrchestrator.discardAuthorizationHandoffContext(reason: reason)
            },
            relockProtectedData: {
                await protectedDataSessionCoordinator.relockCurrentSession()
            },
            postAuthenticationHandler: { authenticationContext, source in
                do {
                    _ = try await privateKeyControlStore.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
                        authenticationContext: authenticationContext,
                        persistSharedRight: { secret in
                            try await protectedDataSessionCoordinator.persistSharedRight(secretData: secret)
                        },
                        firstDomainSharedRightCleaner: firstDomainSharedRightCleaner
                    )
                } catch {
                    config.privateKeyControlState = privateKeyControlStore.privateKeyControlState
                }
                let postUnlockOutcome = await protectedDataPostUnlockCoordinator.openRegisteredDomains(
                    authenticationContext: authenticationContext,
                    localizedReason: String(
                        localized: "protectedData.postUnlock.reason",
                        defaultValue: "Authenticate to unlock protected app data."
                    ),
                    source: source
                )
                _ = await contactService.openContactsAfterPostUnlock(
                    gateDecision: ContactsPostAuthGateDecision(
                        postUnlockOutcome: postUnlockOutcome,
                        frameworkState: protectedDataSessionCoordinator.frameworkState
                    ),
                    wrappingRootKey: { contactsWrappingRootKey }
                )
                protectedOrdinarySettingsCoordinator.loadAfterAppAuthentication(
                    availability: Self.protectedOrdinarySettingsAvailability(
                        postUnlockOutcome: postUnlockOutcome,
                        protectedSettingsStore: protectedSettingsStore
                    )
                )
                config.privateKeyControlState = privateKeyControlStore.privateKeyControlState
                Self.recoverPrivateKeyControlJournalsAfterPostUnlock(
                    authManager: authManager,
                    keyManagement: keyManagement,
                    config: config,
                    privateKeyControlStore: privateKeyControlStore
                )
                appSessionOrchestrator.recordPostAuthenticationCompletion()
            },
            contentClearHandler: {
                protectedOrdinarySettingsCoordinator.relock()
                appSessionOrchestrator.requestContentClear()
            },
            shouldBypassAuthentication: { !requiresManualAuthentication },
            operationPromptInProgressProvider: {
                authPromptCoordinator.isOperationPromptInProgress
            },
            traceStore: authLifecycleTraceStore
        )
        #if os(macOS)
        wireOperationPromptLifecycle(from: authPromptCoordinator, to: appLockController)
        #endif
        let pgpServices = makePgpServiceGraph(
            engine: engine,
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            contactImportAdapter: contactImportAdapter,
            selfTestAdapter: selfTestAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            secureEnclaveCustodyHandleStore: SecureEnclaveCustodyHandleStore(
                keyStore: SystemSecureEnclaveCustodyKeyStore(traceStore: authLifecycleTraceStore)
            ),
            secureEnclaveDigestSigner: SystemSecureEnclaveCustodyDigestSigner()
        )
        let localDataResetService = LocalDataResetService(
            keychain: keychain,
            protectedDataStorageRoot: protectedDataStorageRoot,
            defaults: defaults,
            defaultsDomainName: suiteName,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            authManager: authManager,
            keyManagement: keyManagement,
            contactService: contactService,
            selfTestService: pgpServices.selfTestService,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            appLockController: appLockController,
            temporaryArtifactStore: pgpServices.temporaryArtifactStore,
            protectedDataRootSecretExists: {
                protectedDataSessionCoordinator.hasPersistedRootSecret()
            },
            traceStore: authLifecycleTraceStore
        )

        let container = AppContainer(
            authLifecycleTraceStore: authLifecycleTraceStore,
            appLockController: appLockController,
            authPromptCoordinator: authPromptCoordinator,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            protectedDataStorageRoot: protectedDataStorageRoot,
            protectedDataRegistryStore: protectedDataRegistryStore,
            protectedDomainKeyManager: protectedDomainKeyManager,
            protectedDomainRecoveryCoordinator: protectedDomainRecoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            contactsDomainStore: nil,
            protectedSettingsStore: protectedSettingsStore,
            protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore,
            protectedDataPostUnlockCoordinator: protectedDataPostUnlockCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            encryptionService: pgpServices.encryptionService,
            decryptionService: pgpServices.decryptionService,
            passwordMessageService: pgpServices.passwordMessageService,
            signingService: pgpServices.signingService,
            certificateSignatureService: pgpServices.certificateSignatureService,
            qrService: pgpServices.qrService,
            selfTestService: pgpServices.selfTestService,
            temporaryArtifactStore: pgpServices.temporaryArtifactStore,
            localDataResetService: localDataResetService,
            defaultsSuiteName: suiteName
        )
        if !requiresManualAuthentication {
            container.uiTestContactsBootstrap = UITestContactsBootstrap(
                wrappingRootKey: contactsWrappingRootKey,
                preloadContact: preloadContact
            )
        }
        return container
    }
    #endif

    @MainActor
    @discardableResult
    func prepareUITestContactsIfNeeded() async -> ContactsAvailability {
        guard var bootstrap = uiTestContactsBootstrap else {
            return contactService.contactsAvailability
        }
        if let cachedAvailability = bootstrap.cachedAvailability {
            guard cachedAvailability != contactService.contactsAvailability else {
                return cachedAvailability
            }
            bootstrap.cachedAvailability = nil
            uiTestContactsBootstrap = bootstrap
        }
        if bootstrap.isPreparing {
            return await withCheckedContinuation { continuation in
                uiTestContactsBootstrap?.waiters.append(continuation)
            }
        }

        bootstrap.isPreparing = true
        uiTestContactsBootstrap = bootstrap
        let availability = await contactService.openContactsAfterPostUnlock(
            gateDecision: ContactsPostAuthGateDecision(
                postUnlockOutcome: .opened([ContactsDomainStore.domainID]),
                frameworkState: .sessionAuthorized
            ),
            wrappingRootKey: { bootstrap.wrappingRootKey }
        )
        var didPreloadContact = bootstrap.didPreloadContact
        if availability == .availableProtectedDomain,
           bootstrap.preloadContact,
           !bootstrap.didPreloadContact {
            do {
                try Self.preloadUITestContact(
                    engine: engine,
                    contactService: contactService
                )
                didPreloadContact = true
            } catch {
                didPreloadContact = false
            }
        }
        let waiters = uiTestContactsBootstrap?.waiters ?? []
        uiTestContactsBootstrap?.didPreloadContact = didPreloadContact
        uiTestContactsBootstrap?.cachedAvailability = availability
        uiTestContactsBootstrap?.isPreparing = false
        uiTestContactsBootstrap?.waiters.removeAll()
        for waiter in waiters {
            waiter.resume(returning: availability)
        }
        return availability
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
        _ = try contactService.importContact(publicKeyData: generated.publicKeyData)
    }

    private static func makeSandboxContactsDomainStore(
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
            sharedRightIdentifier: "com.cypherair.uitests.contacts.\(UUID().uuidString)",
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

    private static func protectedOrdinarySettingsAvailability(
        postUnlockOutcome: ProtectedDataPostUnlockOutcome,
        protectedSettingsStore: ProtectedSettingsStore
    ) -> ProtectedOrdinarySettingsAvailability {
        switch postUnlockOutcome {
        case .opened, .noProtectedDomainPresent, .noRegisteredDomainPresent:
            protectedSettingsStore.syncPreAuthorizationState()
            return protectedSettingsStore.domainState == .unlocked ? .available : .unavailable
        case .domainOpenFailed(let domainID) where domainID == ProtectedSettingsStore.domainID:
            protectedSettingsStore.syncPreAuthorizationState()
            return protectedSettingsStore.domainState == .unlocked ? .available : .unavailable
        case .noRegisteredOpeners,
             .noAuthenticatedContext,
             .pendingMutationRecoveryRequired,
             .frameworkRecoveryNeeded,
             .authorizationDenied,
             .domainOpenFailed:
            return .unavailable
        }
    }

    static func recoverPrivateKeyControlJournalsAfterPostUnlock(
        authManager: AuthenticationManager,
        keyManagement: KeyManagementService,
        config: AppConfiguration,
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) {
        guard privateKeyControlStore.privateKeyControlState.isUnlocked else {
            return
        }

        // Re-wrap recovery enumerates software-custody keys only: device-bound
        // Secure Enclave keys have no SE-wrapped bundle, classify as
        // unrecoverable, and would block target-mode persistence while the
        // recovery journal is destroyed (silent mode/ACL desync).
        let rewrapSummary = authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: PGPKeyIdentity.softwareCustodyFingerprints(in: keyManagement.keys)
        )
        let modifyExpiryOutcome = keyManagement.checkAndRecoverFromInterruptedModifyExpiry()
        config.privateKeyControlState = privateKeyControlStore.privateKeyControlState
        if let warning = postUnlockRecoveryLoadWarning(
            rewrapSummary: rewrapSummary,
            modifyExpiryOutcome: modifyExpiryOutcome
        ) {
            config.appendPostUnlockRecoveryLoadWarning(warning)
        }
    }

    static func postUnlockRecoveryLoadWarning(
        rewrapSummary: KeyMigrationRecoverySummary?,
        modifyExpiryOutcome: KeyMigrationRecoveryOutcome?
    ) -> String? {
        var diagnostics: [String] = []
        for diagnostic in rewrapSummary?.startupDiagnostics ?? [] where !diagnostics.contains(diagnostic) {
            diagnostics.append(diagnostic)
        }
        if let diagnostic = modifyExpiryOutcome?.startupDiagnostic,
           !diagnostics.contains(diagnostic) {
            diagnostics.append(diagnostic)
        }
        return diagnostics.isEmpty ? nil : diagnostics.joined(separator: "\n")
    }
}
