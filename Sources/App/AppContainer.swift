import Foundation

/// Centralized dependency container for the application.
final class AppContainer: @unchecked Sendable {
    let authLifecycleTraceStore: AuthLifecycleTraceStore?
    let authenticationShieldCoordinator: AuthenticationShieldCoordinator
    let authPromptCoordinator: AuthenticationPromptCoordinator
    let secureEnclave: any SecureEnclaveManageable
    let keychain: any KeychainManageable
    let authManager: AuthenticationManager
    let config: AppConfiguration
    let protectedDataStorageRoot: ProtectedDataStorageRoot
    let protectedDataRegistryStore: ProtectedDataRegistryStore
    let protectedDomainKeyManager: ProtectedDomainKeyManager
    let protectedDomainRecoveryCoordinator: ProtectedDomainRecoveryCoordinator
    let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    let privateKeyControlStore: PrivateKeyControlStore
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
    let localDataResetService: LocalDataResetService
    let contactsDirectory: URL?
    let defaultsSuiteName: String?

    init(
        authLifecycleTraceStore: AuthLifecycleTraceStore?,
        authenticationShieldCoordinator: AuthenticationShieldCoordinator,
        authPromptCoordinator: AuthenticationPromptCoordinator,
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        authManager: AuthenticationManager,
        config: AppConfiguration,
        protectedDataStorageRoot: ProtectedDataStorageRoot,
        protectedDataRegistryStore: ProtectedDataRegistryStore,
        protectedDomainKeyManager: ProtectedDomainKeyManager,
        protectedDomainRecoveryCoordinator: ProtectedDomainRecoveryCoordinator,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        privateKeyControlStore: PrivateKeyControlStore,
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
        localDataResetService: LocalDataResetService,
        contactsDirectory: URL? = nil,
        defaultsSuiteName: String? = nil
    ) {
        self.authLifecycleTraceStore = authLifecycleTraceStore
        self.authenticationShieldCoordinator = authenticationShieldCoordinator
        self.authPromptCoordinator = authPromptCoordinator
        self.secureEnclave = secureEnclave
        self.keychain = keychain
        self.authManager = authManager
        self.config = config
        self.protectedDataStorageRoot = protectedDataStorageRoot
        self.protectedDataRegistryStore = protectedDataRegistryStore
        self.protectedDomainKeyManager = protectedDomainKeyManager
        self.protectedDomainRecoveryCoordinator = protectedDomainRecoveryCoordinator
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
        self.privateKeyControlStore = privateKeyControlStore
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
        self.localDataResetService = localDataResetService
        self.contactsDirectory = contactsDirectory
        self.defaultsSuiteName = defaultsSuiteName
    }

    static func makeDefault(
        authTraceEnabled: Bool = false
    ) -> AppContainer {
        let authLifecycleTraceStore = AuthLifecycleTraceStore(isEnabled: authTraceEnabled)
        let secureEnclave = HardwareSecureEnclave(traceStore: authLifecycleTraceStore)
        let keychain = SystemKeychain(traceStore: authLifecycleTraceStore)
        let authenticationShieldCoordinator = AuthenticationShieldCoordinator(
            traceStore: authLifecycleTraceStore
        )
        let authPromptCoordinator = AuthenticationPromptCoordinator(
            shieldEventHandler: makeShieldEventHandler(
                coordinator: authenticationShieldCoordinator
            ),
            traceStore: authLifecycleTraceStore
        )
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let defaults = UserDefaults.standard
        let config = AppConfiguration(defaults: defaults)
        let protectedDataStorageRoot = ProtectedDataStorageRoot(traceStore: authLifecycleTraceStore)
        let protectedDomainKeyManager = ProtectedDomainKeyManager(storageRoot: protectedDataStorageRoot)
        let protectedDataRegistryStore = ProtectedDataRegistryStore(
            storageRoot: protectedDataStorageRoot,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            traceStore: authLifecycleTraceStore
        )
        let protectedDomainRecoveryCoordinator = ProtectedDomainRecoveryCoordinator(
            registryStore: protectedDataRegistryStore
        )
        let protectedDataRightStoreClient = ProtectedDataRightStoreClient(traceStore: authLifecycleTraceStore)
        let protectedDataSessionCoordinator = ProtectedDataSessionCoordinator(
            rootSecretStore: KeychainProtectedDataRootSecretStore(traceStore: authLifecycleTraceStore),
            legacyRightStoreClient: protectedDataRightStoreClient,
            domainKeyManager: protectedDomainKeyManager,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            appSessionPolicyProvider: { config.appSessionAuthenticationPolicy },
            recordRootSecretEnvelopeMinimumVersion: { version in
                try await protectedDataRegistryStore.recordRootSecretEnvelopeMinimumVersion(version)
            },
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let firstDomainSharedRightCleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: protectedDataStorageRoot,
            hasPersistedSharedRight: { identifier in
                protectedDataSessionCoordinator.hasPersistedRootSecret(identifier: identifier)
            },
            removePersistedSharedRight: { identifier in
                try await protectedDataSessionCoordinator.removePersistedSharedRight(identifier: identifier)
            },
            traceStore: authLifecycleTraceStore
        )
        let privateKeyControlStore = PrivateKeyControlStore(
            defaults: defaults,
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let protectedSettingsStore = ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let protectedDataFrameworkSentinelStore = ProtectedDataFrameworkSentinelStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
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
                ),
                ProtectedDataPostUnlockDomainOpener(
                    domainID: ProtectedSettingsStore.domainID,
                    open: { wrappingRootKey in
                        _ = try await protectedSettingsStore.openDomainIfNeeded(
                            wrappingRootKey: wrappingRootKey
                        )
                    }
                ),
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
            ],
            traceStore: authLifecycleTraceStore
        )
        let engine = PgpEngine()
        let keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: .standard,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            authLifecycleTraceStore: authLifecycleTraceStore
        )
        let appSessionOrchestrator = AppSessionOrchestrator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { config.gracePeriod },
            evaluateAppAuthenticationWithSource: { reason, source in
                try await authManager.evaluateAppSession(
                    policy: config.appSessionAuthenticationPolicy,
                    reason: reason,
                    source: source
                )
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
                await keyManagement.migrateLegacyMetadataAfterAppAuthentication(
                    authenticationContext: authenticationContext,
                    source: source
                )
                _ = await protectedDataPostUnlockCoordinator.openRegisteredDomains(
                    authenticationContext: authenticationContext,
                    localizedReason: String(
                        localized: "protectedData.postUnlock.reason",
                        defaultValue: "Authenticate to unlock protected app data."
                    ),
                    source: source
                )
                config.privateKeyControlState = privateKeyControlStore.privateKeyControlState
                Self.recoverPrivateKeyControlJournalsAfterPostUnlock(
                    authManager: authManager,
                    keyManagement: keyManagement,
                    config: config,
                    privateKeyControlStore: privateKeyControlStore
                )
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
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
        let contactsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("contacts", isDirectory: true)
        let localDataResetService = LocalDataResetService(
            keychain: keychain,
            legacyRightStoreClient: protectedDataRightStoreClient,
            protectedDataStorageRoot: protectedDataStorageRoot,
            contactsDirectory: contactsDirectory,
            defaults: defaults,
            defaultsDomainName: Bundle.main.bundleIdentifier,
            config: config,
            authManager: authManager,
            keyManagement: keyManagement,
            contactService: contactService,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            protectedDataRootSecretExists: {
                protectedDataSessionCoordinator.hasPersistedRootSecret()
            },
            traceStore: authLifecycleTraceStore
        )

        return AppContainer(
            authLifecycleTraceStore: authLifecycleTraceStore,
            authenticationShieldCoordinator: authenticationShieldCoordinator,
            authPromptCoordinator: authPromptCoordinator,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedDataStorageRoot: protectedDataStorageRoot,
            protectedDataRegistryStore: protectedDataRegistryStore,
            protectedDomainKeyManager: protectedDomainKeyManager,
            protectedDomainRecoveryCoordinator: protectedDomainRecoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            protectedSettingsStore: protectedSettingsStore,
            protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore,
            protectedDataPostUnlockCoordinator: protectedDataPostUnlockCoordinator,
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
            localDataResetService: localDataResetService
        )
    }

    static func makeUITest(
        requiresManualAuthentication: Bool = false,
        preloadContact: Bool = false,
        authTraceEnabled: Bool = false
    ) -> AppContainer {
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let authLifecycleTraceStore = AuthLifecycleTraceStore(isEnabled: authTraceEnabled)
        let authenticationShieldCoordinator = AuthenticationShieldCoordinator(
            traceStore: authLifecycleTraceStore
        )
        let authPromptCoordinator = AuthenticationPromptCoordinator(
            shieldEventHandler: makeShieldEventHandler(
                coordinator: authenticationShieldCoordinator
            ),
            traceStore: authLifecycleTraceStore
        )
        let suiteName = "com.cypherair.uitests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName) ?? .standard
        defaults.removePersistentDomain(forName: suiteName)
        defaults.set(!requiresManualAuthentication, forKey: "com.cypherair.preference.uiTestBypassAuthentication")

        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let config = AppConfiguration(defaults: defaults)
        let engine = PgpEngine()
        let contactsDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirUITests-\(UUID().uuidString)", isDirectory: true)
        let applicationSupportDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let protectedDataBaseDirectory = applicationSupportDirectory
            .appendingPathComponent("CypherAirUITestProtectedData-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: contactsDirectory,
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
        let protectedDomainKeyManager = ProtectedDomainKeyManager(storageRoot: protectedDataStorageRoot)
        let protectedDataRegistryStore = ProtectedDataRegistryStore(
            storageRoot: protectedDataStorageRoot,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            traceStore: authLifecycleTraceStore
        )
        let protectedDomainRecoveryCoordinator = ProtectedDomainRecoveryCoordinator(
            registryStore: protectedDataRegistryStore
        )
        let protectedDataRightStoreClient = ProtectedDataRightStoreClient(traceStore: authLifecycleTraceStore)
        let protectedDataSessionCoordinator = ProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRootSecretStore(),
            legacyRightStoreClient: protectedDataRightStoreClient,
            domainKeyManager: protectedDomainKeyManager,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            appSessionPolicyProvider: { config.appSessionAuthenticationPolicy },
            recordRootSecretEnvelopeMinimumVersion: { version in
                try await protectedDataRegistryStore.recordRootSecretEnvelopeMinimumVersion(version)
            },
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let firstDomainSharedRightCleaner = ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: protectedDataStorageRoot,
            hasPersistedSharedRight: { identifier in
                protectedDataSessionCoordinator.hasPersistedRootSecret(identifier: identifier)
            },
            removePersistedSharedRight: { identifier in
                try await protectedDataSessionCoordinator.removePersistedSharedRight(identifier: identifier)
            },
            traceStore: authLifecycleTraceStore
        )
        let privateKeyControlStore = PrivateKeyControlStore(
            defaults: defaults,
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
            defaults: defaults,
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let protectedDataFrameworkSentinelStore = ProtectedDataFrameworkSentinelStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
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
                ),
                ProtectedDataPostUnlockDomainOpener(
                    domainID: ProtectedSettingsStore.domainID,
                    open: { wrappingRootKey in
                        _ = try await protectedSettingsStore.openDomainIfNeeded(
                            wrappingRootKey: wrappingRootKey
                        )
                    }
                ),
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
            ],
            traceStore: authLifecycleTraceStore
        )
        let keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            authLifecycleTraceStore: authLifecycleTraceStore
        )
        let appSessionOrchestrator = AppSessionOrchestrator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { !requiresManualAuthentication },
            gracePeriodProvider: { config.gracePeriod },
            evaluateAppAuthenticationWithSource: { reason, source in
                try await authManager.evaluateAppSession(
                    policy: config.appSessionAuthenticationPolicy,
                    reason: reason,
                    source: source
                )
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
                await keyManagement.migrateLegacyMetadataAfterAppAuthentication(
                    authenticationContext: authenticationContext,
                    source: source
                )
                _ = await protectedDataPostUnlockCoordinator.openRegisteredDomains(
                    authenticationContext: authenticationContext,
                    localizedReason: String(
                        localized: "protectedData.postUnlock.reason",
                        defaultValue: "Authenticate to unlock protected app data."
                    ),
                    source: source
                )
                config.privateKeyControlState = privateKeyControlStore.privateKeyControlState
                Self.recoverPrivateKeyControlJournalsAfterPostUnlock(
                    authManager: authManager,
                    keyManagement: keyManagement,
                    config: config,
                    privateKeyControlStore: privateKeyControlStore
                )
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
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
        let localDataResetService = LocalDataResetService(
            keychain: keychain,
            legacyRightStoreClient: nil,
            protectedDataStorageRoot: protectedDataStorageRoot,
            contactsDirectory: contactsDirectory,
            defaults: defaults,
            defaultsDomainName: suiteName,
            config: config,
            authManager: authManager,
            keyManagement: keyManagement,
            contactService: contactService,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            protectedDataRootSecretExists: {
                protectedDataSessionCoordinator.hasPersistedRootSecret()
            },
            traceStore: authLifecycleTraceStore
        )

        if preloadContact {
            try? preloadUITestContact(engine: engine, contactService: contactService)
        }

        return AppContainer(
            authLifecycleTraceStore: authLifecycleTraceStore,
            authenticationShieldCoordinator: authenticationShieldCoordinator,
            authPromptCoordinator: authPromptCoordinator,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedDataStorageRoot: protectedDataStorageRoot,
            protectedDataRegistryStore: protectedDataRegistryStore,
            protectedDomainKeyManager: protectedDomainKeyManager,
            protectedDomainRecoveryCoordinator: protectedDomainRecoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            protectedSettingsStore: protectedSettingsStore,
            protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore,
            protectedDataPostUnlockCoordinator: protectedDataPostUnlockCoordinator,
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
            localDataResetService: localDataResetService,
            contactsDirectory: contactsDirectory,
            defaultsSuiteName: suiteName
        )
    }

    private static func makeShieldEventHandler(
        coordinator: AuthenticationShieldCoordinator
    ) -> AuthenticationPromptCoordinator.ShieldEventHandler {
        { kind, delta in
            await MainActor.run {
                if delta > 0 {
                    coordinator.begin(kind)
                } else {
                    coordinator.end(kind)
                }
            }
        }
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

    static func recoverPrivateKeyControlJournalsAfterPostUnlock(
        authManager: AuthenticationManager,
        keyManagement: KeyManagementService,
        config: AppConfiguration,
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) {
        guard privateKeyControlStore.privateKeyControlState.isUnlocked else {
            return
        }

        let rewrapSummary = authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: keyManagement.keys.map(\.fingerprint)
        )
        let modifyExpiryOutcome = keyManagement.checkAndRecoverFromInterruptedModifyExpiry()
        config.privateKeyControlState = privateKeyControlStore.privateKeyControlState
        if let warning = postUnlockRecoveryLoadWarning(
            rewrapSummary: rewrapSummary,
            modifyExpiryOutcome: modifyExpiryOutcome
        ) {
            config.postUnlockRecoveryLoadWarning = warning
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
