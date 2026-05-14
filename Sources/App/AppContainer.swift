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
    let contactsDirectory: URL?
    let legacySelfTestReportsDirectory: URL?
    let defaultsSuiteName: String?

    init(
        authLifecycleTraceStore: AuthLifecycleTraceStore?,
        authenticationShieldCoordinator: AuthenticationShieldCoordinator,
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
        contactsDirectory: URL? = nil,
        legacySelfTestReportsDirectory: URL? = nil,
        defaultsSuiteName: String? = nil
    ) {
        self.authLifecycleTraceStore = authLifecycleTraceStore
        self.authenticationShieldCoordinator = authenticationShieldCoordinator
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
        self.contactsDirectory = contactsDirectory
        self.legacySelfTestReportsDirectory = legacySelfTestReportsDirectory
        self.defaultsSuiteName = defaultsSuiteName
    }

    private struct AuthenticationPromptStack {
        let authLifecycleTraceStore: AuthLifecycleTraceStore
        let authenticationShieldCoordinator: AuthenticationShieldCoordinator
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
        let authenticationShieldCoordinator = AuthenticationShieldCoordinator(
            traceStore: authLifecycleTraceStore
        )
        let authPromptCoordinator = AuthenticationPromptCoordinator(
            shieldEventHandler: makeShieldEventHandler(
                coordinator: authenticationShieldCoordinator
            ),
            traceStore: authLifecycleTraceStore
        )
        return AuthenticationPromptStack(
            authLifecycleTraceStore: authLifecycleTraceStore,
            authenticationShieldCoordinator: authenticationShieldCoordinator,
            authPromptCoordinator: authPromptCoordinator
        )
    }

    private static func makeProtectedDataSessionCoordinator(
        rootSecretStore: any ProtectedDataRootSecretStoreProtocol,
        legacyRightStoreClient: (any ProtectedDataRightStoreClientProtocol)?,
        domainKeyManager: ProtectedDomainKeyManager,
        registryStore: ProtectedDataRegistryStore,
        config: AppConfiguration,
        authPromptCoordinator: AuthenticationPromptCoordinator,
        traceStore: AuthLifecycleTraceStore?
    ) -> ProtectedDataSessionCoordinator {
        ProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            legacyRightStoreClient: legacyRightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            appSessionPolicyProvider: { config.appSessionAuthenticationPolicy },
            recordRootSecretEnvelopeMinimumVersion: { version in
                try await registryStore.recordRootSecretEnvelopeMinimumVersion(version)
            },
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: traceStore
        )
    }

    private static func makeFirstDomainSharedRightCleaner(
        storageRoot: ProtectedDataStorageRoot,
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator,
        traceStore: AuthLifecycleTraceStore?
    ) -> ProtectedDataFirstDomainSharedRightCleaner {
        ProtectedDataFirstDomainSharedRightCleaner(
            storageRoot: storageRoot,
            hasPersistedSharedRight: { identifier in
                protectedDataSessionCoordinator.hasPersistedRootSecret(identifier: identifier)
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
                try await protectedSettingsStore.ensureCommittedAndMigrateSettingsIfNeeded(
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
        keyManagement: KeyManagementService,
        contactService: ContactService
    ) -> PgpServiceGraph {
        let temporaryArtifactStore = AppTemporaryArtifactStore()
        return PgpServiceGraph(
            temporaryArtifactStore: temporaryArtifactStore,
            encryptionService: EncryptionService(
                engine: engine,
                keyManagement: keyManagement,
                contactService: contactService,
                temporaryArtifactStore: temporaryArtifactStore
            ),
            decryptionService: DecryptionService(
                engine: engine,
                keyManagement: keyManagement,
                contactService: contactService,
                temporaryArtifactStore: temporaryArtifactStore
            ),
            passwordMessageService: PasswordMessageService(
                engine: engine,
                keyManagement: keyManagement,
                contactService: contactService
            ),
            signingService: SigningService(
                engine: engine,
                keyManagement: keyManagement,
                contactService: contactService
            ),
            certificateSignatureService: CertificateSignatureService(
                engine: engine,
                keyManagement: keyManagement,
                contactService: contactService
            ),
            qrService: QRService(engine: engine),
            selfTestService: SelfTestService(engine: engine)
        )
    }

    static func makeDefault(
        authTraceEnabled: Bool = false
    ) -> AppContainer {
        let authentication = makeAuthenticationPromptStack(authTraceEnabled: authTraceEnabled)
        let authLifecycleTraceStore = authentication.authLifecycleTraceStore
        let authenticationShieldCoordinator = authentication.authenticationShieldCoordinator
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
        let protectedDataSessionCoordinator = makeProtectedDataSessionCoordinator(
            rootSecretStore: KeychainProtectedDataRootSecretStore(traceStore: authLifecycleTraceStore),
            legacyRightStoreClient: protectedDataRightStoreClient,
            domainKeyManager: protectedDomainKeyManager,
            registryStore: protectedDataRegistryStore,
            config: config,
            authPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let firstDomainSharedRightCleaner = makeFirstDomainSharedRightCleaner(
            storageRoot: protectedDataStorageRoot,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
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
        let legacyKeyMetadataStore = KeyMetadataStore(
            keychain: keychain,
            traceStore: authLifecycleTraceStore
        )
        let keyMetadataDomainStore = KeyMetadataDomainStore(
            legacyMetadataStore: legacyKeyMetadataStore,
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let engine = PgpEngine()
        let documentDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let contactsDirectory = documentDirectory
            .appendingPathComponent("contacts", isDirectory: true)
        let legacySelfTestReportsDirectory = documentDirectory
            .appendingPathComponent("self-test", isDirectory: true)
        let contactsLegacyRepository = ContactRepository(contactsDirectory: contactsDirectory)
        let contactsMigrationSource = ContactsLegacyMigrationSource(
            engine: engine,
            repository: contactsLegacyRepository
        )
        let contactsDomainStore = ContactsDomainStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            },
            initialSnapshotProvider: {
                try contactsMigrationSource.makeInitialSnapshot()
            }
        )
        authManager.configurePrivateKeyControlStore(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(privateKeyControlStore)
        let keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: .standard,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            authLifecycleTraceStore: authLifecycleTraceStore,
            metadataPersistence: keyMetadataDomainStore
        )
        protectedDataSessionCoordinator.registerRelockParticipant(keyManagement)
        protectedDataSessionCoordinator.registerRelockParticipant(keyMetadataDomainStore)
        protectedDataSessionCoordinator.registerRelockParticipant(contactsDomainStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedSettingsStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedDataFrameworkSentinelStore)
        let contactService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory,
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
                    ensureCommittedWithContext: { context in
                        keyManagement.beginKeyMetadataLoad()
                        do {
                            try await keyMetadataDomainStore.ensureCommittedIfNeeded(
                                wrappingRootKey: context.wrappingRootKey,
                                authenticationContext: context.authenticationContext
                            )
                        } catch {
                            keyManagement.markKeyMetadataRecoveryNeeded()
                            throw error
                        }
                    },
                    openWithContext: { context in
                        keyManagement.beginKeyMetadataLoad()
                        do {
                            _ = try await keyMetadataDomainStore.openDomainIfNeeded(
                                wrappingRootKey: context.wrappingRootKey,
                                authenticationContext: context.authenticationContext
                            )
                            try keyManagement.completeKeyMetadataLoad(
                                migrationWarning: keyMetadataDomainStore.migrationWarning,
                                source: context.authenticationContext == nil ? "postUnlockNoContext" : "postUnlock"
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
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: {
                protectedOrdinarySettingsCoordinator.gracePeriodForSession
            },
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
                let postUnlockOutcome = await protectedDataPostUnlockCoordinator.openRegisteredDomains(
                    authenticationContext: authenticationContext,
                    localizedReason: String(
                        localized: "protectedData.postUnlock.reason",
                        defaultValue: "Authenticate to unlock protected app data."
                    ),
                    source: source
                )
                _ = await contactService.openContactsAfterPostUnlock(
                    gateResult: ContactsPostAuthGateResult(
                        postUnlockOutcome: postUnlockOutcome,
                        frameworkState: protectedDataSessionCoordinator.frameworkState
                    ),
                    wrappingRootKey: {
                        try protectedDataSessionCoordinator.wrappingRootKeyData()
                    }
                )
                config.appendPostUnlockRecoveryLoadWarning(
                    contactService.protectedDomainMigrationWarning
                )
                protectedOrdinarySettingsCoordinator.loadAfterAppAuthentication(
                    protectedSettingsDomainState: Self.protectedSettingsDomainStateForOrdinarySettings(
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
            },
            contentClearHandler: {
                protectedOrdinarySettingsCoordinator.relock()
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let pgpServices = makePgpServiceGraph(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let localDataResetService = LocalDataResetService(
            keychain: keychain,
            legacyRightStoreClient: protectedDataRightStoreClient,
            protectedDataStorageRoot: protectedDataStorageRoot,
            contactsDirectory: contactsDirectory,
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
            temporaryArtifactStore: pgpServices.temporaryArtifactStore,
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory,
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
            localDataResetService: localDataResetService,
            contactsDirectory: contactsDirectory,
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory
        )
    }

    static func makeUITest(
        requiresManualAuthentication: Bool = false,
        preloadContact: Bool = false,
        authTraceEnabled: Bool = false
    ) -> AppContainer {
        let authentication = makeAuthenticationPromptStack(authTraceEnabled: authTraceEnabled)
        let authLifecycleTraceStore = authentication.authLifecycleTraceStore
        let authenticationShieldCoordinator = authentication.authenticationShieldCoordinator
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
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let config = AppConfiguration(defaults: defaults)
        let engine = PgpEngine()
        let documentDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirUITestDocuments-\(UUID().uuidString)", isDirectory: true)
        let contactsDirectory = documentDirectory
            .appendingPathComponent("contacts", isDirectory: true)
        let legacySelfTestReportsDirectory = documentDirectory
            .appendingPathComponent("self-test", isDirectory: true)
        let applicationSupportDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let protectedDataBaseDirectory = applicationSupportDirectory
            .appendingPathComponent("CypherAirUITestProtectedData-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: documentDirectory,
            withIntermediateDirectories: true
        )
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
        let protectedDataSessionCoordinator = makeProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRootSecretStore(),
            legacyRightStoreClient: protectedDataRightStoreClient,
            domainKeyManager: protectedDomainKeyManager,
            registryStore: protectedDataRegistryStore,
            config: config,
            authPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let firstDomainSharedRightCleaner = makeFirstDomainSharedRightCleaner(
            storageRoot: protectedDataStorageRoot,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
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
        let protectedOrdinarySettingsCoordinator: ProtectedOrdinarySettingsCoordinator
        if requiresManualAuthentication {
            protectedOrdinarySettingsCoordinator = ProtectedOrdinarySettingsCoordinator(
                persistence: ProtectedSettingsOrdinarySettingsPersistence(
                    protectedSettingsStore: protectedSettingsStore
                )
            )
        } else {
            protectedOrdinarySettingsCoordinator = ProtectedOrdinarySettingsCoordinator(
                persistence: LegacyOrdinarySettingsStore(defaults: defaults)
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
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            authLifecycleTraceStore: authLifecycleTraceStore
        )
        try? keyManagement.loadKeys()
        let contactService = ContactService(
            engine: engine,
            contactsDirectory: contactsDirectory
        )
        protectedDataSessionCoordinator.registerRelockParticipant(contactService)
        if !requiresManualAuthentication {
            _ = try? contactService.openLegacyCompatibilityForTests()
        }
        let appSessionOrchestrator = AppSessionOrchestrator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { !requiresManualAuthentication },
            gracePeriodProvider: {
                protectedOrdinarySettingsCoordinator.gracePeriodForSession
            },
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
                let postUnlockOutcome = await protectedDataPostUnlockCoordinator.openRegisteredDomains(
                    authenticationContext: authenticationContext,
                    localizedReason: String(
                        localized: "protectedData.postUnlock.reason",
                        defaultValue: "Authenticate to unlock protected app data."
                    ),
                    source: source
                )
                _ = contactService.openLegacyCompatibilityAfterPostUnlock(
                    gateResult: ContactsPostAuthGateResult(
                        postUnlockOutcome: postUnlockOutcome,
                        frameworkState: protectedDataSessionCoordinator.frameworkState
                    )
                )
                protectedOrdinarySettingsCoordinator.loadAfterAppAuthentication(
                    protectedSettingsDomainState: Self.protectedSettingsDomainStateForOrdinarySettings(
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
            },
            contentClearHandler: {
                protectedOrdinarySettingsCoordinator.relock()
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: authLifecycleTraceStore
        )
        let pgpServices = makePgpServiceGraph(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let localDataResetService = LocalDataResetService(
            keychain: keychain,
            legacyRightStoreClient: nil,
            protectedDataStorageRoot: protectedDataStorageRoot,
            contactsDirectory: contactsDirectory,
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
            temporaryArtifactStore: pgpServices.temporaryArtifactStore,
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory,
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
            contactsDirectory: contactsDirectory,
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory,
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
        try contactService.openLegacyCompatibilityForTests()
        let generated = try engine.generateKey(
            name: "UITest Contact",
            email: "uitest-contact@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
    }

    private static func protectedSettingsDomainStateForOrdinarySettings(
        postUnlockOutcome: ProtectedDataPostUnlockOutcome,
        protectedSettingsStore: ProtectedSettingsStore
    ) -> ProtectedSettingsDomainState {
        switch postUnlockOutcome {
        case .opened, .noProtectedDomainPresent, .noRegisteredDomainPresent:
            protectedSettingsStore.syncPreAuthorizationState()
            return protectedSettingsStore.domainState
        case .domainOpenFailed(let domainID) where domainID == ProtectedSettingsStore.domainID:
            protectedSettingsStore.syncPreAuthorizationState()
            return protectedSettingsStore.domainState
        case .noRegisteredOpeners,
             .noAuthenticatedContext,
             .pendingMutationRecoveryRequired,
             .frameworkRecoveryNeeded,
             .authorizationDenied,
             .domainOpenFailed:
            return .frameworkUnavailable
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

        let rewrapSummary = authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: keyManagement.keys.map(\.fingerprint)
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
