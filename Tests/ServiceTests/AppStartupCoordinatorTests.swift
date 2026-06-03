import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class AppStartupCoordinatorTests: XCTestCase {
    func test_appStartupCoordinator_cleansPhase7TemporaryArtifactsAndTutorialDefaults() throws {
        let baseDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirStartupTemp-\(UUID().uuidString)", isDirectory: true)
        let preferencesDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirStartupPrefs-\(UUID().uuidString)", isDirectory: true)
        let legacySelfTestDirectory = baseDirectory
            .appendingPathComponent("legacy-self-test", isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: baseDirectory)
            try? FileManager.default.removeItem(at: preferencesDirectory)
        }
        try makePhase7TemporaryArtifacts(in: baseDirectory)
        try FileManager.default.createDirectory(at: preferencesDirectory, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: legacySelfTestDirectory, withIntermediateDirectories: true)
        try Data("legacy".utf8).write(
            to: legacySelfTestDirectory.appendingPathComponent("self-test.txt"),
            options: .atomic
        )
        let fixedTutorialSuiteName = AppTemporaryArtifactStore.tutorialSandboxDefaultsSuiteName
        let fixedTutorialPlist = preferencesDirectory.appendingPathComponent("\(fixedTutorialSuiteName).plist")
        try Data("fixed".utf8).write(to: fixedTutorialPlist, options: .atomic)
        let legacyTutorialSuiteName = "com.cypherair.tutorial.\(UUID().uuidString)"
        let legacyTutorialPlist = preferencesDirectory.appendingPathComponent("\(legacyTutorialSuiteName).plist")
        try Data("orphan".utf8).write(to: legacyTutorialPlist, options: .atomic)
        let similarTutorialSuiteName = "com.cypherair.tutorial.not-a-uuid"
        let similarTutorialPlist = preferencesDirectory.appendingPathComponent("\(similarTutorialSuiteName).plist")
        try Data("keep".utf8).write(to: similarTutorialPlist, options: .atomic)

        let store = CypherAir.AppTemporaryArtifactStore(
            temporaryDirectory: baseDirectory,
            preferencesDirectory: preferencesDirectory
        )
        AppStartupCoordinator().cleanupTemporaryFiles(
            temporaryArtifactStore: store,
            legacySelfTestReportsDirectory: legacySelfTestDirectory
        )

        XCTAssertTrue(store.remainingTemporaryArtifacts().isEmpty)
        XCTAssertTrue(store.remainingTutorialDefaultsSuites().isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixedTutorialPlist.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacyTutorialPlist.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: similarTutorialPlist.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacySelfTestDirectory.path))
    }

    func test_appStartupCoordinator_mergedStartupMessages_appendsRecoveryDiagnostics() {
        let coordinator = AppStartupCoordinator()
        let merged = coordinator.mergedStartupMessages(
            loadErrors: ["Contacts failed to load"],
            recoveryDiagnostics: [
                "A previous secure key migration could not be recovered. Restore from backup if private-key operations fail."
            ]
        )

        XCTAssertEqual(
            merged,
            """
            Contacts failed to load
            A previous secure key migration could not be recovered. Restore from backup if private-key operations fail.
            """
        )
    }

    func test_appStartupCoordinator_mergedStartupMessages_recoveryDiagnostic_isGeneric() {
        let coordinator = AppStartupCoordinator()
        let merged = coordinator.mergedStartupMessages(
            loadErrors: [],
            recoveryDiagnostics: [
                "A previous secure key migration could not be fully recovered. CypherAir X will retry recovery on next launch."
            ]
        )

        XCTAssertNotNil(merged)
        XCTAssertFalse(merged?.contains("fingerprint") == true)
        XCTAssertFalse(merged?.contains("89abcdef") == true)
    }


    func test_appStartupCoordinator_deletedKeyDoesNotRestoreInterruptedModifyExpiryBundle() async throws {
        let engine = PgpEngine()
        let mockSE = MockSecureEnclave()
        let mockKC = MockKeychain()
        let suiteName = "com.cypherair.startup.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let setupAuthManager = AuthenticationManager(
            secureEnclave: mockSE,
            keychain: mockKC,
            defaults: defaults
        )
        let setupPrivateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        setupAuthManager.configurePrivateKeyControlStore(setupPrivateKeyControlStore)
        let setupKeyManagement = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: setupAuthManager,
            defaults: defaults,
            privateKeyControlStore: setupPrivateKeyControlStore
        )

        let identity = try await setupKeyManagement.generateKey(
            name: "Startup Test",
            email: "startup@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let fingerprint = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        let seKeyData = try mockKC.load(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account
        )
        let saltData = try mockKC.load(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account
        )
        let sealedData = try mockKC.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account
        )

        try mockKC.save(
            seKeyData,
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try mockKC.save(
            saltData,
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try mockKC.save(
            sealedData,
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )

        defaults.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        defaults.set(fingerprint, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        try setupKeyManagement.deleteKey(fingerprint: fingerprint)

        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let authManager = AuthenticationManager(
            secureEnclave: mockSE,
            keychain: mockKC,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let keyManagementPrivateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        authManager.configurePrivateKeyControlStore(keyManagementPrivateKeyControlStore)
        let keyManagement = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: keyManagementPrivateKeyControlStore
        )
        let config = AppConfiguration(defaults: defaults)
        let protectedOrdinarySettingsCoordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: LegacyOrdinarySettingsStore(defaults: defaults)
        )
        protectedOrdinarySettingsCoordinator.loadForAuthenticatedTestBypass()
        let contactDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirStartupTests-\(UUID().uuidString)", isDirectory: true)
        let legacySelfTestReportsDirectory = contactDirectory
            .appendingPathComponent("self-test", isDirectory: true)
        let protectedDataBaseDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirProtectedDataStartupTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: contactDirectory) }
        defer { try? FileManager.default.removeItem(at: protectedDataBaseDirectory) }
        let protectedDataStorageRoot = CypherAir.ProtectedDataStorageRoot(baseDirectory: protectedDataBaseDirectory)
        let protectedDomainKeyManager = CypherAir.ProtectedDomainKeyManager(storageRoot: protectedDataStorageRoot)
        let protectedDataRegistryStore = CypherAir.ProtectedDataRegistryStore(
            storageRoot: protectedDataStorageRoot,
            sharedRightIdentifier: CypherAir.ProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let protectedDomainRecoveryCoordinator = CypherAir.ProtectedDomainRecoveryCoordinator(
            registryStore: protectedDataRegistryStore
        )
        let protectedDataSessionCoordinator = CypherAir.ProtectedDataSessionCoordinator(
            rootSecretStore: CypherAir.MockProtectedDataRootSecretStore(),
            legacyRightStoreClient: CypherAir.ProtectedDataRightStoreClient(),
            domainKeyManager: protectedDomainKeyManager,
            sharedRightIdentifier: CypherAir.ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            appSessionPolicyProvider: { config.appSessionAuthenticationPolicy },
            authenticationPromptCoordinator: authPromptCoordinator
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
        let privateKeyControlStore = PrivateKeyControlStore(
            defaults: defaults,
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
        let appSessionOrchestrator = CypherAir.AppSessionOrchestrator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: {
                protectedOrdinarySettingsCoordinator.gracePeriodForSession
            },
            evaluateAppAuthentication: { reason in
                try await authManager.evaluateAppSession(
                    policy: config.appSessionAuthenticationPolicy,
                    reason: reason
                )
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let selfTestAdapter = PGPSelfTestOperationAdapter(engine: engine)
        let contactsDomainStore = try TestHelpers.makeContactsDomainStore(
            engine: engine,
            contactsDirectory: contactDirectory
        )
        let contactService = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            contactsDomainStore: contactsDomainStore
        )
        let textEncryptor = TestHelpers.makeTextEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let fileEncryptor = TestHelpers.makeFileEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let encryptionService = EncryptionService(
            keyManagement: keyManagement,
            contactService: contactService,
            textEncryptor: textEncryptor,
            fileEncryptor: fileEncryptor
        )
        let decryptionService = DecryptionService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let passwordMessageEncryptor = TestHelpers.makePasswordMessageEncryptor(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let passwordMessageService = PasswordMessageService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            passwordEncryptor: passwordMessageEncryptor
        )
        let cleartextSigner = TestHelpers.makeCleartextSigner(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let detachedFileSigner = TestHelpers.makeDetachedFileSigner(
            engine: engine,
            keyManagement: keyManagement,
            messageAdapter: messageAdapter
        )
        let signingService = SigningService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            cleartextSigner: cleartextSigner,
            detachedFileSigner: detachedFileSigner
        )
        let certificateSignatureService = CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let qrService = QRService(contactImportAdapter: contactImportAdapter)
        let selfTestService = SelfTestService(
            selfTestAdapter: selfTestAdapter,
            messageAdapter: messageAdapter
        )
        let localDataResetService = LocalDataResetService(
            keychain: mockKC,
            protectedDataStorageRoot: protectedDataStorageRoot,
            defaults: defaults,
            defaultsDomainName: suiteName,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            authManager: authManager,
            keyManagement: keyManagement,
            contactService: contactService,
            selfTestService: selfTestService,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory
        )
        let container = AppContainer(
            authLifecycleTraceStore: nil,
            authenticationShieldCoordinator: CypherAir.AuthenticationShieldCoordinator(),
            authPromptCoordinator: authPromptCoordinator,
            secureEnclave: mockSE,
            keychain: mockKC,
            authManager: authManager,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            protectedDataStorageRoot: protectedDataStorageRoot,
            protectedDataRegistryStore: protectedDataRegistryStore,
            protectedDomainKeyManager: protectedDomainKeyManager,
            protectedDomainRecoveryCoordinator: protectedDomainRecoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            protectedSettingsStore: protectedSettingsStore,
            protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore,
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
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory,
            defaultsSuiteName: suiteName
        )

        let result = AppStartupCoordinator().performStartup(using: container)

        XCTAssertNil(result.loadError)
        XCTAssertTrue(keyManagement.keys.isEmpty)
        XCTAssertTrue(defaults.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))
        XCTAssertEqual(defaults.string(forKey: AuthPreferences.modifyExpiryFingerprintKey), fingerprint)
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account
        ))
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account
        ))
    }

    private func makePhase7TemporaryArtifacts(in temporaryDirectory: URL) throws {
        let decryptedDir = temporaryDirectory.appendingPathComponent("decrypted", isDirectory: true)
        let streamingDir = temporaryDirectory.appendingPathComponent("streaming", isDirectory: true)
        let exportURL = temporaryDirectory.appendingPathComponent("export-\(UUID().uuidString)-sample.asc")
        let tutorialDir = temporaryDirectory
            .appendingPathComponent("CypherAirGuidedTutorial-\(UUID().uuidString)", isDirectory: true)

        try FileManager.default.createDirectory(
            at: decryptedDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: streamingDir.appendingPathComponent("op-\(UUID().uuidString)", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(at: tutorialDir, withIntermediateDirectories: true)
        try Data("export".utf8).write(to: exportURL, options: .atomic)
    }
}
