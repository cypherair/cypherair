import Foundation
import Sealing
import Stores
import Vault

/// The production object graph: one vault, the services over it, and the
/// lock controller that opens and closes them.
final class AppContainer: @unchecked Sendable {
    let vault: AppVault
    let appLockController: AppLockController
    let authPromptCoordinator: AuthenticationPromptCoordinator
    let appSettings: AppSettingsCoordinator
    let appSessionOrchestrator: AppSessionOrchestrator
    let engine: PgpEngine
    let keyManagement: KeyManagementService
    let contactService: ContactService
    let encryptionService: EncryptionService
    let decryptionService: DecryptionService
    let signingService: SigningService
    let certificateSignatureService: CertificateSignatureService
    let qrService: QRService
    let selfTestService: SelfTestService
    let temporaryArtifactStore: AppTemporaryArtifactStore
    let localDataResetService: LocalDataResetService
    let localDataResetRestartCoordinator: LocalDataResetRestartCoordinator
    private let loadServicesAfterUnlock: @MainActor () async -> Void

    struct PgpServiceGraph {
        let encryptionService: EncryptionService
        let decryptionService: DecryptionService
        let signingService: SigningService
        let certificateSignatureService: CertificateSignatureService
        let qrService: QRService
        let selfTestService: SelfTestService
    }

    private init(
        vault: AppVault,
        appLockController: AppLockController,
        authPromptCoordinator: AuthenticationPromptCoordinator,
        appSettings: AppSettingsCoordinator,
        appSessionOrchestrator: AppSessionOrchestrator,
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        pgpServices: PgpServiceGraph,
        temporaryArtifactStore: AppTemporaryArtifactStore,
        localDataResetService: LocalDataResetService,
        localDataResetRestartCoordinator: LocalDataResetRestartCoordinator,
        loadServicesAfterUnlock: @escaping @MainActor () async -> Void
    ) {
        self.vault = vault
        self.appLockController = appLockController
        self.authPromptCoordinator = authPromptCoordinator
        self.appSettings = appSettings
        self.appSessionOrchestrator = appSessionOrchestrator
        self.engine = engine
        self.keyManagement = keyManagement
        self.contactService = contactService
        encryptionService = pgpServices.encryptionService
        decryptionService = pgpServices.decryptionService
        signingService = pgpServices.signingService
        certificateSignatureService = pgpServices.certificateSignatureService
        qrService = pgpServices.qrService
        selfTestService = pgpServices.selfTestService
        self.temporaryArtifactStore = temporaryArtifactStore
        self.localDataResetService = localDataResetService
        self.localDataResetRestartCoordinator = localDataResetRestartCoordinator
        self.loadServicesAfterUnlock = loadServicesAfterUnlock
    }

    var lockSurfaceServices: AppLockSurfaceServices {
        AppLockSurfaceServices(
            keyManagement: keyManagement,
            appSessionOrchestrator: appSessionOrchestrator,
            localDataReset: localDataResetService,
            restartCoordinator: localDataResetRestartCoordinator
        )
    }

    @MainActor
    static func makeDefault() -> AppContainer {
        let engine = PgpEngine()
        let vault: AppVault
        do {
            vault = try AppVault.production(engine: engine)
        } catch {
            fatalError("The protected data directory is unavailable: \(error)")
        }
        return compose(vault: vault, engine: engine, custodyGeneration: vault.vault.enclave.isAvailable)
    }

    #if DEBUG
    /// The sandbox vault in a fresh temporary directory; `startUITestSession`
    /// opens it.
    @MainActor
    static func makeUITest() -> AppContainer {
        let engine = PgpEngine()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirUITestVault-\(UUID().uuidString)", isDirectory: true)
        let vault: AppVault
        do {
            vault = try AppVault.sandbox(directory: directory)
        } catch {
            fatalError("The UI-test vault directory is unavailable: \(error)")
        }
        return compose(vault: vault, engine: engine, custodyGeneration: true)
    }

    /// Creates the sandbox vault under `passphrase`, then either opens the
    /// session as if unlocked or leaves the lock surface waiting for it.
    @MainActor
    func startUITestSession(passphrase: String, startsUnlocked: Bool, preloadContact: Bool) {
        Task { @MainActor in
            do {
                try await vault.bootstrap(passphrase: SensitiveBuffer.utf8(passphrase), reason: "")
            } catch {
                return
            }
            guard startsUnlocked else {
                vault.relock()
                appLockController.noteVaultReady()
                return
            }
            await loadServicesAfterUnlock()
            appSessionOrchestrator.recordAuthentication()
            appLockController.noteSessionOpened()
            if preloadContact {
                try? Self.preloadUITestContact(engine: engine, contactService: contactService)
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
            validity: .never,
            suite: .ed25519LegacyCurve25519Legacy
        )
        _ = try contactService.importContact(publicKeyData: generated.publicKeyData)
    }
    #endif

    func sweepTemporaryArtifactsAtLaunch() {
        let temporaryArtifactStore = temporaryArtifactStore
        Task.detached(priority: .utility) {
            _ = temporaryArtifactStore.sweepAbandonedArtifacts()
        }
    }

    @MainActor
    private static func compose(vault: AppVault, engine: PgpEngine, custodyGeneration: Bool) -> AppContainer {
        let authPromptCoordinator = AuthenticationPromptCoordinator()
        let keyAdapter = PGPKeyOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let selfTestAdapter = PGPSelfTestOperationAdapter(engine: engine)
        let publicBindingInspector = PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine)
        let compositeBindingInspector = PGPSecureEnclaveCompositeBindingInspector(engine: engine)
        let temporaryArtifactStore = AppTemporaryArtifactStore()

        let appSettings = AppSettingsCoordinator(persistence: VaultSettingsPersistence(vault: vault))
        let appSessionOrchestrator = AppSessionOrchestrator()

        let keyManagement = KeyManagementService(
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            vault: vault,
            authenticationPromptCoordinator: authPromptCoordinator,
            compositeCustodyRouterContext: CompositeCustodyRouterContext(bindingInspector: compositeBindingInspector),
            secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext(
                publicBindingInspector: publicBindingInspector,
                compositeBindingInspector: compositeBindingInspector
            ),
            metadataPersistence: VaultKeyMetadataStore(vault: vault),
            secureEnclaveCustodyGenerationServiceFactory: custodyGeneration
                ? { catalogStore, invalidationGate, commitCoordinator in
                    SecureEnclaveCustodyGenerationService(
                        certificateBuilder: PGPSecureEnclaveCustodyGenerationAdapter(engine: engine),
                        vault: vault,
                        digestSigner: CustodyOperations(),
                        compositeCertificateBuilder: PGPSecureEnclaveCompositeGenerationAdapter(engine: engine),
                        compositeSigner: CustodyOperations(),
                        catalogStore: catalogStore,
                        resolver: PGPKeyCapabilityResolver(),
                        invalidationGate: invalidationGate,
                        commitCoordinator: commitCoordinator,
                        authenticationPromptCoordinator: authPromptCoordinator
                    )
                }
                : nil,
            secureEnclaveCustodyRecoveryService: SecureEnclaveCustodyGenerationRecoveryService(
                publicBindingInspector: publicBindingInspector,
                vault: vault,
                compositeBindingInspector: compositeBindingInspector
            )
        )
        let contactService = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            vault: vault
        )
        let pgpServices = makePgpServiceGraph(
            engine: engine,
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            contactImportAdapter: contactImportAdapter,
            selfTestAdapter: selfTestAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            temporaryArtifactStore: temporaryArtifactStore
        )

        let loadServicesAfterUnlock: @MainActor () async -> Void = {
            try? keyManagement.loadKeys()
            await contactService.openContacts(ownSignerKeys: keyManagement.keys)
            appSettings.load()
        }
        let appLockController = AppLockController(
            vault: vault,
            gracePeriodProvider: { appSettings.gracePeriodForSession },
            lastAuthenticationDateProvider: { appSessionOrchestrator.lastAuthenticationDate },
            recordSuccessfulAuthentication: { appSessionOrchestrator.recordAuthentication() },
            loadServices: loadServicesAfterUnlock,
            relockServices: {
                try await keyManagement.relockVault()
                try await contactService.relockVault()
                appSettings.relock()
            },
            contentClearHandler: {
                appSettings.relock()
                appSessionOrchestrator.requestContentClear()
            },
            operationPromptInProgressProvider: {
                authPromptCoordinator.isOperationPromptInProgress
            }
        )
        #if os(macOS)
        wireOperationPromptLifecycle(from: authPromptCoordinator, to: appLockController)
        #endif

        let localDataResetService = LocalDataResetService(
            vault: vault,
            appSettings: appSettings,
            keyManagement: keyManagement,
            contactService: contactService,
            selfTestService: pgpServices.selfTestService,
            appSessionOrchestrator: appSessionOrchestrator,
            appLockController: appLockController,
            temporaryArtifactStore: temporaryArtifactStore
        )
        return AppContainer(
            vault: vault,
            appLockController: appLockController,
            authPromptCoordinator: authPromptCoordinator,
            appSettings: appSettings,
            appSessionOrchestrator: appSessionOrchestrator,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            pgpServices: pgpServices,
            temporaryArtifactStore: temporaryArtifactStore,
            localDataResetService: localDataResetService,
            localDataResetRestartCoordinator: LocalDataResetRestartCoordinator(),
            loadServicesAfterUnlock: loadServicesAfterUnlock
        )
    }

    #if os(macOS)
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

    /// The message, key, and self-test services over one key-management
    /// service. Every private operation routes through the vault's custody.
    static func makePgpServiceGraph(
        engine: PgpEngine,
        keyAdapter: PGPKeyOperationAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        contactImportAdapter: PGPContactImportAdapter,
        selfTestAdapter: PGPSelfTestOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        temporaryArtifactStore: AppTemporaryArtifactStore
    ) -> PgpServiceGraph {
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let custody = CustodyOperations()
        let router = {
            keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine)
            )
        }
        keyManagement.configurePrivateKeyExpiryMutationService(
            PrivateKeyExpiryMutationService(
                router: router(),
                keyAdapter: keyAdapter,
                digestSigner: custody,
                compositeSigner: custody
            )
        )
        keyManagement.configurePrivateKeySelectiveRevocationService(
            PrivateKeySelectiveRevocationService(
                router: router(),
                certificateAdapter: certificateAdapter,
                digestSigner: custody,
                compositeSigner: custody
            )
        )
        return PgpServiceGraph(
            encryptionService: EncryptionService(
                keyManagement: keyManagement,
                contactService: contactService,
                textEncryptor: PrivateKeyTextEncryptionService(
                    router: router(),
                    softwarePrivateKeyAccess: keyManagement,
                    messageAdapter: messageAdapter,
                    digestSigner: custody,
                    compositeSigner: custody
                ),
                fileEncryptor: PrivateKeyStreamingFileEncryptionService(
                    router: router(),
                    softwarePrivateKeyAccess: keyManagement,
                    messageAdapter: messageAdapter,
                    digestSigner: custody,
                    compositeSigner: custody
                ),
                temporaryArtifactStore: temporaryArtifactStore
            ),
            decryptionService: DecryptionService(
                messageAdapter: messageAdapter,
                keyManagement: keyManagement,
                contactService: contactService,
                messageDecryptor: PrivateKeyMessageDecryptionService(
                    router: router(),
                    softwarePrivateKeyAccess: keyManagement,
                    messageAdapter: messageAdapter,
                    keyAgreement: custody,
                    compositeDecapsulator: custody
                ),
                fileDecryptor: PrivateKeyStreamingFileDecryptionService(
                    router: router(),
                    softwarePrivateKeyAccess: keyManagement,
                    messageAdapter: messageAdapter,
                    keyAgreement: custody,
                    compositeDecapsulator: custody
                ),
                temporaryArtifactStore: temporaryArtifactStore
            ),
            signingService: SigningService(
                messageAdapter: messageAdapter,
                keyManagement: keyManagement,
                contactService: contactService,
                cleartextSigner: PrivateKeyCleartextSigningService(
                    router: router(),
                    softwarePrivateKeyAccess: keyManagement,
                    messageAdapter: messageAdapter,
                    digestSigner: custody,
                    compositeSigner: custody
                ),
                detachedFileSigner: PrivateKeyDetachedFileSigningService(
                    router: router(),
                    softwarePrivateKeyAccess: keyManagement,
                    messageAdapter: messageAdapter,
                    digestSigner: custody,
                    compositeSigner: custody
                )
            ),
            certificateSignatureService: CertificateSignatureService(
                certificateAdapter: certificateAdapter,
                keyManagement: keyManagement,
                contactService: contactService,
                certificationSigner: PrivateKeyContactCertificationService(
                    router: router(),
                    softwarePrivateKeyAccess: keyManagement,
                    certificateAdapter: certificateAdapter,
                    digestSigner: custody,
                    compositeSigner: custody
                )
            ),
            qrService: QRService(contactImportAdapter: contactImportAdapter),
            selfTestService: SelfTestService(
                selfTestAdapter: selfTestAdapter,
                messageAdapter: messageAdapter
            )
        )
    }
}
