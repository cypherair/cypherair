import Foundation

enum TutorialSandboxContainerError: LocalizedError {
    case directoryCreationFailed
    case vaultUnavailable

    var errorDescription: String? {
        switch self {
        case .directoryCreationFailed:
            String(localized: "guidedTutorial.error.sandboxDirectory", defaultValue: "Could not create isolated tutorial storage.")
        case .vaultUnavailable:
            String(localized: "guidedTutorial.error.sandboxVault", defaultValue: "Could not open the isolated tutorial vault.")
        }
    }
}

/// The tutorial's own object graph over a sandbox vault: software keys, rows
/// in memory, domain files in a temporary directory erased at cleanup, and no
/// prompts. Nothing here reaches the real vault.
final class TutorialSandboxContainer {
    let engine: PgpEngine
    let vault: AppVault
    let appSettings: AppSettingsCoordinator
    let keyManagement: KeyManagementService
    let contactService: ContactService
    let encryptionService: EncryptionService
    let decryptionService: DecryptionService
    let signingService: SigningService
    let certificateSignatureService: CertificateSignatureService
    let qrService: QRService
    let selfTestService: SelfTestService
    let sandboxDirectory: URL

    private var didCleanup = false

    init(temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()) throws {
        let sandboxDirectory: URL
        do {
            sandboxDirectory = try temporaryArtifactStore.makeTutorialSandboxDirectory()
        } catch {
            throw TutorialSandboxContainerError.directoryCreationFailed
        }
        self.sandboxDirectory = sandboxDirectory
        do {
            vault = try AppVault.sandbox(directory: sandboxDirectory.appendingPathComponent("vault", isDirectory: true))
        } catch {
            throw TutorialSandboxContainerError.vaultUnavailable
        }
        engine = PgpEngine()
        let appSettings = AppSettingsCoordinator(persistence: InMemoryAppSettingsStore())
        appSettings.load()
        self.appSettings = appSettings
        let keyAdapter = PGPKeyOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let selfTestAdapter = PGPSelfTestOperationAdapter(engine: engine)
        keyManagement = KeyManagementService(
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            vault: vault,
            authenticationPromptCoordinator: AuthenticationPromptCoordinator(),
            metadataPersistence: VaultKeyMetadataStore(vault: vault)
        )
        contactService = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            vault: vault
        )
        let services = AppContainer.makePgpServiceGraph(
            engine: engine,
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            contactImportAdapter: contactImportAdapter,
            selfTestAdapter: selfTestAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            temporaryArtifactStore: temporaryArtifactStore
        )
        encryptionService = services.encryptionService
        decryptionService = services.decryptionService
        signingService = services.signingService
        certificateSignatureService = services.certificateSignatureService
        qrService = services.qrService
        selfTestService = services.selfTestService
    }

    /// Opens the sandbox vault on first use and loads keys and contacts from it.
    func openIfNeeded() async throws {
        try Task.checkCancellation()
        if !vault.isUnlocked {
            do {
                try await vault.bootstrapSandbox()
            } catch {
                throw TutorialSandboxContainerError.vaultUnavailable
            }
        }
        try Task.checkCancellation()
        if keyManagement.metadataLoadState != .loaded {
            try keyManagement.loadKeys()
        }
        if !contactService.contactsAvailability.isAvailable {
            let availability = await contactService.openContacts(ownSignerKeys: keyManagement.keys)
            try Task.checkCancellation()
            guard availability.isAvailable else {
                throw TutorialSandboxContainerError.vaultUnavailable
            }
        }
    }

    func cleanup() {
        guard !didCleanup else { return }
        didCleanup = true
        vault.relock()
        try? TemporaryArtifactEraser.erase(at: sandboxDirectory)
    }

    deinit {
        cleanup()
    }
}
