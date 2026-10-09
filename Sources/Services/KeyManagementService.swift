import Foundation
import LocalAuthentication
import Stores

@Observable
final class KeyManagementService: @unchecked Sendable {
    private(set) var keys: [PGPKeyIdentity] = []
    private(set) var metadataLoadState: KeyMetadataLoadState = .locked
    private(set) var secureEnclaveCustodyRecoveryReport: SecureEnclaveCustodyGenerationRecoveryReport = .empty

    private let certificateAdapter: PGPCertificateOperationAdapter
    private let vault: AppVault
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService
    private let provisioningService: KeyProvisioningService
    private let secureEnclaveCustodyGenerationService: SecureEnclaveCustodyGenerationService?
    private let secureEnclaveCustodyRecoveryService: (any SecureEnclaveCustodyGenerationRecoveryClassifying)?
    private let exportService: KeyExportService
    private let selectiveRevocationService: SelectiveRevocationService
    private let mutationService: KeyMutationService
    private let provisioningInvalidationGate: KeyProvisioningInvalidationGate
    private let provisioningCommitCoordinator: KeyProvisioningCommitCoordinator
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let postProvisioningCheckpoint: KeyProvisioningService.ProvisioningCheckpoint?
    private let commitDrainWaiterRegisteredCheckpoint: KeyProvisioningService.ProvisioningCheckpoint?
    private let relockInvalidationCheckpoint: KeyProvisioningService.ProvisioningCheckpoint?
    private let compositeCustodyRouterContext: CompositeCustodyRouterContext?

    var isSecureEnclaveCustodyGenerationAvailable: Bool {
        secureEnclaveCustodyGenerationService != nil
    }

    init(
        keyAdapter: PGPKeyOperationAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        vault: AppVault,
        memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo(),
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        compositeCustodyRouterContext: CompositeCustodyRouterContext? = nil,
        secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext? = nil,
        metadataPersistence: any KeyMetadataPersistence,
        provisioningCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        afterImportOffMainActorCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        afterPermanentStoreCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        identityStoreCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        postProvisioningCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        commitDrainWaiterRegisteredCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        relockInvalidationCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        secureEnclaveCustodyGenerationServiceFactory: ((
            KeyCatalogStore,
            KeyProvisioningInvalidationGate,
            KeyProvisioningCommitCoordinator
        ) -> SecureEnclaveCustodyGenerationService)? = nil,
        secureEnclaveCustodyRecoveryService: (any SecureEnclaveCustodyGenerationRecoveryClassifying)? = nil
    ) {
        let catalogStore = KeyCatalogStore(metadataStore: metadataPersistence)
        let privateKeyAccessService = PrivateKeyAccessService(
            vault: vault,
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            certificatePrimaryFingerprint: keyAdapter.certificatePrimaryFingerprintInspector()
        )
        let provisioningInvalidationGate = KeyProvisioningInvalidationGate()
        let provisioningCommitCoordinator = KeyProvisioningCommitCoordinator()
        self.certificateAdapter = certificateAdapter
        self.vault = vault
        self.catalogStore = catalogStore
        self.privateKeyAccessService = privateKeyAccessService
        self.provisioningInvalidationGate = provisioningInvalidationGate
        self.provisioningCommitCoordinator = provisioningCommitCoordinator
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.postProvisioningCheckpoint = postProvisioningCheckpoint
        self.commitDrainWaiterRegisteredCheckpoint = commitDrainWaiterRegisteredCheckpoint
        self.relockInvalidationCheckpoint = relockInvalidationCheckpoint
        self.compositeCustodyRouterContext = compositeCustodyRouterContext
        self.provisioningService = KeyProvisioningService(
            keyAdapter: keyAdapter,
            vault: vault,
            memoryInfo: memoryInfo,
            catalogStore: catalogStore,
            invalidationGate: provisioningInvalidationGate,
            commitCoordinator: provisioningCommitCoordinator,
            beforePermanentStorageCheckpoint: provisioningCheckpoint,
            afterImportOffMainActorCheckpoint: afterImportOffMainActorCheckpoint,
            afterPermanentStoreCheckpoint: afterPermanentStoreCheckpoint,
            afterIdentityStoreCheckpoint: identityStoreCheckpoint
        )
        self.secureEnclaveCustodyGenerationService = secureEnclaveCustodyGenerationServiceFactory?(
            catalogStore,
            provisioningInvalidationGate,
            provisioningCommitCoordinator
        )
        self.secureEnclaveCustodyRecoveryService = secureEnclaveCustodyRecoveryService
        self.exportService = KeyExportService(
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            catalogStore: catalogStore,
            privateKeyAccessService: privateKeyAccessService,
            memoryInfo: memoryInfo
        )
        self.selectiveRevocationService = SelectiveRevocationService(
            certificateAdapter: certificateAdapter,
            catalogStore: catalogStore,
            privateKeyAccessService: privateKeyAccessService
        )
        self.mutationService = KeyMutationService(
            keyAdapter: keyAdapter,
            vault: vault,
            catalogStore: catalogStore,
            privateKeyAccessService: privateKeyAccessService,
            secureEnclaveCustodyDeletionContext: secureEnclaveCustodyDeletionContext
        )
    }

    func loadKeys() throws {
        metadataLoadState = .loading
        do {
            try catalogStore.loadAll()
            syncKeysAndSecureEnclaveRecoveryReport()
            metadataLoadState = .loaded
        } catch {
            catalogStore.clearInMemoryIdentities()
            keys = []
            secureEnclaveCustodyRecoveryReport = .empty
            metadataLoadState = .recoveryNeeded
            throw error
        }
    }

    func markKeyMetadataLocked() {
        catalogStore.clearInMemoryIdentities()
        keys = []
        secureEnclaveCustodyRecoveryReport = .empty
        metadataLoadState = .locked
    }

    func markKeyMetadataRecoveryNeeded() {
        catalogStore.clearInMemoryIdentities()
        keys = []
        secureEnclaveCustodyRecoveryReport = .empty
        metadataLoadState = .recoveryNeeded
    }

    func resetInMemoryStateAfterLocalDataReset() {
        provisioningInvalidationGate.invalidate()
        markKeyMetadataLocked()
    }

    func generateKey(name: String, email: String?, validity: PGPKeyValidity, family: PGPKeyFamily) async throws -> PGPKeyIdentity {
        if let suite = family.softwareGenerationSuite {
            return try await generateKey(name: name, email: email, validity: validity, suite: suite)
        }
        return try await generateSecureEnclaveCustodyKey(name: name, email: email, validity: validity, family: family)
    }

    func generateKey(name: String, email: String?, validity: PGPKeyValidity, suite: PGPKeySuite) async throws -> PGPKeyIdentity {
        let token = provisioningInvalidationGate.makeToken()
        try Task.checkCancellation()
        try provisioningInvalidationGate.checkValid(token)
        let identity = try await provisioningService.generateKey(name: name, email: email, validity: validity, suite: suite, invalidationToken: token)
        if let postProvisioningCheckpoint {
            await postProvisioningCheckpoint()
        }
        try provisioningInvalidationGate.checkValid(token)
        syncKeysAndSecureEnclaveRecoveryReport()
        return identity
    }

    func generateSecureEnclaveCustodyKey(name: String, email: String?, validity: PGPKeyValidity, family: PGPKeyFamily) async throws -> PGPKeyIdentity {
        guard let secureEnclaveCustodyGenerationService else {
            throw CypherAirError.keyOperationUnavailable(category: .operationUnavailableByPolicy)
        }
        let token = provisioningInvalidationGate.makeToken()
        let identity: PGPKeyIdentity
        do {
            identity = try await secureEnclaveCustodyGenerationService.generateKey(name: name, email: email, validity: validity, family: family, invalidationToken: token)
        } catch let error as CustodyError {
            throw CypherAirError.keyOperationUnavailable(category: error.failureCategory)
        }
        if let postProvisioningCheckpoint {
            await postProvisioningCheckpoint()
        }
        try provisioningInvalidationGate.checkValid(token)
        syncKeysAndSecureEnclaveRecoveryReport()
        return identity
    }

    func importKey(armoredData: Data, passphrase: String) async throws -> PGPKeyIdentity {
        let token = provisioningInvalidationGate.makeToken()
        try Task.checkCancellation()
        try provisioningInvalidationGate.checkValid(token)
        let identity = try await provisioningService.importKey(armoredData: armoredData, passphrase: passphrase, invalidationToken: token)
        if let postProvisioningCheckpoint {
            await postProvisioningCheckpoint()
        }
        try provisioningInvalidationGate.checkValid(token)
        syncKeysAndSecureEnclaveRecoveryReport()
        return identity
    }

    func exportKeyBackupData(fingerprint: String, passphrase: String) async throws -> Data {
        try await exportService.exportKey(fingerprint: fingerprint, passphrase: passphrase)
    }

    func confirmKeyBackupExported(fingerprint: String) throws {
        try catalogStore.markBackedUp(fingerprint: fingerprint)
        syncKeysAndSecureEnclaveRecoveryReport()
    }

    func exportRevocationCertificate(fingerprint: String) async throws -> Data {
        let armoredRevocation = try await exportService.exportRevocationCertificate(fingerprint: fingerprint)
        syncKeysAndSecureEnclaveRecoveryReport()
        return armoredRevocation
    }

    func exportSubkeyRevocationCertificate(fingerprint: String, subkeySelection: SubkeySelectionOption) async throws -> Data {
        try await selectiveRevocationService.exportSubkeyRevocationCertificate(fingerprint: fingerprint, subkeySelection: subkeySelection)
    }

    func exportUserIdRevocationCertificate(fingerprint: String, userIdSelection: UserIdSelectionOption) async throws -> Data {
        try await selectiveRevocationService.exportUserIdRevocationCertificate(fingerprint: fingerprint, userIdSelection: userIdSelection)
    }

    func modifyExpiry(fingerprint: String, newValidity: PGPKeyValidity) async throws -> PGPKeyIdentity {
        defer { syncKeysAndSecureEnclaveRecoveryReport() }
        return try await mutationService.modifyExpiry(fingerprint: fingerprint, newValidity: newValidity)
    }

    func deleteKey(fingerprint: String) throws {
        defer { syncKeysAndSecureEnclaveRecoveryReport() }
        try mutationService.deleteKey(fingerprint: fingerprint)
    }

    func setDefaultKey(fingerprint: String) throws {
        defer { syncKeysAndSecureEnclaveRecoveryReport() }
        try mutationService.setDefaultKey(fingerprint: fingerprint)
    }

    var defaultKey: PGPKeyIdentity? {
        keys.first(where: \.isDefault)
    }

    func encryptToSelfIdentity(fingerprint: String?) throws -> PGPKeyIdentity {
        if let fingerprint {
            guard let key = keys.first(where: { $0.fingerprint == fingerprint }) else {
                throw CypherAirError.encryptionFailed(
                    reason: String(
                        localized: "encrypt.encryptToSelf.staleSelection",
                        defaultValue: "Your Encrypt to Self key is no longer available. Review the selection and try again."
                    )
                )
            }
            return key
        }
        guard let defaultKey else {
            throw CypherAirError.noKeySelected
        }
        return defaultKey
    }

    func exportPublicKey(fingerprint: String) throws -> Data {
        try exportService.exportPublicKey(fingerprint: fingerprint)
    }

    func loadSelectionCatalog(fingerprint: String) async throws -> CertificateSelectionCatalog {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.keyMetadataUnavailable
        }
        return try await Self.discoverSelectionCatalogOffMainActor(
            certificateAdapter: certificateAdapter,
            certData: identity.publicKeyData,
            expectedFingerprint: identity.fingerprint
        )
    }

    func unwrapPrivateKey(fingerprint: String) async throws -> Data {
        try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
    }

    func makePrivateKeyOperationRouter(
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting
    ) -> PrivateKeyOperationRouter {
        PrivateKeyOperationRouter(
            catalogStore: catalogStore,
            resolver: resolver,
            vault: vault,
            publicBindingInspector: publicBindingInspector,
            compositeBindingInspector: compositeCustodyRouterContext?.bindingInspector,
            authenticationPromptCoordinator: authenticationPromptCoordinator
        )
    }

    func configurePrivateKeyExpiryMutationService(_ service: any PrivateKeyExpiryMutationRouting) {
        mutationService.configureExpiryMutationService(service)
    }

    func configurePrivateKeySelectiveRevocationService(_ service: any PrivateKeySelectiveRevocationRouting) {
        selectiveRevocationService.configureRevocationRoutingService(service)
    }

    @concurrent
    private static func discoverSelectionCatalogOffMainActor(
        certificateAdapter: PGPCertificateOperationAdapter,
        certData: Data,
        expectedFingerprint: String
    ) async throws -> CertificateSelectionCatalog {
        try certificateAdapter.validatedCatalog(certData: certData, expectedFingerprint: expectedFingerprint)
    }

    private func syncKeysAndSecureEnclaveRecoveryReport() {
        keys = catalogStore.keys
        guard let secureEnclaveCustodyRecoveryService else {
            secureEnclaveCustodyRecoveryReport = .empty
            return
        }
        secureEnclaveCustodyRecoveryReport = secureEnclaveCustodyRecoveryService.classify(identities: keys)
    }
}

extension KeyManagementService: VaultRelockParticipant {
    func relockVault() async throws {
        provisioningInvalidationGate.invalidate()
        if let relockInvalidationCheckpoint {
            await relockInvalidationCheckpoint()
        }
        await provisioningCommitCoordinator.waitForActiveCommitsToFinish(
            waiterRegisteredCheckpoint: commitDrainWaiterRegisteredCheckpoint
        )
        markKeyMetadataLocked()
    }
}
