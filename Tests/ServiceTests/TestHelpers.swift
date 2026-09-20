import Foundation
import Sealing
import Stores
import Vault
import XCTest
@testable import CypherAir

enum TestHelpers {
    /// A sandbox vault opened under a known passphrase in its own temporary
    /// directory. Software keys, rows in memory, no prompts.
    struct Sandbox {
        static let passphrase = "correct horse battery staple"

        let vault: AppVault
        let directory: URL

        /// Locks the vault and opens it again through its passphrase, the way
        /// a relaunch would; every cached domain is re-read from disk.
        func reopen() async throws {
            vault.relock()
            let attempt = vault.beginUnlock(reason: "")
            let session = try await attempt.submit(passphrase: SensitiveBuffer.utf8(Self.passphrase))
            _ = vault.adopt(session: session)
        }

        func cleanup() {
            vault.relock()
            try? FileManager.default.removeItem(at: directory)
        }
    }

    static func makeSandbox() async throws -> Sandbox {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirTests-\(UUID().uuidString)", isDirectory: true)
        let vault = try AppVault.sandbox(directory: directory)
        try await vault.bootstrap(passphrase: SensitiveBuffer.utf8(Sandbox.passphrase), reason: "")
        return Sandbox(vault: vault, directory: directory)
    }

    static func makeKeyManagement(
        engine: PgpEngine = PgpEngine(),
        sandbox givenSandbox: Sandbox? = nil,
        memoryInfo: (any MemoryInfoProvidable)? = nil,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator? = nil,
        custodyGeneration: Bool = true,
        provisioningCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        afterImportOffMainActorCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        afterPermanentStoreCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        identityStoreCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        postProvisioningCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        commitDrainWaiterRegisteredCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        relockInvalidationCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil
    ) async throws -> (service: KeyManagementService, sandbox: Sandbox) {
        let sandbox: Sandbox
        if let given = givenSandbox {
            sandbox = given
        } else {
            sandbox = try await makeSandbox()
        }
        let vault = sandbox.vault
        let keyAdapter = PGPKeyOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let publicBindingInspector = PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine)
        let compositeBindingInspector = PGPSecureEnclaveCompositeBindingInspector(engine: engine)
        let promptCoordinator = authenticationPromptCoordinator ?? AuthenticationPromptCoordinator()
        let service = KeyManagementService(
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            vault: vault,
            memoryInfo: memoryInfo ?? SystemMemoryInfo(),
            authenticationPromptCoordinator: promptCoordinator,
            compositeCustodyRouterContext: CompositeCustodyRouterContext(bindingInspector: compositeBindingInspector),
            secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext(
                publicBindingInspector: publicBindingInspector,
                compositeBindingInspector: compositeBindingInspector
            ),
            metadataPersistence: VaultKeyMetadataStore(vault: vault),
            provisioningCheckpoint: provisioningCheckpoint,
            afterImportOffMainActorCheckpoint: afterImportOffMainActorCheckpoint,
            afterPermanentStoreCheckpoint: afterPermanentStoreCheckpoint,
            identityStoreCheckpoint: identityStoreCheckpoint,
            postProvisioningCheckpoint: postProvisioningCheckpoint,
            commitDrainWaiterRegisteredCheckpoint: commitDrainWaiterRegisteredCheckpoint,
            relockInvalidationCheckpoint: relockInvalidationCheckpoint,
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
                        authenticationPromptCoordinator: promptCoordinator
                    )
                }
                : nil,
            secureEnclaveCustodyRecoveryService: SecureEnclaveCustodyGenerationRecoveryService(
                publicBindingInspector: publicBindingInspector,
                vault: vault,
                compositeBindingInspector: compositeBindingInspector
            )
        )
        try service.loadKeys()
        return (service, sandbox)
    }

    /// A key-management service over a sandbox vault that was never opened:
    /// for screen models that inject their own key actions.
    static func makeLockedKeyManagement(engine: PgpEngine = PgpEngine()) -> KeyManagementService {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirTests-\(UUID().uuidString)", isDirectory: true)
        let vault = try! AppVault.sandbox(directory: directory)
        return KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            vault: vault,
            authenticationPromptCoordinator: AuthenticationPromptCoordinator(),
            metadataPersistence: VaultKeyMetadataStore(vault: vault)
        )
    }

    static func makeContactService(
        engine: PgpEngine = PgpEngine(),
        sandbox givenSandbox: Sandbox? = nil
    ) async throws -> (service: ContactService, sandbox: Sandbox) {
        let sandbox: Sandbox
        if let given = givenSandbox {
            sandbox = given
        } else {
            sandbox = try await makeSandbox()
        }
        let service = ContactService(engine: engine, vault: sandbox.vault)
        await service.openContacts(ownSignerKeys: [])
        return (service, sandbox)
    }

    @discardableResult
    static func generateAndStoreKey(
        service: KeyManagementService,
        suite: PGPKeySuite,
        name: String = "Test User",
        email: String? = "test@example.com"
    ) async throws -> PGPKeyIdentity {
        try await service.generateKey(
            name: name,
            email: email,
            validity: .never,
            suite: suite
        )
    }

    @discardableResult
    static func generateLegacyKey(
        service: KeyManagementService,
        name: String = "Alice",
        email: String? = "alice@example.com"
    ) async throws -> PGPKeyIdentity {
        try await generateAndStoreKey(service: service, suite: .ed25519LegacyCurve25519Legacy, name: name, email: email)
    }

    @discardableResult
    static func generateModernHighKey(
        service: KeyManagementService,
        name: String = "Bob",
        email: String? = "bob@example.com"
    ) async throws -> PGPKeyIdentity {
        try await generateAndStoreKey(service: service, suite: .ed448X448, name: name, email: email)
    }

    /// Imports a fixture secret certificate as a portable key. Fixtures carry
    /// unprotected secrets and import refuses those, so the engine re-protects
    /// the key under a throwaway passphrase first.
    @discardableResult
    static func provisionFixtureBackedIdentity(
        secretCertData: Data,
        engine: PgpEngine,
        service: KeyManagementService,
        isDefault: Bool = false
    ) async throws -> PGPKeyIdentity {
        let passphrase = "fixture-passphrase-\(UUID().uuidString)"
        let protected = try engine.exportSecretKey(certData: secretCertData, passphrase: passphrase)
        let identity = try await service.importKey(armoredData: protected, passphrase: passphrase)
        if isDefault {
            try service.setDefaultKey(fingerprint: identity.fingerprint)
        }
        return try XCTUnwrap(service.keys.first { $0.fingerprint == identity.fingerprint })
    }

    static func makeServiceStack(
        engine: PgpEngine = PgpEngine(),
        memoryInfo: (any MemoryInfoProvidable)? = nil
    ) async throws -> ServiceStack {
        let sandbox = try await makeSandbox()
        let (keyMgmt, _) = try await makeKeyManagement(engine: engine, sandbox: sandbox, memoryInfo: memoryInfo)
        let (contactSvc, _) = try await makeContactService(engine: engine, sandbox: sandbox)
        let temporaryArtifactStore = AppTemporaryArtifactStore(temporaryDirectory: sandbox.directory)
        let services = AppContainer.makePgpServiceGraph(
            engine: engine,
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            contactImportAdapter: PGPContactImportAdapter(engine: engine),
            selfTestAdapter: PGPSelfTestOperationAdapter(engine: engine),
            keyManagement: keyMgmt,
            contactService: contactSvc,
            temporaryArtifactStore: temporaryArtifactStore
        )
        return ServiceStack(
            engine: engine,
            sandbox: sandbox,
            keyManagement: keyMgmt,
            contactService: contactSvc,
            encryptionService: services.encryptionService,
            decryptionService: services.decryptionService,
            signingService: services.signingService,
            certificateSignatureService: services.certificateSignatureService,
            temporaryArtifactStore: temporaryArtifactStore
        )
    }

    struct ServiceStack {
        let engine: PgpEngine
        let sandbox: Sandbox
        let keyManagement: KeyManagementService
        let contactService: ContactService
        let encryptionService: EncryptionService
        let decryptionService: DecryptionService
        let signingService: SigningService
        let certificateSignatureService: CertificateSignatureService
        let temporaryArtifactStore: AppTemporaryArtifactStore

        var tempDir: URL { sandbox.directory }

        func cleanup() {
            sandbox.cleanup()
        }
    }

    static func makeContactCertificationSigner(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        certificateAdapter: PGPCertificateOperationAdapter? = nil
    ) -> PrivateKeyContactCertificationService {
        PrivateKeyContactCertificationService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine)
            ),
            softwarePrivateKeyAccess: keyManagement,
            certificateAdapter: certificateAdapter ?? PGPCertificateOperationAdapter(engine: engine),
            digestSigner: CustodyOperations(),
            compositeSigner: CustodyOperations()
        )
    }

    static func cleanupTempDir(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }
}

extension ContactService {
    convenience init(engine: PgpEngine, vault: AppVault) {
        self.init(
            contactImportAdapter: PGPContactImportAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            vault: vault
        )
    }

    var testContactKeyRecords: [ContactKeyRecord] {
        guard let snapshot = try? currentContactsDomainSnapshot() else {
            return []
        }
        return snapshot.keyRecords
            .sorted { lhs, rhs in
                if lhs.contactId != rhs.contactId {
                    return lhs.contactId < rhs.contactId
                }
                return lhs.fingerprint < rhs.fingerprint
            }
    }

    var testContactFingerprints: [String] {
        testContactKeyRecords.map(\.fingerprint)
    }
}

extension ContactSnapshotMutator {
    init(
        engine: PgpEngine,
        importMatcher: ContactImportMatcher = ContactImportMatcher()
    ) {
        self.init(
            contactImportAdapter: PGPContactImportAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            importMatcher: importMatcher
        )
    }
}
