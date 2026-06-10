import Foundation
import XCTest
@testable import CypherAir

/// Shared test infrastructure for Services layer tests.
/// Creates mock-backed service instances for integration-style testing.
enum TestHelpers {
    // MARK: - KeyManagementService Factory

    /// Create a KeyManagementService backed by mock SE, Keychain, and Authenticator.
    /// Returns the service and all three mocks for verification.
    static func makeKeyManagement(
        engine: PgpEngine = PgpEngine(),
        memoryInfo: (any MemoryInfoProvidable)? = nil,
        privateKeyControlStore: (any PrivateKeyControlStoreProtocol)? = nil,
        metadataPersistence: (any KeyMetadataPersistence)? = nil
    ) -> (
        service: KeyManagementService,
        mockSE: MockSecureEnclave,
        mockKC: MockKeychain,
        mockAuth: MockAuthenticator,
        metadataPersistence: any KeyMetadataPersistence
    ) {
        let mockSE = MockSecureEnclave()
        let mockKC = MockKeychain()
        let mockAuth = MockAuthenticator()
        let privateKeyControlStore = privateKeyControlStore ?? InMemoryPrivateKeyControlStore(mode: .standard)
        let metadataPersistence = metadataPersistence ?? InMemoryKeyMetadataStore()
        let keyAdapter = PGPKeyOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)

        let service: KeyManagementService
        if let memInfo = memoryInfo {
            service = KeyManagementService(
                keyAdapter: keyAdapter, certificateAdapter: certificateAdapter, secureEnclave: mockSE,
                keychain: mockKC, authenticator: mockAuth,
                memoryInfo: memInfo,
                defaults: .standard,
                privateKeyControlStore: privateKeyControlStore,
                metadataPersistence: metadataPersistence
            )
        } else {
            service = KeyManagementService(
                keyAdapter: keyAdapter, certificateAdapter: certificateAdapter, secureEnclave: mockSE,
                keychain: mockKC, authenticator: mockAuth,
                defaults: .standard,
                privateKeyControlStore: privateKeyControlStore,
                metadataPersistence: metadataPersistence
            )
        }

        return (service, mockSE, mockKC, mockAuth, metadataPersistence)
    }

    // MARK: - ContactService Factory

    /// Create a ContactService using a temporary directory for contacts storage.
    /// Returns the service and the temp directory URL (caller should clean up in tearDown).
    static func makeContactService(
        engine: PgpEngine = PgpEngine()
    ) async -> (service: ContactService, tempDir: URL) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirTests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let wrappingRootKey = Data(repeating: 0xA4, count: 32)
        let contactsDomainStore = try? makeContactsDomainStore(
            engine: engine,
            contactsDirectory: tempDir,
            wrappingRootKey: wrappingRootKey
        )

        let service = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            contactsDomainStore: contactsDomainStore
        )
        await openContactsForTests(
            service,
            wrappingRootKey: wrappingRootKey
        )
        return (service, tempDir)
    }

    static func makeContactsDomainStore(
        engine: PgpEngine,
        contactsDirectory: URL,
        wrappingRootKey: Data = Data(repeating: 0xA4, count: 32)
    ) throws -> ContactsDomainStore {
        let storageRoot = ProtectedDataStorageRoot(
            baseDirectory: contactsDirectory.appendingPathComponent(
                "protected-contacts",
                isDirectory: true
            )
        )
        let registryStore = ProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.contacts.\(UUID().uuidString)"
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
            domainKeyManager: ProtectedDomainKeyManager(storageRoot: storageRoot),
            currentWrappingRootKey: { wrappingRootKey }
        )
    }

    @discardableResult
    static func openContactsForTests(
        _ service: ContactService,
        wrappingRootKey: Data = Data(repeating: 0xA4, count: 32)
    ) async -> ContactsAvailability {
        await service.openContactsAfterPostUnlock(
            gateDecision: ContactsPostAuthGateDecision(
                postUnlockOutcome: .opened([ContactsDomainStore.domainID]),
                frameworkState: .sessionAuthorized
            ),
            wrappingRootKey: { wrappingRootKey }
        )
    }

    // MARK: - Key Generation Helpers

    /// Generate a key pair and store it in the mock-backed KeyManagementService.
    /// Returns the PGPKeyIdentity of the generated key.
    @discardableResult
    static func generateAndStoreKey(
        service: KeyManagementService,
        profile: PGPKeyProfile,
        name: String = "Test User",
        email: String? = "test@example.com"
    ) async throws -> PGPKeyIdentity {
        try await service.generateKey(
            name: name,
            email: email,
            expirySeconds: nil,
            profile: profile
        )
    }

    /// Generate a Profile A key and return its identity.
    @discardableResult
    static func generateProfileAKey(
        service: KeyManagementService,
        name: String = "Alice",
        email: String? = "alice@example.com"
    ) async throws -> PGPKeyIdentity {
        try await generateAndStoreKey(service: service, profile: .universal, name: name, email: email)
    }

    /// Generate a Profile B key and return its identity.
    @discardableResult
    static func generateProfileBKey(
        service: KeyManagementService,
        name: String = "Bob",
        email: String? = "bob@example.com"
    ) async throws -> PGPKeyIdentity {
        try await generateAndStoreKey(service: service, profile: .advanced, name: name, email: email)
    }

    /// Provision an unencrypted secret-cert fixture into the mock-backed key management stack
    /// by SE-wrapping it, persisting the wrapped bundle and metadata, then reloading the service.
    ///
    /// This intentionally does not go through `KeyManagementService.importKey(...)`, because
    /// test fixtures such as `ffi_detailed_recipient_secret.gpg` are not passphrase-protected.
    @discardableResult
    static func provisionFixtureBackedIdentity(
        secretCertData: Data,
        engine: PgpEngine,
        service: KeyManagementService,
        mockSE: MockSecureEnclave,
        mockKC: MockKeychain,
        metadataPersistence: any KeyMetadataPersistence,
        isDefault: Bool = false
    ) throws -> PGPKeyIdentity {
        let info = try engine.parseKeyInfo(keyData: secretCertData)
        let metadata = PGPKeyMetadataAdapter.metadata(from: info)
        let armoredPublicKey = try engine.armorPublicKey(certData: secretCertData)
        let publicKeyData = try engine.dearmor(armored: armoredPublicKey)

        let handle = try mockSE.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try mockSE.wrap(
            privateKey: secretCertData,
            using: handle,
            fingerprint: metadata.fingerprint
        )

        let bundleStore = KeyBundleStore(keychain: mockKC)
        try bundleStore.saveBundle(bundle, fingerprint: metadata.fingerprint)

        let identity = PGPKeyIdentity(
            fingerprint: metadata.fingerprint,
            keyVersion: metadata.keyVersion,
            profile: metadata.profile,
            userId: metadata.userId,
            hasEncryptionSubkey: metadata.hasEncryptionSubkey,
            isRevoked: metadata.isRevoked,
            isExpired: metadata.isExpired,
            isDefault: isDefault,
            isBackedUp: false,
            publicKeyData: publicKeyData,
            revocationCert: Data(),
            primaryAlgo: metadata.primaryAlgo,
            subkeyAlgo: metadata.subkeyAlgo,
            expiryDate: metadata.expiryDate,
            openPGPConfigurationIdentity: metadata.profile.openPGPConfiguration.identity,
            privateKeyCustodyKind: .softwareSecretCertificate
        )

        try metadataPersistence.save(identity)
        try service.loadKeys()

        return identity
    }

    // MARK: - Full Service Stack Factory

    /// Create a complete service stack (KeyManagement + Contact + Encryption + Decryption
    /// + PasswordMessage + Signing)
    /// backed by mocks. Useful for end-to-end integration tests.
    static func makeServiceStack(
        engine: PgpEngine = PgpEngine(),
        memoryInfo: (any MemoryInfoProvidable)? = nil
    ) async -> ServiceStack {
        let (keyMgmt, mockSE, mockKC, mockAuth, metadataPersistence) = makeKeyManagement(engine: engine, memoryInfo: memoryInfo)
        let (contactSvc, tempDir) = await makeContactService(engine: engine)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let selfTestAdapter = PGPSelfTestOperationAdapter(engine: engine)
        let textEncryptor = makeTextEncryptor(
            engine: engine,
            keyManagement: keyMgmt,
            messageAdapter: messageAdapter
        )
        let fileEncryptor = makeFileEncryptor(
            engine: engine,
            keyManagement: keyMgmt,
            messageAdapter: messageAdapter
        )
        let passwordMessageEncryptor = makePasswordMessageEncryptor(
            engine: engine,
            keyManagement: keyMgmt,
            messageAdapter: messageAdapter
        )
        let expiryMutator = makeExpiryMutator(
            engine: engine,
            keyManagement: keyMgmt
        )
        keyMgmt.configurePrivateKeyExpiryMutationService(expiryMutator)
        keyMgmt.configurePrivateKeySelectiveRevocationService(
            makeSelectiveRevocationService(
                engine: engine,
                keyManagement: keyMgmt
            )
        )

        let encryptionSvc = EncryptionService(
            keyManagement: keyMgmt,
            contactService: contactSvc,
            textEncryptor: textEncryptor,
            fileEncryptor: fileEncryptor
        )
        let messageDecryptor = makeMessageDecryptor(
            engine: engine,
            keyManagement: keyMgmt,
            messageAdapter: messageAdapter
        )
        let fileDecryptor = makeFileDecryptor(
            engine: engine,
            keyManagement: keyMgmt,
            messageAdapter: messageAdapter
        )
        let decryptionSvc = DecryptionService(
            messageAdapter: messageAdapter,
            keyManagement: keyMgmt,
            contactService: contactSvc,
            messageDecryptor: messageDecryptor,
            fileDecryptor: fileDecryptor
        )
        let passwordMessageSvc = PasswordMessageService(
            messageAdapter: messageAdapter,
            keyManagement: keyMgmt,
            contactService: contactSvc,
            passwordEncryptor: passwordMessageEncryptor
        )
        let cleartextSigner = makeCleartextSigner(
            engine: engine,
            keyManagement: keyMgmt,
            messageAdapter: messageAdapter
        )
        let detachedFileSigner = makeDetachedFileSigner(
            engine: engine,
            keyManagement: keyMgmt,
            messageAdapter: messageAdapter
        )
        let contactCertificationSigner = makeContactCertificationSigner(
            engine: engine,
            keyManagement: keyMgmt,
            certificateAdapter: certificateAdapter
        )
        let signingSvc = SigningService(
            messageAdapter: messageAdapter,
            keyManagement: keyMgmt,
            contactService: contactSvc,
            cleartextSigner: cleartextSigner,
            detachedFileSigner: detachedFileSigner
        )
        let certificateSignatureSvc = CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: keyMgmt,
            contactService: contactSvc,
            certificationSigner: contactCertificationSigner
        )

        return ServiceStack(
            engine: engine,
            messageAdapter: messageAdapter,
            keyManagement: keyMgmt,
            metadataPersistence: metadataPersistence,
            contactService: contactSvc,
            textEncryptor: textEncryptor,
            fileEncryptor: fileEncryptor,
            passwordMessageEncryptor: passwordMessageEncryptor,
            detachedFileSigner: detachedFileSigner,
            encryptionService: encryptionSvc,
            decryptionService: decryptionSvc,
            passwordMessageService: passwordMessageSvc,
            signingService: signingSvc,
            certificateSignatureService: certificateSignatureSvc,
            selfTestService: SelfTestService(
                selfTestAdapter: selfTestAdapter,
                messageAdapter: messageAdapter
            ),
            mockSE: mockSE,
            mockKC: mockKC,
            mockAuth: mockAuth,
            tempDir: tempDir
        )
    }

    /// Holds all services and mocks for a complete test environment.
    struct ServiceStack {
        let engine: PgpEngine
        let messageAdapter: PGPMessageOperationAdapter
        let keyManagement: KeyManagementService
        let metadataPersistence: any KeyMetadataPersistence
        let contactService: ContactService
        let textEncryptor: any TextMessageEncrypting
        let fileEncryptor: any StreamingFileEncrypting
        let passwordMessageEncryptor: any PasswordMessageEncrypting
        let detachedFileSigner: any DetachedFileSigning
        let encryptionService: EncryptionService
        let decryptionService: DecryptionService
        let passwordMessageService: PasswordMessageService
        let signingService: SigningService
        let certificateSignatureService: CertificateSignatureService
        let selfTestService: SelfTestService
        let mockSE: MockSecureEnclave
        let mockKC: MockKeychain
        let mockAuth: MockAuthenticator
        let tempDir: URL

        /// Clean up temporary files. Call in tearDown.
        func cleanup() {
            try? FileManager.default.removeItem(at: tempDir)
        }
    }

    static func makeCleartextSigner(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        messageAdapter: PGPMessageOperationAdapter,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        digestSigner: any SecureEnclaveCustodyDigestSigning = SystemSecureEnclaveCustodyDigestSigner()
    ) -> PrivateKeyCleartextSigningService {
        PrivateKeyCleartextSigningService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: digestSigner
        )
    }

    static func makeMessageDecryptor(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        messageAdapter: PGPMessageOperationAdapter,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        keyAgreement: any SecureEnclaveCustodyKeyAgreement = SystemSecureEnclaveCustodyKeyAgreement()
    ) -> PrivateKeyMessageDecryptionService {
        PrivateKeyMessageDecryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            keyAgreement: keyAgreement
        )
    }

    static func makeFileDecryptor(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        messageAdapter: PGPMessageOperationAdapter,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        keyAgreement: any SecureEnclaveCustodyKeyAgreement = SystemSecureEnclaveCustodyKeyAgreement()
    ) -> PrivateKeyStreamingFileDecryptionService {
        PrivateKeyStreamingFileDecryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            keyAgreement: keyAgreement
        )
    }

    static func makeTextEncryptor(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        messageAdapter: PGPMessageOperationAdapter,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        digestSigner: any SecureEnclaveCustodyDigestSigning = SystemSecureEnclaveCustodyDigestSigner()
    ) -> PrivateKeyTextEncryptionService {
        PrivateKeyTextEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: digestSigner
        )
    }

    static func makeFileEncryptor(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        messageAdapter: PGPMessageOperationAdapter,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        digestSigner: any SecureEnclaveCustodyDigestSigning = SystemSecureEnclaveCustodyDigestSigner()
    ) -> PrivateKeyStreamingFileEncryptionService {
        PrivateKeyStreamingFileEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: digestSigner
        )
    }

    static func makePasswordMessageEncryptor(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        messageAdapter: PGPMessageOperationAdapter,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        digestSigner: any SecureEnclaveCustodyDigestSigning = SystemSecureEnclaveCustodyDigestSigner()
    ) -> PrivateKeyPasswordMessageEncryptionService {
        PrivateKeyPasswordMessageEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: digestSigner
        )
    }

    static func makeDetachedFileSigner(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        messageAdapter: PGPMessageOperationAdapter,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        digestSigner: any SecureEnclaveCustodyDigestSigning = SystemSecureEnclaveCustodyDigestSigner()
    ) -> PrivateKeyDetachedFileSigningService {
        PrivateKeyDetachedFileSigningService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: digestSigner
        )
    }

    static func makeExpiryMutator(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        keyAdapter: PGPKeyOperationAdapter? = nil,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        digestSigner: any SecureEnclaveCustodyDigestSigning = SystemSecureEnclaveCustodyDigestSigner()
    ) -> PrivateKeyExpiryMutationService {
        PrivateKeyExpiryMutationService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            keyAdapter: keyAdapter ?? PGPKeyOperationAdapter(engine: engine),
            digestSigner: digestSigner
        )
    }

    static func makeSelectiveRevocationService(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        certificateAdapter: PGPCertificateOperationAdapter? = nil,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        digestSigner: any SecureEnclaveCustodyDigestSigning = SystemSecureEnclaveCustodyDigestSigner()
    ) -> PrivateKeySelectiveRevocationService {
        PrivateKeySelectiveRevocationService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            certificateAdapter: certificateAdapter ?? PGPCertificateOperationAdapter(engine: engine),
            digestSigner: digestSigner
        )
    }

    static func makeContactCertificationSigner(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        certificateAdapter: PGPCertificateOperationAdapter? = nil,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        handleStore: SecureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: MockSecureEnclaveCustodyKeyStore()
        ),
        digestSigner: any SecureEnclaveCustodyDigestSigning = SystemSecureEnclaveCustodyDigestSigner()
    ) -> PrivateKeyContactCertificationService {
        PrivateKeyContactCertificationService(
            router: keyManagement.makePrivateKeyOperationRouter(
                resolver: resolver,
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: handleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            certificateAdapter: certificateAdapter ?? PGPCertificateOperationAdapter(engine: engine),
            digestSigner: digestSigner
        )
    }

    // MARK: - Cleanup

    /// Remove a temporary directory created by makeContactService.
    static func cleanupTempDir(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }
}

extension ContactService {
    convenience init(
        engine: PgpEngine,
        contactsDirectory: URL? = nil,
        contactsDomainStore: ContactsDomainStore? = nil
    ) {
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let resolvedContactsDomainStore = contactsDomainStore ?? contactsDirectory.flatMap {
            try? TestHelpers.makeContactsDomainStore(
                engine: engine,
                contactsDirectory: $0
            )
        }
        self.init(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            contactsDomainStore: resolvedContactsDomainStore
        )
    }

    @discardableResult
    func openProtectedContactsForTests() async throws -> ContactsAvailability {
        let availability = await TestHelpers.openContactsForTests(self)
        guard availability == .availableProtectedDomain else {
            throw CypherAirError.contactsUnavailable(availability)
        }
        return availability
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
            importMatcher: importMatcher
        )
    }
}
