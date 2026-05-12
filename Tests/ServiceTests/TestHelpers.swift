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
        privateKeyControlStore: (any PrivateKeyControlStoreProtocol)? = nil
    ) -> (service: KeyManagementService, mockSE: MockSecureEnclave, mockKC: MockKeychain, mockAuth: MockAuthenticator) {
        let mockSE = MockSecureEnclave()
        let mockKC = MockKeychain()
        let mockAuth = MockAuthenticator()
        let privateKeyControlStore = privateKeyControlStore ?? InMemoryPrivateKeyControlStore(mode: .standard)

        let service: KeyManagementService
        if let memInfo = memoryInfo {
            service = KeyManagementService(
                engine: engine, secureEnclave: mockSE,
                keychain: mockKC, authenticator: mockAuth,
                memoryInfo: memInfo,
                defaults: .standard,
                privateKeyControlStore: privateKeyControlStore
            )
        } else {
            service = KeyManagementService(
                engine: engine, secureEnclave: mockSE,
                keychain: mockKC, authenticator: mockAuth,
                defaults: .standard,
                privateKeyControlStore: privateKeyControlStore
            )
        }

        return (service, mockSE, mockKC, mockAuth)
    }

    // MARK: - ContactService Factory

    /// Create a ContactService using a temporary directory for contacts storage.
    /// Returns the service and the temp directory URL (caller should clean up in tearDown).
    static func makeContactService(
        engine: PgpEngine = PgpEngine()
    ) -> (service: ContactService, tempDir: URL) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirTests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        let service = ContactService(engine: engine, contactsDirectory: tempDir)
        try? service.openLegacyCompatibilityForTests()
        return (service, tempDir)
    }

    // MARK: - Key Generation Helpers

    /// Generate a key pair and store it in the mock-backed KeyManagementService.
    /// Returns the PGPKeyIdentity of the generated key.
    @discardableResult
    static func generateAndStoreKey(
        service: KeyManagementService,
        profile: KeyProfile,
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
        isDefault: Bool = false
    ) throws -> PGPKeyIdentity {
        let info = try engine.parseKeyInfo(keyData: secretCertData)
        let armoredPublicKey = try engine.armorPublicKey(certData: secretCertData)
        let publicKeyData = try engine.dearmor(armored: armoredPublicKey)

        let handle = try mockSE.generateWrappingKey(accessControl: nil)
        let bundle = try mockSE.wrap(
            privateKey: secretCertData,
            using: handle,
            fingerprint: info.fingerprint
        )

        let bundleStore = KeyBundleStore(keychain: mockKC)
        try bundleStore.saveBundle(bundle, fingerprint: info.fingerprint)

        let identity = PGPKeyIdentity(
            fingerprint: info.fingerprint,
            keyVersion: info.keyVersion,
            profile: info.profile,
            userId: info.userId,
            hasEncryptionSubkey: info.hasEncryptionSubkey,
            isRevoked: info.isRevoked,
            isExpired: info.isExpired,
            isDefault: isDefault,
            isBackedUp: false,
            publicKeyData: publicKeyData,
            revocationCert: Data(),
            primaryAlgo: info.primaryAlgo,
            subkeyAlgo: info.subkeyAlgo,
            expiryDate: info.expiryTimestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        )

        let metadataStore = KeyMetadataStore(keychain: mockKC)
        try metadataStore.save(identity)
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
    ) -> ServiceStack {
        let (keyMgmt, mockSE, mockKC, mockAuth) = makeKeyManagement(engine: engine, memoryInfo: memoryInfo)
        let (contactSvc, tempDir) = makeContactService(engine: engine)

        let encryptionSvc = EncryptionService(engine: engine, keyManagement: keyMgmt, contactService: contactSvc)
        let decryptionSvc = DecryptionService(engine: engine, keyManagement: keyMgmt, contactService: contactSvc)
        let passwordMessageSvc = PasswordMessageService(
            engine: engine,
            keyManagement: keyMgmt,
            contactService: contactSvc
        )
        let signingSvc = SigningService(engine: engine, keyManagement: keyMgmt, contactService: contactSvc)
        let certificateSignatureSvc = CertificateSignatureService(
            engine: engine,
            keyManagement: keyMgmt,
            contactService: contactSvc
        )

        return ServiceStack(
            engine: engine,
            keyManagement: keyMgmt,
            contactService: contactSvc,
            encryptionService: encryptionSvc,
            decryptionService: decryptionSvc,
            passwordMessageService: passwordMessageSvc,
            signingService: signingSvc,
            certificateSignatureService: certificateSignatureSvc,
            mockSE: mockSE,
            mockKC: mockKC,
            mockAuth: mockAuth,
            tempDir: tempDir
        )
    }

    /// Holds all services and mocks for a complete test environment.
    struct ServiceStack {
        let engine: PgpEngine
        let keyManagement: KeyManagementService
        let contactService: ContactService
        let encryptionService: EncryptionService
        let decryptionService: DecryptionService
        let passwordMessageService: PasswordMessageService
        let signingService: SigningService
        let certificateSignatureService: CertificateSignatureService
        let mockSE: MockSecureEnclave
        let mockKC: MockKeychain
        let mockAuth: MockAuthenticator
        let tempDir: URL

        /// Clean up temporary files. Call in tearDown.
        func cleanup() {
            try? FileManager.default.removeItem(at: tempDir)
        }
    }

    // MARK: - Cleanup

    /// Remove a temporary directory created by makeContactService.
    static func cleanupTempDir(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }
}
