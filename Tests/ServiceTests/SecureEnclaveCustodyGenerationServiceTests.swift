import Foundation
import XCTest
@testable import CypherAir

final class SecureEnclaveCustodyGenerationServiceTests: XCTestCase {
    func test_hiddenGenerationPersistsP256SecureEnclaveIdentity() async throws {
        for configurationIdentity in [
            PGPKeyConfiguration.Identity.compatibleP256V4,
            .modernP256V6
        ] {
            let expectedProfile: PGPKeyProfile = configurationIdentity.configuration.keyVersion == 4
                ? .universal
                : .advanced
            let keyStore = MockSecureEnclaveCustodyKeyStore()
            let metadataStore = MemoryKeyMetadataPersistence()
            let builder = MockSecureEnclaveCustodyCertificateBuilder(
                result: Self.material(
                    fingerprint: "abc\(configurationIdentity.rawValue)",
                    keyVersion: configurationIdentity.configuration.keyVersion
                )
            )
            let service = makeService(
                keyStore: keyStore,
                metadataStore: metadataStore,
                builder: builder,
                policy: .testSecureEnclaveGeneration
            )

            let identity = try await service.generateHiddenKey(
                name: "Secure Enclave",
                email: "se@example.test",
                expirySeconds: 3600,
                configurationIdentity: configurationIdentity,
                invalidationToken: KeyProvisioningInvalidationGate().makeToken()
            )

            XCTAssertEqual(identity.openPGPConfigurationIdentity, configurationIdentity)
            XCTAssertEqual(
                identity.privateKeyCustodyKind,
                PGPPrivateKeyCustodyKind.appleSecureEnclavePrivateOperations
            )
            XCTAssertEqual(identity.keyVersion, configurationIdentity.configuration.keyVersion)
            XCTAssertEqual(identity.profile, expectedProfile)
            XCTAssertFalse(identity.publicKeyData.isEmpty)
            XCTAssertFalse(identity.revocationCert.isEmpty)
            XCTAssertEqual(metadataStore.identities, [identity])
            XCTAssertEqual(keyStore.storedHandleCount(), 2)
            XCTAssertEqual(builder.requests.count, 1)
            XCTAssertEqual(builder.requests[0].configuration.identity, configurationIdentity)
            XCTAssertEqual(builder.requests[0].handlePair.signing.role, PGPPrivateOperationRole.signing)
            XCTAssertEqual(builder.requests[0].handlePair.keyAgreement.role, PGPPrivateOperationRole.keyAgreement)
        }
    }

    func test_generationPolicyAndConfigurationFailBeforeHandleCreation() async throws {
        let productionKeyStore = MockSecureEnclaveCustodyKeyStore()
        let productionService = makeService(
            keyStore: productionKeyStore,
            policy: .production
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await productionService.generateHiddenKey(
                name: "Secure Enclave",
                email: Optional<String>.none,
                expirySeconds: Optional<UInt64>.none,
                configurationIdentity: PGPKeyConfiguration.Identity.compatibleP256V4,
                invalidationToken: KeyProvisioningInvalidationGate().makeToken()
            )
        }
        XCTAssertEqual(productionKeyStore.storedHandleCount(), 0)

        let invalidConfigurationKeyStore = MockSecureEnclaveCustodyKeyStore()
        let invalidConfigurationService = makeService(
            keyStore: invalidConfigurationKeyStore,
            policy: .testSecureEnclaveGeneration
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await invalidConfigurationService.generateHiddenKey(
                name: "Software",
                email: Optional<String>.none,
                expirySeconds: Optional<UInt64>.none,
                configurationIdentity: PGPKeyConfiguration.Identity.compatibleSoftwareV4,
                invalidationToken: KeyProvisioningInvalidationGate().makeToken()
            )
        }
        XCTAssertEqual(invalidConfigurationKeyStore.storedHandleCount(), 0)
    }

    func test_builderFailureAndDuplicateFingerprintCleanupHandles() async throws {
        let builderFailureKeyStore = MockSecureEnclaveCustodyKeyStore()
        let builderFailureService = makeService(
            keyStore: builderFailureKeyStore,
            builder: MockSecureEnclaveCustodyCertificateBuilder(error: CypherAirError.keyGenerationFailed(reason: "builder"))
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await builderFailureService.generateHiddenKey(
                name: "Builder Failure",
                email: Optional<String>.none,
                expirySeconds: Optional<UInt64>.none,
                configurationIdentity: PGPKeyConfiguration.Identity.compatibleP256V4,
                invalidationToken: KeyProvisioningInvalidationGate().makeToken()
            )
        }
        XCTAssertEqual(builderFailureKeyStore.storedHandleCount(), 0)
        XCTAssertEqual(builderFailureKeyStore.deleteRequests.map(\.role), [.signing, .keyAgreement])

        let duplicateKeyStore = MockSecureEnclaveCustodyKeyStore()
        let duplicateMetadataStore = MemoryKeyMetadataPersistence()
        duplicateMetadataStore.seed([
            Self.identity(fingerprint: "duplicate", configurationIdentity: .compatibleP256V4)
        ])
        let duplicateService = makeService(
            keyStore: duplicateKeyStore,
            metadataStore: duplicateMetadataStore,
            builder: MockSecureEnclaveCustodyCertificateBuilder(
                result: Self.material(fingerprint: "duplicate", keyVersion: 4)
            )
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await duplicateService.generateHiddenKey(
                name: "Duplicate",
                email: Optional<String>.none,
                expirySeconds: Optional<UInt64>.none,
                configurationIdentity: PGPKeyConfiguration.Identity.compatibleP256V4,
                invalidationToken: KeyProvisioningInvalidationGate().makeToken()
            )
        }
        XCTAssertEqual(duplicateKeyStore.storedHandleCount(), 0)
        XCTAssertEqual(duplicateMetadataStore.identities.count, 1)
    }

    func test_metadataSaveFailureCleansHandlesAndLeavesNoCommittedIdentity() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let metadataStore = MemoryKeyMetadataPersistence()
        metadataStore.failNextSave = true
        let service = makeService(
            keyStore: keyStore,
            metadataStore: metadataStore,
            builder: MockSecureEnclaveCustodyCertificateBuilder(
                result: Self.material(fingerprint: "savefailure", keyVersion: 6)
            )
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await service.generateHiddenKey(
                name: "Save Failure",
                email: Optional<String>.none,
                expirySeconds: Optional<UInt64>.none,
                configurationIdentity: PGPKeyConfiguration.Identity.modernP256V6,
                invalidationToken: KeyProvisioningInvalidationGate().makeToken()
            )
        }
        XCTAssertEqual(keyStore.storedHandleCount(), 0)
        XCTAssertTrue(metadataStore.identities.isEmpty)
    }

    func test_postIdentityCommitFailureRollsBackMetadataBeforeHandles() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let metadataStore = MemoryKeyMetadataPersistence()
        let service = makeService(
            keyStore: keyStore,
            metadataStore: metadataStore,
            builder: MockSecureEnclaveCustodyCertificateBuilder(
                result: Self.material(fingerprint: "postcommit", keyVersion: 4)
            ),
            afterIdentityCommitCheckpoint: {
                throw PostIdentityCommitTestError.simulatedFailure
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await service.generateHiddenKey(
                name: "Post Commit",
                email: Optional<String>.none,
                expirySeconds: Optional<UInt64>.none,
                configurationIdentity: PGPKeyConfiguration.Identity.compatibleP256V4,
                invalidationToken: KeyProvisioningInvalidationGate().makeToken()
            )
        } inspectError: { error in
            XCTAssertTrue(error is PostIdentityCommitTestError)
        }
        XCTAssertTrue(metadataStore.identities.isEmpty)
        XCTAssertEqual(keyStore.storedHandleCount(), 0)
        XCTAssertEqual(keyStore.deleteRequests.map(\.role), [.signing, .keyAgreement])
    }

    func test_postIdentityCommitRollbackFailureKeepsHandlesWhenMetadataCannotRollback() async throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let metadataStore = MemoryKeyMetadataPersistence()
        metadataStore.failNextDelete = true
        let service = makeService(
            keyStore: keyStore,
            metadataStore: metadataStore,
            builder: MockSecureEnclaveCustodyCertificateBuilder(
                result: Self.material(fingerprint: "rollbackfailure", keyVersion: 6)
            ),
            afterIdentityCommitCheckpoint: {
                throw PostIdentityCommitTestError.simulatedFailure
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await service.generateHiddenKey(
                name: "Rollback Failure",
                email: Optional<String>.none,
                expirySeconds: Optional<UInt64>.none,
                configurationIdentity: PGPKeyConfiguration.Identity.modernP256V6,
                invalidationToken: KeyProvisioningInvalidationGate().makeToken()
            )
        } inspectError: { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
            )
        }
        XCTAssertEqual(metadataStore.identities.map(\.fingerprint), ["rollbackfailure"])
        XCTAssertEqual(keyStore.storedHandleCount(), 2)
        XCTAssertTrue(keyStore.deleteRequests.isEmpty)
    }

    func test_signingCallbackMapsHandleErrorToSanitizedCallbackFailure() throws {
        let loadedPair = try loadedHandlePair()
        let bridge = PGPSecureEnclaveExternalSigningProviderBridge(
            handle: loadedPair.signing,
            digestSigner: ThrowingSecureEnclaveCustodyDigestSigner(
                error: SecureEnclaveCustodyHandleError.hardwareUnavailable
            )
        )

        XCTAssertThrowsError(
            try bridge.signSha256Digest(digest: Data(repeating: 0xA5, count: 32))
        ) { error in
            XCTAssertEqual(
                error as? ExternalP256SigningError,
                ExternalP256SigningError.Failed(category: .hardwareUnavailable)
            )
        }
    }

    func test_signingCallbackMapsCancellationToCallbackCancellation() throws {
        let loadedPair = try loadedHandlePair()
        let bridge = PGPSecureEnclaveExternalSigningProviderBridge(
            handle: loadedPair.signing,
            digestSigner: ThrowingSecureEnclaveCustodyDigestSigner(error: CancellationError())
        )

        XCTAssertThrowsError(
            try bridge.signSha256Digest(digest: Data(repeating: 0xA5, count: 32))
        ) { error in
            XCTAssertEqual(
                error as? ExternalP256SigningError,
                ExternalP256SigningError.OperationCancelled
            )
        }
    }

    func test_signingCallbackMapsUnknownErrorToExternalOperationFailed() throws {
        let loadedPair = try loadedHandlePair()
        let bridge = PGPSecureEnclaveExternalSigningProviderBridge(
            handle: loadedPair.signing,
            digestSigner: ThrowingSecureEnclaveCustodyDigestSigner(error: RawSigningCallbackError())
        )

        XCTAssertThrowsError(
            try bridge.signSha256Digest(digest: Data(repeating: 0xA5, count: 32))
        ) { error in
            XCTAssertEqual(
                error as? ExternalP256SigningError,
                ExternalP256SigningError.Failed(category: .externalOperationFailed)
            )
        }
    }

    private func makeService(
        keyStore: MockSecureEnclaveCustodyKeyStore,
        metadataStore: MemoryKeyMetadataPersistence = MemoryKeyMetadataPersistence(),
        builder: MockSecureEnclaveCustodyCertificateBuilder? = nil,
        policy: PGPKeyCapabilityResolver.Policy = .testSecureEnclaveGeneration,
        commitCoordinator: KeyProvisioningCommitCoordinator = KeyProvisioningCommitCoordinator(),
        afterIdentityCommitCheckpoint: SecureEnclaveCustodyGenerationService.GenerationCheckpoint? = nil
    ) -> SecureEnclaveCustodyGenerationService {
        let catalogStore = KeyCatalogStore(metadataStore: metadataStore)
        try? catalogStore.loadAll()
        return SecureEnclaveCustodyGenerationService(
            certificateBuilder: builder ?? MockSecureEnclaveCustodyCertificateBuilder(
                result: Self.material(fingerprint: "default", keyVersion: 4)
            ),
            handleStore: SecureEnclaveCustodyHandleStore(
                keyStore: keyStore,
                handleSetIdentifierGenerator: { "hidden-generation" }
            ),
            digestSigner: MockSecureEnclaveCustodyDigestSigner(),
            catalogStore: catalogStore,
            resolver: PGPKeyCapabilityResolver(policy: policy),
            invalidationGate: KeyProvisioningInvalidationGate(),
            commitCoordinator: commitCoordinator,
            afterIdentityCommitCheckpoint: afterIdentityCommitCheckpoint
        )
    }

    private func loadedHandlePair() throws -> SecureEnclaveCustodyLoadedHandlePair {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: {
                try SecureEnclaveCustodyHandleReference.generateHandleSetIdentifier()
            }
        )
        let pair = try store.createHandlePair()
        return try store.loadHandlePair(expected: pair)
    }

    private static func material(
        fingerprint: String,
        keyVersion: UInt8
    ) -> PGPSecureEnclaveCustodyGeneratedMaterial {
        PGPSecureEnclaveCustodyGeneratedMaterial(
            publicKeyData: Data("public-\(fingerprint)".utf8),
            revocationCert: Data("revocation-\(fingerprint)".utf8),
            metadata: PGPKeyMetadata(
                fingerprint: fingerprint,
                keyVersion: keyVersion,
                userId: "Secure Enclave <se@example.test>",
                hasEncryptionSubkey: true,
                isRevoked: false,
                isExpired: false,
                profile: keyVersion == 4 ? .universal : .advanced,
                primaryAlgo: "ECDSA P-256",
                subkeyAlgo: "ECDH P-256",
                expiryTimestamp: nil
            ),
            signingKeyFingerprint: "\(fingerprint)-signing",
            keyAgreementSubkeyFingerprint: "\(fingerprint)-agreement"
        )
    }

    private static func identity(
        fingerprint: String,
        configurationIdentity: PGPKeyConfiguration.Identity
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: configurationIdentity.configuration.keyVersion,
            profile: configurationIdentity.configuration.keyVersion == 4 ? .universal : .advanced,
            userId: "Existing",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: true,
            isBackedUp: false,
            publicKeyData: Data("existing".utf8),
            revocationCert: Data("existing-revocation".utf8),
            primaryAlgo: "ECDSA P-256",
            subkeyAlgo: "ECDH P-256",
            expiryDate: nil,
            openPGPConfigurationIdentity: configurationIdentity,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
    }
}

private final class MockSecureEnclaveCustodyCertificateBuilder: SecureEnclaveCustodyCertificateBuilding, @unchecked Sendable {
    struct Request {
        let configuration: PGPKeyConfiguration
        let handlePair: SecureEnclaveCustodyLoadedHandlePair
    }

    private let result: PGPSecureEnclaveCustodyGeneratedMaterial?
    private let error: Error?
    private(set) var requests: [Request] = []

    init(
        result: PGPSecureEnclaveCustodyGeneratedMaterial? = nil,
        error: Error? = nil
    ) {
        self.result = result
        self.error = error
    }

    func generatePublicCertificate(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        configuration: PGPKeyConfiguration,
        handlePair: SecureEnclaveCustodyLoadedHandlePair,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) async throws -> PGPSecureEnclaveCustodyGeneratedMaterial {
        requests.append(Request(configuration: configuration, handlePair: handlePair))
        if let error {
            throw error
        }
        return try XCTUnwrap(result)
    }
}

private struct MockSecureEnclaveCustodyDigestSigner: SecureEnclaveCustodyDigestSigning {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        try SecureEnclaveP256RawSignature(
            r: Data(repeating: 1, count: 32),
            s: Data(repeating: 2, count: 32)
        )
    }
}

private enum MemoryKeyMetadataPersistenceError: Error {
    case saveFailed
    case deleteFailed
}

private final class MemoryKeyMetadataPersistence: KeyMetadataPersistence {
    private(set) var identities: [PGPKeyIdentity] = []
    var failNextSave = false
    var failNextDelete = false

    func seed(_ identities: [PGPKeyIdentity]) {
        self.identities = identities
    }

    func loadAll() throws -> [PGPKeyIdentity] {
        identities
    }

    func save(_ identity: PGPKeyIdentity) throws {
        if failNextSave {
            failNextSave = false
            throw MemoryKeyMetadataPersistenceError.saveFailed
        }
        identities.append(identity)
    }

    func update(_ identity: PGPKeyIdentity) throws {
        if let index = identities.firstIndex(where: { $0.fingerprint == identity.fingerprint }) {
            identities[index] = identity
        } else {
            identities.append(identity)
        }
    }

    func delete(fingerprint: String) throws {
        if failNextDelete {
            failNextDelete = false
            throw MemoryKeyMetadataPersistenceError.deleteFailed
        }
        identities.removeAll { $0.fingerprint == fingerprint }
    }
}

private enum PostIdentityCommitTestError: Error {
    case simulatedFailure
}

private struct RawSigningCallbackError: Error {}

private struct ThrowingSecureEnclaveCustodyDigestSigner: SecureEnclaveCustodyDigestSigning {
    let error: Error

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw error
    }
}

private func XCTAssertThrowsErrorAsync(
    _ expression: () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line,
    inspectError: (Error) -> Void = { _ in }
) async {
    do {
        try await expression()
        XCTFail("Expected expression to throw.", file: file, line: line)
    } catch {
        inspectError(error)
    }
}
