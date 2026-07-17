import CryptoKit
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Device-only evidence for the Secure Enclave custody handle store.
///
/// These tests exercise real Secure Enclave keys created by
/// `SystemSecureEnclaveCustodyKeyStore` as CryptoKit blob rows. They are
/// intentionally selected only by `CypherAir-DeviceTests`.
final class DeviceSecureEnclaveCustodyHandleStoreTests: SecureEnclaveCustodyDeviceTestCase {
    func test_custodyHandlePair_createReloadInventoryDelete_onDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let created = try store.createLoadedHandlePair(authenticationContext: nil)
        let pair = try SecureEnclaveCustodyHandlePair(
            signing: created.signing.binding,
            keyAgreement: created.keyAgreement.binding
        )
        defer {
            try? store.deleteHandlePair(pair)
        }

        XCTAssertEqual(pair.signing.publicKeyRaw.count, 65)
        XCTAssertEqual(pair.keyAgreement.publicKeyRaw.count, 65)
        XCTAssertNotEqual(pair.signing.publicKeyRaw, pair.keyAgreement.publicKeyRaw)
        XCTAssertNotNil(created.signing.privateKey)
        XCTAssertNotNil(created.keyAgreement.privateKey)

        let reloadedSigning = try store.loadHandle(
            reference: pair.signing.reference,
            expectedPublicKeyRaw: pair.signing.publicKeyRaw,
            authenticationContext: nil
        )
        let reloadedKeyAgreement = try store.loadHandle(
            reference: pair.keyAgreement.reference,
            expectedPublicKeyRaw: pair.keyAgreement.publicKeyRaw,
            authenticationContext: nil
        )
        XCTAssertEqual(reloadedSigning.binding, pair.signing)
        XCTAssertEqual(reloadedKeyAgreement.binding, pair.keyAgreement)
        XCTAssertNotNil(reloadedSigning.privateKey)
        XCTAssertNotNil(reloadedKeyAgreement.privateKey)

        let located = try store.locateHandlePair(
            signingPublicKeyRaw: pair.signing.publicKeyRaw,
            keyAgreementPublicKeyRaw: pair.keyAgreement.publicKeyRaw
        )
        XCTAssertEqual(located, pair)

        let summary = try store.inventorySummaryForLocalRecovery()
        XCTAssertGreaterThanOrEqual(summary.totalHandleCount, 2)
        XCTAssertGreaterThanOrEqual(summary.completeSetCount, 1)

        try store.deleteHandlePair(pair)
        XCTAssertEqual(store.inspectHandlePair(handleSetIdentifier: pair.handleSetIdentifier), .missing)
        recordEvidence(
            .handlePairGenerationPersistence,
            handleCount: summary.totalHandleCount,
            completeSetCount: summary.completeSetCount
        )
    }

    func test_custodyPrivateOperations_succeedAfterBiometricAuthentication_onDevice() async throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let created = try store.createLoadedHandlePair(authenticationContext: nil)
        let pair = try SecureEnclaveCustodyHandlePair(
            signing: created.signing.binding,
            keyAgreement: created.keyAgreement.binding
        )
        defer {
            try? store.deleteHandlePair(pair)
        }
        let context = try await authenticatedBiometricsContext(
            reason: "Authenticate to validate Secure Enclave custody private operations."
        )
        defer {
            context.invalidate()
        }

        let signingHandle = try store.loadHandle(
            reference: pair.signing.reference,
            expectedPublicKeyRaw: pair.signing.publicKeyRaw,
            authenticationContext: context
        )
        let digest = Data(SHA256.hash(data: Data("CypherAir custody device signing evidence".utf8)))
        let signature = try SystemSecureEnclaveCustodyDigestSigner()
            .signSHA256Digest(digest, using: signingHandle)
        try assertValidP256Signature(
            signature,
            digest: digest,
            publicKeyX963: pair.signing.publicKeyRaw
        )

        let keyAgreementHandle = try store.loadHandle(
            reference: pair.keyAgreement.reference,
            expectedPublicKeyRaw: pair.keyAgreement.publicKeyRaw,
            authenticationContext: context
        )
        let peerPrivateKey = P256.KeyAgreement.PrivateKey()
        let request = ExternalP256KeyAgreementRequest(
            recipientPublicKey: pair.keyAgreement.publicKeyRaw,
            ephemeralPublicKey: peerPrivateKey.publicKey.x963Representation
        )
        let sharedSecret = try SystemSecureEnclaveCustodyKeyAgreement()
            .deriveSharedSecret(request: request, using: keyAgreementHandle)
        XCTAssertEqual(sharedSecret.raw.count, 32)

        let custodyPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: pair.keyAgreement.publicKeyRaw
        )
        let expectedSecret = try peerPrivateKey.sharedSecretFromKeyAgreement(with: custodyPublicKey)
        let expectedSecretData = expectedSecret.withUnsafeBytes { Data($0) }
        XCTAssertEqual(sharedSecret.raw, expectedSecretData)
        recordEvidence(.signing)
    }

    func test_custodyPrivateOperations_interactionNotAllowedFailsClosed_onDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let created = try store.createLoadedHandlePair(authenticationContext: nil)
        let pair = try SecureEnclaveCustodyHandlePair(
            signing: created.signing.binding,
            keyAgreement: created.keyAgreement.binding
        )
        defer {
            try? store.deleteHandlePair(pair)
        }
        let context = LAContext()
        context.interactionNotAllowed = true

        do {
            let signingHandle = try store.loadHandle(
                reference: pair.signing.reference,
                expectedPublicKeyRaw: pair.signing.publicKeyRaw,
                authenticationContext: context
            )
            let digest = Data(SHA256.hash(data: Data("CypherAir custody denied signing evidence".utf8)))
            XCTAssertThrowsError(
                try SystemSecureEnclaveCustodyDigestSigner()
                    .signSHA256Digest(digest, using: signingHandle)
            ) { error in
                XCTAssertTrue(
                    sanitizedPrivateOperationFailureCategories.contains(failureCategory(for: error)),
                    "Unexpected signing failure category: \(error)"
                )
                assertDoesNotLeak(error, pair: pair)
            }
        } catch {
            XCTAssertTrue(
                sanitizedPrivateOperationFailureCategories.contains(failureCategory(for: error)),
                "Unexpected load failure category: \(error)"
            )
            assertDoesNotLeak(error, pair: pair)
        }
        recordEvidence(.interactionNotAllowedProxy)
    }

    func test_custodyHandleStateFailures_failClosedOnDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let created = try store.createLoadedHandlePair(authenticationContext: nil)
        let pair = try SecureEnclaveCustodyHandlePair(
            signing: created.signing.binding,
            keyAgreement: created.keyAgreement.binding
        )
        defer {
            try? store.deleteHandlePair(pair)
        }

        // A load whose expected public key disagrees with the stored row fails
        // closed as a binding mismatch, with no leak in the error text.
        XCTAssertThrowsError(try store.loadHandle(
            reference: pair.signing.reference,
            expectedPublicKeyRaw: pair.keyAgreement.publicKeyRaw,
            authenticationContext: nil
        )) { error in
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .handlePublicKeyBindingMismatch
            )
            assertDoesNotLeak(error, pair: pair)
        }

        try keyStore.deleteKey(reference: pair.signing.reference)
        XCTAssertEqual(
            store.inspectHandlePair(handleSetIdentifier: pair.handleSetIdentifier),
            .partial(presentRoles: [.keyAgreement])
        )
        XCTAssertThrowsError(try store.loadHandle(
            reference: pair.signing.reference,
            expectedPublicKeyRaw: pair.signing.publicKeyRaw,
            authenticationContext: nil
        )) { error in
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .privateHandleMissing
            )
            assertDoesNotLeak(error, pair: pair)
        }

        try keyStore.deleteKey(reference: pair.keyAgreement.reference)
        XCTAssertEqual(store.inspectHandlePair(handleSetIdentifier: pair.handleSetIdentifier), .missing)
        XCTAssertThrowsError(try store.locateHandlePair(
            signingPublicKeyRaw: pair.signing.publicKeyRaw,
            keyAgreementPublicKeyRaw: pair.keyAgreement.publicKeyRaw
        )) { error in
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .privateHandleMissing
            )
        }
        recordEvidence(.wrongPublicBinding, observedCategory: .handlePublicKeyBindingMismatch)
        recordEvidence(.missingHandle, observedCategory: .privateHandleMissing)
    }

    /// Device-level wrong-role evidence: real Secure Enclave-created handle bindings,
    /// fed to the production digest signer and key-agreement guards with the roles
    /// swapped. The role guard fires before any private-key use, so no private key and
    /// no biometric prompt are needed — this proves real bindings carry the correct
    /// role and that both guards fail closed on a cross-role handle.
    func test_custodyRoleGuards_crossRoleUseFailsClosed_onDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let created = try store.createLoadedHandlePair(authenticationContext: nil)
        let pair = try SecureEnclaveCustodyHandlePair(
            signing: created.signing.binding,
            keyAgreement: created.keyAgreement.binding
        )
        defer {
            try? store.deleteHandlePair(pair)
        }

        let keyAgreementBoundHandle = SecureEnclaveCustodyLoadedHandle(
            binding: pair.keyAgreement,
            privateKey: nil
        )
        let signingBoundHandle = SecureEnclaveCustodyLoadedHandle(
            binding: pair.signing,
            privateKey: nil
        )

        // A .keyAgreement handle must not sign.
        let digest = Data(SHA256.hash(data: Data("CypherAir custody wrong-role evidence".utf8)))
        XCTAssertThrowsError(
            try SystemSecureEnclaveCustodyDigestSigner().signSHA256Digest(digest, using: keyAgreementBoundHandle)
        ) { error in
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .privateOperationRoleMismatch
            )
            assertDoesNotLeak(error, pair: pair)
        }

        // A .signing handle must not perform key agreement.
        let request = ExternalP256KeyAgreementRequest(
            recipientPublicKey: pair.signing.publicKeyRaw,
            ephemeralPublicKey: pair.keyAgreement.publicKeyRaw
        )
        XCTAssertThrowsError(
            try SystemSecureEnclaveCustodyKeyAgreement().deriveSharedSecret(request: request, using: signingBoundHandle)
        ) { error in
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .privateOperationRoleMismatch
            )
            assertDoesNotLeak(error, pair: pair)
        }

        recordEvidence(.wrongRole, observedCategory: .privateOperationRoleMismatch)
    }
}
