import CryptoKit
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

/// Device-only evidence for the future Secure Enclave custody handle store.
///
/// These tests exercise real Secure Enclave `kSecClassKey` rows created by
/// `SystemSecureEnclaveCustodyKeyStore`. They are intentionally selected only by
/// `CypherAir-DeviceTests`.
final class DeviceSecureEnclaveCustodyHandleStoreTests: SecureEnclaveCustodyDeviceTestCase {
    func test_custodyHandlePair_createReloadInventoryDelete_onDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let traceStore = AuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let keyStore = SystemSecureEnclaveCustodyKeyStore(traceStore: traceStore)
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let pair = try store.createHandlePair()
        defer {
            try? store.deleteHandlePair(pair)
        }

        XCTAssertEqual(pair.signing.publicKeyX963.count, 65)
        XCTAssertEqual(pair.keyAgreement.publicKeyX963.count, 65)
        XCTAssertNotEqual(pair.signing.publicKeyX963, pair.keyAgreement.publicKeyX963)

        let loadedPair = try store.loadHandlePair(expected: pair, authenticationContext: nil)
        XCTAssertEqual(loadedPair.signing.binding, pair.signing)
        XCTAssertEqual(loadedPair.keyAgreement.binding, pair.keyAgreement)
        XCTAssertNotNil(loadedPair.signing.privateKey)
        XCTAssertNotNil(loadedPair.keyAgreement.privateKey)

        let summary = try store.inventorySummaryForLocalRecovery()
        XCTAssertGreaterThanOrEqual(summary.totalHandleCount, 2)
        XCTAssertGreaterThanOrEqual(summary.completeSetCount, 1)

        try store.deleteHandlePair(pair)
        XCTAssertEqual(store.inspectHandlePair(handleSetIdentifier: pair.handleSetIdentifier), .missing)
        assertTraceIsSanitized(traceStore.recentEntries, pair: pair)
    }

    func test_custodyPrivateOperations_succeedAfterBiometricAuthentication_onDevice() async throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let pair = try store.createHandlePair()
        defer {
            try? store.deleteHandlePair(pair)
        }
        let context = try await authenticatedBiometricsContext(
            reason: "Authenticate to validate Secure Enclave custody private operations."
        )
        defer {
            context.invalidate()
        }

        let signingKey = try loadPrivateKey(
            reference: pair.signing.reference,
            authenticationContext: context
        )
        let digest = Data(SHA256.hash(data: Data("CypherAir custody device signing evidence".utf8)))
        let signature = try signDigest(digest, using: signingKey)
        let signingPublicKey = try XCTUnwrap(SecKeyCopyPublicKey(signingKey))
        try verifySignature(signature, digest: digest, publicKey: signingPublicKey)

        let agreementKey = try loadPrivateKey(
            reference: pair.keyAgreement.reference,
            authenticationContext: context
        )
        let peerPrivateKey = P256.KeyAgreement.PrivateKey()
        let peerPublicKey = try secKeyFromP256PublicKey(peerPrivateKey.publicKey.x963Representation)
        let sharedSecret = try deriveSharedSecret(privateKey: agreementKey, peerPublicKey: peerPublicKey)
        XCTAssertEqual(sharedSecret.count, 32)

        let custodyPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: pair.keyAgreement.publicKeyX963
        )
        let expectedSecret = try peerPrivateKey.sharedSecretFromKeyAgreement(with: custodyPublicKey)
        let expectedSecretData = expectedSecret.withUnsafeBytes { Data($0) }
        XCTAssertEqual(sharedSecret, expectedSecretData)
    }

    func test_custodyPrivateOperations_interactionNotAllowedFailsClosed_onDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let pair = try store.createHandlePair()
        defer {
            try? store.deleteHandlePair(pair)
        }
        let context = LAContext()
        context.interactionNotAllowed = true

        do {
            let signingKey = try loadPrivateKey(
                reference: pair.signing.reference,
                authenticationContext: context
            )
            let digest = Data(SHA256.hash(data: Data("CypherAir custody denied signing evidence".utf8)))
            XCTAssertThrowsError(try signDigest(digest, using: signingKey)) { error in
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
    }

    func test_custodyHandleStateFailures_failClosedOnDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let pair = try store.createHandlePair()
        defer {
            try? store.deleteHandlePair(pair)
        }

        let wrongPublicPair = try SecureEnclaveCustodyHandlePair(
            signing: SecureEnclaveCustodyHandlePublicBinding(
                reference: pair.signing.reference,
                publicKeyX963: pair.keyAgreement.publicKeyX963
            ),
            keyAgreement: SecureEnclaveCustodyHandlePublicBinding(
                reference: pair.keyAgreement.reference,
                publicKeyX963: pair.signing.publicKeyX963
            )
        )
        XCTAssertEqual(
            store.classifyHandleAvailability(expected: wrongPublicPair),
            .unavailable(.handlePublicKeyBindingMismatch)
        )
        XCTAssertThrowsError(try store.loadHandlePair(expected: wrongPublicPair, authenticationContext: nil)) { error in
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
        XCTAssertEqual(
            store.classifyHandleAvailability(expected: pair),
            .unavailable(.migrationOrRecoveryRequired)
        )

        try keyStore.deleteKey(reference: pair.keyAgreement.reference)
        XCTAssertEqual(store.inspectHandlePair(handleSetIdentifier: pair.handleSetIdentifier), .missing)
        XCTAssertEqual(store.classifyHandleAvailability(expected: pair), .unavailable(.privateHandleMissing))
    }

    func test_custodyTraceMetadataDoesNotLeakHandleLocators_onDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let traceStore = AuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let keyStore = SystemSecureEnclaveCustodyKeyStore(traceStore: traceStore)
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let pair = try store.createHandlePair()
        defer {
            try? store.deleteHandlePair(pair)
        }
        _ = try store.loadHandlePair(expected: pair, authenticationContext: nil)
        try store.deleteHandlePair(pair)

        assertTraceIsSanitized(traceStore.recentEntries, pair: pair)
    }
}
