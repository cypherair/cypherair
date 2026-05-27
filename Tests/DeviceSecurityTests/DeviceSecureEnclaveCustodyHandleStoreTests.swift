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
final class DeviceSecureEnclaveCustodyHandleStoreTests: DeviceSecurityTestCase {
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

        let loadedPair = try store.loadHandlePair(expected: pair)
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
        XCTAssertThrowsError(try store.loadHandlePair(expected: wrongPublicPair)) { error in
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

    func test_custodyResetCleanupDeletesRealCustodyKeyRows_onDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let pair = try store.createHandlePair()
        defer {
            try? store.deleteHandlePair(pair)
        }
        XCTAssertGreaterThanOrEqual(try store.remainingHandleCountForLocalDataReset(), 2)

        let result = store.cleanupAllHandlesForLocalDataReset()
        XCTAssertNil(result.failureCategory)
        XCTAssertGreaterThanOrEqual(result.inspectedHandleCount, 2)
        XCTAssertGreaterThanOrEqual(result.deletedHandleCount, 2)
        XCTAssertEqual(try store.remainingHandleCountForLocalDataReset(), 0)
        XCTAssertEqual(store.inspectHandlePair(handleSetIdentifier: pair.handleSetIdentifier), .missing)
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
        _ = try store.loadHandlePair(expected: pair)
        try store.deleteHandlePair(pair)

        assertTraceIsSanitized(traceStore.recentEntries, pair: pair)
    }

    private var sanitizedPrivateOperationFailureCategories: Set<PGPKeyOperationFailureCategory> {
        [
            .localAuthenticationCancelled,
            .localAuthenticationFailed,
            .localAuthenticationUnavailable,
            .localAuthenticationLockedOut,
            .privateHandleInaccessible,
            .privateHandleUnauthorized
        ]
    }

    private func requireSecureEnclaveCustodyHardware() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw XCTSkip(
                "Biometric authentication is unavailable: \(error?.localizedDescription ?? "unknown")"
            )
        }
    }

    private func authenticatedBiometricsContext(reason: String) async throws -> LAContext {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw XCTSkip(
                "Biometric authentication is unavailable: \(error?.localizedDescription ?? "unknown")"
            )
        }

        try await waitForAuthenticationSessionToSettle()
        let authenticated = try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        )
        XCTAssertTrue(authenticated)
        context.interactionNotAllowed = true
        return context
    }

    private func loadPrivateKey(
        reference: SecureEnclaveCustodyHandleReference,
        authenticationContext: LAContext?
    ) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: reference.applicationTagData,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let result,
              CFGetTypeID(result) == SecKeyGetTypeID() else {
            throw secureEnclaveCustodyError(for: status, role: reference.role)
        }
        return result as! SecKey
    }

    private func signDigest(_ digest: Data, using privateKey: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        try XCTSkipUnless(
            SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm),
            "ECDSA SHA-256 digest signing is unavailable for this key."
        )

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            digest as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() as Error?
                ?? SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        return signature
    }

    private func verifySignature(_ signature: Data, digest: Data, publicKey: SecKey) throws {
        let algorithm = SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(
            publicKey,
            algorithm,
            digest as CFData,
            signature as CFData,
            &error
        )
        if !verified {
            throw error?.takeRetainedValue() as Error?
                ?? SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
    }

    private func deriveSharedSecret(privateKey: SecKey, peerPublicKey: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.ecdhKeyExchangeStandard
        try XCTSkipUnless(
            SecKeyIsAlgorithmSupported(privateKey, .keyExchange, algorithm),
            "P-256 ECDH key exchange is unavailable for this key."
        )

        var error: Unmanaged<CFError>?
        guard let sharedSecret = SecKeyCopyKeyExchangeResult(
            privateKey,
            algorithm,
            peerPublicKey,
            [:] as CFDictionary,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() as Error?
                ?? SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }
        return sharedSecret
    }

    private func secKeyFromP256PublicKey(_ publicKeyX963: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(
            publicKeyX963 as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw error?.takeRetainedValue() as Error?
                ?? SecureEnclaveCustodyHandleError.invalidPublicKey(.keyAgreement)
        }
        return publicKey
    }

    private func secureEnclaveCustodyError(
        for status: OSStatus,
        role: PGPPrivateOperationRole
    ) -> SecureEnclaveCustodyHandleError {
        switch status {
        case errSecItemNotFound:
            return .privateHandleMissing(role)
        case errSecUserCanceled:
            return .localAuthenticationCancelled(role)
        case errSecAuthFailed:
            return .localAuthenticationFailed(role)
        case errSecInteractionNotAllowed:
            return .privateHandleUnauthorized(role)
        case errSecNotAvailable:
            return .hardwareUnavailable
        default:
            return .privateHandleInaccessible(role)
        }
    }

    private func failureCategory(for error: Error) -> PGPKeyOperationFailureCategory {
        if let custodyError = error as? SecureEnclaveCustodyHandleError {
            return custodyError.failureCategory
        }
        let nsError = error as NSError
        if nsError.domain == LAError.errorDomain,
           let code = LAError.Code(rawValue: nsError.code) {
            switch code {
            case .userCancel, .systemCancel, .appCancel:
                return .localAuthenticationCancelled
            case .biometryLockout:
                return .localAuthenticationLockedOut
            case .biometryNotAvailable, .biometryNotEnrolled:
                return .localAuthenticationUnavailable
            case .authenticationFailed:
                return .localAuthenticationFailed
            case .notInteractive:
                return .privateHandleUnauthorized
            default:
                return .privateHandleInaccessible
            }
        }
        return .privateHandleInaccessible
    }

    private func assertDoesNotLeak(
        _ error: Error,
        pair: SecureEnclaveCustodyHandlePair,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let text = String(describing: error)
        assertSanitizedText(text, pair: pair, file: file, line: line)
    }

    private func assertTraceIsSanitized(
        _ entries: [AuthLifecycleTraceStore.Entry],
        pair: SecureEnclaveCustodyHandlePair,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertFalse(entries.isEmpty, file: file, line: line)
        let text = entries
            .flatMap { entry in
                [entry.name] + entry.metadata.flatMap { [$0.key, $0.value] }
            }
            .joined(separator: " ")
        assertSanitizedText(text, pair: pair, file: file, line: line)
    }

    private func assertSanitizedText(
        _ text: String,
        pair: SecureEnclaveCustodyHandlePair,
        file: StaticString,
        line: UInt
    ) {
        XCTAssertFalse(text.contains(pair.handleSetIdentifier), file: file, line: line)
        XCTAssertFalse(text.contains(pair.signing.reference.applicationTagString), file: file, line: line)
        XCTAssertFalse(text.contains(pair.keyAgreement.reference.applicationTagString), file: file, line: line)
        XCTAssertFalse(text.contains(pair.signing.publicKeyX963.base64EncodedString()), file: file, line: line)
        XCTAssertFalse(text.contains(pair.keyAgreement.publicKeyX963.base64EncodedString()), file: file, line: line)
        XCTAssertFalse(text.contains(hex(pair.signing.publicKeyX963)), file: file, line: line)
        XCTAssertFalse(text.contains(hex(pair.keyAgreement.publicKeyX963)), file: file, line: line)
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
