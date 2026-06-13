import CryptoKit
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

/// Shared base for device-only Secure Enclave **custody** tests — the device-bound
/// P-256 signing + key-agreement handle model, distinct from the legacy Secure
/// Enclave software-key wrapping exercised through `DeviceSecurityTestCase`.
///
/// It owns the hardware/biometric guards, the real `SecKey` private-operation
/// helpers, failure-category mapping, and the sanitized-output assertions shared by
/// the custody device tests, so each lives in exactly one place. Custody test
/// classes inherit from this instead of copying these helpers per file.
class SecureEnclaveCustodyDeviceTestCase: DeviceSecurityTestCase {
    // MARK: - Hardware / biometric guards

    /// Skip unless this run has a real Secure Enclave and an enrolled biometric set.
    final func requireSecureEnclaveCustodyHardware() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw XCTSkip(
                "Biometric authentication is unavailable: \(error?.localizedDescription ?? "unknown")"
            )
        }
    }

    /// Acquire a single authenticated biometric `LAContext`, then forbid further
    /// interaction so callers can reuse it across private operations with one approval.
    final func authenticatedBiometricsContext(reason: String) async throws -> LAContext {
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

    // MARK: - Real SecKey private operations

    /// Load a Secure Enclave custody private key by application tag. A nil context
    /// omits `kSecUseAuthenticationContext`, which is how the non-interactive
    /// fail-closed path is exercised.
    final func loadPrivateKey(
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

    final func signDigest(_ digest: Data, using privateKey: SecKey) throws -> Data {
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

    final func verifySignature(_ signature: Data, digest: Data, publicKey: SecKey) throws {
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

    final func deriveSharedSecret(privateKey: SecKey, peerPublicKey: SecKey) throws -> Data {
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

    final func secKeyFromP256PublicKey(_ publicKeyX963: Data) throws -> SecKey {
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

    // MARK: - Failure-category mapping

    /// Sanitized failure categories acceptable when a private operation is denied
    /// without interaction; none of them carry a fingerprint or locator.
    var sanitizedPrivateOperationFailureCategories: Set<PGPKeyOperationFailureCategory> {
        [
            .localAuthenticationCancelled,
            .localAuthenticationFailed,
            .localAuthenticationUnavailable,
            .localAuthenticationLockedOut,
            .privateHandleInaccessible,
            .privateHandleUnauthorized
        ]
    }

    final func secureEnclaveCustodyError(
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

    final func failureCategory(for error: Error) -> PGPKeyOperationFailureCategory {
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

    // MARK: - Sanitized-output assertions

    final func assertDoesNotLeak(
        _ error: Error,
        pair: SecureEnclaveCustodyHandlePair,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let text = String(describing: error)
        assertSanitizedText(text, pair: pair, file: file, line: line)
    }

    final func assertTraceIsSanitized(
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

    final func assertSanitizedText(
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

    final func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Evidence

    /// Emit a sanitized Phase 8 evidence line whose `outcome` reflects whether this
    /// test method has recorded any assertion failure up to this point. XCTest
    /// assertions are non-fatal, so a literal `.passed` would mislead the evidence
    /// matrix on a regression (the test goes red, yet the harvested line still
    /// claimed passed). Deriving the outcome from `testRun?.failureCount` keeps an
    /// emitted `outcome=passed` honest, and conservatively marks `.failed` once any
    /// assertion in the method has failed.
    final func recordEvidence(
        _ scenario: SecureEnclaveCustodyEvidenceScenario,
        configuration: SecureEnclaveCustodyEvidenceConfiguration? = nil,
        observedCategory: PGPKeyOperationFailureCategory? = nil,
        handleCount: Int? = nil,
        completeSetCount: Int? = nil
    ) {
        let outcome: SecureEnclaveCustodyEvidenceOutcome =
            (testRun?.failureCount ?? 0) == 0 ? .passed : .failed
        SecureEnclaveCustodyEvidenceLog.record(
            SecureEnclaveCustodyEvidenceSummary(
                scenario: scenario,
                configuration: configuration,
                outcome: outcome,
                observedCategory: observedCategory,
                handleCount: handleCount,
                completeSetCount: completeSetCount
            )
        )
    }
}
