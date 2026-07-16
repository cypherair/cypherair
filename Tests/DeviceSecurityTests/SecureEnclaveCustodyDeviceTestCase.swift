import CryptoKit
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Shared base for device-only Secure Enclave **custody** tests — the device-bound
/// signing + key-agreement handle model, distinct from the legacy Secure
/// Enclave software-key wrapping exercised through `DeviceSecurityTestCase`.
///
/// It owns the hardware/biometric guards, software cross-verification of real
/// enclave outputs, failure-category mapping, and the sanitized-output
/// assertions shared by the custody device tests, so each lives in exactly one
/// place. Custody test classes inherit from this instead of copying these
/// helpers per file.
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

    // MARK: - Software cross-verification of real enclave outputs

    /// Verify a raw r‖s ECDSA signature produced by the enclave against the
    /// handle's public binding with software CryptoKit — independent of the
    /// production signer's own self-verify.
    final func assertValidP256Signature(
        _ signature: SecureEnclaveP256RawSignature,
        digest: Data,
        publicKeyX963: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
        let ecdsaSignature = try P256.Signing.ECDSASignature(
            rawRepresentation: signature.r + signature.s
        )
        let rawDigest = try XCTUnwrap(DeviceRawSHA256Digest(digest), file: file, line: line)
        XCTAssertTrue(
            publicKey.isValidSignature(ecdsaSignature, for: rawDigest),
            "Enclave signature failed software verification",
            file: file,
            line: line
        )
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
        XCTAssertFalse(text.contains(pair.signing.publicKeyRaw.base64EncodedString()), file: file, line: line)
        XCTAssertFalse(text.contains(pair.keyAgreement.publicKeyRaw.base64EncodedString()), file: file, line: line)
        XCTAssertFalse(text.contains(hex(pair.signing.publicKeyRaw)), file: file, line: line)
        XCTAssertFalse(text.contains(hex(pair.keyAgreement.publicKeyRaw)), file: file, line: line)
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

/// Carries a precomputed 32-byte digest into CryptoKit's digest verification,
/// mirroring the production signer's digest wrapper.
struct DeviceRawSHA256Digest: Digest {
    static var byteCount: Int { 32 }

    private let bytes: [UInt8]

    init?(_ digest: Data) {
        guard digest.count == Self.byteCount else {
            return nil
        }
        self.bytes = [UInt8](digest)
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    func makeIterator() -> Array<UInt8>.Iterator {
        bytes.makeIterator()
    }

    var description: String {
        "DeviceRawSHA256Digest"
    }
}
