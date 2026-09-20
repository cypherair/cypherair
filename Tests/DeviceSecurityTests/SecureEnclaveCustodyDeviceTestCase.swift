import CryptoKit
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Device tests that drive Secure Enclave custody keys under a real biometric
/// prompt. Every test costs the operator one Face ID or Touch ID.
class SecureEnclaveCustodyDeviceTestCase: DeviceSecurityTestCase {
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

    final func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    final func recordEvidence(
        _ scenario: SecureEnclaveCustodyEvidenceScenario,
        configuration: SecureEnclaveCustodyEvidenceFamily? = nil,
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
