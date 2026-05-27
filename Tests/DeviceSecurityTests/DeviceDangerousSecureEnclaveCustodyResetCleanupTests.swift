import CryptoKit
import LocalAuthentication
import XCTest
@testable import CypherAir

/// DANGEROUS device-only evidence for Reset All Local Data custody cleanup.
///
/// This test deletes every app-owned Secure Enclave custody `kSecClassKey` row
/// for the current app bundle, not only keys created during this test. Run it
/// only on a disposable install or device state where losing all future custody
/// handles is acceptable. It is intentionally excluded from
/// `CypherAir-DeviceTests` and selected only by
/// `CypherAir-DangerousDeviceTests`.
final class DeviceDangerousSecureEnclaveCustodyResetCleanupTests: DeviceSecurityTestCase {
    func test_DANGEROUS_resetCleanupDeletesAllAppOwnedCustodyKeyRows_onDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let traceStore = AuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let keyStore = SystemSecureEnclaveCustodyKeyStore(traceStore: traceStore)
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

        let entries = traceStore.recentEntries
        XCTAssertTrue(entries.contains { $0.name == "secureEnclaveCustody.inventory.start" })
        XCTAssertTrue(entries.contains { $0.name == "secureEnclaveCustody.inventory.finish" })
        XCTAssertTrue(entries.contains { $0.name == "secureEnclaveCustody.deleteInventoryKey.start" })
        XCTAssertTrue(entries.contains { $0.name == "secureEnclaveCustody.deleteInventoryKey.finish" })
        assertTraceIsSanitized(
            entries.filter { $0.name.hasPrefix("secureEnclaveCustody.") },
            pair: pair
        )
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
