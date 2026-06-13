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
final class DeviceDangerousSecureEnclaveCustodyResetCleanupTests: SecureEnclaveCustodyDeviceTestCase {
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
        recordEvidence(.localResetCleanup, handleCount: result.inspectedHandleCount)
    }
}
