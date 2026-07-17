import CryptoKit
import LocalAuthentication
import XCTest
@testable import CypherAir

/// DANGEROUS device-only evidence for Reset All Local Data custody cleanup.
///
/// This test deletes every app-owned Secure Enclave custody handle row for the
/// current app bundle, not only keys created during this test. Run it
/// only on a disposable install or device state where losing all future custody
/// handles is acceptable. It is intentionally excluded from
/// `CypherAir-DeviceTests` and selected only by
/// `CypherAir-DangerousDeviceTests`.
final class DeviceDangerousSecureEnclaveCustodyResetCleanupTests: SecureEnclaveCustodyDeviceTestCase {
    func test_DANGEROUS_resetCleanupDeletesAllAppOwnedCustodyKeyRows_onDevice() throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let pairLoaded = try store.createLoadedHandlePair(authenticationContext: nil)
        let pair = try SecureEnclaveCustodyHandlePair(
            signing: pairLoaded.signing.binding,
            keyAgreement: pairLoaded.keyAgreement.binding
        )
        defer {
            try? store.deleteHandlePair(pair)
        }
        XCTAssertGreaterThanOrEqual(try store.remainingHandleCountForLocalDataReset(), 2)

        let result = store.cleanupAllHandlesForLocalDataReset()
        XCTAssertNil(result.failureCategory)
        XCTAssertGreaterThanOrEqual(result.inspectedHandleCount, 2)
        XCTAssertGreaterThanOrEqual(result.deletedHandleCount, 2)
        XCTAssertEqual(try store.remainingHandleCountForLocalDataReset(), 0)
        recordEvidence(.localResetCleanup, handleCount: result.inspectedHandleCount)
    }
}
