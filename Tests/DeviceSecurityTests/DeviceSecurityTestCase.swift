import XCTest
@testable import CypherAir

/// Tests that need the real device: the hardware enclave, the Keychain, or
/// the system memory. Never part of the unit lane.
class DeviceSecurityTestCase: XCTestCase {
    /// The system needs a moment between two authentication sheets.
    final func waitForAuthenticationSessionToSettle() async throws {
        try await Task.sleep(for: .seconds(2))
    }
}
