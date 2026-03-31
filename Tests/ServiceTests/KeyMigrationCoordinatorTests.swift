import XCTest
@testable import CypherAir

final class KeyMigrationCoordinatorTests: XCTestCase {
    private let fingerprint = "89abcdef0123456789abcdef0123456789abcdef"

    private var keychain: MockKeychain!
    private var bundleStore: KeyBundleStore!
    private var migrationCoordinator: KeyMigrationCoordinator!

    override func setUp() {
        super.setUp()
        keychain = MockKeychain()
        bundleStore = KeyBundleStore(keychain: keychain)
        migrationCoordinator = KeyMigrationCoordinator(bundleStore: bundleStore)
    }

    override func tearDown() {
        migrationCoordinator = nil
        bundleStore = nil
        keychain = nil
        super.tearDown()
    }

    func test_recoveryAction_permanentCompleteAndPendingPartial_returnsDeletePending() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        XCTAssertEqual(
            migrationCoordinator.recoveryAction(for: fingerprint),
            .deletePending
        )
    }

    func test_recoverInterruptedMigration_pendingOnlyComplete_promotesPending() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .promotedPending)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .complete
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    func test_recoverInterruptedMigration_permanentCompleteAndPendingPartial_cleansPending() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .cleanedPending)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    private func makeBundle() -> WrappedKeyBundle {
        WrappedKeyBundle(
            seKeyData: Data([0x10, 0x11, 0x12]),
            salt: Data([0x13, 0x14, 0x15]),
            sealedBox: Data([0x16, 0x17, 0x18])
        )
    }
}
