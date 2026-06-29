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

    // The single-row envelope makes intra-bundle `.partial` states impossible: a row is
    // atomically present (`.complete`) or absent (`.missing`). These tests therefore cover
    // the reachable `(permanent, pending)` state space; the coordinator keeps its `.partial`
    // arms as fail-closed dead-defense.

    func test_recoveryAction_permanentCompleteAndPendingComplete_returnsDeletePending() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        XCTAssertEqual(
            migrationCoordinator.recoveryAction(for: fingerprint),
            .deletePending
        )
    }

    func test_recoveryAction_permanentCompleteAndPendingMissing_returnsNone() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)

        XCTAssertEqual(
            migrationCoordinator.recoveryAction(for: fingerprint),
            .none
        )
    }

    func test_recoveryAction_permanentMissingAndPendingComplete_returnsPromotePending() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        XCTAssertEqual(
            migrationCoordinator.recoveryAction(for: fingerprint),
            .promotePending
        )
    }

    func test_recoveryAction_withoutCompleteBundle_returnsUnrecoverable() {
        XCTAssertEqual(
            migrationCoordinator.recoveryAction(for: fingerprint),
            .unrecoverable
        )
    }

    func test_recoverInterruptedMigration_pendingOnlyComplete_promotesPendingSafe() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .promotedPendingSafe)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .complete
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    func test_recoverInterruptedMigration_pendingOnlyComplete_promotesPendingContent() throws {
        let pending = makeBundle(0x42)
        try bundleStore.saveBundle(pending, fingerprint: fingerprint, namespace: .pending)

        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .promotedPendingSafe)
        XCTAssertEqual(
            try bundleStore.loadBundle(fingerprint: fingerprint).envelope,
            pending.envelope
        )
    }

    func test_recoverInterruptedMigration_permanentCompleteAndPendingComplete_cleansPendingSafe() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .cleanedPendingSafe)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .complete
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    func test_recoverInterruptedMigration_retryableFailure_returnsRetryableFailure() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)
        keychain.failOnSaveNumber = keychain.saveCallCount + 1

        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .retryableFailure)
    }

    func test_recoverInterruptedMigration_withoutCompleteBundle_returnsUnrecoverable() {
        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .unrecoverable)
    }

    func test_recoverInterruptedMigrations_summaryKeepsRetryableFlagsAndSuppressesAuthModeUpdate() throws {
        let retryableFingerprint = fingerprint
        let promotedFingerprint = "00112233445566778899aabbccddeeff00112233"

        try bundleStore.saveBundle(makeBundle(), fingerprint: retryableFingerprint, namespace: .pending)
        try bundleStore.saveBundle(makeBundle(), fingerprint: promotedFingerprint, namespace: .pending)
        keychain.saveError = MockKeychainError.saveFailed

        let summary = migrationCoordinator.recoverInterruptedMigrations(
            for: [retryableFingerprint, promotedFingerprint]
        )

        XCTAssertFalse(summary.shouldClearRecoveryFlag)
        XCTAssertFalse(summary.shouldUpdateAuthMode)
        XCTAssertTrue(summary.startupDiagnostics.contains {
            $0.contains("retry")
        })
    }

    private func makeBundle(_ tag: UInt8 = 0x10) -> WrappedKeyBundle {
        WrappedKeyBundle(envelope: Data([tag, tag &+ 1, tag &+ 2]))
    }
}
