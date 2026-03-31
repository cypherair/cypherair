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

    func test_recoveryAction_partialPermanentAndCompletePending_returnsReplacePermanent() throws {
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        XCTAssertEqual(
            migrationCoordinator.recoveryAction(for: fingerprint),
            .replacePermanentWithPending
        )
    }

    func test_recoveryAction_withoutCompleteBundle_returnsUnrecoverable() throws {
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try keychain.save(
            Data([0xBB]),
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

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

    func test_recoverInterruptedMigration_permanentCompleteAndPendingPartial_cleansPendingSafe() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .cleanedPendingSafe)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
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

    func test_recoverInterruptedMigration_partialPermanentAndCompletePending_replacesPermanent() throws {
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .promotedPendingSafe)
        XCTAssertEqual(
            try bundleStore.loadBundle(fingerprint: fingerprint).salt,
            makeBundle().salt
        )
    }

    func test_recoverInterruptedMigration_retryableFailure_returnsRetryableFailure() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)
        keychain.failOnSaveNumber = keychain.saveCallCount + 1

        let outcome = migrationCoordinator.recoverInterruptedMigration(for: fingerprint)

        XCTAssertEqual(outcome, .retryableFailure)
    }

    func test_recoverInterruptedMigration_withoutCompleteBundle_returnsUnrecoverable() throws {
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

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

    private func makeBundle() -> WrappedKeyBundle {
        WrappedKeyBundle(
            seKeyData: Data([0x10, 0x11, 0x12]),
            salt: Data([0x13, 0x14, 0x15]),
            sealedBox: Data([0x16, 0x17, 0x18])
        )
    }
}
