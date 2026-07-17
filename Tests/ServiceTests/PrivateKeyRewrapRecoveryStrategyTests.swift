import XCTest
@testable import CypherAir

final class PrivateKeyRewrapRecoveryStrategyTests: XCTestCase {
    private let fingerprint = "89abcdef0123456789abcdef0123456789abcdef"

    private var keychain: MockKeychain!
    private var bundleStore: KeyBundleStore!
    private var rewrapRecoveryStrategy: PrivateKeyRewrapRecoveryStrategy!

    override func setUp() {
        super.setUp()
        keychain = MockKeychain()
        bundleStore = KeyBundleStore(keychain: keychain)
        rewrapRecoveryStrategy = PrivateKeyRewrapRecoveryStrategy(bundleStore: bundleStore)
    }

    override func tearDown() {
        rewrapRecoveryStrategy = nil
        bundleStore = nil
        keychain = nil
        super.tearDown()
    }

    // The single-row envelope makes intra-bundle `.partial` states impossible: a row is
    // atomically present (`.complete`) or absent (`.missing`). These tests therefore cover
    // the reachable `(permanent, pending)` state space; the strategy keeps its `.partial`
    // arms as fail-closed dead-defense.

    func test_recoveryAction_permanentCompleteAndPendingComplete_returnsDeletePending() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        XCTAssertEqual(
            rewrapRecoveryStrategy.recoveryAction(for: fingerprint),
            .deletePending
        )
    }

    func test_recoveryAction_permanentCompleteAndPendingMissing_returnsNone() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)

        XCTAssertEqual(
            rewrapRecoveryStrategy.recoveryAction(for: fingerprint),
            .none
        )
    }

    func test_recoveryAction_permanentMissingAndPendingComplete_returnsPromotePending() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        XCTAssertEqual(
            rewrapRecoveryStrategy.recoveryAction(for: fingerprint),
            .promotePending
        )
    }

    func test_recoveryAction_withoutCompleteBundle_returnsUnrecoverable() {
        XCTAssertEqual(
            rewrapRecoveryStrategy.recoveryAction(for: fingerprint),
            .unrecoverable
        )
    }

    func test_recoverInterruptedRewrap_pendingOnlyComplete_promotesPendingSafe() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        let outcome = rewrapRecoveryStrategy.recoverInterruptedRewrap(for: fingerprint)

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

    func test_recoverInterruptedRewrap_pendingOnlyComplete_promotesPendingContent() throws {
        let pending = makeBundle(0x42)
        try bundleStore.saveBundle(pending, fingerprint: fingerprint, namespace: .pending)

        let outcome = rewrapRecoveryStrategy.recoverInterruptedRewrap(for: fingerprint)

        XCTAssertEqual(outcome, .promotedPendingSafe)
        XCTAssertEqual(
            try bundleStore.loadBundle(fingerprint: fingerprint).envelope,
            pending.envelope
        )
    }

    func test_recoverInterruptedRewrap_permanentCompleteAndPendingComplete_cleansPendingSafe() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        let outcome = rewrapRecoveryStrategy.recoverInterruptedRewrap(for: fingerprint)

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

    func test_recoverInterruptedRewrap_retryableFailure_returnsRetryableFailure() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)
        keychain.failOnSaveNumber = keychain.saveCallCount + 1

        let outcome = rewrapRecoveryStrategy.recoverInterruptedRewrap(for: fingerprint)

        XCTAssertEqual(outcome, .retryableFailure)
    }

    func test_recoverInterruptedRewrap_withoutCompleteBundle_returnsUnrecoverable() {
        let outcome = rewrapRecoveryStrategy.recoverInterruptedRewrap(for: fingerprint)

        XCTAssertEqual(outcome, .unrecoverable)
    }

    func test_recoverInterruptedRewraps_summaryKeepsRetryableFlagsAndSuppressesAuthModeUpdate() throws {
        let retryableFingerprint = fingerprint
        let promotedFingerprint = "00112233445566778899aabbccddeeff00112233"

        try bundleStore.saveBundle(makeBundle(), fingerprint: retryableFingerprint, namespace: .pending)
        try bundleStore.saveBundle(makeBundle(), fingerprint: promotedFingerprint, namespace: .pending)
        keychain.saveError = MockKeychainError.saveFailed

        let summary = rewrapRecoveryStrategy.recoverInterruptedRewraps(
            for: [retryableFingerprint, promotedFingerprint]
        )

        XCTAssertFalse(summary.shouldClearRecoveryFlag)
        XCTAssertFalse(summary.shouldUpdateAuthMode)
        XCTAssertTrue(summary.outcomes.contains(.retryableFailure))
    }

    private func makeBundle(_ tag: UInt8 = 0x10) -> WrappedKeyBundle {
        WrappedKeyBundle(envelope: Data([tag, tag &+ 1, tag &+ 2]))
    }
}
