import XCTest
@testable import CypherAir

final class KeyBundleStoreTests: XCTestCase {
    private let fingerprint = "0123456789abcdef0123456789abcdef01234567"

    private var keychain: MockKeychain!
    private var bundleStore: KeyBundleStore!

    override func setUp() {
        super.setUp()
        keychain = MockKeychain()
        bundleStore = KeyBundleStore(keychain: keychain)
    }

    override func tearDown() {
        bundleStore = nil
        keychain = nil
        super.tearDown()
    }

    func test_saveAndLoadBundle_roundTrips() throws {
        let bundle = makeBundle()
        try bundleStore.saveBundle(bundle, fingerprint: fingerprint)

        XCTAssertEqual(try bundleStore.loadBundle(fingerprint: fingerprint).envelope, bundle.envelope)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .complete
        )
    }

    func test_loadBundle_whenMissing_throws() {
        XCTAssertThrowsError(try bundleStore.loadBundle(fingerprint: fingerprint))
    }

    func test_saveBundle_writeFailure_surfacesAndPersistsNothing() {
        keychain.failOnSaveNumber = 1

        XCTAssertThrowsError(try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint))
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .missing
        )
    }

    func test_saveNewBundle_receiptRollback_removesCreatedRow() throws {
        let receipt = try bundleStore.saveNewBundle(makeBundle(), fingerprint: fingerprint)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .complete
        )

        bundleStore.rollback(receipt)

        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .missing
        )
    }

    func test_saveNewBundle_duplicate_keepsPreexistingBundle() throws {
        let original = makeBundle()
        try bundleStore.saveBundle(original, fingerprint: fingerprint)

        XCTAssertThrowsError(
            try bundleStore.saveNewBundle(makeDifferentBundle(), fingerprint: fingerprint)
        )

        XCTAssertEqual(try bundleStore.loadBundle(fingerprint: fingerprint).envelope, original.envelope)
    }

    func test_promotePendingToPermanent_movesRow() throws {
        let pending = makeBundle()
        try bundleStore.saveBundle(pending, fingerprint: fingerprint, namespace: .pending)

        try bundleStore.promotePendingToPermanent(fingerprint: fingerprint)

        XCTAssertEqual(try bundleStore.loadBundle(fingerprint: fingerprint).envelope, pending.envelope)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    func test_promotePending_permanentWriteFailure_keepsPending() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)
        keychain.failOnSaveNumber = keychain.saveCallCount + 1

        XCTAssertThrowsError(try bundleStore.promotePendingToPermanent(fingerprint: fingerprint))
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .missing
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .complete
        )
    }

    func test_replacePermanentWithPending_replacesResidualPermanent() throws {
        try bundleStore.saveBundle(makeDifferentBundle(), fingerprint: fingerprint, namespace: .permanent)
        let pending = makeBundle()
        try bundleStore.saveBundle(pending, fingerprint: fingerprint, namespace: .pending)

        try bundleStore.replacePermanentWithPending(fingerprint: fingerprint)

        XCTAssertEqual(try bundleStore.loadBundle(fingerprint: fingerprint).envelope, pending.envelope)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    func test_replacePermanentWithPending_withoutResidualPermanent_succeeds() throws {
        let pending = makeBundle()
        try bundleStore.saveBundle(pending, fingerprint: fingerprint, namespace: .pending)

        try bundleStore.replacePermanentWithPending(fingerprint: fingerprint)

        XCTAssertEqual(try bundleStore.loadBundle(fingerprint: fingerprint).envelope, pending.envelope)
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    func test_replacePermanentWithPending_deleteFailure_keepsPending() throws {
        try bundleStore.saveBundle(makeDifferentBundle(), fingerprint: fingerprint, namespace: .permanent)
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        keychain.failOnDeleteNumber = 1

        XCTAssertThrowsError(try bundleStore.replacePermanentWithPending(fingerprint: fingerprint))
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .complete
        )
    }

    func test_deleteBundle_removesRow() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)

        try bundleStore.deleteBundle(fingerprint: fingerprint)

        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .missing
        )
    }

    func test_deleteBundleAllowingMissing_toleratesMissingRow() {
        XCTAssertNoThrow(try bundleStore.deleteBundleAllowingMissing(fingerprint: fingerprint))
    }

    func test_bundleState_reflectsRowPresence() throws {
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .missing
        )

        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint)

        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .complete
        )
    }

    private func makeBundle() -> WrappedKeyBundle {
        WrappedKeyBundle(envelope: Data([0x01, 0x02, 0x03]))
    }

    private func makeDifferentBundle() -> WrappedKeyBundle {
        WrappedKeyBundle(envelope: Data([0x21, 0x22, 0x23]))
    }
}
