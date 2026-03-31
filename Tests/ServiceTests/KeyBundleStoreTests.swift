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

    func test_saveBundle_secondWriteFailure_rollsBackFirstItem() {
        keychain.failOnSaveNumber = 2

        XCTAssertThrowsError(try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint))
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .missing
        )
    }

    func test_promotePending_secondPermanentWriteFailure_rollsBackPermanentAndKeepsPending() throws {
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)
        keychain.failOnSaveNumber = keychain.saveCallCount + 2

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

    func test_bundleState_whenOnlyOneItemExists_returnsPartial() throws {
        try keychain.save(
            Data([0x01]),
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .partial
        )
    }

    private func makeBundle() -> WrappedKeyBundle {
        WrappedKeyBundle(
            seKeyData: Data([0x01, 0x02, 0x03]),
            salt: Data([0x04, 0x05, 0x06]),
            sealedBox: Data([0x07, 0x08, 0x09])
        )
    }
}
