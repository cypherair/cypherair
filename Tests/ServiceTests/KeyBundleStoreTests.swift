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

    func test_saveNewBundle_receiptRollback_removesCreatedItems() throws {
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

    func test_saveNewBundle_duplicateFirstItem_keepsPreexistingBundle() throws {
        let original = makeBundle()
        try bundleStore.saveBundle(original, fingerprint: fingerprint)

        XCTAssertThrowsError(
            try bundleStore.saveNewBundle(makeDifferentBundle(), fingerprint: fingerprint)
        )

        let stored = try bundleStore.loadBundle(fingerprint: fingerprint)
        XCTAssertEqual(stored.seKeyData, original.seKeyData)
        XCTAssertEqual(stored.salt, original.salt)
        XCTAssertEqual(stored.sealedBox, original.sealedBox)
    }

    func test_saveNewBundle_duplicateSecondItem_keepsPreexistingItemAndRollsBackCreatedItem() throws {
        let account = KeychainConstants.defaultAccount
        let originalSalt = Data([0xAA])
        try keychain.save(
            originalSalt,
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )

        XCTAssertThrowsError(try bundleStore.saveNewBundle(makeBundle(), fingerprint: fingerprint))

        XCTAssertFalse(
            keychain.exists(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: account
            )
        )
        XCTAssertEqual(
            try keychain.load(
                service: KeychainConstants.saltService(fingerprint: fingerprint),
                account: account
            ),
            originalSalt
        )
        XCTAssertFalse(
            keychain.exists(
                service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
                account: account
            )
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

    func test_replacePermanentWithPending_residualSeKey_replacesBundle() throws {
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        try bundleStore.replacePermanentWithPending(fingerprint: fingerprint)

        XCTAssertEqual(
            try bundleStore.loadBundle(fingerprint: fingerprint).seKeyData,
            makeBundle().seKeyData
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    func test_replacePermanentWithPending_residualSalt_replacesBundle() throws {
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        try bundleStore.replacePermanentWithPending(fingerprint: fingerprint)

        XCTAssertEqual(
            try bundleStore.loadBundle(fingerprint: fingerprint).salt,
            makeBundle().salt
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    func test_replacePermanentWithPending_residualSealed_replacesBundle() throws {
        try keychain.save(
            Data([0xAA]),
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        try bundleStore.replacePermanentWithPending(fingerprint: fingerprint)

        XCTAssertEqual(
            try bundleStore.loadBundle(fingerprint: fingerprint).sealedBox,
            makeBundle().sealedBox
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .missing
        )
    }

    func test_replacePermanentWithPending_deleteFailure_keepsPendingAndRemainingPermanent() throws {
        let account = KeychainConstants.defaultAccount
        try keychain.save(
            Data([0x01]),
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            Data([0x02]),
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        keychain.failOnDeleteNumber = 2

        XCTAssertThrowsError(try bundleStore.replacePermanentWithPending(fingerprint: fingerprint))
        XCTAssertTrue(
            keychain.exists(
                service: KeychainConstants.saltService(fingerprint: fingerprint),
                account: account
            )
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .complete
        )
    }

    func test_replacePermanentWithPending_saveFailure_rollsBackNewPermanentAndKeepsPending() throws {
        let account = KeychainConstants.defaultAccount
        try keychain.save(
            Data([0x01]),
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try bundleStore.saveBundle(makeBundle(), fingerprint: fingerprint, namespace: .pending)

        keychain.failOnSaveNumber = keychain.saveCallCount + 2

        XCTAssertThrowsError(try bundleStore.replacePermanentWithPending(fingerprint: fingerprint))
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .pending),
            .complete
        )
        XCTAssertEqual(
            bundleStore.bundleState(fingerprint: fingerprint, namespace: .permanent),
            .missing
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

    private func makeDifferentBundle() -> WrappedKeyBundle {
        WrappedKeyBundle(
            seKeyData: Data([0x21, 0x22, 0x23]),
            salt: Data([0x24, 0x25, 0x26]),
            sealedBox: Data([0x27, 0x28, 0x29])
        )
    }
}
