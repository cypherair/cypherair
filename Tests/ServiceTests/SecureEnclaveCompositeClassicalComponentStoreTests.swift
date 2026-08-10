import Foundation
import XCTest
@testable import CypherAir

/// The namespace boundary around the split-custody classical component
/// (docs/CUSTODY.md §7): the sealed component lives in exactly one row family
/// of its own, and no software-custody path can reach or reinterpret it.
final class SecureEnclaveCompositeClassicalComponentStoreTests: XCTestCase {
    private let fingerprint = "0123456789abcdef0123456789abcdef01234567"

    private var keychain: MockKeychain!
    private var secureEnclave: MockSecureEnclave!
    private var store: SecureEnclaveCompositeClassicalComponentStore!

    override func setUp() {
        super.setUp()
        keychain = MockKeychain()
        secureEnclave = MockSecureEnclave()
        store = SecureEnclaveCompositeClassicalComponentStore(
            secureEnclave: secureEnclave,
            keychain: keychain
        )
    }

    override func tearDown() {
        store = nil
        secureEnclave = nil
        keychain = nil
        super.tearDown()
    }

    func test_store_writesToItsOwnNamespaceAndNoOther() throws {
        try storeComponent()

        XCTAssertEqual(
            keychain.saveCalls.map(\.service),
            [KeychainConstants.splitCustodyClassicalComponentService(fingerprint: fingerprint)]
        )
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertEqual(
            KeyBundleStore(keychain: keychain).bundleState(fingerprint: fingerprint, namespace: .permanent),
            .missing,
            "The software envelope store must not see the classical component"
        )
    }

    func test_storeThenLoad_returnsBothHalvesAndZeroizesTheInputs() throws {
        var eddsaSecret = Data(repeating: 0x31, count: 32)
        var ecdhSecret = Data(repeating: 0x32, count: 32)

        try store.store(
            fingerprint: fingerprint,
            eddsaSecret: &eddsaSecret,
            ecdhSecret: &ecdhSecret,
            tier: .postQuantum
        )

        XCTAssertEqual(eddsaSecret, Data(repeating: 0x00, count: 32))
        XCTAssertEqual(ecdhSecret, Data(repeating: 0x00, count: 32))

        let component = try store.load(
            fingerprint: fingerprint,
            authenticationContext: nil,
            tier: .postQuantum
        )
        defer { component.zeroize() }

        XCTAssertEqual(component.eddsaSecret, Data(repeating: 0x31, count: 32))
        XCTAssertEqual(component.ecdhSecret, Data(repeating: 0x32, count: 32))
    }

    func test_load_readsOnlyItsOwnNamespace() throws {
        try storeComponent()

        // Relocate the row into the software envelope namespace: the component
        // is reachable only where this store writes it, never by fingerprint
        // alone from a neighbouring row family.
        let componentRow = try keychain.load(
            service: KeychainConstants.splitCustodyClassicalComponentService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
        try keychain.delete(
            service: KeychainConstants.splitCustodyClassicalComponentService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )
        try keychain.save(
            componentRow,
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        XCTAssertThrowsError(
            try store.load(fingerprint: fingerprint, authenticationContext: nil, tier: .postQuantum)
        )
    }

    func test_softwareCertificateConsumer_cannotOpenTheComponentRow() throws {
        try storeComponent()

        let componentRow = try keychain.load(
            service: KeychainConstants.splitCustodyClassicalComponentService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        )

        // The software private-key path decodes the row before reconstructing an
        // enclave handle; the authenticated payload kind stops it there.
        XCTAssertThrowsError(
            try PrivateKeyEnvelopeCodec.seKeyData(
                from: componentRow,
                expectedFingerprint: fingerprint,
                expectedPayloadKind: .softwareSecretCertificate
            )
        ) { error in
            XCTAssertEqual(error as? PrivateKeyEnvelopeError, .payloadKindMismatch)
        }
    }

    func test_componentExists_reflectsRowPresenceWithoutUnwrapping() throws {
        XCTAssertFalse(store.componentExists(fingerprint: fingerprint))

        try storeComponent()

        XCTAssertTrue(store.componentExists(fingerprint: fingerprint))
        XCTAssertEqual(secureEnclave.unwrapCallCount, 0)
        XCTAssertEqual(secureEnclave.reconstructCallCount, 0)
    }

    func test_discardStoredComponent_removesTheRow() throws {
        try storeComponent()

        store.discardStoredComponent(fingerprint: fingerprint)

        XCTAssertFalse(store.componentExists(fingerprint: fingerprint))
    }

    func test_store_rejectsSecretsOfTheWrongTierLength() {
        var eddsaSecret = Data(repeating: 0x41, count: 32)
        var ecdhSecret = Data(repeating: 0x42, count: 32)

        XCTAssertThrowsError(
            try store.store(
                fingerprint: fingerprint,
                eddsaSecret: &eddsaSecret,
                ecdhSecret: &ecdhSecret,
                tier: .postQuantumHigh
            )
        )
        XCTAssertFalse(store.componentExists(fingerprint: fingerprint))
    }

    private func storeComponent() throws {
        var eddsaSecret = Data(repeating: 0x31, count: 32)
        var ecdhSecret = Data(repeating: 0x32, count: 32)
        try store.store(
            fingerprint: fingerprint,
            eddsaSecret: &eddsaSecret,
            ecdhSecret: &ecdhSecret,
            tier: .postQuantum
        )
    }
}
