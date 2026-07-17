import CryptoKit
import Foundation
import XCTest
@testable import CypherAir

/// Behavior guards for the ephemeral real-primitive sandbox custody:
/// the in-memory keychain's real row semantics plus its wipe-on-cleanup
/// contract, and one full wrap → reconstruct → unwrap roundtrip through the
/// real Secure Enclave (skipped where no enclave exists).
@MainActor
final class TutorialSandboxPrimitivesTests: TutorialSandboxDefaultsSerializedTestCase {

    // MARK: - EphemeralKeychainStore

    func test_ephemeralKeychainStore_reproducesRealRowSemanticsAndWipes() throws {
        let store = EphemeralKeychainStore()
        let service = "com.cypherair.tests.ephemeral.row"
        let account = "com.cypherair.tests"

        try store.save(Data([0x01, 0x02]), service: service, account: account, accessControl: nil)
        XCTAssertThrowsError(
            try store.save(Data([0x03]), service: service, account: account, accessControl: nil)
        ) { error in
            XCTAssertEqual(error as? EphemeralKeychainStoreError, .duplicateItem)
        }
        XCTAssertThrowsError(
            try store.load(service: "com.cypherair.tests.ephemeral.absent", account: account)
        ) { error in
            XCTAssertEqual(error as? EphemeralKeychainStoreError, .itemNotFound)
        }

        store.wipe()

        XCTAssertFalse(store.exists(service: service, account: account))
        XCTAssertEqual(try store.listItems(servicePrefix: "com.cypherair", account: account), [])
        // A wiped store accepts the same row again: rows were removed, not poisoned.
        XCTAssertNoThrow(
            try store.save(Data([0x04]), service: service, account: account, accessControl: nil)
        )
    }

    func test_tutorialContainerCleanup_wipesEphemeralKeychainRows() throws {
        let container = try TutorialSandboxContainer()
        let markerService = KeychainConstants.privateKeyEnvelopeService(fingerprint: "abcdef0123456789")
        try container.keychain.save(
            Data([0xAB]),
            service: markerService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        container.cleanup()

        XCTAssertFalse(
            container.keychain.exists(service: markerService, account: KeychainConstants.defaultAccount)
        )
    }

    // MARK: - EphemeralKeyWrappingCustody

    func test_ephemeralCustody_roundtripsOnRealEnclaveAndFailsClosedAcrossFingerprints() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave is required for the ephemeral key-wrapping custody.")
        }

        let custody = EphemeralKeyWrappingCustody()
        let fingerprint = "0123456789abcdef0123456789abcdef01234567"
        var secret = Data("tutorial-sandbox-demo-private-key".utf8)
        defer { secret.zeroize() }

        let handle = try custody.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try custody.wrap(privateKey: secret, using: handle, fingerprint: fingerprint)

        // Production-shaped open path: reconstruct the enclave key from the
        // representation the envelope row carries, then unwrap promptlessly.
        let reconstructed = try custody.reconstructKey(
            from: handle.dataRepresentation,
            authenticationContext: nil
        )
        var unwrapped = try custody.unwrap(bundle: bundle, using: reconstructed, fingerprint: fingerprint)
        defer { unwrapped.zeroize() }
        XCTAssertEqual(unwrapped, secret)

        // The fingerprint binding fails closed on a mismatched identity.
        XCTAssertThrowsError(
            try custody.unwrap(
                bundle: bundle,
                using: reconstructed,
                fingerprint: "feedfacefeedfacefeedfacefeedfacefeedface"
            )
        )
    }
}
