import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Stores
import Vault
import VaultTestSupport
import XCTest

final class CustodyKeyStoreTests: XCTestCase {
    private var enclave: FakeEnclave!
    private var session: UnlockedSession!
    private var store: CustodyKeyStore!
    private var rowStores: [String: InMemoryRowStore] = [:]

    override func setUp() async throws {
        try await super.setUp()
        enclave = FakeEnclave()
        let vault = Vault(enclave: enclave, rootRows: InMemoryRowStore(), stretcher: FakeStretcher(), authenticator: CountingAuthenticator())
        session = try await vault.bootstrap(passphrase: .text("pass"), reason: "test")
        let shared = OSAllocatedUnfairLockBox<[String: InMemoryRowStore]>([:])
        store = CustodyKeyStore(enclave: enclave) { tier, role in
            shared.withLock { stores in
                let key = "\(tier.rawValue).\(role.rawValue)"
                if let existing = stores[key] { return existing }
                let created = InMemoryRowStore(); stores[key] = created; return created
            }
        }
    }

    func test_createPair_usesThePasswordPolicyEverywhereButMLKEM() throws {
        let policiesBefore = enclave.createdPolicies.count
        _ = try store.createPair(tier: .classicalP256, session: session, context: session.operationContext())
        _ = try store.createPair(tier: .postQuantum, session: session, context: session.operationContext())
        _ = try store.createPair(tier: .postQuantumHigh, session: session, context: session.operationContext())
        XCTAssertEqual(Array(enclave.createdPolicies.dropFirst(policiesBefore)), [
            .biometricAndPassword, .biometricAndPassword,
            .biometricAndPassword, .biometricOnly,
            .biometricAndPassword, .biometricOnly,
        ])
        XCTAssertEqual(try store.inventory().bindings.count, 6)
        XCTAssertEqual(try store.inventory().malformedRowCount, 0)
    }

    func test_locateLoadAndOperate_p256() throws {
        let pair = try store.createPair(tier: .classicalP256, session: session, context: session.operationContext())
        let located = try store.locatePair(tier: .classicalP256, signingPublicKeyRaw: pair.signing.binding.publicKeyRaw, keyAgreementPublicKeyRaw: pair.keyAgreement.binding.publicKeyRaw)
        XCTAssertEqual(located.handleSetIdentifier, pair.signing.reference.handleSetIdentifier)

        let signing = try store.loadHandle(reference: located.signing.reference, expectedPublicKeyRaw: located.signing.publicKeyRaw, session: session, context: session.operationContext())
        let digest = Data(SHA256.hash(data: Data("message".utf8)))
        let (r, s) = try signing.signDigest(digest)
        XCTAssertEqual(r.count + s.count, 64)

        let agreement = try store.loadHandle(reference: located.keyAgreement.reference, expectedPublicKeyRaw: located.keyAgreement.publicKeyRaw, session: session, context: session.operationContext())
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try agreement.sharedSecret(recipientPublicKeyX963: located.keyAgreement.publicKeyRaw, ephemeralPublicKeyX963: ephemeral.publicKey.x963Representation)
        let expected = try ephemeral.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: located.keyAgreement.publicKeyRaw))
        XCTAssertEqual(secret.withUnsafeBytes { Data($0) }, expected.withUnsafeBytes { Data($0) })
        do {
            _ = try agreement.sharedSecret(recipientPublicKeyX963: located.signing.publicKeyRaw, ephemeralPublicKeyX963: ephemeral.publicKey.x963Representation)
            XCTFail("a request naming another public key must be refused")
        } catch {
            XCTAssertEqual(error as? CustodyError, .handlePublicKeyBindingMismatch(.keyAgreement))
        }
    }

    func test_loadAndOperate_postQuantum() throws {
        let pair = try store.createPair(tier: .postQuantum, session: session, context: session.operationContext())
        let signing = try store.loadHandle(reference: pair.signing.reference, expectedPublicKeyRaw: pair.signing.binding.publicKeyRaw, session: session, context: session.operationContext())
        let signature = try signing.signMessage(Data("composite".utf8))
        XCTAssertTrue(try MLDSA65.PublicKey(rawRepresentation: pair.signing.binding.publicKeyRaw).isValidSignature(signature, for: Data("composite".utf8)))

        let kem = try store.loadHandle(reference: pair.keyAgreement.reference, expectedPublicKeyRaw: pair.keyAgreement.binding.publicKeyRaw, session: session, context: session.operationContext())
        let encapsulation = try MLKEM768.PublicKey(rawRepresentation: pair.keyAgreement.binding.publicKeyRaw).encapsulate()
        let secret = try kem.decapsulate(encapsulation.encapsulated)
        XCTAssertEqual(secret.withUnsafeBytes { Data($0) }, encapsulation.sharedSecret.withUnsafeBytes { Data($0) })
    }

    func test_bindingMismatch_partialPair_andMissing_areDistinguished() throws {
        let pair = try store.createPair(tier: .classicalP256, session: session, context: session.operationContext())
        let other = P256.Signing.PrivateKey().publicKey.x963Representation
        XCTAssertThrowsError(try store.locatePair(tier: .classicalP256, signingPublicKeyRaw: other, keyAgreementPublicKeyRaw: pair.keyAgreement.binding.publicKeyRaw)) {
            XCTAssertEqual($0 as? CustodyError, .handlePublicKeyBindingMismatch(.signing))
        }
        XCTAssertThrowsError(try store.loadHandle(reference: pair.signing.reference, expectedPublicKeyRaw: other, session: session, context: session.operationContext())) {
            XCTAssertEqual($0 as? CustodyError, .handlePublicKeyBindingMismatch(.signing))
        }
        try store.deletePair(try CustodyHandlePair(signing: pair.signing.binding, keyAgreement: pair.keyAgreement.binding))
        XCTAssertThrowsError(try store.locatePair(tier: .classicalP256, signingPublicKeyRaw: pair.signing.binding.publicKeyRaw, keyAgreementPublicKeyRaw: pair.keyAgreement.binding.publicKeyRaw)) {
            XCTAssertEqual($0 as? CustodyError, .privateHandleMissing(.signing))
        }
        XCTAssertEqual(try store.inventory().totalRowCount, 0)
    }

    func test_relockedSession_cannotLoadCredentialKeys() throws {
        let pair = try store.createPair(tier: .classicalP256, session: session, context: session.operationContext())
        session.relock()
        XCTAssertThrowsError(try store.loadHandle(reference: pair.signing.reference, expectedPublicKeyRaw: pair.signing.binding.publicKeyRaw, session: session, context: LAContext())) {
            XCTAssertEqual($0 as? CustodyError, .locked)
        }
    }

    func test_deleteAll_clearsEveryTier() throws {
        _ = try store.createPair(tier: .classicalP256, session: session, context: session.operationContext())
        _ = try store.createPair(tier: .postQuantumHigh, session: session, context: session.operationContext())
        try store.deleteAll()
        XCTAssertEqual(try store.inventory().totalRowCount, 0)
    }
}

/// A tiny lock box for the test's shared row stores.
private final class OSAllocatedUnfairLockBox<T>: @unchecked Sendable {
    private var value: T
    private let lock = NSLock()
    init(_ value: T) { self.value = value }
    func withLock<R>(_ body: (inout T) -> R) -> R { lock.lock(); defer { lock.unlock() }; return body(&value) }
}
