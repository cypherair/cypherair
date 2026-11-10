import CryptoKit
import Foundation
import Sealing
import Stores
import Vault
import VaultTestSupport
import XCTest

final class CustodyKeyStoreTests: XCTestCase {
    private var enclave: FakeEnclave!
    private var session: UnlockedSession!
    private var store: CustodyKeyStore!

    override func setUp() async throws {
        try await super.setUp()
        enclave = FakeEnclave()
        let vault = Vault(enclave: enclave, rootRows: InMemoryRowStore(), stretcher: FakeStretcher(), authenticator: CountingAuthenticator())
        session = try await vault.bootstrap(passphrase: .text("pass"), reason: "test")
        store = CustodyKeyStore(enclave: enclave)
    }

    private func approval(_ kind: ApprovalKind = .biometrics) async throws -> OperationApproval {
        try await session.approve(kind, reason: "test")
    }

    private func load(_ handle: LoadedCustodyHandle, expecting publicKey: Data? = nil) async throws -> LoadedCustodyHandle {
        try store.loadHandle(
            role: handle.role,
            tier: handle.tier,
            blob: handle.blob,
            expectedPublicKey: publicKey ?? handle.publicKey,
            approval: try await approval()
        )
    }

    func test_createPair_usesThePasswordPolicyEverywhereButMLKEM() async throws {
        let policiesBefore = enclave.createdPolicies.count
        for tier in CustodyTier.allCases {
            _ = try store.createPair(tier: tier, approval: try await approval())
        }
        XCTAssertEqual(Array(enclave.createdPolicies.dropFirst(policiesBefore)), [
            .biometricAndPassword, .biometricAndPassword,
            .biometricAndPassword, .biometricOnly,
            .biometricAndPassword, .biometricOnly,
        ])
    }

    func test_blobsLoadAndOperate_p256() async throws {
        let pair = try store.createPair(tier: .classicalP256, approval: try await approval())

        let signing = try await load(pair.signing)
        let digest = Data(SHA256.hash(data: Data("message".utf8)))
        let (r, s) = try signing.signDigest(digest)
        XCTAssertEqual(r.count + s.count, 64)

        let agreement = try await load(pair.keyAgreement)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try agreement.sharedSecret(recipientPublicKeyX963: pair.keyAgreement.publicKey, ephemeralPublicKeyX963: ephemeral.publicKey.x963Representation)
        let expected = try ephemeral.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: pair.keyAgreement.publicKey))
        XCTAssertEqual(secret.withUnsafeBytes { Data($0) }, expected.withUnsafeBytes { Data($0) })
        do {
            _ = try agreement.sharedSecret(recipientPublicKeyX963: pair.signing.publicKey, ephemeralPublicKeyX963: ephemeral.publicKey.x963Representation)
            XCTFail("a request naming another public key must be refused")
        } catch {
            XCTAssertEqual(error, .handlePublicKeyBindingMismatch(.keyAgreement))
        }
    }

    func test_blobsLoadAndOperate_postQuantum() async throws {
        let pair = try store.createPair(tier: .postQuantum, approval: try await approval())
        let signing = try await load(pair.signing)
        let signature = try signing.signMessage(Data("composite".utf8))
        XCTAssertTrue(try MLDSA65.PublicKey(rawRepresentation: pair.signing.publicKey).isValidSignature(signature, for: Data("composite".utf8)))

        let kem = try await load(pair.keyAgreement)
        let encapsulation = try MLKEM768.PublicKey(rawRepresentation: pair.keyAgreement.publicKey).encapsulate()
        let secret = try kem.decapsulate(encapsulation.encapsulated)
        XCTAssertEqual(secret.withUnsafeBytes { Data($0) }, encapsulation.sharedSecret.withUnsafeBytes { Data($0) })
    }

    func test_aBlobThatIsNotTheExpectedKey_isRefused() async throws {
        let pair = try store.createPair(tier: .classicalP256, approval: try await approval())
        let other = P256.Signing.PrivateKey().publicKey.x963Representation
        do {
            _ = try await load(pair.signing, expecting: other)
            XCTFail("a blob loaded against another public key")
        } catch {
            XCTAssertEqual(error as? CustodyError, .handlePublicKeyBindingMismatch(.signing))
        }
    }

    func test_aPresenceApproval_doesNotReachADeviceBoundKey() async throws {
        do {
            _ = try store.createPair(tier: .classicalP256, approval: try await approval(.presence))
            XCTFail("a presence approval made a device-bound key")
        } catch {
            XCTAssertEqual(error as? CustodyError, .approvalKindMismatch)
        }
    }

    func test_relockedSession_cannotLoadCredentialKeys() async throws {
        let pair = try store.createPair(tier: .classicalP256, approval: try await approval())
        let approval = try await approval()
        session.relock()
        XCTAssertThrowsError(try store.loadHandle(role: .signing, tier: .classicalP256, blob: pair.signing.blob, expectedPublicKey: pair.signing.publicKey, approval: approval)) {
            XCTAssertEqual($0 as? CustodyError, .locked)
        }
    }
}
