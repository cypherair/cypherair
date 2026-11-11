import CryptoKit
import Foundation
import Sealing
import Stores
import Testing
import Vault
import VaultTestSupport

struct CustodyKeyStoreTests {
    let enclave = FakeEnclave()
    let session: UnlockedSession
    let store: CustodyKeyStore

    init() async throws {
        let vault = Vault(enclave: enclave, rootRows: InMemoryRowStore(), stretcher: FakeStretcher(), authenticator: CountingAuthenticator())
        session = try await vault.bootstrap(passphrase: .text("pass"), reason: "test").session
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

    @Test func `Creating a pair uses the password policy everywhere but ML-KEM`() async throws {
        let policiesBefore = enclave.createdPolicies.count
        for tier in CustodyTier.allCases {
            _ = try store.createPair(tier: tier, approval: try await approval())
        }
        #expect(Array(enclave.createdPolicies.dropFirst(policiesBefore)) == [
            .biometricAndPassword, .biometricAndPassword,
            .biometricAndPassword, .biometricOnly,
            .biometricAndPassword, .biometricOnly,
        ])
    }

    @Test func `P-256 blobs load and operate`() async throws {
        let pair = try store.createPair(tier: .classicalP256, approval: try await approval())

        let signing = try await load(pair.signing)
        let digest = Data(SHA256.hash(data: Data("message".utf8)))
        let (r, s) = try signing.signDigest(digest)
        #expect(r.count + s.count == 64)

        let agreement = try await load(pair.keyAgreement)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try agreement.sharedSecret(recipientPublicKeyX963: pair.keyAgreement.publicKey, ephemeralPublicKeyX963: ephemeral.publicKey.x963Representation)
        let expected = try ephemeral.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: pair.keyAgreement.publicKey))
        #expect(secret.withUnsafeBytes { Data($0) } == expected.withUnsafeBytes { Data($0) })
        #expect(throws: CustodyError.handlePublicKeyBindingMismatch(.keyAgreement), "a request naming another public key must be refused") {
            _ = try agreement.sharedSecret(recipientPublicKeyX963: pair.signing.publicKey, ephemeralPublicKeyX963: ephemeral.publicKey.x963Representation)
        }
    }

    @Test func `Post-quantum blobs load and operate`() async throws {
        let pair = try store.createPair(tier: .postQuantum, approval: try await approval())
        let signing = try await load(pair.signing)
        let signature = try signing.signMessage(Data("composite".utf8))
        #expect(try MLDSA65.PublicKey(rawRepresentation: pair.signing.publicKey).isValidSignature(signature, for: Data("composite".utf8)))

        let kem = try await load(pair.keyAgreement)
        let encapsulation = try MLKEM768.PublicKey(rawRepresentation: pair.keyAgreement.publicKey).encapsulate()
        let secret = try kem.decapsulate(encapsulation.encapsulated)
        #expect(secret.withUnsafeBytes { Data($0) } == encapsulation.sharedSecret.withUnsafeBytes { Data($0) })
    }

    @Test func `A blob that is not the expected key is refused`() async throws {
        let pair = try store.createPair(tier: .classicalP256, approval: try await approval())
        let other = P256.Signing.PrivateKey().publicKey.x963Representation
        await #expect(throws: CustodyError.handlePublicKeyBindingMismatch(.signing)) {
            _ = try await load(pair.signing, expecting: other)
        }
    }

    @Test func `A presence approval neither makes nor loads a device-bound key`() async throws {
        let pair = try store.createPair(tier: .classicalP256, approval: try await approval())
        let presence = try await approval(.presence)
        #expect(throws: CustodyError.approvalKindMismatch) {
            _ = try store.createPair(tier: .classicalP256, approval: presence)
        }
        #expect(throws: CustodyError.approvalKindMismatch) {
            _ = try store.loadHandle(role: .signing, tier: .classicalP256, blob: pair.signing.blob, expectedPublicKey: pair.signing.publicKey, approval: presence)
        }
    }

    @Test func `An ended approval makes and loads nothing`() async throws {
        let pair = try store.createPair(tier: .classicalP256, approval: try await approval())
        let ended = try await approval()
        ended.end()
        #expect(throws: CustodyError.approvalEnded) {
            _ = try store.createPair(tier: .classicalP256, approval: ended)
        }
        #expect(throws: CustodyError.approvalEnded) {
            _ = try store.loadHandle(role: .signing, tier: .classicalP256, blob: pair.signing.blob, expectedPublicKey: pair.signing.publicKey, approval: ended)
        }
    }

    @Test func `A relocked session makes and loads no key of any type`() async throws {
        var handles: [LoadedCustodyHandle] = []
        for tier in CustodyTier.allCases {
            let pair = try store.createPair(tier: tier, approval: try await approval())
            handles += [pair.signing, pair.keyAgreement]
        }
        let approval = try await approval()
        session.relock()
        #expect(throws: CustodyError.locked) {
            _ = try store.createPair(tier: .postQuantum, approval: approval)
        }
        for handle in handles {
            #expect(throws: CustodyError.locked, "\(handle.tier) \(handle.role)") {
                _ = try store.loadHandle(role: handle.role, tier: handle.tier, blob: handle.blob, expectedPublicKey: handle.publicKey, approval: approval)
            }
        }
    }
}
