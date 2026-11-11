import Foundation
import Sealing
import Stores
import Testing
import Vault
import VaultTestSupport

struct SealedSecretTests {
    let enclave = FakeEnclave()
    let keychain = InMemoryKeychain()
    let authenticator = CountingAuthenticator()
    let session: UnlockedSession

    init() async throws {
        let vault = Vault(enclave: enclave, rootRows: keychain.rows(service: Vault.sealedRootService), stretcher: FakeStretcher(), authenticator: authenticator)
        let new = try await vault.bootstrap(passphrase: .text("pass"), reason: "test")
        try new.store()
        session = new.session
    }

    private func approval() async throws -> OperationApproval {
        try await session.approve(.presence, reason: "test")
    }

    /// Opens under a fresh approval and drops the value.
    private func open(_ sealed: Data, kind: SealedSecret.Kind) async throws {
        _ = try SealedSecret.open(sealed, kind: kind, approval: try await approval())
    }

    @Test(arguments: [SealedSecret.Kind.secretKeys, .classicalHalves])
    func `Each kind opens as sealed and stores nothing`(kind: SealedSecret.Kind) async throws {
        let sealed = try SealedSecret.seal(.text("secret"), kind: kind, session: session)
        let opened = try SealedSecret.open(sealed, kind: kind, approval: try await approval())
        #expect(opened.withUnsafeBytes { Data($0) } == Data("secret".utf8))
        #expect(keychain.contents.map(\.service) == [Vault.sealedRootService])
        #expect(enclave.createdPolicies.count == 2, "sealing creates no enclave key")
    }

    @Test func `A value of one kind does not open as the other`() async throws {
        let secretKeys = try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: session)
        let halves = try SealedSecret.seal(.text("halves"), kind: .classicalHalves, session: session)
        await #expect(throws: StoreError.damaged) { try await open(secretKeys, kind: .classicalHalves) }
        await #expect(throws: StoreError.damaged) { try await open(halves, kind: .secretKeys) }
    }

    @Test func `A damaged value is damaged`() async throws {
        var sealed = try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: session)
        sealed[sealed.count / 2] ^= 0xFF
        await #expect(throws: StoreError.damaged) { try await open(sealed, kind: .secretKeys) }
    }

    @Test func `A value sealed by another vault is damaged`() async throws {
        let other = try await Vault(enclave: FakeEnclave(), rootRows: InMemoryRowStore(), stretcher: FakeStretcher(), authenticator: CountingAuthenticator())
            .bootstrap(passphrase: .text("pass"), reason: "test").session
        let sealed = try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: other)
        await #expect(throws: StoreError.damaged) { try await open(sealed, kind: .secretKeys) }
    }

    @Test func `Check refuses what cannot open, without a prompt`() throws {
        let other = try UnlockedSession.sandbox(enclave: SoftwareEnclave())
        let refused = [
            (try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: other), SealedSecret.Kind.secretKeys),
            (try SealedSecret.seal(.text("halves"), kind: .classicalHalves, session: session), .secretKeys),
            (Data("not a sealed value".utf8), .secretKeys),
        ]
        let prompts = authenticator.prompts

        try SealedSecret.check(try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: session), kind: .secretKeys, session: session)
        for (sealed, kind) in refused {
            #expect(throws: StoreError.damaged) { try SealedSecret.check(sealed, kind: kind, session: session) }
        }
        #expect(authenticator.prompts == prompts)
    }

    @Test func `An ended approval opens nothing`() async throws {
        let sealed = try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: session)
        let approval = try await approval()
        approval.end()
        #expect(throws: StoreError.vault(.approvalEnded)) {
            _ = try SealedSecret.open(sealed, kind: .secretKeys, approval: approval)
        }
    }

    @Test func `A relocked session cannot seal or open`() async throws {
        let sealed = try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: session)
        let approval = try await approval()
        session.relock()
        #expect(throws: StoreError.vault(.locked)) { try SealedSecret.seal(.text("x"), kind: .secretKeys, session: session) }
        #expect(throws: StoreError.vault(.locked)) {
            _ = try SealedSecret.open(sealed, kind: .secretKeys, approval: approval)
        }
    }
}
