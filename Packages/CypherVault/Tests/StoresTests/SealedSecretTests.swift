import Foundation
import Sealing
import Stores
import Vault
import VaultTestSupport
import XCTest

final class SealedSecretTests: XCTestCase {
    private var enclave: FakeEnclave!
    private var keychain: InMemoryKeychain!
    private var session: UnlockedSession!

    override func setUp() async throws {
        try await super.setUp()
        enclave = FakeEnclave()
        keychain = InMemoryKeychain()
        let vault = Vault(enclave: enclave, rootRows: keychain.rows(service: Vault.sealedRootService), stretcher: FakeStretcher(), authenticator: CountingAuthenticator())
        session = try await vault.bootstrap(passphrase: .text("pass"), reason: "test")
    }

    private func approval() async throws -> OperationApproval {
        try await session.approve(.presence, reason: "test")
    }

    /// `open` returns a non-copyable buffer, which the throwing assertion cannot take.
    private func assertOpenThrows(_ sealed: Data, kind: SealedSecret.Kind, _ expected: StoreError, line: UInt = #line) async throws {
        let approval = try await approval()
        do {
            _ = try SealedSecret.open(sealed, kind: kind, approval: approval)
            XCTFail("open succeeded", line: line)
        } catch {
            XCTAssertEqual(error, expected, line: line)
        }
    }

    func test_eachKind_opensAsSealed_andStoresNothing() async throws {
        for kind in [SealedSecret.Kind.secretKeys, .classicalHalves] {
            let sealed = try SealedSecret.seal(.text("secret"), kind: kind, session: session)
            let opened = try SealedSecret.open(sealed, kind: kind, approval: try await approval())
            XCTAssertTrue(opened.contentEquals(.text("secret")))
        }
        XCTAssertEqual(keychain.contents.map(\.service), [Vault.sealedRootService])
        XCTAssertEqual(enclave.createdPolicies.count, 2, "sealing creates no enclave key")
    }

    func test_aValueOfOneKind_doesNotOpenAsTheOther() async throws {
        let secretKeys = try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: session)
        let halves = try SealedSecret.seal(.text("halves"), kind: .classicalHalves, session: session)
        try await assertOpenThrows(secretKeys, kind: .classicalHalves, .damaged)
        try await assertOpenThrows(halves, kind: .secretKeys, .damaged)
    }

    func test_aDamagedValue_isDamaged() async throws {
        var sealed = try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: session)
        sealed[sealed.count / 2] ^= 0xFF
        try await assertOpenThrows(sealed, kind: .secretKeys, .damaged)
    }

    func test_aValueSealedByAnotherVault_isDamaged() async throws {
        let other = try await Vault(enclave: FakeEnclave(), rootRows: InMemoryRowStore(), stretcher: FakeStretcher(), authenticator: CountingAuthenticator())
            .bootstrap(passphrase: .text("pass"), reason: "test")
        let sealed = try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: other)
        try await assertOpenThrows(sealed, kind: .secretKeys, .damaged)
    }

    func test_relockedSession_cannotSealOrOpen() async throws {
        let sealed = try SealedSecret.seal(.text("secret"), kind: .secretKeys, session: session)
        let approval = try await approval()
        session.relock()
        XCTAssertThrowsError(try SealedSecret.seal(.text("x"), kind: .secretKeys, session: session)) { XCTAssertEqual($0 as? StoreError, .vault(.locked)) }
        do {
            _ = try SealedSecret.open(sealed, kind: .secretKeys, approval: approval)
            XCTFail("a relocked session opened a value")
        } catch {
            XCTAssertEqual(error, .vault(.locked))
        }
    }
}
