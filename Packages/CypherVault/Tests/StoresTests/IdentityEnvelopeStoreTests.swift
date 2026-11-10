import Foundation
import Sealing
import Stores
import Vault
import VaultTestSupport
import XCTest

final class IdentityEnvelopeStoreTests: XCTestCase {
    private var enclave: FakeEnclave!
    private var rows: InMemoryRowStore!
    private var session: UnlockedSession!
    private var store: IdentityEnvelopeStore!

    override func setUp() async throws {
        try await super.setUp()
        enclave = FakeEnclave()
        rows = InMemoryRowStore()
        let vault = Vault(enclave: enclave, rootRows: InMemoryRowStore(), stretcher: FakeStretcher(), authenticator: CountingAuthenticator())
        session = try await vault.bootstrap(passphrase: .text("pass"), reason: "test")
        store = IdentityEnvelopeStore(kind: .secretCertificate, rows: rows)
    }


    private func approval() async throws -> OperationApproval {
        try await session.approve(.presence, reason: "test")
    }

    /// `open` returns a non-copyable buffer, which the throwing assertion cannot take.
    private func assertOpenThrows(_ fingerprint: String, _ expected: StoreError? = nil, line: UInt = #line) async throws {
        let approval = try await approval()
        do {
            _ = try store.open(fingerprint: fingerprint, session: session, approval: approval)
            XCTFail("open succeeded", line: line)
        } catch {
            if let expected { XCTAssertEqual(error as? StoreError, expected, line: line) }
        }
    }

    func test_sealThenOpen_roundTrips_underTheIdentityKey() async throws {
        try store.seal(.text("secret certificate"), fingerprint: "ABCDEF0123", session: session)
        XCTAssertTrue(try store.contains(fingerprint: "abcdef0123"))
        XCTAssertEqual(try store.fingerprints(), ["abcdef0123"])
        let opened = try store.open(fingerprint: "abcdef0123", session: session, approval: try await approval())
        XCTAssertTrue(opened.contentEquals(.text("secret certificate")))
        XCTAssertEqual(enclave.createdPolicies.count, 2, "sealing a portable key creates no enclave key")
    }

    func test_replaceInPlace_thenDelete() async throws {
        try store.seal(.text("v1"), fingerprint: "aa", session: session)
        try store.seal(.text("v2"), fingerprint: "aa", session: session)
        let approval = try await approval()
        XCTAssertTrue(try store.open(fingerprint: "aa", session: session, approval: approval).contentEquals(.text("v2")))
        try store.delete(fingerprint: "aa")
        XCTAssertFalse(try store.contains(fingerprint: "aa"))
        try await assertOpenThrows("aa", .missing)
    }

    func test_rowMovedBetweenFingerprints_orDamaged_isRefused() async throws {
        try store.seal(.text("secret"), fingerprint: "aa", session: session)
        let data = try XCTUnwrap(try rows.read(account: "aa"))
        try rows.write(account: "bb", data: data)
        try await assertOpenThrows("bb", .damaged)
        rows.corrupt(account: "aa")
        try await assertOpenThrows("aa")
    }

    func test_wrongKindNamespace_isRefused() async throws {
        try store.seal(.text("secret"), fingerprint: "aa", session: session)
        let splitStore = IdentityEnvelopeStore(kind: .splitCustodyComponent, rows: rows)
        do {
            _ = try splitStore.open(fingerprint: "aa", session: session, approval: try await approval())
            XCTFail("a split-custody store opened a portable-key row")
        } catch {
            XCTAssertEqual(error as? StoreError, .damaged)
        }
    }

    func test_relockedSession_cannotSealOrOpen() async throws {
        try store.seal(.text("secret"), fingerprint: "aa", session: session)
        let approval = try await approval()
        session.relock()
        XCTAssertThrowsError(try store.seal(.text("x"), fingerprint: "bb", session: session)) { XCTAssertEqual($0 as? StoreError, .vault(.locked)) }
        do {
            _ = try store.open(fingerprint: "aa", session: session, approval: approval)
            XCTFail("a relocked session opened a row")
        } catch {
            XCTAssertEqual(error, .vault(.locked))
        }
    }

    func test_invalidFingerprint_isRefused() {
        XCTAssertThrowsError(try store.contains(fingerprint: "not hex")) { XCTAssertEqual($0 as? StoreError, .invalidFingerprint) }
    }
}
