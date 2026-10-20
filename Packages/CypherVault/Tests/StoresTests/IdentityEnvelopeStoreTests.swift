import Foundation
import LocalAuthentication
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


    /// `open` returns a non-copyable buffer, which the throwing assertion cannot take.
    private func assertOpenThrows(_ fingerprint: String, context: LAContext? = nil, _ expected: StoreError? = nil, line: UInt = #line) {
        do {
            _ = try store.open(fingerprint: fingerprint, session: session, context: context ?? session.operationContext())
            XCTFail("open succeeded", line: line)
        } catch {
            if let expected { XCTAssertEqual(error as? StoreError, expected, line: line) }
        }
    }

    func test_sealThenOpen_roundTrips_underTheIdentityKey() throws {
        try store.seal(.text("secret certificate"), fingerprint: "ABCDEF0123", session: session)
        XCTAssertTrue(try store.contains(fingerprint: "abcdef0123"))
        XCTAssertEqual(try store.fingerprints(), ["abcdef0123"])
        let opened = try store.open(fingerprint: "abcdef0123", session: session, context: session.operationContext())
        XCTAssertTrue(opened.contentEquals(.text("secret certificate")))
        XCTAssertEqual(enclave.createdPolicies.count, 2, "sealing a portable key creates no enclave key")
    }

    func test_replaceInPlace_thenDelete() throws {
        try store.seal(.text("v1"), fingerprint: "aa", session: session)
        try store.seal(.text("v2"), fingerprint: "aa", session: session)
        XCTAssertTrue(try store.open(fingerprint: "aa", session: session, context: session.operationContext()).contentEquals(.text("v2")))
        try store.delete(fingerprint: "aa")
        XCTAssertFalse(try store.contains(fingerprint: "aa"))
        assertOpenThrows("aa", .missing)
    }

    func test_rowMovedBetweenFingerprints_orDamaged_isRefused() throws {
        try store.seal(.text("secret"), fingerprint: "aa", session: session)
        let data = try XCTUnwrap(try rows.read(account: "aa"))
        try rows.write(account: "bb", data: data)
        assertOpenThrows("bb", .damaged)
        rows.corrupt(account: "aa")
        assertOpenThrows("aa")
    }

    func test_wrongKindNamespace_isRefused() throws {
        try store.seal(.text("secret"), fingerprint: "aa", session: session)
        let splitStore = IdentityEnvelopeStore(kind: .splitCustodyComponent, rows: rows)
        do {
            _ = try splitStore.open(fingerprint: "aa", session: session, context: session.operationContext())
            XCTFail("a split-custody store opened a portable-key row")
        } catch {
            XCTAssertEqual(error as? StoreError, .damaged)
        }
    }

    func test_relockedSession_cannotSealOrOpen() throws {
        try store.seal(.text("secret"), fingerprint: "aa", session: session)
        session.relock()
        XCTAssertThrowsError(try store.seal(.text("x"), fingerprint: "bb", session: session)) { XCTAssertEqual($0 as? StoreError, .vault(.locked)) }
        assertOpenThrows("aa", context: LAContext(), .vault(.locked))
    }

    func test_invalidFingerprint_isRefused() {
        XCTAssertThrowsError(try store.contains(fingerprint: "not hex")) { XCTAssertEqual($0 as? StoreError, .invalidFingerprint) }
    }
}
