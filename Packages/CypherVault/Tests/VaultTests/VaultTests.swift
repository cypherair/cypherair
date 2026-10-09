import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Vault
import VaultTestSupport
import XCTest

final class VaultTests: XCTestCase {
    private var enclave: FakeEnclave!
    private var storage: InMemoryRowStore!
    private var authenticator: CountingAuthenticator!
    private var vault: Vault!

    override func setUp() {
        super.setUp()
        enclave = FakeEnclave()
        storage = InMemoryRowStore()
        authenticator = CountingAuthenticator()
        vault = Vault(enclave: enclave, rootRows: storage, stretcher: FakeStretcher(), authenticator: authenticator)
    }

    private func bootstrap(_ passphrase: String = "correct horse") async throws -> UnlockedSession {
        try await vault.bootstrap(passphrase: .text(passphrase), reason: "test")
    }

    private func unlock(_ passphrase: String) async throws -> UnlockedSession {
        try await vault.beginUnlock(reason: "test").submit(passphrase: .text(passphrase))
    }

    private func keyBytes(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

    func test_bootstrap_createsExactlyTwoKeys_bothUnderPresenceAndPassword() async throws {
        let session = try await bootstrap()
        XCTAssertEqual(enclave.createdPolicies, [.presenceAndPassword, .presenceAndPassword])
        XCTAssertEqual(authenticator.prompts, 1)
        XCTAssertTrue(try vault.sealedRootExists())
        XCTAssertFalse(session.isLocked)
    }

    func test_unlock_reproducesTheSameSessionValues() async throws {
        let first = try await bootstrap()
        let contactsKey = keyBytes(try first.domainKey("contacts"))
        let second = try await unlock("correct horse")
        XCTAssertEqual(keyBytes(try second.domainKey("contacts")), contactsKey)
        XCTAssertNotEqual(keyBytes(try second.domainKey("settings")), contactsKey)
        XCTAssertEqual(second.identityWrappingKeyBlob, first.identityWrappingKeyBlob)
    }

    func test_wrongPassphrase_isRejected_andRetryOnTheSameAttemptNeedsNoSecondPrompt() async throws {
        _ = try await bootstrap()
        let promptsAfterBootstrap = authenticator.prompts
        let attempt = vault.beginUnlock(reason: "test")
        do {
            _ = try await attempt.submit(passphrase: .text("wrong"))
            XCTFail("wrong passphrase opened the root")
        } catch {
            XCTAssertEqual(error as? VaultError, .passphraseRejected)
        }
        let session = try await attempt.submit(passphrase: .text("correct horse"))
        XCTAssertFalse(session.isLocked)
        XCTAssertEqual(authenticator.prompts, promptsAfterBootstrap + 1)
    }

    func test_cancelledOrFailedPresence_neverTouchesTheRoot() async throws {
        _ = try await bootstrap()
        authenticator.failure = .authenticationCancelled
        do {
            _ = try await unlock("correct horse")
            XCTFail("unlock succeeded without presence")
        } catch {
            XCTAssertEqual(error as? VaultError, .authenticationCancelled)
        }
    }

    func test_changePassphrase_keepsIdentityKeyAndRoot_andRetiresTheOldPassphrase() async throws {
        let before = try await bootstrap("old one")
        let contactsKey = keyBytes(try before.domainKey("contacts"))
        let secret = SensitiveBuffer.text("portable key")
        let envelope = try before.sealForIdentity(plaintext: secret, kind: .secretCertificate, associatedData: Data("fp".utf8))

        try await vault.changePassphrase(current: .text("old one"), new: .text("new one"), reason: "test")

        do {
            _ = try await unlock("old one")
            XCTFail("old passphrase still opens the root")
        } catch {
            XCTAssertEqual(error as? VaultError, .passphraseRejected)
        }
        let after = try await unlock("new one")
        XCTAssertEqual(keyBytes(try after.domainKey("contacts")), contactsKey, "root secret must survive a passphrase change")
        XCTAssertEqual(after.identityWrappingKeyBlob, before.identityWrappingKeyBlob, "identity keys never change with the passphrase")
        let opened = try after.openIdentityEnvelope(envelope, kind: .secretCertificate, context: after.operationContext())
        XCTAssertTrue(opened.contentEquals(.text("portable key")))
        XCTAssertEqual(enclave.createdPolicies.count, 3, "a passphrase change creates exactly one new key")
    }

    func test_changePassphrase_withWrongCurrent_changesNothing() async throws {
        _ = try await bootstrap("old one")
        let stored = try storage.read(account: Vault.sealedRootAccount)
        do {
            try await vault.changePassphrase(current: .text("nope"), new: .text("new one"), reason: "test")
            XCTFail("change accepted a wrong current passphrase")
        } catch {
            XCTAssertEqual(error as? VaultError, .passphraseRejected)
        }
        XCTAssertEqual(try storage.read(account: Vault.sealedRootAccount), stored)
    }

    func test_relock_erasesTheSession() async throws {
        let session = try await bootstrap()
        session.relock()
        XCTAssertTrue(session.isLocked)
        XCTAssertThrowsError(try session.domainKey("contacts")) { XCTAssertEqual($0 as? VaultError, .locked) }
        XCTAssertThrowsError(try session.withIdentityCredential { _ in 0 }) { XCTAssertEqual($0 as? VaultError, .locked) }
        let secret = SensitiveBuffer.text("x")
        XCTAssertThrowsError(try session.sealForIdentity(plaintext: secret, kind: .secretCertificate, associatedData: Data()))
    }

    func test_identityEnvelope_needsTheIdentityCredential() async throws {
        let session = try await bootstrap()
        let secret = SensitiveBuffer.text("certificate")
        let envelope = try session.sealForIdentity(plaintext: secret, kind: .secretCertificate, associatedData: Data("fp".utf8))
        let opened = try session.openIdentityEnvelope(envelope, kind: .secretCertificate, context: session.operationContext())
        XCTAssertTrue(opened.contentEquals(.text("certificate")))
        // The fake enclave refuses the identity key without the exact credential,
        // exactly as the hardware does; a foreign credential must not open it.
        XCTAssertThrowsError(try enclave.keyAgreementKey(from: session.identityWrappingKeyBlob, credential: .text("not it"), context: LAContext()))
    }

    func test_damagedOrMissingRoot_isReportedAsSuch() async throws {
        do {
            _ = try await unlock("anything")
            XCTFail("unlock without a root succeeded")
        } catch {
            XCTAssertEqual(error as? VaultError, .noSealedRoot)
        }
        _ = try await bootstrap()
        storage.corrupt(account: Vault.sealedRootAccount)
        do {
            _ = try await unlock("correct horse")
            XCTFail("corrupt root opened")
        } catch {
            XCTAssertEqual(error as? VaultError, .sealedRootCorrupt)
        }
    }

    func test_reset_deletesTheRoot() async throws {
        _ = try await bootstrap()
        try vault.reset()
        XCTAssertFalse(try vault.sealedRootExists())
    }

    func test_unavailableEnclave_failsClosed() async throws {
        enclave.isAvailable = false
        do {
            _ = try await bootstrap()
            XCTFail("bootstrap without an enclave succeeded")
        } catch {
            XCTAssertEqual(error as? VaultError, .enclaveUnavailable)
        }
    }
}
