import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Testing
import Vault
import VaultTestSupport

struct VaultTests {
    let enclave = FakeEnclave()
    let storage = InMemoryRowStore()
    let authenticator = CountingAuthenticator()
    let vault: Vault

    init() {
        vault = Vault(enclave: enclave, rootRows: storage, stretcher: FakeStretcher(), authenticator: authenticator)
    }

    private func bootstrap(_ passphrase: String = "correct horse") async throws -> UnlockedSession {
        let new = try await vault.bootstrap(passphrase: .text(passphrase), reason: "test")
        try new.store()
        return new.session
    }

    private func unlock(_ passphrase: String) async throws -> UnlockedSession {
        try await vault.beginUnlock(reason: "test").submit(passphrase: .text(passphrase))
    }

    private func keyBytes(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

    @Test func `Bootstrap creates exactly two keys, both under presence and password`() async throws {
        let session = try await bootstrap()
        #expect(enclave.createdPolicies == [.presenceAndPassword, .presenceAndPassword])
        #expect(authenticator.prompts == 1)
        #expect(try vault.sealedRootExists())
        #expect(!session.isLocked)
    }

    @Test func `Unlock reproduces the same session values`() async throws {
        let first = try await bootstrap()
        let contactsKey = keyBytes(try first.domainKey("contacts"))
        let second = try await unlock("correct horse")
        #expect(keyBytes(try second.domainKey("contacts")) == contactsKey)
        #expect(keyBytes(try second.domainKey("settings")) != contactsKey)
        #expect(second.identityWrappingKeyBlob == first.identityWrappingKeyBlob)
    }

    @Test func `Wrong passphrase is rejected, and a retry on the same attempt needs no second prompt`() async throws {
        _ = try await bootstrap()
        let promptsAfterBootstrap = authenticator.prompts
        let attempt = vault.beginUnlock(reason: "test")
        await #expect(throws: VaultError.passphraseRejected) {
            _ = try await attempt.submit(passphrase: .text("wrong"))
        }
        let session = try await attempt.submit(passphrase: .text("correct horse"))
        #expect(!session.isLocked)
        #expect(authenticator.prompts == promptsAfterBootstrap + 1)
    }

    @Test func `A cancelled presence at unlock is reported as cancelled`() async throws {
        _ = try await bootstrap()
        authenticator.failure = .authenticationCancelled
        await #expect(throws: VaultError.authenticationCancelled) {
            _ = try await unlock("correct horse")
        }
    }

    @Test func `Changing the passphrase keeps the identity key and root, and retires the old passphrase`() async throws {
        let before = try await bootstrap("old one")
        let contactsKey = keyBytes(try before.domainKey("contacts"))
        let secret = SensitiveBuffer.text("portable key")
        let envelope = try before.sealForIdentity(plaintext: secret, kind: .secretKeys, associatedData: Data("fp".utf8))

        try await vault.changePassphrase(current: .text("old one"), new: .text("new one"), reason: "test")

        await #expect(throws: VaultError.passphraseRejected) {
            _ = try await unlock("old one")
        }
        let after = try await unlock("new one")
        #expect(keyBytes(try after.domainKey("contacts")) == contactsKey, "root secret must survive a passphrase change")
        #expect(after.identityWrappingKeyBlob == before.identityWrappingKeyBlob, "identity keys never change with the passphrase")
        let opened = try after.openIdentityEnvelope(envelope, kind: .secretKeys, approval: try await after.approve(.presence, reason: "test"))
        #expect(opened.withUnsafeBytes { Data($0) } == Data("portable key".utf8))
        #expect(enclave.createdPolicies.count == 3, "a passphrase change creates exactly one new key")
    }

    @Test func `Changing the passphrase with a wrong current one changes nothing`() async throws {
        _ = try await bootstrap("old one")
        let stored = try storage.read(account: Vault.sealedRootAccount)
        await #expect(throws: VaultError.passphraseRejected) {
            try await vault.changePassphrase(current: .text("nope"), new: .text("new one"), reason: "test")
        }
        #expect(try storage.read(account: Vault.sealedRootAccount) == stored)
    }

    @Test func `Relock erases the session`() async throws {
        let session = try await bootstrap()
        session.relock()
        #expect(session.isLocked)
        #expect(throws: VaultError.locked) { try session.domainKey("contacts") }
        #expect(throws: VaultError.locked) { try session.withIdentityCredential { _ in 0 } }
        let secret = SensitiveBuffer.text("x")
        #expect(throws: VaultError.locked) {
            try session.sealForIdentity(plaintext: secret, kind: .secretKeys, associatedData: Data())
        }
    }

    @Test func `An approval asks once for its kind, and then bars interaction`() async throws {
        let session = try await bootstrap()
        let before = (all: authenticator.prompts, biometric: authenticator.biometricPrompts)

        let presence = try await session.approve(.presence, reason: "test")
        #expect(authenticator.prompts == before.all + 1)
        #expect(authenticator.biometricPrompts == before.biometric)
        #expect(presence.kind == .presence)
        #expect(presence.context.interactionNotAllowed)

        let biometrics = try await session.approve(.biometrics, reason: "test")
        #expect(authenticator.prompts == before.all + 2)
        #expect(authenticator.biometricPrompts == before.biometric + 1)
        #expect(biometrics.kind == .biometrics)
        #expect(biometrics.context.interactionNotAllowed)
    }

    @Test(arguments: [VaultError.authenticationCancelled, .authenticationFailed, .authenticationUnavailable])
    func `A failed approval is reported as its own case`(failure: VaultError) async throws {
        let session = try await bootstrap()
        authenticator.failure = failure
        await #expect(throws: failure) {
            _ = try await session.approve(.presence, reason: "test")
        }
    }

    @Test func `A locked session gives no approval and shows no prompt`() async throws {
        let session = try await bootstrap()
        session.relock()
        let prompts = authenticator.prompts
        await #expect(throws: VaultError.locked) {
            _ = try await session.approve(.presence, reason: "test")
        }
        #expect(authenticator.prompts == prompts)
    }

    @Test func `A damaged or missing root is reported as such`() async throws {
        await #expect(throws: VaultError.noSealedRoot) {
            _ = try await unlock("anything")
        }
        _ = try await bootstrap()
        storage.corrupt(account: Vault.sealedRootAccount)
        await #expect(throws: VaultError.sealedRootCorrupt) {
            _ = try await unlock("correct horse")
        }
    }

    @Test func `Bootstrap stores nothing until the vault is stored`() async throws {
        let new = try await vault.bootstrap(passphrase: .text("correct horse"), reason: "test")
        #expect(try !vault.sealedRootExists())
        #expect(!new.session.isLocked)
        try new.store()
        #expect(try vault.sealedRootExists())
        #expect(throws: VaultError.internalFailure("a sealed root already exists")) { try new.store() }
    }

    @Test func `Reset deletes the root`() async throws {
        _ = try await bootstrap()
        try vault.reset()
        #expect(try !vault.sealedRootExists())
    }

    @Test func `An unavailable enclave fails closed`() async throws {
        enclave.isAvailable = false
        await #expect(throws: VaultError.enclaveUnavailable) {
            _ = try await bootstrap()
        }
    }
}
