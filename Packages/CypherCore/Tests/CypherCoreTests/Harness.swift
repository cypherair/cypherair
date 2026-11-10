import Foundation
import LocalAuthentication
import Stores
import Vault
import VaultTestSupport
import os
@testable import CypherCore

struct UnexpectedPhase: Error, CustomStringConvertible {
    let description: String
}

/// A core on the software composition and the real engine, with the doubles
/// the tests steer.
@MainActor
struct Harness {
    static let passphrase = "correct horse battery"

    let files = FailableDomainFiles()
    let keychain = InMemoryKeychain()
    let authenticator = TestAuthenticator()
    let composition: Composition
    let core: AppCore

    init() {
        composition = .software(
            prompts: PromptTexts(createVault: "test", unlock: "test"),
            enclave: FakeEnclave(),
            keychain: keychain,
            files: files,
            authenticator: authenticator
        )
        core = AppCore(composition: composition)
    }

    /// A second launch on the same device.
    func relaunched() -> AppCore {
        AppCore(composition: composition)
    }

    /// Starts the core and creates the vault.
    func created() async throws -> Workspace {
        await core.start()
        try await firstRun().create(passphrase: Self.passphrase)
        return try workspace()
    }

    func firstRun() throws -> FirstRun {
        guard case .firstRun(let firstRun) = core.phase else { throw UnexpectedPhase(description: "\(core.phase)") }
        return firstRun
    }

    func unlock() throws -> Unlock {
        guard case .locked(let unlock) = core.phase else { throw UnexpectedPhase(description: "\(core.phase)") }
        return unlock
    }

    func workspace() throws -> Workspace {
        guard case .unlocked(let workspace) = core.phase else { throw UnexpectedPhase(description: "\(core.phase)") }
        return workspace
    }

    func recovery() throws -> Recovery {
        guard case .damaged(let recovery) = core.phase else { throw UnexpectedPhase(description: "\(core.phase)") }
        return recovery
    }
}

/// Presence that is never shown. It counts each request, fails with `failure`
/// when one is set, and runs `duringPrompt` while the prompt would be up.
final class TestAuthenticator: Authenticator, @unchecked Sendable {
    private let state = OSAllocatedUnfairLock(initialState: (prompts: 0, failure: VaultError?.none))
    @MainActor var duringPrompt: (@MainActor () -> Void)?

    var prompts: Int { state.withLock { $0.prompts } }

    var failure: VaultError? {
        get { state.withLock { $0.failure } }
        set { state.withLock { $0.failure = newValue } }
    }

    func authenticate(context: LAContext, reason: String) async throws(VaultError) {
        try await prompt()
    }

    func authenticateBiometrics(context: LAContext, reason: String) async throws(VaultError) {
        try await prompt()
    }

    private func prompt() async throws(VaultError) {
        let failure = state.withLock { state in
            state.prompts += 1
            return state.failure
        }
        await MainActor.run { duringPrompt?() }
        if let failure { throw failure }
    }
}
