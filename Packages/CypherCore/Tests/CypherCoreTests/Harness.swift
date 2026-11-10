import Foundation
import Stores
import Vault
import VaultTestSupport
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
    let authenticator = CountingAuthenticator()
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
