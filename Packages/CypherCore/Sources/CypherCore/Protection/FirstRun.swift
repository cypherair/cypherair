internal import Sealing
internal import Stores
internal import Vault

/// The phase of a device that holds no vault.
@MainActor
public final class FirstRun {
    private weak var core: AppCore?
    private let composition: Composition
    private var working = false

    init(core: AppCore, composition: Composition) {
        self.core = core
        self.composition = composition
    }

    /// Creates the vault from `passphrase` behind one presence prompt and
    /// writes the first values of the three files. Then the app is unlocked.
    /// A passphrase with a problem is refused before any prompt.
    public func create(passphrase: String) async throws(CoreError) {
        guard isCurrent, !working else { throw .cancelled }
        guard Passphrase.problems(in: passphrase).isEmpty else { throw .passphraseTooWeak }
        working = true
        defer { working = false }

        let vault = composition.vault
        let session: OpenSession
        do {
            session = OpenSession(vaultSession: try await vault.bootstrap(passphrase: .passphrase(passphrase), reason: composition.prompts.createVault))
        } catch {
            throw CoreError(error)
        }
        let domains = composition.domains
        do throws(CoreError) {
            let keys = try domains.keys(from: session)
            do {
                try await Blocking.run { () throws(StoreError) in try domains.write(.firstValues, with: keys) }
            } catch {
                throw CoreError(error)
            }
        } catch {
            // A sealed root without its files would be damage at the next
            // launch. Without the root, first run simply starts over.
            session.close()
            try? await Blocking.run { () throws(VaultError) in try vault.reset() }
            throw error
        }
        guard let core, isCurrent else {
            session.close()
            throw .cancelled
        }
        core.phase = .unlocked(Workspace(core: core, session: session, domains: domains, payloads: .firstValues))
    }

    private var isCurrent: Bool {
        guard let core, case .firstRun(let current) = core.phase else { return false }
        return current === self
    }
}
