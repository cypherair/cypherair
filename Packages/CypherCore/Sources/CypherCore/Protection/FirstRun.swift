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
    /// A passphrase with a problem is refused before any prompt. A device lock
    /// while this runs leaves the new vault locked.
    public func create(passphrase: String) async throws(CoreError) {
        guard let core, isCurrent, !working else { throw .cancelled }
        guard Passphrase.problems(in: passphrase).isEmpty else { throw .passphraseTooWeak }
        working = true
        defer { working = false }
        let locks = core.lockCount

        let vault = composition.vault
        let session: OpenSession
        do {
            session = OpenSession(vaultSession: try await vault.bootstrap(passphrase: .passphrase(passphrase), reason: composition.prompts.createVault))
        } catch {
            throw CoreError(error)
        }
        let domains = composition.domains
        await domains.takeAllTurns()
        defer { domains.passAllTurns() }
        let contents: WorkspaceContents
        do throws(CoreError) {
            let keys = try domains.keys(from: session)
            do {
                contents = try await Blocking.run { () throws(StoreError) in
                    try domains.write(.firstValues, with: keys)
                    return WorkspaceContents(.firstValues)
                }
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
        guard isCurrent else {
            session.close()
            throw .cancelled
        }
        guard core.lockCount == locks else {
            session.close()
            core.phase = .locked(Unlock(core: core, composition: composition))
            throw .cancelled
        }
        core.phase = .unlocked(Workspace(core: core, composition: composition, session: session, contents: contents))
    }

    private var isCurrent: Bool {
        guard let core, case .firstRun(let current) = core.phase else { return false }
        return current === self
    }
}
