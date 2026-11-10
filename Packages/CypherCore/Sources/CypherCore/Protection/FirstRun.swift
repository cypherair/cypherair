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

        let new: NewVault
        do {
            new = try await composition.vault.bootstrap(passphrase: .passphrase(passphrase), reason: composition.prompts.createVault)
        } catch {
            throw CoreError(error)
        }
        let session = OpenSession(vaultSession: new.session)
        let domains = composition.domains
        await domains.takeAllTurns()
        defer { domains.passAllTurns() }
        // The files first, then the sealed root: the root marks a finished
        // first run, so a stop at any point leaves a device that starts over.
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
            do {
                try await Blocking.run { () throws(VaultError) in try new.store() }
            } catch {
                throw CoreError(error)
            }
        } catch {
            session.close()
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
