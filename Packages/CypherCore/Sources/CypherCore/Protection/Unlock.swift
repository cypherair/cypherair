internal import Sealing
internal import Vault

/// The phase of a locked app.
@MainActor
public final class Unlock {
    private weak var core: AppCore?
    private let composition: Composition
    private var attempt: UnlockAttempt?
    private var working = false

    init(core: AppCore, composition: Composition) {
        self.core = core
        self.composition = composition
    }

    /// Opens the vault with `passphrase`. The first submission shows the
    /// presence prompt; after a wrong passphrase the next one shows none. Then
    /// the three files are read: the app is unlocked when each is intact, and
    /// damaged otherwise.
    public func submit(passphrase: String) async throws(CoreError) {
        guard isCurrent, !working else { throw .cancelled }
        // No passphrase is empty, and the engine refuses to stretch one.
        guard !passphrase.isEmpty else { throw .wrongPassphrase }
        working = true
        defer { working = false }

        let attempt = self.attempt ?? composition.vault.beginUnlock(reason: composition.prompts.unlock)
        self.attempt = attempt
        let session: OpenSession
        do {
            session = OpenSession(vaultSession: try await attempt.submit(passphrase: .passphrase(passphrase)))
        } catch {
            throw CoreError(error)
        }
        self.attempt = nil
        let domains = composition.domains
        let reading: Domains.Reading
        do {
            let keys = try domains.keys(from: session)
            reading = await Blocking.run { domains.read(with: keys) }
        } catch {
            session.close()
            throw error
        }
        guard let core, isCurrent else {
            session.close()
            throw .cancelled
        }
        switch reading {
        case .intact(let payloads):
            core.phase = .unlocked(Workspace(core: core, session: session, domains: domains, payloads: payloads))
        case .damaged(let report):
            core.phase = .damaged(Recovery(report: report, session: session))
        }
    }

    private var isCurrent: Bool {
        guard let core, case .locked(let current) = core.phase else { return false }
        return current === self
    }
}
