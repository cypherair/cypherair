internal import Sealing
internal import Stores
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
    /// damaged otherwise. A device lock while this runs voids it: the app
    /// stays locked, and the next submission prompts again.
    public func submit(passphrase: String) async throws(CoreError) {
        guard let core, isCurrent, !working else { throw .cancelled }
        // No passphrase is empty, and the engine refuses to stretch one.
        guard !passphrase.isEmpty else { throw .wrongPassphrase }
        working = true
        defer { working = false }
        let locks = core.lockCount

        let attempt = self.attempt ?? composition.vault.beginUnlock(reason: composition.prompts.unlock)
        self.attempt = attempt
        let vaultSession: UnlockedSession
        do {
            vaultSession = try await attempt.submit(passphrase: .passphrase(passphrase))
        } catch {
            if core.lockCount != locks {
                forget(attempt)
                throw .cancelled
            }
            throw CoreError(error)
        }
        self.attempt = nil
        let session = OpenSession(vaultSession: vaultSession)

        let domains = composition.domains
        await domains.takeAllTurns()
        defer { domains.passAllTurns() }
        let opened: Opened
        do throws(CoreError) {
            let keys = try domains.keys(from: session)
            do {
                opened = try await Blocking.run { () throws(StoreError) in Opened(try domains.read(with: keys)) }
            } catch {
                throw CoreError(error)
            }
        } catch {
            session.close()
            throw error
        }
        guard isCurrent, core.lockCount == locks else {
            session.close()
            throw .cancelled
        }
        switch opened {
        case .intact(let contents):
            core.phase = .unlocked(Workspace(core: core, composition: composition, session: session, contents: contents))
        case .damaged(let report, let keys, let recoverableKeys):
            core.phase = .damaged(Recovery(core: core, composition: composition, session: session, report: report, keys: keys, recoverableKeys: recoverableKeys))
        }
    }

    /// Ends the attempt that holds the presence check, so the next submission
    /// prompts again. A running submission then fails.
    func endAttempt(whileRunning: Bool) {
        guard whileRunning || !working, let attempt else { return }
        forget(attempt)
    }

    private func forget(_ attempt: UnlockAttempt) {
        attempt.cancel()
        if self.attempt === attempt {
            self.attempt = nil
        }
    }

    private var isCurrent: Bool {
        guard let core, case .locked(let current) = core.phase else { return false }
        return current === self
    }
}

/// The files as unlock found them, with the lists computed off the main actor.
private enum Opened: Sendable {
    case intact(WorkspaceContents)
    case damaged(DamageReport, keys: KeysPayload?, recoverableKeys: [Key])

    init(_ reading: Domains.Reading) {
        switch reading {
        case .intact(let payloads):
            self = .intact(WorkspaceContents(payloads))
        case .damaged(let report, let keys):
            self = .damaged(report, keys: keys, recoverableKeys: keys.map(Keys.list(of:)) ?? [])
        }
    }
}
