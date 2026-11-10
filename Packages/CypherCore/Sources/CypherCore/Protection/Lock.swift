/// What the app reports. The core decides when to lock.
public enum PresenceEvent: Sendable {
    case wentAway
    case cameBack
    case deviceLocked
}

extension AppCore {
    /// Locks when the device locks, or when the app was away for the relock
    /// delay. A delay of zero locks the moment the app goes away; a longer one
    /// is checked when the app comes back. On the lock screen, both events end
    /// the unlock attempt, so the next submission shows the presence prompt
    /// again; going away does so only while no submission runs, because a
    /// running one may have its own sheet up.
    public func report(_ event: PresenceEvent) {
        switch event {
        case .deviceLocked:
            lock()
        case .wentAway:
            if case .locked(let unlock) = phase {
                unlock.endAttempt(whileRunning: false)
            }
            guard let delay = relockDelay else { return }
            if delay == .zero {
                lock()
            } else if awaySince == nil {
                awaySince = .now
            }
        case .cameBack:
            guard let since = awaySince else { return }
            awaySince = nil
            if let delay = relockDelay, ContinuousClock.now - since >= delay {
                lock()
            }
        }
    }

    /// Sets the phase to `locked`, then erases the session values in the vault
    /// and drops the decoded values. Applies in the damaged phase too. In the
    /// locked and first-run phases it voids an unlock or a first run in flight.
    /// Going away during one does not count: that may be its own Face ID sheet.
    func lock() {
        lockCount += 1
        awaySince = nil
        guard let composition else { return }
        switch phase {
        case .unlocked(let workspace):
            phase = .locked(Unlock(core: self, composition: composition))
            workspace.close()
        case .damaged(let recovery):
            phase = .locked(Unlock(core: self, composition: composition))
            recovery.close()
        case .locked(let unlock):
            unlock.endAttempt(whileRunning: true)
        case .starting, .firstRun, .restartRequired:
            return
        }
    }

    /// Nil when no session is open. The damaged phase may have no readable
    /// settings, so it locks at once.
    private var relockDelay: Duration? {
        switch phase {
        case .unlocked(let workspace): .seconds(workspace.settings.values.relockAfter.rawValue)
        case .damaged: .zero
        case .starting, .firstRun, .locked, .restartRequired: nil
        }
    }
}
