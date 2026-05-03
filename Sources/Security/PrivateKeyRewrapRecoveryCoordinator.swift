import Foundation

final class PrivateKeyRewrapRecoveryCoordinator {
    private let bundleStore: KeyBundleStore
    private let migrationCoordinator: KeyMigrationCoordinator

    init(
        bundleStore: KeyBundleStore,
        migrationCoordinator: KeyMigrationCoordinator
    ) {
        self.bundleStore = bundleStore
        self.migrationCoordinator = migrationCoordinator
    }

    func checkAndRecoverFromInterruptedRewrap(
        fingerprints: [String],
        privateKeyControlStore: (any PrivateKeyControlStoreProtocol)?
    ) -> KeyMigrationRecoverySummary? {
        guard let privateKeyControlStore,
              let journal = try? privateKeyControlStore.recoveryJournal(),
              let targetMode = journal.rewrapTargetMode else {
            return nil
        }

        // If the metadata set is empty but a recovery flag was present, we cannot
        // identify which bundles need recovery. Treat that as unrecoverable.
        let effectiveSummary: KeyMigrationRecoverySummary
        if fingerprints.isEmpty {
            effectiveSummary = KeyMigrationRecoverySummary(outcomes: [.unrecoverable])
        } else {
            effectiveSummary = recoverInterruptedRewrapMigrations(
                for: fingerprints,
                phase: journal.rewrapPhase
            )
        }

        // Persist target mode only when the selected phase strategy proves all
        // recoverable bundles are aligned with the target ACL.
        let shouldCompleteRewrap: Bool
        if journal.rewrapPhase == .commitRequired {
            shouldCompleteRewrap = effectiveSummary.isRewrapTargetCommitSafe
        } else {
            shouldCompleteRewrap = effectiveSummary.shouldUpdateAuthMode
        }

        if shouldCompleteRewrap {
            do {
                try privateKeyControlStore.completeRewrap(targetMode: targetMode)
            } catch {
                return effectiveSummary.appendingRetryableFailure()
            }
        } else if effectiveSummary.shouldClearRecoveryFlag {
            try? privateKeyControlStore.clearRewrapJournal()
        }

        return effectiveSummary
    }

    private func recoverInterruptedRewrapMigrations(
        for fingerprints: [String],
        phase: PrivateKeyControlRewrapPhase?
    ) -> KeyMigrationRecoverySummary {
        guard phase == .commitRequired else {
            return migrationCoordinator.recoverInterruptedMigrations(
                for: fingerprints,
                seKeyAccessControl: nil
            )
        }

        return KeyMigrationRecoverySummary(
            outcomes: fingerprints.map(recoverCommitRequiredRewrapMigration)
        )
    }

    private func recoverCommitRequiredRewrapMigration(
        for fingerprint: String
    ) -> KeyMigrationRecoveryOutcome {
        let permanentState = bundleStore.bundleState(
            fingerprint: fingerprint,
            namespace: .permanent
        )
        let pendingState = bundleStore.bundleState(
            fingerprint: fingerprint,
            namespace: .pending
        )

        switch (permanentState, pendingState) {
        case (.complete, .missing):
            return .noActionSafe
        case (.complete, .complete), (.partial, .complete):
            do {
                try bundleStore.replacePermanentWithPending(
                    fingerprint: fingerprint,
                    seKeyAccessControl: nil
                )
                return .promotedPendingSafe
            } catch {
                return .retryableFailure
            }
        case (.missing, .complete):
            do {
                try bundleStore.promotePendingToPermanent(
                    fingerprint: fingerprint,
                    seKeyAccessControl: nil
                )
                return .promotedPendingSafe
            } catch {
                return .retryableFailure
            }
        case (.complete, .partial):
            return .retryableFailure
        case (.partial, .missing),
             (.partial, .partial),
             (.missing, .partial),
             (.missing, .missing):
            return .unrecoverable
        }
    }
}
