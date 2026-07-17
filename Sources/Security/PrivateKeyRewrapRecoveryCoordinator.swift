import Foundation

final class PrivateKeyRewrapRecoveryCoordinator {
    private let bundleStore: KeyBundleStore
    private let rewrapRecoveryStrategy: PrivateKeyRewrapRecoveryStrategy

    init(
        bundleStore: KeyBundleStore,
        rewrapRecoveryStrategy: PrivateKeyRewrapRecoveryStrategy
    ) {
        self.bundleStore = bundleStore
        self.rewrapRecoveryStrategy = rewrapRecoveryStrategy
    }

    func checkAndRecoverFromInterruptedRewrap(
        fingerprints: [String],
        privateKeyControlStore: (any PrivateKeyControlStoreProtocol)?
    ) -> PrivateKeyRewrapRecoverySummary? {
        guard let privateKeyControlStore,
              let journal = try? privateKeyControlStore.recoveryJournal(),
              let targetMode = journal.rewrapTargetMode else {
            return nil
        }

        // If the metadata set is empty but a recovery flag was present, we cannot
        // identify which bundles need recovery. Treat that as unrecoverable.
        let effectiveSummary: PrivateKeyRewrapRecoverySummary
        if fingerprints.isEmpty {
            effectiveSummary = PrivateKeyRewrapRecoverySummary(outcomes: [.unrecoverable])
        } else {
            effectiveSummary = recoverInterruptedRewraps(
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

    private func recoverInterruptedRewraps(
        for fingerprints: [String],
        phase: PrivateKeyControlRewrapPhase?
    ) -> PrivateKeyRewrapRecoverySummary {
        guard phase == .commitRequired else {
            return rewrapRecoveryStrategy.recoverInterruptedRewraps(for: fingerprints)
        }

        return PrivateKeyRewrapRecoverySummary(
            outcomes: fingerprints.map(recoverCommitRequiredRewrap)
        )
    }

    private func recoverCommitRequiredRewrap(
        for fingerprint: String
    ) -> PrivateKeyRewrapRecoveryOutcome {
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
        case (.complete, .complete):
            do {
                try bundleStore.replacePermanentWithPending(fingerprint: fingerprint)
                return .promotedPendingSafe
            } catch {
                return .retryableFailure
            }
        case (.missing, .complete):
            do {
                try bundleStore.promotePendingToPermanent(fingerprint: fingerprint)
                return .promotedPendingSafe
            } catch {
                return .retryableFailure
            }
        case (.missing, .missing):
            return .unrecoverable
        }
    }
}
