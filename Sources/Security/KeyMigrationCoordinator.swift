import Foundation
import Security

/// Recovery actions for interrupted pending/permanent bundle migrations.
enum KeyMigrationRecoveryAction: Equatable {
    case none
    case deletePending
    case promotePending
}

/// Recovery outcome after applying the chosen action.
enum KeyMigrationRecoveryOutcome: Equatable {
    case noAction
    case cleanedPending
    case promotedPending
    case promotionFailed
}

/// Shared migration recovery logic for auth-mode rewrap and modify-expiry flows.
struct KeyMigrationCoordinator {
    private let bundleStore: KeyBundleStore

    init(bundleStore: KeyBundleStore) {
        self.bundleStore = bundleStore
    }

    func recoveryAction(for fingerprint: String) -> KeyMigrationRecoveryAction {
        let permanentState = bundleStore.bundleState(
            fingerprint: fingerprint,
            namespace: .permanent
        )
        let pendingState = bundleStore.bundleState(
            fingerprint: fingerprint,
            namespace: .pending
        )

        switch (permanentState, pendingState) {
        case (.complete, .complete), (.complete, .partial):
            return .deletePending
        case (.partial, .complete), (.missing, .complete):
            return .promotePending
        default:
            return .none
        }
    }

    func recoverInterruptedMigration(
        for fingerprint: String,
        seKeyAccessControl: SecAccessControl? = nil
    ) -> KeyMigrationRecoveryOutcome {
        switch recoveryAction(for: fingerprint) {
        case .none:
            return .noAction
        case .deletePending:
            bundleStore.cleanupPendingBundle(fingerprint: fingerprint)
            return .cleanedPending
        case .promotePending:
            do {
                try bundleStore.promotePendingToPermanent(
                    fingerprint: fingerprint,
                    seKeyAccessControl: seKeyAccessControl
                )
                return .promotedPending
            } catch {
                return .promotionFailed
            }
        }
    }
}
