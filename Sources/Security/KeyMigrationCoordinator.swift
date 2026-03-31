import Foundation
import Security

/// Recovery actions for interrupted pending/permanent bundle migrations.
enum KeyMigrationRecoveryAction: Equatable {
    case none
    case deletePending
    case promotePending
    case replacePermanentWithPending
    case unrecoverable
}

/// Strategy-level recovery outcome for one fingerprint.
enum KeyMigrationRecoveryOutcome: Equatable {
    case noActionSafe
    case cleanedPendingSafe
    case promotedPendingSafe
    case retryableFailure
    case unrecoverable

    var shouldClearRecoveryFlag: Bool {
        self != .retryableFailure
    }

    var startupDiagnostic: String? {
        switch self {
        case .retryableFailure:
            return String(
                localized: "startup.recovery.retryable",
                defaultValue: "A previous secure key migration could not be fully recovered. CypherAir will retry recovery on next launch."
            )
        case .unrecoverable:
            return String(
                localized: "startup.recovery.unrecoverable",
                defaultValue: "A previous secure key migration could not be recovered. Restore from backup if private-key operations fail."
            )
        case .noActionSafe, .cleanedPendingSafe, .promotedPendingSafe:
            return nil
        }
    }
}

/// Aggregated recovery result for multi-key auth-mode recovery.
struct KeyMigrationRecoverySummary: Equatable {
    let outcomes: [KeyMigrationRecoveryOutcome]

    var shouldClearRecoveryFlag: Bool {
        !outcomes.contains(.retryableFailure)
    }

    var shouldUpdateAuthMode: Bool {
        shouldClearRecoveryFlag
            && !outcomes.contains(.unrecoverable)
            && outcomes.contains(.promotedPendingSafe)
    }

    var startupDiagnostics: [String] {
        var diagnostics: [String] = []
        for diagnostic in outcomes.compactMap(\.startupDiagnostic) where !diagnostics.contains(diagnostic) {
            diagnostics.append(diagnostic)
        }
        return diagnostics
    }
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
        case (.complete, .missing):
            return .none
        case (.complete, .complete), (.complete, .partial):
            return .deletePending
        case (.missing, .complete):
            return .promotePending
        case (.partial, .complete):
            return .replacePermanentWithPending
        case (.partial, .missing),
             (.partial, .partial),
             (.missing, .partial),
             (.missing, .missing):
            return .unrecoverable
        }
    }

    func recoverInterruptedMigration(
        for fingerprint: String,
        seKeyAccessControl: SecAccessControl? = nil
    ) -> KeyMigrationRecoveryOutcome {
        switch recoveryAction(for: fingerprint) {
        case .none:
            return .noActionSafe
        case .deletePending:
            do {
                try bundleStore.deleteBundleAllowingMissing(
                    fingerprint: fingerprint,
                    namespace: .pending
                )
                return .cleanedPendingSafe
            } catch {
                return .retryableFailure
            }
        case .promotePending:
            do {
                try bundleStore.promotePendingToPermanent(
                    fingerprint: fingerprint,
                    seKeyAccessControl: seKeyAccessControl
                )
                return .promotedPendingSafe
            } catch {
                return .retryableFailure
            }
        case .replacePermanentWithPending:
            do {
                try bundleStore.replacePermanentWithPending(
                    fingerprint: fingerprint,
                    seKeyAccessControl: seKeyAccessControl
                )
                return .promotedPendingSafe
            } catch {
                return .retryableFailure
            }
        case .unrecoverable:
            return .unrecoverable
        }
    }

    func recoverInterruptedMigrations(
        for fingerprints: [String],
        seKeyAccessControl: SecAccessControl? = nil
    ) -> KeyMigrationRecoverySummary {
        let outcomes = fingerprints.map {
            recoverInterruptedMigration(for: $0, seKeyAccessControl: seKeyAccessControl)
        }
        return KeyMigrationRecoverySummary(outcomes: outcomes)
    }
}
