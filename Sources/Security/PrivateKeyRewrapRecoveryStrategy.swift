import Foundation
import Security

/// Recovery actions for interrupted pending/permanent bundle rewraps.
enum PrivateKeyRewrapRecoveryAction: Equatable {
    case none
    case deletePending
    case promotePending
    case replacePermanentWithPending
    case unrecoverable
}

/// Strategy-level recovery outcome for one fingerprint.
enum PrivateKeyRewrapRecoveryOutcome: Equatable {
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
                defaultValue: "A previous secure key protection change could not be fully recovered. CypherAir X will retry recovery on next launch."
            )
        case .unrecoverable:
            return String(
                localized: "startup.recovery.unrecoverable",
                defaultValue: "A previous secure key protection change could not be recovered. Restore from backup if private-key operations fail."
            )
        case .noActionSafe, .cleanedPendingSafe, .promotedPendingSafe:
            return nil
        }
    }
}

/// Aggregated recovery result for multi-key auth-mode recovery.
struct PrivateKeyRewrapRecoverySummary: Equatable {
    let outcomes: [PrivateKeyRewrapRecoveryOutcome]

    var shouldClearRecoveryFlag: Bool {
        !outcomes.contains(.retryableFailure)
    }

    var shouldUpdateAuthMode: Bool {
        shouldClearRecoveryFlag
            && !outcomes.contains(.unrecoverable)
            && outcomes.contains(.promotedPendingSafe)
    }

    var isRewrapTargetCommitSafe: Bool {
        !outcomes.isEmpty && outcomes.allSatisfy {
            $0 == .noActionSafe || $0 == .promotedPendingSafe
        }
    }

    func appendingRetryableFailure() -> PrivateKeyRewrapRecoverySummary {
        guard !outcomes.contains(.retryableFailure) else {
            return self
        }
        return PrivateKeyRewrapRecoverySummary(outcomes: outcomes + [.retryableFailure])
    }

    var startupDiagnostics: [String] {
        var diagnostics: [String] = []
        for diagnostic in outcomes.compactMap(\.startupDiagnostic) where !diagnostics.contains(diagnostic) {
            diagnostics.append(diagnostic)
        }
        return diagnostics
    }
}

/// Shared rewrap-recovery logic for auth-mode rewrap and modify-expiry flows.
struct PrivateKeyRewrapRecoveryStrategy {
    private let bundleStore: KeyBundleStore

    init(bundleStore: KeyBundleStore) {
        self.bundleStore = bundleStore
    }

    func recoveryAction(for fingerprint: String) -> PrivateKeyRewrapRecoveryAction {
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

    func recoverInterruptedRewrap(for fingerprint: String) -> PrivateKeyRewrapRecoveryOutcome {
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
                try bundleStore.promotePendingToPermanent(fingerprint: fingerprint)
                return .promotedPendingSafe
            } catch {
                return .retryableFailure
            }
        case .replacePermanentWithPending:
            do {
                try bundleStore.replacePermanentWithPending(fingerprint: fingerprint)
                return .promotedPendingSafe
            } catch {
                return .retryableFailure
            }
        case .unrecoverable:
            return .unrecoverable
        }
    }

    func recoverInterruptedRewraps(for fingerprints: [String]) -> PrivateKeyRewrapRecoverySummary {
        let outcomes = fingerprints.map {
            recoverInterruptedRewrap(for: $0)
        }
        return PrivateKeyRewrapRecoverySummary(outcomes: outcomes)
    }
}
