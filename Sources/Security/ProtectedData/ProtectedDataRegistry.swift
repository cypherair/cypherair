import Foundation

enum CreateDomainPhase: String, Codable, Sendable {
    case journaled
    case sharedResourceProvisioned
    case artifactsStaged
    case validated
    case membershipCommitted
}

enum DeleteDomainPhase: String, Codable, Sendable {
    case journaled
    case artifactsDeleted
    case membershipRemoved
    case sharedResourceCleanupStarted
}

enum PendingMutation: Codable, Equatable, Sendable {
    case createDomain(targetDomainID: ProtectedDataDomainID, phase: CreateDomainPhase)
    case deleteDomain(targetDomainID: ProtectedDataDomainID, phase: DeleteDomainPhase)

    private enum CodingKeys: String, CodingKey {
        case kind
        case targetDomainID
        case createPhase
        case deletePhase
    }

    private enum Kind: String, Codable {
        case createDomain
        case deleteDomain
    }

    var targetDomainID: ProtectedDataDomainID {
        switch self {
        case .createDomain(let domainID, _), .deleteDomain(let domainID, _):
            domainID
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(Kind.self, forKey: .kind)

        switch kind {
        case .createDomain:
            self = .createDomain(
                targetDomainID: try container.decode(ProtectedDataDomainID.self, forKey: .targetDomainID),
                phase: try container.decode(CreateDomainPhase.self, forKey: .createPhase)
            )
        case .deleteDomain:
            self = .deleteDomain(
                targetDomainID: try container.decode(ProtectedDataDomainID.self, forKey: .targetDomainID),
                phase: try container.decode(DeleteDomainPhase.self, forKey: .deletePhase)
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        switch self {
        case .createDomain(let domainID, let phase):
            try container.encode(Kind.createDomain, forKey: .kind)
            try container.encode(domainID, forKey: .targetDomainID)
            try container.encode(phase, forKey: .createPhase)
        case .deleteDomain(let domainID, let phase):
            try container.encode(Kind.deleteDomain, forKey: .kind)
            try container.encode(domainID, forKey: .targetDomainID)
            try container.encode(phase, forKey: .deletePhase)
        }
    }
}

struct ProtectedDataRegistry: Codable, Equatable, Sendable {
    static let currentFormatVersion = 1

    let formatVersion: Int
    let sharedRightIdentifier: String
    var sharedResourceLifecycleState: SharedResourceLifecycleState
    var committedMembership: [ProtectedDataDomainID: ProtectedDataCommittedDomainState]
    var pendingMutation: PendingMutation?

    static func emptySteadyState(sharedRightIdentifier: String) -> ProtectedDataRegistry {
        ProtectedDataRegistry(
            formatVersion: currentFormatVersion,
            sharedRightIdentifier: sharedRightIdentifier,
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: nil
        )
    }

    func validateConsistency() -> String? {
        if formatVersion != Self.currentFormatVersion {
            return "Unsupported registry format version \(formatVersion)."
        }

        if committedMembership.isEmpty {
            switch sharedResourceLifecycleState {
            case .ready:
                return "Shared resource cannot be ready when committed membership is empty."
            case .absent, .cleanupPending:
                break
            }
        } else {
            switch sharedResourceLifecycleState {
            case .absent, .cleanupPending:
                return "Shared resource must be ready when committed membership is non-empty."
            case .ready:
                break
            }
        }

        guard let pendingMutation else {
            if committedMembership.isEmpty && sharedResourceLifecycleState == .cleanupPending {
                return "cleanupPending requires an in-flight delete-domain mutation."
            }
            return nil
        }

        let target = pendingMutation.targetDomainID
        switch pendingMutation {
        case .createDomain(_, let phase):
            switch phase {
            case .journaled, .sharedResourceProvisioned, .artifactsStaged, .validated:
                if committedMembership[target] != nil {
                    return "Create-domain target must not appear in committed membership before membershipCommitted."
                }
                if committedMembership.isEmpty && sharedResourceLifecycleState != .absent {
                    return "First-domain create must keep shared resource absent until membershipCommitted."
                }
                if !committedMembership.isEmpty && sharedResourceLifecycleState != .ready {
                    return "Non-first-domain create must keep shared resource ready."
                }
            case .membershipCommitted:
                if committedMembership[target] == nil {
                    return "Create-domain membershipCommitted requires the target to exist in committed membership."
                }
                if sharedResourceLifecycleState != .ready {
                    return "Create-domain membershipCommitted requires shared resource ready."
                }
            }
        case .deleteDomain(_, let phase):
            switch phase {
            case .journaled, .artifactsDeleted:
                if committedMembership[target] == nil {
                    return "Delete-domain target must remain in committed membership before membershipRemoved."
                }
                if sharedResourceLifecycleState != .ready {
                    return "Delete-domain journaled/artifactsDeleted requires shared resource ready."
                }
            case .membershipRemoved:
                if committedMembership[target] != nil {
                    return "Delete-domain membershipRemoved requires target absent from committed membership."
                }
                if committedMembership.isEmpty {
                    if sharedResourceLifecycleState != .cleanupPending {
                        return "Last-domain delete must enter cleanupPending after membershipRemoved."
                    }
                } else if sharedResourceLifecycleState != .ready {
                    return "Non-last-domain delete must keep shared resource ready."
                }
            case .sharedResourceCleanupStarted:
                if committedMembership[target] != nil {
                    return "Delete-domain sharedResourceCleanupStarted requires target absent from committed membership."
                }
                if !committedMembership.isEmpty || sharedResourceLifecycleState != .cleanupPending {
                    return "sharedResourceCleanupStarted requires empty membership with cleanupPending."
                }
            }
        }

        return nil
    }

    func classifyRecoveryDisposition() -> ProtectedDataRecoveryDisposition {
        guard validateConsistency() == nil else {
            return .frameworkRecoveryNeeded
        }

        guard let pendingMutation else {
            if committedMembership.isEmpty && sharedResourceLifecycleState == .absent {
                return .resumeSteadyState
            }
            if !committedMembership.isEmpty && sharedResourceLifecycleState == .ready {
                return .resumeSteadyState
            }
            return .frameworkRecoveryNeeded
        }

        switch pendingMutation {
        case .createDomain(let targetDomainID, let phase):
            switch phase {
            case .journaled, .sharedResourceProvisioned, .artifactsStaged, .validated:
                if committedMembership[targetDomainID] == nil {
                    return .continuePendingMutation
                }
            case .membershipCommitted:
                if committedMembership[targetDomainID] != nil && sharedResourceLifecycleState == .ready {
                    return .continuePendingMutation
                }
            }
        case .deleteDomain(let targetDomainID, let phase):
            switch phase {
            case .journaled, .artifactsDeleted:
                if committedMembership[targetDomainID] != nil && sharedResourceLifecycleState == .ready {
                    return .continuePendingMutation
                }
            case .membershipRemoved:
                if committedMembership[targetDomainID] == nil {
                    if committedMembership.isEmpty && sharedResourceLifecycleState == .cleanupPending {
                        return .continuePendingMutation
                    }
                    if !committedMembership.isEmpty && sharedResourceLifecycleState == .ready {
                        return .continuePendingMutation
                    }
                }
            case .sharedResourceCleanupStarted:
                if committedMembership.isEmpty && sharedResourceLifecycleState == .cleanupPending {
                    return .continuePendingMutation
                }
            }
        }

        return .frameworkRecoveryNeeded
    }
}
