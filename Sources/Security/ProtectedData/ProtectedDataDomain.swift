import Foundation

struct ProtectedDataDomainID: RawRepresentable, Codable, Hashable, ExpressibleByStringLiteral, Sendable {
    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    init(stringLiteral value: StringLiteralType) {
        self.rawValue = value
    }
}

enum ProtectedDataCommittedDomainState: String, Codable, Sendable {
    case active
    case recoveryNeeded
}

enum SharedResourceLifecycleState: String, Codable, Sendable {
    case absent
    case ready
    case cleanupPending
}

enum ProtectedDataFrameworkState: Equatable, Sendable {
    case sessionLocked
    case sessionAuthorized
    case frameworkRecoveryNeeded
    case restartRequired
}

enum ProtectedDataBootstrapState: Equatable, Sendable {
    case loadedExistingRegistry
    case bootstrappedEmptyRegistry
    case frameworkRecoveryNeeded
}

enum ProtectedDataRecoveryDisposition: Equatable, Sendable {
    case resumeSteadyState
    case continuePendingMutation
    case frameworkRecoveryNeeded
}

enum ProtectedDataBootstrapOutcome: Equatable, Sendable {
    case emptySteadyState(registry: ProtectedDataRegistry, didBootstrap: Bool)
    case loadedRegistry(registry: ProtectedDataRegistry, recoveryDisposition: ProtectedDataRecoveryDisposition)
    case frameworkRecoveryNeeded
}

enum ProtectedDataAccessGateDecision: Equatable, Sendable {
    case frameworkRecoveryNeeded
    case pendingMutationRecoveryRequired
    case authorizationRequired(registry: ProtectedDataRegistry)
    case alreadyAuthorized(registry: ProtectedDataRegistry)
    case noProtectedDomainPresent
}

enum ProtectedDataAuthorizationResult: Equatable, Sendable {
    case authorized
    case cancelledOrDenied
    case frameworkRecoveryNeeded
}

enum ProtectedDataError: Error, LocalizedError, Equatable {
    case invalidDomainMasterKeyLength(Int)
    case invalidNonceLength(Int)
    case invalidAuthenticationTagLength(Int)
    case invalidCiphertextLength(Int)
    case invalidRegistry(String)
    case registryMissingWithArtifacts
    case missingPersistedRight(String)
    case missingWrappingRootKey
    case internalFailure(String)
    case authorizingUnavailable
    case restartRequired

    var errorDescription: String? {
        switch self {
        case .invalidDomainMasterKeyLength(let length):
            "ProtectedData domain master key must be 32 bytes, got \(length)."
        case .invalidNonceLength(let length):
            "Wrapped DMK nonce must be 12 bytes, got \(length)."
        case .invalidAuthenticationTagLength(let length):
            "Wrapped DMK authentication tag must be 16 bytes, got \(length)."
        case .invalidCiphertextLength(let length):
            "Wrapped DMK ciphertext must be 32 bytes, got \(length)."
        case .invalidRegistry(let reason):
            "ProtectedData registry is invalid: \(reason)"
        case .registryMissingWithArtifacts:
            "ProtectedData registry is missing while protected-data artifacts still exist."
        case .missingPersistedRight(let identifier):
            "ProtectedData shared right is missing for identifier \(identifier)."
        case .missingWrappingRootKey:
            "ProtectedData wrapping root key is not available in the current session."
        case .internalFailure(let reason):
            reason
        case .authorizingUnavailable:
            "ProtectedData authorization is currently unavailable."
        case .restartRequired:
            "ProtectedData access is blocked until the app restarts."
        }
    }
}

extension Data {
    mutating func protectedDataZeroize() {
        guard !isEmpty else {
            return
        }
        resetBytes(in: startIndex..<endIndex)
    }
}
