import Foundation
import LocalAuthentication

struct ProtectedDataPostUnlockDomainOpener: Sendable {
    let domainID: ProtectedDataDomainID
    private let ensureCommitted: (@Sendable (Data) async throws -> Void)?
    private let open: @Sendable (Data) async throws -> Void

    init(
        domainID: ProtectedDataDomainID,
        ensureCommittedIfNeeded: (@Sendable (Data) async throws -> Void)? = nil,
        open: @escaping @Sendable (Data) async throws -> Void
    ) {
        self.domainID = domainID
        self.ensureCommitted = ensureCommittedIfNeeded
        self.open = open
    }

    var canEnsureCommitted: Bool {
        ensureCommitted != nil
    }

    func ensureCommittedIfNeeded(wrappingRootKey: Data) async throws {
        try await ensureCommitted?(wrappingRootKey)
    }

    func openDomain(wrappingRootKey: Data) async throws {
        try await open(wrappingRootKey)
    }
}

enum ProtectedDataPostUnlockOutcome: Equatable, Sendable {
    case opened([ProtectedDataDomainID])
    case noAuthenticatedContext
    case noRegisteredOpeners
    case noProtectedDomainPresent
    case noRegisteredDomainPresent
    case pendingMutationRecoveryRequired
    case frameworkRecoveryNeeded
    case authorizationDenied
    case domainOpenFailed(ProtectedDataDomainID)
}

struct ProtectedDataPostUnlockCoordinator: @unchecked Sendable {
    static let noOp = ProtectedDataPostUnlockCoordinator()

    private let currentRegistryProvider: () throws -> ProtectedDataRegistry
    private let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator?
    private let domainOpeners: [ProtectedDataPostUnlockDomainOpener]

    init(
        currentRegistryProvider: @escaping () throws -> ProtectedDataRegistry = {
            throw ProtectedDataError.authorizingUnavailable
        },
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator? = nil,
        domainOpeners: [ProtectedDataPostUnlockDomainOpener] = []
    ) {
        self.currentRegistryProvider = currentRegistryProvider
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
        self.domainOpeners = domainOpeners
    }

    func openRegisteredDomains(
        authenticationContext: LAContext?,
        localizedReason: String,
        source: String
    ) async -> ProtectedDataPostUnlockOutcome {
        guard !domainOpeners.isEmpty else {
            return .noRegisteredOpeners
        }
        guard let authenticationContext else {
            return .noAuthenticatedContext
        }
        guard let protectedDataSessionCoordinator else {
            return .frameworkRecoveryNeeded
        }

        let registry: ProtectedDataRegistry
        do {
            registry = try currentRegistryProvider()
        } catch {
            return .frameworkRecoveryNeeded
        }

        switch registry.classifyRecoveryDisposition() {
        case .frameworkRecoveryNeeded:
            return .frameworkRecoveryNeeded
        case .continuePendingMutation:
            return .pendingMutationRecoveryRequired
        case .resumeSteadyState:
            break
        }

        guard !registry.committedMembership.isEmpty,
              registry.sharedResourceLifecycleState == .ready else {
            return .noProtectedDomainPresent
        }

        let initiallyCommittedOpeners = domainOpeners.filter {
            registry.committedMembership[$0.domainID] != nil
        }
        guard !initiallyCommittedOpeners.isEmpty else {
            return .noRegisteredDomainPresent
        }

        if protectedDataSessionCoordinator.frameworkState != .sessionAuthorized {
            let authorizationResult = await protectedDataSessionCoordinator.beginProtectedDataAuthorization(
                registry: registry,
                localizedReason: localizedReason,
                authenticationContext: authenticationContext
            )
            switch authorizationResult {
            case .authorized:
                break
            case .cancelledOrDenied:
                return .authorizationDenied
            case .frameworkRecoveryNeeded:
                return .frameworkRecoveryNeeded
            }
        }

        do {
            var wrappingRootKey = try protectedDataSessionCoordinator.wrappingRootKeyData()
            defer {
                wrappingRootKey.protectedDataZeroize()
            }

            var openedDomainIDs: [ProtectedDataDomainID] = []
            var currentRegistry = registry
            for opener in domainOpeners {
                do {
                    if currentRegistry.committedMembership[opener.domainID] == nil {
                        guard opener.canEnsureCommitted else {
                            continue
                        }
                        try await opener.ensureCommittedIfNeeded(wrappingRootKey: wrappingRootKey)
                        currentRegistry = try currentRegistryProvider()
                    }
                    guard currentRegistry.committedMembership[opener.domainID] != nil else {
                        continue
                    }
                    guard currentRegistry.pendingMutation == nil,
                          currentRegistry.sharedResourceLifecycleState == .ready else {
                        return .pendingMutationRecoveryRequired
                    }
                    try await opener.openDomain(wrappingRootKey: wrappingRootKey)
                    openedDomainIDs.append(opener.domainID)
                } catch {
                    return .domainOpenFailed(opener.domainID)
                }
            }

            return .opened(openedDomainIDs)
        } catch {
            return .frameworkRecoveryNeeded
        }
    }
}
