import Foundation
import LocalAuthentication

struct ProtectedDataPostUnlockOpenContext: @unchecked Sendable {
    let wrappingRootKey: Data
    let authenticationContext: LAContext?
}

struct ProtectedDataPostUnlockDomainOpener: Sendable {
    let domainID: ProtectedDataDomainID
    private let ensureCommitted: (@Sendable (ProtectedDataPostUnlockOpenContext) async throws -> Void)?
    private let open: @Sendable (ProtectedDataPostUnlockOpenContext) async throws -> Void

    init(
        domainID: ProtectedDataDomainID,
        ensureCommittedIfNeeded: (@Sendable (Data) async throws -> Void)? = nil,
        open: @escaping @Sendable (Data) async throws -> Void
    ) {
        self.domainID = domainID
        if let ensureCommittedIfNeeded {
            self.ensureCommitted = { context in
                try await ensureCommittedIfNeeded(context.wrappingRootKey)
            }
        } else {
            self.ensureCommitted = nil
        }
        self.open = { context in
            try await open(context.wrappingRootKey)
        }
    }

    init(
        domainID: ProtectedDataDomainID,
        ensureCommittedWithContext: (@Sendable (ProtectedDataPostUnlockOpenContext) async throws -> Void)? = nil,
        openWithContext: @escaping @Sendable (ProtectedDataPostUnlockOpenContext) async throws -> Void
    ) {
        self.domainID = domainID
        self.ensureCommitted = ensureCommittedWithContext
        self.open = openWithContext
    }

    var canEnsureCommitted: Bool {
        ensureCommitted != nil
    }

    func ensureCommittedIfNeeded(context: ProtectedDataPostUnlockOpenContext) async throws {
        try await ensureCommitted?(context)
    }

    func openDomain(context: ProtectedDataPostUnlockOpenContext) async throws {
        try await open(context)
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
    private let traceStore: AuthLifecycleTraceStore?

    init(
        currentRegistryProvider: @escaping () throws -> ProtectedDataRegistry = {
            throw ProtectedDataError.authorizingUnavailable
        },
        protectedDataSessionCoordinator: ProtectedDataSessionCoordinator? = nil,
        domainOpeners: [ProtectedDataPostUnlockDomainOpener] = [],
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.currentRegistryProvider = currentRegistryProvider
        self.protectedDataSessionCoordinator = protectedDataSessionCoordinator
        self.domainOpeners = domainOpeners
        self.traceStore = traceStore
    }

    func openRegisteredDomains(
        authenticationContext: LAContext?,
        localizedReason: String,
        source: String
    ) async -> ProtectedDataPostUnlockOutcome {
        guard !domainOpeners.isEmpty else {
            return finish(.noRegisteredOpeners, source: source)
        }
        guard let authenticationContext else {
            return finish(.noAuthenticatedContext, source: source)
        }
        guard let protectedDataSessionCoordinator else {
            return finish(.frameworkRecoveryNeeded, source: source)
        }

        let registry: ProtectedDataRegistry
        do {
            registry = try currentRegistryProvider()
        } catch {
            return finish(.frameworkRecoveryNeeded, source: source, error: error)
        }

        switch registry.classifyRecoveryDisposition() {
        case .frameworkRecoveryNeeded:
            return finish(.frameworkRecoveryNeeded, source: source)
        case .continuePendingMutation:
            return finish(.pendingMutationRecoveryRequired, source: source)
        case .resumeSteadyState:
            break
        }

        guard !registry.committedMembership.isEmpty,
              registry.sharedResourceLifecycleState == .ready else {
            return finish(.noProtectedDomainPresent, source: source)
        }

        let initiallyCommittedOpeners = domainOpeners.filter {
            registry.committedMembership[$0.domainID] != nil
        }
        guard !initiallyCommittedOpeners.isEmpty else {
            return finish(.noRegisteredDomainPresent, source: source)
        }

        if protectedDataSessionCoordinator.frameworkState != .sessionAuthorized {
            let authorizationResult = await protectedDataSessionCoordinator.beginProtectedDataAuthorization(
                registry: registry,
                localizedReason: localizedReason,
                authenticationContext: authenticationContext,
                allowLegacyMigration: false
            )
            switch authorizationResult {
            case .authorized:
                break
            case .cancelledOrDenied:
                return finish(.authorizationDenied, source: source)
            case .frameworkRecoveryNeeded:
                return finish(.frameworkRecoveryNeeded, source: source)
            }
        }

        do {
            var wrappingRootKey = try protectedDataSessionCoordinator.wrappingRootKeyData()
            defer {
                wrappingRootKey.protectedDataZeroize()
            }
            let openContext = ProtectedDataPostUnlockOpenContext(
                wrappingRootKey: wrappingRootKey,
                authenticationContext: authenticationContext
            )

            var openedDomainIDs: [ProtectedDataDomainID] = []
            var currentRegistry = registry
            for opener in domainOpeners {
                do {
                    if currentRegistry.committedMembership[opener.domainID] == nil {
                        guard opener.canEnsureCommitted else {
                            continue
                        }
                        try await opener.ensureCommittedIfNeeded(context: openContext)
                        currentRegistry = try currentRegistryProvider()
                    }
                    guard currentRegistry.committedMembership[opener.domainID] != nil else {
                        continue
                    }
                    guard currentRegistry.pendingMutation == nil,
                          currentRegistry.sharedResourceLifecycleState == .ready else {
                        return finish(
                            .pendingMutationRecoveryRequired,
                            source: source
                        )
                    }
                    try await opener.openDomain(context: openContext)
                    openedDomainIDs.append(opener.domainID)
                } catch {
                    return finish(
                        .domainOpenFailed(opener.domainID),
                        source: source,
                        error: error
                    )
                }
            }

            return finish(.opened(openedDomainIDs), source: source)
        } catch {
            return finish(.frameworkRecoveryNeeded, source: source, error: error)
        }
    }

    private func finish(
        _ outcome: ProtectedDataPostUnlockOutcome,
        source: String,
        error: Error? = nil
    ) -> ProtectedDataPostUnlockOutcome {
        var metadata = [
            "outcome": traceValue(for: outcome),
            "source": source
        ]
        if let error {
            metadata.merge(AuthTraceMetadata.errorMetadata(error), uniquingKeysWith: { _, new in new })
        }
        traceStore?.record(
            category: .operation,
            name: "protectedData.postUnlock.openDomains",
            metadata: metadata
        )
        return outcome
    }

    private func traceValue(for outcome: ProtectedDataPostUnlockOutcome) -> String {
        switch outcome {
        case .opened(let domainIDs):
            "opened:\(domainIDs.map(\.rawValue).joined(separator: ","))"
        case .noAuthenticatedContext:
            "noAuthenticatedContext"
        case .noRegisteredOpeners:
            "noRegisteredOpeners"
        case .noProtectedDomainPresent:
            "noProtectedDomainPresent"
        case .noRegisteredDomainPresent:
            "noRegisteredDomainPresent"
        case .pendingMutationRecoveryRequired:
            "pendingMutationRecoveryRequired"
        case .frameworkRecoveryNeeded:
            "frameworkRecoveryNeeded"
        case .authorizationDenied:
            "authorizationDenied"
        case .domainOpenFailed(let domainID):
            "domainOpenFailed:\(domainID.rawValue)"
        }
    }
}

