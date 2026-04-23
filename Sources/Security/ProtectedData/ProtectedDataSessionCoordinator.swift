import Foundation
import LocalAuthentication

@Observable
final class ProtectedDataSessionCoordinator {
    private let rightStoreClient: any ProtectedDataRightStoreClientProtocol
    private let domainKeyManager: ProtectedDomainKeyManager
    private let sharedRightIdentifier: String
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let traceStore: AuthLifecycleTraceStore?

    private var sharedRight: (any ProtectedDataPersistedRightHandle)?
    private var wrappingRootKey: Data?
    private var relockParticipants: [any ProtectedDataRelockParticipant] = []

    private(set) var frameworkState: ProtectedDataFrameworkState = .sessionLocked

    init(
        rightStoreClient: any ProtectedDataRightStoreClientProtocol,
        domainKeyManager: ProtectedDomainKeyManager,
        sharedRightIdentifier: String,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator = AuthenticationPromptCoordinator(),
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.rightStoreClient = rightStoreClient
        self.domainKeyManager = domainKeyManager
        self.sharedRightIdentifier = sharedRightIdentifier
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.traceStore = traceStore
    }

    func persistSharedRight(secretData: Data) async throws {
        let right = LARight(requirement: .default)
        sharedRight = try await rightStoreClient.saveRight(
            right,
            identifier: sharedRightIdentifier,
            secret: secretData
        )
    }

    func removePersistedSharedRight(identifier: String) async throws {
        try await rightStoreClient.removeRight(forIdentifier: identifier)
        sharedRight = nil
        if wrappingRootKey != nil {
            wrappingRootKey?.protectedDataZeroize()
            wrappingRootKey = nil
        }
        frameworkState = .sessionLocked
    }

    func beginProtectedDataAuthorization(
        registry: ProtectedDataRegistry,
        localizedReason: String
    ) async -> ProtectedDataAuthorizationResult {
        traceStore?.record(
            category: .operation,
            name: "protectedSettings.authorization.start",
            metadata: [
                "frameworkState": String(describing: frameworkState),
                "sharedResourceState": registry.sharedResourceLifecycleState.rawValue
            ]
        )
        if frameworkState == .restartRequired {
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "frameworkRecoveryNeeded", "reason": "restartRequired"]
            )
            return .frameworkRecoveryNeeded
        }

        guard registry.sharedResourceLifecycleState == .ready else {
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "frameworkRecoveryNeeded", "reason": "sharedResourceNotReady"]
            )
            return .frameworkRecoveryNeeded
        }

        do {
            if sharedRight == nil {
                sharedRight = try await rightStoreClient.right(forIdentifier: registry.sharedRightIdentifier)
            }
        } catch {
            frameworkState = .frameworkRecoveryNeeded
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "frameworkRecoveryNeeded", "reason": "rightLookupFailed"]
            )
            return .frameworkRecoveryNeeded
        }

        guard let sharedRight else {
            frameworkState = .frameworkRecoveryNeeded
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "frameworkRecoveryNeeded", "reason": "missingSharedRight"]
            )
            return .frameworkRecoveryNeeded
        }

        do {
            try await authenticationPromptCoordinator.withOperationPrompt {
                try await sharedRight.authorize(localizedReason: localizedReason)
            }
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "cancelledOrDenied", "reason": "authorizeThrew"]
            )
            return .cancelledOrDenied
        }
        do {
            var rawSecret = try await sharedRight.rawSecretData()
            let derivedWrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rawSecret)

            if wrappingRootKey != nil {
                wrappingRootKey?.protectedDataZeroize()
            }
            wrappingRootKey = derivedWrappingRootKey
            frameworkState = .sessionAuthorized
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "authorized"]
            )
            return .authorized
        } catch {
            await sharedRight.deauthorize()
            if wrappingRootKey != nil {
                wrappingRootKey?.protectedDataZeroize()
                wrappingRootKey = nil
            }
            frameworkState = .frameworkRecoveryNeeded
            traceStore?.record(
                category: .operation,
                name: "protectedSettings.authorization.finish",
                metadata: ["result": "frameworkRecoveryNeeded", "reason": "secretReadFailed"]
            )
            return .frameworkRecoveryNeeded
        }
    }

    func authorizeSharedRight(localizedReason: String) async throws {
        if frameworkState == .sessionAuthorized {
            return
        }
        throw ProtectedDataError.authorizingUnavailable
    }

    func wrappingRootKeyData() throws -> Data {
        guard let wrappingRootKey else {
            throw ProtectedDataError.missingWrappingRootKey
        }
        return wrappingRootKey
    }

    func registerRelockParticipant(_ participant: any ProtectedDataRelockParticipant) {
        guard !relockParticipants.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(participant) }) else {
            return
        }

        relockParticipants.append(participant)
    }

    func relockCurrentSession() async {
        guard frameworkState != .restartRequired else {
            return
        }

        var participantErrorOccurred = false
        for participant in relockParticipants {
            do {
                try await participant.relockProtectedData()
            } catch {
                participantErrorOccurred = true
            }
        }

        if wrappingRootKey != nil {
            wrappingRootKey?.protectedDataZeroize()
            wrappingRootKey = nil
        }
        domainKeyManager.clearUnlockedDomainMasterKeys()

        if let sharedRight {
            await sharedRight.deauthorize()
        }

        frameworkState = participantErrorOccurred ? .restartRequired : .sessionLocked
    }

    var hasActiveWrappingRootKey: Bool {
        wrappingRootKey != nil
    }
}
