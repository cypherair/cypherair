import Foundation
import LocalAuthentication

@Observable
final class ProtectedDataSessionCoordinator {
    private let rightStoreClient: any ProtectedDataRightStoreClientProtocol
    private let domainKeyManager: ProtectedDomainKeyManager
    private let sharedRightIdentifier: String

    private var sharedRight: (any ProtectedDataPersistedRightHandle)?
    private var wrappingRootKey: Data?
    private var relockParticipants: [any ProtectedDataRelockParticipant] = []

    private(set) var frameworkState: ProtectedDataFrameworkState = .sessionLocked

    init(
        rightStoreClient: any ProtectedDataRightStoreClientProtocol,
        domainKeyManager: ProtectedDomainKeyManager,
        sharedRightIdentifier: String
    ) {
        self.rightStoreClient = rightStoreClient
        self.domainKeyManager = domainKeyManager
        self.sharedRightIdentifier = sharedRightIdentifier
    }

    func persistSharedRight(secretData: Data) async throws {
        let right = LARight(requirement: .default)
        sharedRight = try await rightStoreClient.saveRight(
            right,
            identifier: sharedRightIdentifier,
            secret: secretData
        )
    }

    func beginProtectedDataAuthorization(
        registry: ProtectedDataRegistry,
        localizedReason: String
    ) async -> ProtectedDataAuthorizationResult {
        if frameworkState == .restartRequired {
            return .frameworkRecoveryNeeded
        }

        guard registry.sharedResourceLifecycleState == .ready else {
            return .frameworkRecoveryNeeded
        }

        do {
            if sharedRight == nil {
                sharedRight = try await rightStoreClient.right(forIdentifier: registry.sharedRightIdentifier)
            }
        } catch {
            frameworkState = .frameworkRecoveryNeeded
            return .frameworkRecoveryNeeded
        }

        guard let sharedRight else {
            frameworkState = .frameworkRecoveryNeeded
            return .frameworkRecoveryNeeded
        }

        do {
            try await sharedRight.authorize(localizedReason: localizedReason)
        } catch {
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
            return .authorized
        } catch {
            await sharedRight.deauthorize()
            if wrappingRootKey != nil {
                wrappingRootKey?.protectedDataZeroize()
                wrappingRootKey = nil
            }
            frameworkState = .frameworkRecoveryNeeded
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
