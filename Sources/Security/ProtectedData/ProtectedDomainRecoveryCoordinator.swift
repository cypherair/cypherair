import Foundation
import LocalAuthentication
import Security

protocol ProtectedDomainRecoveryHandler: AnyObject, Sendable {
    var protectedDataDomainID: ProtectedDataDomainID { get }

    func continuePendingCreate(
        phase: CreateDomainPhase,
        authenticationContext: LAContext?
    ) async throws
    func deleteDomainArtifactsForRecovery() throws
}

private struct ProtectedDomainRecoveryAuthenticationContext: @unchecked Sendable {
    let value: LAContext?
}

struct ProtectedDomainRecoveryCoordinator {
    private let registryStore: ProtectedDataRegistryStore

    init(registryStore: ProtectedDataRegistryStore) {
        self.registryStore = registryStore
    }

    func performPreAuthBootstrapClassification() throws -> ProtectedDataRegistryBootstrapResult {
        try registryStore.performSynchronousBootstrap()
    }

    func loadCurrentRegistry() throws -> ProtectedDataRegistry {
        try registryStore.loadRegistry()
    }

    func pendingRecoveryAuthorizationRequirement() -> ProtectedDataMutationAuthorizationRequirement {
        do {
            let registry = try registryStore.loadRegistry()
            guard registry.classifyRecoveryDisposition() != .frameworkRecoveryNeeded else {
                return .frameworkRecoveryNeeded
            }
            guard case let pendingMutation? = registry.pendingMutation else {
                return .notRequired
            }

            switch pendingMutation {
            case .createDomain(_, let phase):
                switch phase {
                case .journaled, .sharedResourceProvisioned, .artifactsStaged, .validated:
                    if registry.committedMembership.isEmpty && registry.sharedResourceLifecycleState == .absent {
                        return .notRequired
                    }
                    guard registry.sharedResourceLifecycleState == .ready else {
                        return .frameworkRecoveryNeeded
                    }
                    return .wrappingRootKeyRequired
                case .membershipCommitted:
                    return .notRequired
                }
            case .deleteDomain:
                return .notRequired
            }
        } catch {
            return .frameworkRecoveryNeeded
        }
    }

    func recoverPendingMutation(
        handler: any ProtectedDomainRecoveryHandler,
        authenticationContext: LAContext? = nil,
        removeSharedRight: @escaping @Sendable (String) async throws -> Void
    ) async throws -> PendingRecoveryOutcome {
        let registry = try registryStore.loadRegistry()
        guard case let pendingMutation? = registry.pendingMutation,
                pendingMutation.targetDomainID == handler.protectedDataDomainID else {
            return .frameworkRecoveryNeeded
        }
        let sharedRightIdentifier = registry.sharedRightIdentifier
        let recoveryAuthenticationContext = ProtectedDomainRecoveryAuthenticationContext(
            value: authenticationContext
        )

        return try await registryStore.recoverPendingMutation(
            targetDomainID: handler.protectedDataDomainID,
            continueReadyCreate: { phase in
                try await handler.continuePendingCreate(
                    phase: phase,
                    authenticationContext: recoveryAuthenticationContext.value
                )
            },
            continueDelete: { _ in
                _ = try await registryStore.completePendingDelete(
                    domainID: handler.protectedDataDomainID,
                    deleteArtifacts: {
                        try handler.deleteDomainArtifactsForRecovery()
                    },
                    cleanupSharedResourceIfNeeded: {
                        try await removeSharedRight(sharedRightIdentifier)
                    }
                )
            }
        )
    }

    func recoverPendingMutation(
        handlers: [any ProtectedDomainRecoveryHandler],
        authenticationContext: LAContext? = nil,
        removeSharedRight: @escaping @Sendable (String) async throws -> Void
    ) async throws -> PendingRecoveryOutcome {
        let registry = try registryStore.loadRegistry()
        guard case let pendingMutation? = registry.pendingMutation else {
            return .frameworkRecoveryNeeded
        }
        guard let handler = handlers.first(where: {
            $0.protectedDataDomainID == pendingMutation.targetDomainID
        }) else {
            return .frameworkRecoveryNeeded
        }

        return try await recoverPendingMutation(
            handler: handler,
            authenticationContext: authenticationContext,
            removeSharedRight: removeSharedRight
        )
    }
}

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

@Observable
final class ProtectedSettingsStore: ProtectedDataRelockParticipant, @unchecked Sendable {
    struct Payload: Codable, Equatable, Sendable {
        static let currentSchemaVersion = 2

        var clipboardNotice: Bool
        var ordinarySettings: ProtectedOrdinarySettingsSnapshot
    }

    private struct PayloadV1: Codable, Equatable, Sendable {
        var clipboardNotice: Bool
    }

    static let domainID: ProtectedDataDomainID = "protected-settings"

    private struct OpenedSnapshot {
        let payload: Payload
        let generationIdentifier: Int
        let schemaVersion: Int

        var requiresOrdinarySettingsMigration: Bool {
            schemaVersion < Payload.currentSchemaVersion
        }
    }

    private enum CommittedSettingsUpgradeFailure: Error {
        case retryable(underlying: Error, state: ProtectedSettingsDomainState)
        case recoveryRequired(underlying: Error)

        var underlyingError: Error {
            switch self {
            case .retryable(let underlying, _),
                 .recoveryRequired(let underlying):
                underlying
            }
        }
    }

    private struct ProtectedSettingsStorageReadFailure: Error {
        let underlying: Error
    }

    private let defaults: UserDefaults
    private let storageRoot: ProtectedDataStorageRoot
    private let registryStore: ProtectedDataRegistryStore
    private let domainKeyManager: ProtectedDomainKeyManager
    private let bootstrapStore: ProtectedDomainBootstrapStore
    private let currentWrappingRootKey: (() throws -> Data)?

    private(set) var domainState: ProtectedSettingsDomainState = .locked
    private(set) var payload: Payload?

    @ObservationIgnored
    private var unlockedGenerationIdentifier: Int?

    init(
        defaults: UserDefaults,
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        bootstrapStore: ProtectedDomainBootstrapStore? = nil,
        currentWrappingRootKey: (() throws -> Data)? = nil
    ) {
        self.defaults = defaults
        self.storageRoot = storageRoot
        self.registryStore = registryStore
        self.domainKeyManager = domainKeyManager
        self.bootstrapStore = bootstrapStore ?? ProtectedDomainBootstrapStore(storageRoot: storageRoot)
        self.currentWrappingRootKey = currentWrappingRootKey
    }

    var clipboardNotice: Bool? {
        payload?.clipboardNotice
    }

    var ordinarySettings: ProtectedOrdinarySettingsSnapshot? {
        payload?.ordinarySettings
    }

    var hasCommittedDomain: Bool {
        (try? registryStore.loadRegistry().committedMembership[Self.domainID] != nil) ?? false
    }

    func ordinarySettingsSnapshot() throws -> ProtectedOrdinarySettingsSnapshot {
        guard domainState == .unlocked,
              let payload else {
            throw ProtectedDataError.invalidRegistry(
                "Protected settings ordinary settings are unavailable while the domain is locked."
            )
        }
        try validateOrdinarySettingsSnapshot(payload.ordinarySettings)
        return payload.ordinarySettings
    }

    func updateOrdinarySettingsSnapshot(
        _ snapshot: ProtectedOrdinarySettingsSnapshot
    ) throws {
        guard domainState == .unlocked,
              let existingPayload = payload else {
            throw ProtectedDataError.invalidRegistry(
                "Protected settings ordinary settings cannot be updated while the domain is locked."
            )
        }

        var normalized = snapshot
        normalized.normalize()
        try validateOrdinarySettingsSnapshot(normalized)
        guard existingPayload.ordinarySettings != normalized else {
            return
        }

        var domainMasterKey = try activeDomainMasterKeyForCurrentSession()
        defer {
            domainMasterKey.protectedDataZeroize()
        }

        let nextGenerationIdentifier = max(unlockedGenerationIdentifier ?? 0, 0) + 1
        let updatedPayload = Payload(
            clipboardNotice: existingPayload.clipboardNotice,
            ordinarySettings: normalized
        )
        try writePayloadGeneration(
            updatedPayload,
            generationIdentifier: nextGenerationIdentifier,
            domainMasterKey: domainMasterKey
        )
        payload = updatedPayload
        unlockedGenerationIdentifier = nextGenerationIdentifier
        domainState = .unlocked
    }

    func resetOrdinarySettingsRuntimeStateAfterLocalDataReset() {
        removeLegacySettingsSources()
        clearUnlockedState()
        domainState = .locked
    }

    func migrationAuthorizationRequirement() -> ProtectedDataMutationAuthorizationRequirement {
        do {
            let registry = try registryStore.loadRegistry()
            if registry.committedMembership[Self.domainID] != nil {
                return .notRequired
            }
            guard registry.classifyRecoveryDisposition() == .resumeSteadyState else {
                return .frameworkRecoveryNeeded
            }
            guard !registry.committedMembership.isEmpty else {
                return registry.sharedResourceLifecycleState == .absent ? .notRequired : .frameworkRecoveryNeeded
            }
            guard registry.sharedResourceLifecycleState == .ready else {
                return .frameworkRecoveryNeeded
            }
            return .wrappingRootKeyRequired
        } catch {
            return .frameworkRecoveryNeeded
        }
    }

    func syncPreAuthorizationState() {
        do {
            let registry = try registryStore.loadRegistry()
            if case .frameworkRecoveryNeeded = registry.classifyRecoveryDisposition() {
                domainState = .frameworkUnavailable
                return
            }
            if let pendingDomainState = pendingDomainState(for: registry) {
                domainState = pendingDomainState
                return
            }
            if registry.committedMembership[Self.domainID] == .recoveryNeeded {
                domainState = .recoveryNeeded
                return
            }
            if payload == nil {
                domainState = .locked
            }
        } catch {
            domainState = .frameworkUnavailable
        }
    }

    func ensureCommittedAndMigrateSettingsIfNeeded(
        persistSharedRight: @escaping @Sendable (Data) async throws -> Void,
        firstDomainSharedRightCleaner: ProtectedDataFirstDomainSharedRightCleaner? = nil,
        currentWrappingRootKey: (() throws -> Data)? = nil
    ) async throws {
        let registry = try registryStore.loadRegistry()
        if registry.committedMembership[Self.domainID] != nil {
            do {
                try upgradeCommittedSettingsPayloadIfNeeded(
                    currentWrappingRootKey: currentWrappingRootKey
                )
            } catch {
                let failure = committedSettingsUpgradeFailure(for: error)
                clearUnlockedState()
                switch failure {
                case .retryable(let underlying, let state):
                    domainState = state
                    throw underlying
                case .recoveryRequired(let underlying):
                    domainState = .recoveryNeeded
                    if registry.committedMembership[Self.domainID] != .recoveryNeeded {
                        _ = try? await registryStore.updateCommittedDomainState(
                            domainID: Self.domainID,
                            to: .recoveryNeeded
                        )
                    }
                    throw underlying
                }
            }
            return
        }

        let initialPayload = legacyInitialPayload()

        if !registry.committedMembership.isEmpty {
            if let pendingDomainState = pendingDomainState(for: registry) {
                domainState = pendingDomainState
                throw ProtectedDataError.invalidRegistry(
                    "Protected settings cannot be created while protected-data recovery is pending."
                )
            }
            guard registry.sharedResourceLifecycleState == .ready else {
                throw ProtectedDataError.invalidRegistry(
                    "Protected settings cannot be created while the shared resource is not ready."
                )
            }
            let wrappingRootKeyProvider = currentWrappingRootKey ?? self.currentWrappingRootKey
            guard let wrappingRootKeyProvider else {
                throw ProtectedDataError.authorizingUnavailable
            }
            let wrappingRootKey = SensitiveBytesBox(data: try wrappingRootKeyProvider())
            defer {
                wrappingRootKey.zeroize()
            }

            _ = try await registryStore.performCreateDomainTransaction(
                domainID: Self.domainID,
                validateBeforeJournal: { registry in
                    guard registry.sharedResourceLifecycleState == .ready,
                          registry.committedMembership.contains(where: { $0.key != Self.domainID }) else {
                        throw ProtectedDataError.invalidRegistry(
                            "Protected settings can only join an existing ready shared resource."
                        )
                    }
                },
                provisionSharedResourceIfNeeded: {},
                stageArtifacts: { [self] in
                    try stageInitialPayload(
                        initialPayload,
                        wrappingRootKey: wrappingRootKey.dataCopy()
                    )
                },
                validateArtifacts: { [self] in
                    try protectedDataValidateSnapshotAndZeroizeDomainMasterKey {
                        try readAuthoritativeSnapshot(
                            wrappingRootKey: wrappingRootKey.dataCopy()
                        )
                    }
                }
            )

            removeLegacySettingsSources()
            clearUnlockedState()
            domainState = .locked
            return
        }
        if let firstDomainSharedRightCleaner {
            do {
                let cleanupOutcome = try await firstDomainSharedRightCleaner.cleanupOrphanedSharedRightIfSafe(
                    registry: registry,
                    source: Self.domainID.rawValue
                )
                if cleanupOutcome == .blockedByArtifacts {
                    domainState = .pendingResetRequired
                    throw ProtectedDataError.invalidRegistry(
                        "Protected settings cannot create the first domain while protected-data artifacts remain without registry membership."
                    )
                }
            } catch {
                if domainState != .pendingResetRequired {
                    domainState = .frameworkUnavailable
                }
                throw error
            }
        }

        let provisionedSecret = SensitiveBytesBox(
            data: try randomData(count: WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength)
        )
        var rawRootKeyInput = provisionedSecret.dataCopy()
        let derivedWrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rawRootKeyInput)
        rawRootKeyInput.protectedDataZeroize()
        let wrappingRootKey = SensitiveBytesBox(data: derivedWrappingRootKey)
        defer {
            provisionedSecret.zeroize()
            wrappingRootKey.zeroize()
        }

        _ = try await registryStore.performCreateDomainTransaction(
            domainID: Self.domainID,
            provisionSharedResourceIfNeeded: {
                try await persistSharedRight(provisionedSecret.dataCopy())
            },
            stageArtifacts: { [self] in
                try stageInitialPayload(
                    initialPayload,
                    wrappingRootKey: wrappingRootKey.dataCopy()
                )
            },
            validateArtifacts: { [self] in
                try protectedDataValidateSnapshotAndZeroizeDomainMasterKey {
                    try readAuthoritativeSnapshot(
                        wrappingRootKey: wrappingRootKey.dataCopy()
                    )
                }
            }
        )

        removeLegacySettingsSources()
        clearUnlockedState()
        domainState = .locked
    }

    func openDomainIfNeeded(wrappingRootKey: Data) async throws -> Payload {
        if let payload, domainState == .unlocked {
            return payload
        }

        let registry = try registryStore.loadRegistry()
        if let pendingDomainState = pendingDomainState(for: registry) {
            domainState = pendingDomainState
            throw ProtectedDataError.invalidRegistry(
                "Protected settings domain has pending recovery work."
            )
        }
        guard registry.committedMembership[Self.domainID] != nil else {
            domainState = .locked
            throw ProtectedDataError.invalidRegistry(
                "Protected settings domain is not committed yet."
            )
        }

        do {
            let readResult = try readAuthoritativeSnapshot(
                wrappingRootKey: wrappingRootKey
            )
            var openedSnapshot = readResult.0
            var unwrappedDomainMasterKey = readResult.1
            defer {
                unwrappedDomainMasterKey.protectedDataZeroize()
            }
            openedSnapshot = try migrateOpenedSettingsSnapshotIfNeeded(
                openedSnapshot,
                domainMasterKey: &unwrappedDomainMasterKey,
                wrappingRootKey: wrappingRootKey
            )
            let cachedDomainMasterKey = Data(unwrappedDomainMasterKey)
            domainKeyManager.cacheUnlockedDomainMasterKey(cachedDomainMasterKey, for: Self.domainID)
            payload = openedSnapshot.payload
            unlockedGenerationIdentifier = openedSnapshot.generationIdentifier
            domainState = .unlocked

            if registry.committedMembership[Self.domainID] == .recoveryNeeded {
                _ = try await registryStore.updateCommittedDomainState(
                    domainID: Self.domainID,
                    to: .active
                )
            }

            return openedSnapshot.payload
        } catch {
            clearUnlockedState()
            domainState = .recoveryNeeded
            if registry.committedMembership[Self.domainID] != .recoveryNeeded {
                _ = try? await registryStore.updateCommittedDomainState(
                    domainID: Self.domainID,
                    to: .recoveryNeeded
                )
            }
            throw externallyVisibleProtectedSettingsError(error)
        }
    }

    func updateClipboardNotice(
        _ isEnabled: Bool,
        wrappingRootKey: Data
    ) async throws {
        let existingPayload = try await openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        guard existingPayload.clipboardNotice != isEnabled else {
            return
        }

        var domainMasterKey = try activeDomainMasterKey(wrappingRootKey: wrappingRootKey)
        defer {
            domainMasterKey.protectedDataZeroize()
        }

        let nextGenerationIdentifier = max(unlockedGenerationIdentifier ?? 0, 0) + 1
        let updatedPayload = Payload(
            clipboardNotice: isEnabled,
            ordinarySettings: existingPayload.ordinarySettings
        )
        try writePayloadGeneration(
            updatedPayload,
            generationIdentifier: nextGenerationIdentifier,
            domainMasterKey: domainMasterKey
        )
        payload = updatedPayload
        unlockedGenerationIdentifier = nextGenerationIdentifier
        domainState = .unlocked
    }

    func resetDomain(
        persistSharedRight: @escaping @Sendable (Data) async throws -> Void,
        removeSharedRight: @escaping @Sendable (String) async throws -> Void,
        firstDomainSharedRightCleaner: ProtectedDataFirstDomainSharedRightCleaner? = nil,
        currentWrappingRootKey: (() throws -> Data)? = nil
    ) async throws {
        try preflightResetAuthorizationIfNeeded(currentWrappingRootKey: currentWrappingRootKey)

        if let registry = try? registryStore.loadRegistry() {
            if case let pendingMutation? = registry.pendingMutation,
               pendingMutation.targetDomainID == Self.domainID {
                switch pendingMutation {
                case .createDomain:
                    _ = try await registryStore.abandonPendingCreate(
                        domainID: Self.domainID,
                        deleteArtifacts: { [self] in
                            try deleteDomainArtifactsForRecovery()
                        },
                        cleanupSharedResourceIfNeeded: {
                            try await removeSharedRight(registry.sharedRightIdentifier)
                        }
                    )
                case .deleteDomain:
                    _ = try await registryStore.completePendingDelete(
                        domainID: Self.domainID,
                        deleteArtifacts: { [self] in
                            try deleteDomainArtifactsForRecovery()
                        },
                        cleanupSharedResourceIfNeeded: {
                            try await removeSharedRight(registry.sharedRightIdentifier)
                        }
                    )
                }
            } else if registry.committedMembership[Self.domainID] != nil {
                _ = try await registryStore.performDeleteDomainTransaction(
                    domainID: Self.domainID,
                    deleteArtifacts: { [self] in
                        try deleteDomainArtifacts()
                    },
                    cleanupSharedResourceIfNeeded: {
                        try await removeSharedRight(registry.sharedRightIdentifier)
                    }
                )
            }
        }

        clearUnlockedState()
        domainState = .locked
        try await ensureCommittedAndMigrateSettingsIfNeeded(
            persistSharedRight: persistSharedRight,
            firstDomainSharedRightCleaner: firstDomainSharedRightCleaner,
            currentWrappingRootKey: currentWrappingRootKey
        )
    }

    func resetAuthorizationRequirement() -> ProtectedDataMutationAuthorizationRequirement {
        do {
            let registry = try registryStore.loadRegistry()
            guard registry.classifyRecoveryDisposition() != .frameworkRecoveryNeeded else {
                return .frameworkRecoveryNeeded
            }
            guard resetWillRecreateIntoExistingSharedResource(registry) else {
                return .notRequired
            }
            guard registry.sharedResourceLifecycleState == .ready else {
                return .frameworkRecoveryNeeded
            }
            return .wrappingRootKeyRequired
        } catch {
            return .frameworkRecoveryNeeded
        }
    }

    func relockProtectedData() async throws {
        clearUnlockedState()
        if domainState == .unlocked {
            domainState = .locked
        }
    }

    private func stageInitialPayload(
        _ payload: Payload,
        wrappingRootKey: Data
    ) throws {
        var domainMasterKey = try domainKeyManager.generateDomainMasterKey()
        defer {
            domainMasterKey.protectedDataZeroize()
        }

        let wrappedRecord = try domainKeyManager.wrapDomainMasterKey(
            domainMasterKey,
            for: Self.domainID,
            wrappingRootKey: wrappingRootKey
        )
        try domainKeyManager.writeWrappedDomainMasterKeyRecordTransaction(
            wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )
        try writePayloadGeneration(
            payload,
            generationIdentifier: 1,
            domainMasterKey: domainMasterKey
        )
    }

    private func writePayloadGeneration(
        _ payload: Payload,
        generationIdentifier: Int,
        domainMasterKey: Data
    ) throws {
        try storageRoot.ensureDomainDirectoryExists(for: Self.domainID)

        var normalizedPayload = payload
        normalizedPayload.ordinarySettings.normalize()
        try validateOrdinarySettingsSnapshot(normalizedPayload.ordinarySettings)

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        var plaintext = try encoder.encode(normalizedPayload)
        defer {
            plaintext.protectedDataZeroize()
        }

        let envelope = try ProtectedDomainEnvelopeCodec.seal(
            plaintext: plaintext,
            domainID: Self.domainID,
            schemaVersion: Payload.currentSchemaVersion,
            generationIdentifier: generationIdentifier,
            domainMasterKey: domainMasterKey
        )
        let envelopeData = try encoder.encode(envelope)
        let pendingURL = storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .pending)
        try storageRoot.writeProtectedData(envelopeData, to: pendingURL)

        let validatedData = try storageRoot.readManagedData(at: pendingURL)
        let decodedEnvelope = try PropertyListDecoder().decode(ProtectedDomainEnvelope.self, from: validatedData)
        var validatedPlaintext = try ProtectedDomainEnvelopeCodec.open(
            envelope: decodedEnvelope,
            domainMasterKey: domainMasterKey
        )
        validatedPlaintext.protectedDataZeroize()

        let currentURL = storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .current)
        let previousURL = storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .previous)
        if try storageRoot.managedItemExists(at: currentURL) {
            try storageRoot.promoteStagedFile(from: currentURL, to: previousURL)
        }
        try storageRoot.promoteStagedFile(from: pendingURL, to: currentURL)

        try bootstrapStore.saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: Payload.currentSchemaVersion,
                expectedCurrentGenerationIdentifier: String(generationIdentifier),
                coarseRecoveryReason: nil,
                wrappedDomainMasterKeyRecordVersion: WrappedDomainMasterKeyRecord.currentFormatVersion
            ),
            for: Self.domainID
        )
    }

    private func readAuthoritativeSnapshot(
        wrappingRootKey: Data
    ) throws -> (OpenedSnapshot, Data) {
        guard let wrappedRecord = try domainKeyManager.loadWrappedDomainMasterKeyRecord(
            for: Self.domainID
        ) else {
            throw ProtectedDataError.missingWrappedDomainMasterKey(Self.domainID)
        }

        var domainMasterKey = try domainKeyManager.unwrapDomainMasterKey(
            from: wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )
        var shouldReturnDomainMasterKey = false
        defer {
            if !shouldReturnDomainMasterKey {
                domainMasterKey.protectedDataZeroize()
            }
        }

        var candidates: [OpenedSnapshot] = []
        var highestObservedGenerationIdentifier: Int?

        for slot in ProtectedDomainGenerationSlot.allCases {
            let url = storageRoot.domainEnvelopeURL(for: Self.domainID, slot: slot)
            guard try storageRoot.managedItemExists(at: url) else {
                continue
            }

            let data: Data
            do {
                data = try storageRoot.readManagedData(at: url)
            } catch {
                throw ProtectedSettingsStorageReadFailure(underlying: error)
            }

            do {
                let envelope = try PropertyListDecoder().decode(ProtectedDomainEnvelope.self, from: data)
                highestObservedGenerationIdentifier = max(
                    highestObservedGenerationIdentifier ?? envelope.generationIdentifier,
                    envelope.generationIdentifier
                )
                var plaintext = try ProtectedDomainEnvelopeCodec.open(
                    envelope: envelope,
                    domainMasterKey: domainMasterKey
                )
                defer {
                    plaintext.protectedDataZeroize()
                }
                candidates.append(
                    try decodeOpenedSnapshot(
                        plaintext: plaintext,
                        envelope: envelope
                    )
                )
            } catch {
                continue
            }
        }

        guard let selectedSnapshot = candidates.max(by: {
            $0.generationIdentifier < $1.generationIdentifier
        }) else {
            throw ProtectedDataError.invalidEnvelope(
                "Protected settings does not contain a readable authoritative generation."
            )
        }
        if let highestObservedGenerationIdentifier,
           selectedSnapshot.generationIdentifier < highestObservedGenerationIdentifier {
            throw ProtectedDataError.invalidEnvelope(
                "Protected settings highest observed generation is not readable."
            )
        }

        shouldReturnDomainMasterKey = true
        return (selectedSnapshot, domainMasterKey)
    }

    private func activeDomainMasterKey(wrappingRootKey: Data) throws -> Data {
        if let cachedKey = domainKeyManager.unlockedDomainMasterKey(for: Self.domainID) {
            return Data(cachedKey)
        }

        guard let wrappedRecord = try domainKeyManager.loadWrappedDomainMasterKeyRecord(
            for: Self.domainID
        ) else {
            throw ProtectedDataError.missingWrappedDomainMasterKey(Self.domainID)
        }

        return try domainKeyManager.unwrapDomainMasterKey(
            from: wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )
    }

    private func activeDomainMasterKeyForCurrentSession() throws -> Data {
        if let cachedKey = domainKeyManager.unlockedDomainMasterKey(for: Self.domainID) {
            return Data(cachedKey)
        }

        guard let currentWrappingRootKey else {
            throw ProtectedDataError.authorizingUnavailable
        }
        var wrappingRootKey = try currentWrappingRootKey()
        defer {
            wrappingRootKey.protectedDataZeroize()
        }
        return try activeDomainMasterKey(wrappingRootKey: wrappingRootKey)
    }

    private func upgradeCommittedSettingsPayloadIfNeeded(
        currentWrappingRootKey: (() throws -> Data)? = nil
    ) throws {
        let registry = try registryStore.loadRegistry()
        if let pendingDomainState = pendingDomainState(for: registry) {
            domainState = pendingDomainState
            throw CommittedSettingsUpgradeFailure.retryable(
                underlying: ProtectedDataError.invalidRegistry(
                    "Protected settings cannot be upgraded while protected-data recovery is pending."
                ),
                state: pendingDomainState
            )
        }
        guard registry.committedMembership[Self.domainID] != nil else {
            return
        }
        guard registry.sharedResourceLifecycleState == .ready else {
            throw CommittedSettingsUpgradeFailure.retryable(
                underlying: ProtectedDataError.invalidRegistry(
                    "Protected settings cannot be upgraded while the shared resource is not ready."
                ),
                state: .frameworkUnavailable
            )
        }

        let wrappingRootKeyProvider = currentWrappingRootKey ?? self.currentWrappingRootKey
        guard let wrappingRootKeyProvider else {
            throw CommittedSettingsUpgradeFailure.retryable(
                underlying: ProtectedDataError.authorizingUnavailable,
                state: .locked
            )
        }
        var wrappingRootKey = try wrappingRootKeyProvider()
        defer {
            wrappingRootKey.protectedDataZeroize()
        }

        let readResult = try readAuthoritativeSnapshot(wrappingRootKey: wrappingRootKey)
        var openedSnapshot = readResult.0
        var domainMasterKey = readResult.1
        defer {
            domainMasterKey.protectedDataZeroize()
        }
        openedSnapshot = try migrateOpenedSettingsSnapshotIfNeeded(
            openedSnapshot,
            domainMasterKey: &domainMasterKey,
            wrappingRootKey: wrappingRootKey
        )
        payload = nil
        unlockedGenerationIdentifier = nil
        if openedSnapshot.requiresOrdinarySettingsMigration {
            domainState = .recoveryNeeded
        } else {
            domainState = .locked
        }
    }

    private func committedSettingsUpgradeFailure(
        for error: Error
    ) -> CommittedSettingsUpgradeFailure {
        if let failure = error as? CommittedSettingsUpgradeFailure {
            return failure
        }
        if let storageReadFailure = error as? ProtectedSettingsStorageReadFailure {
            return .retryable(underlying: storageReadFailure.underlying, state: .frameworkUnavailable)
        }
        if let protectedDataError = error as? ProtectedDataError {
            switch protectedDataError {
            case .missingWrappingRootKey, .authorizingUnavailable:
                return .retryable(underlying: error, state: .locked)
            case .storageRootOutsideApplicationSupport,
                 .fileProtectionUnsupported,
                 .fileProtectionVerificationFailed,
                 .protectedFileWriteFailed,
                 .registryMissingWithArtifacts,
                 .missingPersistedRight,
                 .restartRequired,
                 .internalFailure:
                return .retryable(underlying: error, state: .frameworkUnavailable)
            case .invalidRegistry(let reason):
                if reason.hasPrefix("Unsupported WrappedDomainMasterKeyRecord") {
                    return .recoveryRequired(underlying: error)
                }
                return .retryable(underlying: error, state: .frameworkUnavailable)
            case .missingWrappedDomainMasterKey(let domainID):
                if domainID == Self.domainID {
                    return .recoveryRequired(underlying: error)
                }
                return .retryable(underlying: error, state: .frameworkUnavailable)
            case .invalidDomainMasterKeyLength,
                 .invalidNonceLength,
                 .invalidAuthenticationTagLength,
                 .invalidCiphertextLength,
                 .invalidEnvelope:
                return .recoveryRequired(underlying: error)
            }
        }
        if isFoundationStorageError(error) {
            return .retryable(underlying: error, state: .frameworkUnavailable)
        }
        return .recoveryRequired(underlying: error)
    }

    private func externallyVisibleProtectedSettingsError(_ error: Error) -> Error {
        if let failure = error as? CommittedSettingsUpgradeFailure {
            return failure.underlyingError
        }
        if let storageReadFailure = error as? ProtectedSettingsStorageReadFailure {
            return storageReadFailure.underlying
        }
        return error
    }

    private func isFoundationStorageError(_ error: Error) -> Bool {
        let nsError = error as NSError
        return nsError.domain == NSCocoaErrorDomain || nsError.domain == NSPOSIXErrorDomain
    }

    private func migrateOpenedSettingsSnapshotIfNeeded(
        _ openedSnapshot: OpenedSnapshot,
        domainMasterKey: inout Data,
        wrappingRootKey: Data
    ) throws -> OpenedSnapshot {
        guard openedSnapshot.requiresOrdinarySettingsMigration else {
            removeLegacySettingsSources()
            return openedSnapshot
        }

        var upgradedPayload = Payload(
            clipboardNotice: openedSnapshot.payload.clipboardNotice,
            ordinarySettings: legacyOrdinarySettingsSnapshot()
        )
        upgradedPayload.ordinarySettings.normalize()
        try validateOrdinarySettingsSnapshot(upgradedPayload.ordinarySettings)

        let nextGenerationIdentifier = max(openedSnapshot.generationIdentifier, 0) + 1
        try writePayloadGeneration(
            upgradedPayload,
            generationIdentifier: nextGenerationIdentifier,
            domainMasterKey: domainMasterKey
        )

        let verificationResult = try readAuthoritativeSnapshot(
            wrappingRootKey: wrappingRootKey
        )
        let verifiedSnapshot = verificationResult.0
        var verifiedDomainMasterKey = verificationResult.1
        defer {
            verifiedDomainMasterKey.protectedDataZeroize()
        }
        guard verifiedSnapshot.schemaVersion == Payload.currentSchemaVersion,
              verifiedSnapshot.generationIdentifier == nextGenerationIdentifier,
              verifiedSnapshot.payload == upgradedPayload else {
            throw ProtectedDataError.invalidEnvelope(
                "Protected settings migration verification did not reopen the expected schema v2 payload."
            )
        }

        removeLegacySettingsSources()
        return verifiedSnapshot
    }

    private func decodeOpenedSnapshot(
        plaintext: Data,
        envelope: ProtectedDomainEnvelope
    ) throws -> OpenedSnapshot {
        let decoder = PropertyListDecoder()
        switch envelope.schemaVersion {
        case 1:
            let v1Payload = try decoder.decode(PayloadV1.self, from: plaintext)
            return OpenedSnapshot(
                payload: Payload(
                    clipboardNotice: v1Payload.clipboardNotice,
                    ordinarySettings: .firstRunDefaults
                ),
                generationIdentifier: envelope.generationIdentifier,
                schemaVersion: envelope.schemaVersion
            )
        case Payload.currentSchemaVersion:
            let payload = try decoder.decode(Payload.self, from: plaintext)
            try validateOrdinarySettingsSnapshot(payload.ordinarySettings)
            return OpenedSnapshot(
                payload: payload,
                generationIdentifier: envelope.generationIdentifier,
                schemaVersion: envelope.schemaVersion
            )
        default:
            throw ProtectedDataError.invalidEnvelope(
                "Protected settings payload has unsupported schema version \(envelope.schemaVersion)."
            )
        }
    }

    private func deleteDomainArtifacts() throws {
        try storageRoot.removeItemIfPresent(
            at: storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .pending)
        )
        try storageRoot.removeItemIfPresent(
            at: storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .current)
        )
        try storageRoot.removeItemIfPresent(
            at: storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .previous)
        )
        try storageRoot.removeItemIfPresent(
            at: storageRoot.committedWrappedDomainMasterKeyURL(for: Self.domainID)
        )
        try storageRoot.removeItemIfPresent(
            at: storageRoot.stagedWrappedDomainMasterKeyURL(for: Self.domainID)
        )
        try bootstrapStore.removeMetadata(for: Self.domainID)
        try storageRoot.removeDomainDirectoryIfPresent(for: Self.domainID)
    }

    func deleteDomainArtifactsForRecovery() throws {
        try deleteDomainArtifacts()
    }

    private func preflightResetAuthorizationIfNeeded(
        currentWrappingRootKey: (() throws -> Data)? = nil
    ) throws {
        switch resetAuthorizationRequirement() {
        case .notRequired:
            return
        case .frameworkRecoveryNeeded:
            throw ProtectedDataError.invalidRegistry(
                "Protected settings reset requires framework recovery."
            )
        case .wrappingRootKeyRequired:
            let wrappingRootKeyProvider = currentWrappingRootKey ?? self.currentWrappingRootKey
            guard let wrappingRootKeyProvider else {
                throw ProtectedDataError.authorizingUnavailable
            }
            var wrappingRootKey = try wrappingRootKeyProvider()
            wrappingRootKey.protectedDataZeroize()
        }
    }

    func continuePendingCreate(
        phase: CreateDomainPhase,
        authenticationContext: LAContext?
    ) async throws {
        if phase == .membershipCommitted {
            return
        }

        guard let currentWrappingRootKey else {
            throw ProtectedDataError.authorizingUnavailable
        }
        let initialPayload = legacyInitialPayload()
        let wrappingRootKey = SensitiveBytesBox(data: try currentWrappingRootKey())
        defer {
            wrappingRootKey.zeroize()
        }

        _ = try await registryStore.completePendingCreate(
            domainID: Self.domainID,
            stageArtifacts: { [self] in
                try stageInitialPayload(
                    initialPayload,
                    wrappingRootKey: wrappingRootKey.dataCopy()
                )
            },
            validateArtifacts: { [self] in
                try protectedDataValidateSnapshotAndZeroizeDomainMasterKey {
                    try readAuthoritativeSnapshot(
                        wrappingRootKey: wrappingRootKey.dataCopy()
                    )
                }
            }
        )
    }

    private func resetWillRecreateIntoExistingSharedResource(
        _ registry: ProtectedDataRegistry
    ) -> Bool {
        var membershipAfterReset = registry.committedMembership
        switch registry.pendingMutation {
        case .some(let pendingMutation) where pendingMutation.targetDomainID == Self.domainID:
            membershipAfterReset.removeValue(forKey: Self.domainID)
        case .some:
            return false
        case nil:
            if registry.committedMembership[Self.domainID] != nil {
                membershipAfterReset.removeValue(forKey: Self.domainID)
            }
        }

        return !membershipAfterReset.isEmpty
    }

    private func clearUnlockedState() {
        payload = nil
        unlockedGenerationIdentifier = nil
    }

    private func legacyInitialPayload() -> Payload {
        let clipboardNotice = defaults.object(forKey: AppConfiguration.clipboardNoticeLegacyKey) == nil
            ? true
            : defaults.bool(forKey: AppConfiguration.clipboardNoticeLegacyKey)
        return Payload(
            clipboardNotice: clipboardNotice,
            ordinarySettings: legacyOrdinarySettingsSnapshot()
        )
    }

    private func legacyOrdinarySettingsSnapshot() -> ProtectedOrdinarySettingsSnapshot {
        LegacyOrdinarySettingsStore(defaults: defaults).loadSnapshot()
    }

    private func removeLegacySettingsSources() {
        defaults.removeObject(forKey: AppConfiguration.clipboardNoticeLegacyKey)
        for key in LegacyOrdinarySettingsStore.persistentKeys {
            defaults.removeObject(forKey: key)
        }
    }

    private func validateOrdinarySettingsSnapshot(
        _ snapshot: ProtectedOrdinarySettingsSnapshot
    ) throws {
        guard ProtectedOrdinarySettingsSnapshot.validGracePeriodValues.contains(snapshot.gracePeriod) else {
            throw ProtectedDataError.invalidEnvelope(
                "Protected settings ordinary settings contain an invalid grace period."
            )
        }
        guard snapshot.guidedTutorialCompletedVersion >= 0 else {
            throw ProtectedDataError.invalidEnvelope(
                "Protected settings ordinary settings contain an invalid guided tutorial version."
            )
        }
    }

    private func pendingDomainState(
        for registry: ProtectedDataRegistry
    ) -> ProtectedSettingsDomainState? {
        guard let pendingMutation = registry.pendingMutation else {
            return nil
        }

        switch pendingMutation {
        case .createDomain:
            // Accepted limitation: first-domain pending create remains reset-only
            // because ordinary shared-right authorization is valid only in `ready`.
            if pendingMutation.targetDomainID == Self.domainID,
               registry.committedMembership.isEmpty,
               registry.sharedResourceLifecycleState == .absent {
                return .pendingResetRequired
            }
            return .pendingRetryRequired
        case .deleteDomain:
            return .pendingRetryRequired
        }
    }

    private func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }

        guard status == errSecSuccess else {
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.randomFailure",
                    defaultValue: "A secure random-number operation failed while preparing protected app data."
                )
            )
        }

        return data
    }
}

extension ProtectedSettingsStore: ProtectedDomainRecoveryHandler {
    var protectedDataDomainID: ProtectedDataDomainID {
        Self.domainID
    }
}
