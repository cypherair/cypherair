import Foundation
import Security

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

    func recoverPendingSettingsMutation(
        settingsStore: ProtectedSettingsStore,
        removeSharedRight: @escaping @Sendable (String) async throws -> Void
    ) async throws -> PendingRecoveryOutcome {
        let registry = try registryStore.loadRegistry()
        guard case let pendingMutation? = registry.pendingMutation,
                pendingMutation.targetDomainID == ProtectedSettingsStore.domainID else {
            return .frameworkRecoveryNeeded
        }

        return try await registryStore.recoverPendingMutation(
            targetDomainID: ProtectedSettingsStore.domainID,
            continueReadyCreate: { phase in
                if phase == .membershipCommitted {
                    return
                }

                // Accepted limitation: first-domain pending create stays reset-only
                // and future ready-row create continuation is intentionally deferred
                // until the framework grows a generic, domain-aware continuation path.
                throw ProtectedDataError.invalidRegistry(
                    "Ready-row pending create continuation is not implemented for ProtectedSettings."
                )
            },
            continueDelete: { _ in
                _ = try await registryStore.completePendingDelete(
                    domainID: ProtectedSettingsStore.domainID,
                    deleteArtifacts: {
                        try settingsStore.deleteDomainArtifactsForRecovery()
                    },
                    cleanupSharedResourceIfNeeded: {
                        try await removeSharedRight(registry.sharedRightIdentifier)
                    }
                )
            }
        )
    }
}

@Observable
final class ProtectedSettingsStore: ProtectedDataRelockParticipant, @unchecked Sendable {
    struct Payload: Codable, Equatable, Sendable {
        static let currentSchemaVersion = 1

        var clipboardNotice: Bool
    }

    static let domainID: ProtectedDataDomainID = "protected-settings"

    private struct OpenedSnapshot {
        let payload: Payload
        let generationIdentifier: Int
    }

    private let defaults: UserDefaults
    private let storageRoot: ProtectedDataStorageRoot
    private let registryStore: ProtectedDataRegistryStore
    private let domainKeyManager: ProtectedDomainKeyManager
    private let bootstrapStore: ProtectedDomainBootstrapStore

    private(set) var domainState: ProtectedSettingsDomainState = .locked
    private(set) var payload: Payload?

    @ObservationIgnored
    private var unlockedGenerationIdentifier: Int?

    init(
        defaults: UserDefaults,
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        bootstrapStore: ProtectedDomainBootstrapStore? = nil
    ) {
        self.defaults = defaults
        self.storageRoot = storageRoot
        self.registryStore = registryStore
        self.domainKeyManager = domainKeyManager
        self.bootstrapStore = bootstrapStore ?? ProtectedDomainBootstrapStore(storageRoot: storageRoot)
    }

    var clipboardNotice: Bool? {
        payload?.clipboardNotice
    }

    var hasCommittedDomain: Bool {
        (try? registryStore.loadRegistry().committedMembership[Self.domainID] != nil) ?? false
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

    func migrateLegacyClipboardNoticeIfNeeded(
        persistSharedRight: @escaping @Sendable (Data) async throws -> Void
    ) async throws {
        let registry = try registryStore.loadRegistry()
        if registry.committedMembership[Self.domainID] != nil {
            return
        }

        let clipboardNotice = defaults.object(forKey: AppConfiguration.clipboardNoticeLegacyKey) == nil
            ? true
            : defaults.bool(forKey: AppConfiguration.clipboardNoticeLegacyKey)
        let initialPayload = Payload(clipboardNotice: clipboardNotice)

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
                _ = try readAuthoritativeSnapshot(
                    wrappingRootKey: wrappingRootKey.dataCopy()
                )
            }
        )

        defaults.removeObject(forKey: AppConfiguration.clipboardNoticeLegacyKey)
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
            let (openedSnapshot, unwrappedDomainMasterKey) = try readAuthoritativeSnapshot(
                wrappingRootKey: wrappingRootKey
            )
            let cachedDomainMasterKey = Data(unwrappedDomainMasterKey)
            domainKeyManager.cacheUnlockedDomainMasterKey(cachedDomainMasterKey, for: Self.domainID)
            var mutableDomainMasterKey = unwrappedDomainMasterKey
            mutableDomainMasterKey.protectedDataZeroize()
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
            throw error
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
        let updatedPayload = Payload(clipboardNotice: isEnabled)
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
        removeSharedRight: @escaping @Sendable (String) async throws -> Void
    ) async throws {
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
        defaults.removeObject(forKey: AppConfiguration.clipboardNoticeLegacyKey)
        try await migrateLegacyClipboardNoticeIfNeeded(
            persistSharedRight: persistSharedRight
        )
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

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        var plaintext = try encoder.encode(payload)
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
        var candidates: [OpenedSnapshot] = []

        for slot in ProtectedDomainGenerationSlot.allCases {
            let url = storageRoot.domainEnvelopeURL(for: Self.domainID, slot: slot)
            guard try storageRoot.managedItemExists(at: url) else {
                continue
            }

            do {
                let data = try storageRoot.readManagedData(at: url)
                let envelope = try PropertyListDecoder().decode(ProtectedDomainEnvelope.self, from: data)
                var plaintext = try ProtectedDomainEnvelopeCodec.open(
                    envelope: envelope,
                    domainMasterKey: domainMasterKey
                )
                defer {
                    plaintext.protectedDataZeroize()
                }
                let payload = try PropertyListDecoder().decode(Payload.self, from: plaintext)
                candidates.append(
                    OpenedSnapshot(
                        payload: payload,
                        generationIdentifier: envelope.generationIdentifier
                    )
                )
            } catch {
                continue
            }
        }

        guard let selectedSnapshot = candidates.max(by: {
            $0.generationIdentifier < $1.generationIdentifier
        }) else {
            domainMasterKey.protectedDataZeroize()
            throw ProtectedDataError.invalidEnvelope(
                "Protected settings does not contain a readable authoritative generation."
            )
        }

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

    private func clearUnlockedState() {
        payload = nil
        unlockedGenerationIdentifier = nil
    }

    private func pendingDomainState(
        for registry: ProtectedDataRegistry
    ) -> ProtectedSettingsDomainState? {
        guard let pendingMutation = registry.pendingMutation,
                pendingMutation.targetDomainID == Self.domainID else {
            return nil
        }

        switch pendingMutation {
        case .createDomain:
            // Accepted limitation: first-domain pending create remains reset-only
            // because ordinary shared-right authorization is valid only in `ready`.
            if registry.committedMembership.isEmpty && registry.sharedResourceLifecycleState == .absent {
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
