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
        let domainMasterKey: Data
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
            if registry.pendingMutation?.targetDomainID == Self.domainID {
                domainState = .pendingMutationRecoveryRequired
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

        let provisionedSecret = try randomData(count: WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength)
        var provisioningSecretCopy = provisionedSecret
        let wrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &provisioningSecretCopy)
        defer {
            var secret = provisionedSecret
            secret.protectedDataZeroize()
            var mutableWrappingRootKey = wrappingRootKey
            mutableWrappingRootKey.protectedDataZeroize()
        }

        _ = try await registryStore.performCreateDomainTransaction(
            domainID: Self.domainID,
            provisionSharedResourceIfNeeded: {
                try await persistSharedRight(provisionedSecret)
            },
            stageArtifacts: { [self] in
                try stageInitialPayload(initialPayload, wrappingRootKey: wrappingRootKey)
            },
            validateArtifacts: { [self] in
                _ = try readAuthoritativeSnapshot(wrappingRootKey: wrappingRootKey)
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
        if registry.pendingMutation?.targetDomainID == Self.domainID {
            domainState = .pendingMutationRecoveryRequired
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
            let openedSnapshot = try readAuthoritativeSnapshot(wrappingRootKey: wrappingRootKey)
            let cachedDomainMasterKey = Data(openedSnapshot.domainMasterKey)
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
        if let registry = try? registryStore.loadRegistry(),
           registry.committedMembership[Self.domainID] != nil {
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
    ) throws -> OpenedSnapshot {
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
                        generationIdentifier: envelope.generationIdentifier,
                        domainMasterKey: Data(domainMasterKey)
                    )
                )
            } catch {
                continue
            }
        }

        domainMasterKey.protectedDataZeroize()

        guard let selectedSnapshot = candidates.max(by: {
            $0.generationIdentifier < $1.generationIdentifier
        }) else {
            throw ProtectedDataError.invalidEnvelope(
                "Protected settings does not contain a readable authoritative generation."
            )
        }

        return selectedSnapshot
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

    private func clearUnlockedState() {
        payload = nil
        unlockedGenerationIdentifier = nil
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
