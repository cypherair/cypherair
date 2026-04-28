import Foundation
import LocalAuthentication
import Security

final class KeyMetadataDomainStore: KeyMetadataPersistence, ProtectedDataRelockParticipant, @unchecked Sendable {
    struct Payload: Codable, Equatable {
        static let currentSchemaVersion = 1

        var schemaVersion: Int
        var identities: [PGPKeyIdentity]

        static func initial(identities: [PGPKeyIdentity]) -> Payload {
            Payload(
                schemaVersion: currentSchemaVersion,
                identities: identities.sorted { $0.fingerprint < $1.fingerprint }
            )
        }

        func validateContract() throws {
            guard schemaVersion == Self.currentSchemaVersion else {
                throw ProtectedDataError.invalidEnvelope(
                    "Key metadata payload has an unsupported schema version."
                )
            }
            let fingerprints = identities.map(\.fingerprint)
            guard Set(fingerprints).count == fingerprints.count else {
                throw ProtectedDataError.invalidEnvelope(
                    "Key metadata payload contains duplicate fingerprints."
                )
            }
        }
    }

    static let domainID: ProtectedDataDomainID = "key-metadata"

    private struct OpenedSnapshot {
        let payload: Payload
        let generationIdentifier: Int
    }

    private let legacyMetadataStore: KeyMetadataStore
    private let storageRoot: ProtectedDataStorageRoot
    private let registryStore: ProtectedDataRegistryStore
    private let domainKeyManager: ProtectedDomainKeyManager
    private let bootstrapStore: ProtectedDomainBootstrapStore
    private let currentWrappingRootKey: (() throws -> Data)?

    private(set) var payload: Payload?
    private(set) var domainState: KeyMetadataLoadState = .locked
    private(set) var migrationWarning: String?

    private var unlockedGenerationIdentifier: Int?

    init(
        legacyMetadataStore: KeyMetadataStore,
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        bootstrapStore: ProtectedDomainBootstrapStore? = nil,
        currentWrappingRootKey: (() throws -> Data)? = nil
    ) {
        self.legacyMetadataStore = legacyMetadataStore
        self.storageRoot = storageRoot
        self.registryStore = registryStore
        self.domainKeyManager = domainKeyManager
        self.bootstrapStore = bootstrapStore ?? ProtectedDomainBootstrapStore(storageRoot: storageRoot)
        self.currentWrappingRootKey = currentWrappingRootKey
    }

    func ensureCommittedIfNeeded(
        wrappingRootKey: Data,
        authenticationContext: LAContext?
    ) async throws {
        let registry = try registryStore.loadRegistry()
        if registry.committedMembership[Self.domainID] != nil {
            return
        }
        guard registry.classifyRecoveryDisposition() == .resumeSteadyState else {
            domainState = .recoveryNeeded
            throw ProtectedDataError.invalidRegistry(
                "Key metadata cannot be created while ProtectedData requires recovery."
            )
        }
        guard registry.sharedResourceLifecycleState == .ready,
              !registry.committedMembership.isEmpty,
              registry.pendingMutation == nil else {
            return
        }

        let sourceSnapshot = try legacyMetadataStore.loadMigrationSourceSnapshot(
            authenticationContext: authenticationContext
        )
        let initialPayload = Payload.initial(
            identities: Self.mergedIdentities(from: sourceSnapshot.items)
        )
        let wrappingRootKeyBox = SensitiveBytesBox(data: wrappingRootKey)
        defer {
            wrappingRootKeyBox.zeroize()
        }

        _ = try await registryStore.performCreateDomainTransaction(
            domainID: Self.domainID,
            validateBeforeJournal: { registry in
                guard registry.sharedResourceLifecycleState == .ready,
                      registry.committedMembership.contains(where: { $0.key != Self.domainID }) else {
                    throw ProtectedDataError.invalidRegistry(
                        "Key metadata can only join an existing ready shared resource."
                    )
                }
            },
            provisionSharedResourceIfNeeded: {},
            stageArtifacts: { [self] in
                try stageInitialPayload(
                    initialPayload,
                    wrappingRootKey: wrappingRootKeyBox.dataCopy()
                )
            },
            validateArtifacts: { [self] in
                try protectedDataValidateSnapshotAndZeroizeDomainMasterKey {
                    try readAuthoritativeSnapshot(
                        wrappingRootKey: wrappingRootKeyBox.dataCopy()
                    )
                }
            }
        )

        let cleanupOutcome = legacyMetadataStore.cleanupMigrationSourceItems(
            sourceSnapshot.items.filter { item in
                initialPayload.identities.contains { $0.fingerprint == item.identity.fingerprint }
            },
            authenticationContext: authenticationContext
        )
        updateMigrationWarning(
            failedLoadCount: sourceSnapshot.failedItemCount,
            failedDeleteCount: cleanupOutcome.failedItemCount
        )
        clearUnlockedState()
        domainState = .locked
    }

    @discardableResult
    func openDomainIfNeeded(
        wrappingRootKey: Data,
        authenticationContext: LAContext?
    ) async throws -> Payload {
        if let payload, domainState == .loaded {
            return payload
        }

        let registry = try registryStore.loadRegistry()
        guard registry.pendingMutation == nil,
              registry.sharedResourceLifecycleState == .ready else {
            domainState = .recoveryNeeded
            throw ProtectedDataError.invalidRegistry(
                "Key metadata domain has pending recovery work."
            )
        }
        guard registry.committedMembership[Self.domainID] != nil else {
            domainState = .locked
            throw ProtectedDataError.invalidRegistry(
                "Key metadata domain is not committed yet."
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
            domainState = .loaded

            if registry.committedMembership[Self.domainID] == .recoveryNeeded {
                _ = try await registryStore.updateCommittedDomainState(
                    domainID: Self.domainID,
                    to: .active
                )
            }

            cleanupLegacyRowsMatchingOpenedPayload(authenticationContext: authenticationContext)
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

    func loadAll() throws -> [PGPKeyIdentity] {
        guard let payload, domainState == .loaded else {
            if domainState == .recoveryNeeded {
                throw ProtectedDataError.invalidRegistry(
                    "Key metadata requires recovery before it can be loaded."
                )
            }
            throw ProtectedDataError.authorizingUnavailable
        }
        return payload.identities
    }

    func save(_ identity: PGPKeyIdentity) throws {
        try updatePayload { payload in
            guard !payload.identities.contains(where: { $0.fingerprint == identity.fingerprint }) else {
                throw ProtectedDataError.invalidEnvelope(
                    "Key metadata already contains this fingerprint."
                )
            }
            payload.identities.append(identity)
            payload.identities.sort { $0.fingerprint < $1.fingerprint }
        }
    }

    func update(_ identity: PGPKeyIdentity) throws {
        try updatePayload { payload in
            if let index = payload.identities.firstIndex(where: { $0.fingerprint == identity.fingerprint }) {
                payload.identities[index] = identity
            } else {
                payload.identities.append(identity)
            }
            payload.identities.sort { $0.fingerprint < $1.fingerprint }
        }
    }

    func delete(fingerprint: String) throws {
        try updatePayload { payload in
            payload.identities.removeAll { $0.fingerprint == fingerprint }
        }
    }

    func relockProtectedData() async throws {
        clearUnlockedState()
        if domainState == .loaded {
            domainState = .locked
        }
    }

    private func updatePayload(_ mutate: (inout Payload) throws -> Void) throws {
        guard var updatedPayload = payload,
              domainState == .loaded else {
            if domainState == .recoveryNeeded {
                throw ProtectedDataError.invalidRegistry(
                    "Key metadata requires recovery before it can be updated."
                )
            }
            throw ProtectedDataError.authorizingUnavailable
        }

        try mutate(&updatedPayload)
        try updatedPayload.validateContract()
        try persistUpdatedPayload(updatedPayload)
    }

    private func persistUpdatedPayload(_ updatedPayload: Payload) throws {
        var domainMasterKey = try activeDomainMasterKey()
        defer {
            domainMasterKey.protectedDataZeroize()
        }

        let nextGenerationIdentifier = max(unlockedGenerationIdentifier ?? 0, 0) + 1
        try writePayloadGeneration(
            updatedPayload,
            generationIdentifier: nextGenerationIdentifier,
            domainMasterKey: domainMasterKey
        )
        payload = updatedPayload
        unlockedGenerationIdentifier = nextGenerationIdentifier
        domainState = .loaded
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
        try PropertyListDecoder().decode(Payload.self, from: validatedPlaintext).validateContract()
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
                try payload.validateContract()
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
                "Key metadata does not contain a readable authoritative generation."
            )
        }

        return (selectedSnapshot, domainMasterKey)
    }

    private func activeDomainMasterKey() throws -> Data {
        if let cachedKey = domainKeyManager.unlockedDomainMasterKey(for: Self.domainID) {
            return Data(cachedKey)
        }

        guard let currentWrappingRootKey else {
            throw ProtectedDataError.authorizingUnavailable
        }
        let wrappingRootKey = SensitiveBytesBox(data: try currentWrappingRootKey())
        defer {
            wrappingRootKey.zeroize()
        }
        guard let wrappedRecord = try domainKeyManager.loadWrappedDomainMasterKeyRecord(
            for: Self.domainID
        ) else {
            throw ProtectedDataError.missingWrappedDomainMasterKey(Self.domainID)
        }

        return try domainKeyManager.unwrapDomainMasterKey(
            from: wrappedRecord,
            wrappingRootKey: wrappingRootKey.dataCopy()
        )
    }

    private func cleanupLegacyRowsMatchingOpenedPayload(authenticationContext: LAContext?) {
        guard let payload else {
            return
        }
        do {
            let sourceSnapshot = try legacyMetadataStore.loadMigrationSourceSnapshot(
                authenticationContext: authenticationContext
            )
            let migratedFingerprints = Set(payload.identities.map(\.fingerprint))
            let matchingSourceItems = sourceSnapshot.items.filter { item in
                migratedFingerprints.contains(item.identity.fingerprint)
            }
            let cleanupOutcome = legacyMetadataStore.cleanupMigrationSourceItems(
                matchingSourceItems,
                authenticationContext: authenticationContext
            )
            updateMigrationWarning(
                failedLoadCount: sourceSnapshot.failedItemCount,
                failedDeleteCount: cleanupOutcome.failedItemCount
            )
        } catch {
            migrationWarning = Self.migrationWarningMessage()
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

    private func clearUnlockedState() {
        payload = nil
        unlockedGenerationIdentifier = nil
    }

    private func updateMigrationWarning(
        failedLoadCount: Int,
        failedDeleteCount: Int
    ) {
        migrationWarning = failedLoadCount == 0 && failedDeleteCount == 0
            ? nil
            : Self.migrationWarningMessage()
    }

    static func migrationWarningMessage() -> String {
        String(
            localized: "app.loadWarning.keyMetadataMigration",
            defaultValue: "Some saved key metadata could not be migrated or cleaned up. Your private keys remain protected; restart CypherAir and unlock again to retry."
        )
    }

    private static func mergedIdentities(
        from sourceItems: [KeyMetadataMigrationSourceItem]
    ) -> [PGPKeyIdentity] {
        var byFingerprint: [String: PGPKeyIdentity] = [:]
        for item in sourceItems {
            byFingerprint[item.identity.fingerprint] = item.identity
        }
        return byFingerprint.values.sorted { $0.fingerprint < $1.fingerprint }
    }
}

extension KeyMetadataDomainStore: ProtectedDomainRecoveryHandler {
    var protectedDataDomainID: ProtectedDataDomainID {
        Self.domainID
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
        let sourceSnapshot = try legacyMetadataStore.loadMigrationSourceSnapshot(
            authenticationContext: authenticationContext
        )
        guard authenticationContext != nil || sourceSnapshot.failedItemCount == 0 else {
            throw ProtectedDataError.authorizingUnavailable
        }
        let initialPayload = Payload.initial(
            identities: Self.mergedIdentities(from: sourceSnapshot.items)
        )
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

    func deleteDomainArtifactsForRecovery() throws {
        try deleteDomainArtifacts()
    }
}
