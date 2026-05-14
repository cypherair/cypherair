import Foundation
import LocalAuthentication

enum ContactsDomainStoreState: Equatable {
    case locked
    case loaded
    case recoveryNeeded
}

final class ContactsDomainStore: ProtectedDataRelockParticipant, @unchecked Sendable {
    static let domainID: ProtectedDataDomainID = "contacts"

    private struct OpenedSnapshot {
        let snapshot: ContactsDomainSnapshot
        let generationIdentifier: Int
        let sourceSchemaVersion: Int
    }

    private let storageRoot: ProtectedDataStorageRoot
    private let registryStore: ProtectedDataRegistryStore
    private let domainKeyManager: ProtectedDomainKeyManager
    private let bootstrapStore: ProtectedDomainBootstrapStore
    private let currentWrappingRootKey: (() throws -> Data)?
    private let initialSnapshotProvider: () throws -> ContactsDomainSnapshot

    private(set) var snapshot: ContactsDomainSnapshot?
    private(set) var domainState: ContactsDomainStoreState = .locked

    private var unlockedGenerationIdentifier: Int?

    init(
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        bootstrapStore: ProtectedDomainBootstrapStore? = nil,
        currentWrappingRootKey: (() throws -> Data)? = nil,
        initialSnapshotProvider: @escaping () throws -> ContactsDomainSnapshot = {
            ContactsDomainSnapshot.empty()
        }
    ) {
        self.storageRoot = storageRoot
        self.registryStore = registryStore
        self.domainKeyManager = domainKeyManager
        self.bootstrapStore = bootstrapStore ?? ProtectedDomainBootstrapStore(storageRoot: storageRoot)
        self.currentWrappingRootKey = currentWrappingRootKey
        self.initialSnapshotProvider = initialSnapshotProvider
    }

    func ensureCommittedIfNeeded(
        wrappingRootKey: Data,
        initialSnapshotProvider: () throws -> ContactsDomainSnapshot
    ) async throws {
        let registry = try registryStore.loadRegistry()
        if registry.committedMembership[Self.domainID] != nil {
            return
        }
        guard registry.classifyRecoveryDisposition() == .resumeSteadyState else {
            domainState = .recoveryNeeded
            throw ProtectedDataError.invalidRegistry(
                "Contacts cannot be created while ProtectedData requires recovery."
            )
        }
        guard registry.sharedResourceLifecycleState == .ready,
              !registry.committedMembership.isEmpty,
              registry.pendingMutation == nil else {
            return
        }

        let initialSnapshot = try initialSnapshotProvider()
        try initialSnapshot.validateContract()
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
                        "Contacts can only join an existing ready shared resource."
                    )
                }
            },
            provisionSharedResourceIfNeeded: {},
            stageArtifacts: { [self] in
                try stageInitialSnapshot(
                    initialSnapshot,
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

        clearUnlockedState()
        domainState = .locked
    }

    func hasCommittedDomain() throws -> Bool {
        try registryStore.loadRegistry().committedMembership[Self.domainID] != nil
    }

    @discardableResult
    func openDomainIfNeeded(
        wrappingRootKey: Data
    ) async throws -> ContactsDomainSnapshot {
        if let snapshot, domainState == .loaded {
            return snapshot
        }

        let registry = try registryStore.loadRegistry()
        guard registry.pendingMutation == nil,
              registry.sharedResourceLifecycleState == .ready else {
            domainState = .recoveryNeeded
            throw ProtectedDataError.invalidRegistry(
                "Contacts domain has pending recovery work."
            )
        }
        guard registry.committedMembership[Self.domainID] != nil else {
            domainState = .locked
            throw ProtectedDataError.invalidRegistry(
                "Contacts domain is not committed yet."
            )
        }

        do {
            var (openedSnapshot, unwrappedDomainMasterKey) = try readAuthoritativeSnapshot(
                wrappingRootKey: wrappingRootKey
            )
            defer {
                unwrappedDomainMasterKey.protectedDataZeroize()
            }
            if openedSnapshot.sourceSchemaVersion < ContactsDomainSnapshot.currentSchemaVersion {
                let migratedGenerationIdentifier = openedSnapshot.generationIdentifier + 1
                try writeSnapshotGeneration(
                    openedSnapshot.snapshot,
                    generationIdentifier: migratedGenerationIdentifier,
                    domainMasterKey: unwrappedDomainMasterKey
                )
                unwrappedDomainMasterKey.protectedDataZeroize()
                (openedSnapshot, unwrappedDomainMasterKey) = try readAuthoritativeSnapshot(
                    wrappingRootKey: wrappingRootKey
                )
            }
            let cachedDomainMasterKey = Data(unwrappedDomainMasterKey)
            domainKeyManager.cacheUnlockedDomainMasterKey(cachedDomainMasterKey, for: Self.domainID)
            snapshot = openedSnapshot.snapshot
            unlockedGenerationIdentifier = openedSnapshot.generationIdentifier
            domainState = .loaded

            if registry.committedMembership[Self.domainID] == .recoveryNeeded {
                _ = try await registryStore.updateCommittedDomainState(
                    domainID: Self.domainID,
                    to: .active
                )
            }

            return openedSnapshot.snapshot
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

    func replaceSnapshot(_ updatedSnapshot: ContactsDomainSnapshot) throws {
        guard domainState == .loaded else {
            if domainState == .recoveryNeeded {
                throw ProtectedDataError.invalidRegistry(
                    "Contacts require recovery before they can be updated."
                )
            }
            throw ProtectedDataError.authorizingUnavailable
        }
        try updatedSnapshot.validateContract()

        var domainMasterKey = try activeDomainMasterKey()
        defer {
            domainMasterKey.protectedDataZeroize()
        }

        let nextGenerationIdentifier = max(unlockedGenerationIdentifier ?? 0, 0) + 1
        try writeSnapshotGeneration(
            updatedSnapshot,
            generationIdentifier: nextGenerationIdentifier,
            domainMasterKey: domainMasterKey
        )
        snapshot = updatedSnapshot
        unlockedGenerationIdentifier = nextGenerationIdentifier
        domainState = .loaded
    }

    func relockProtectedData() async throws {
        clearUnlockedState()
        if domainState == .loaded {
            domainState = .locked
        }
    }

    private func stageInitialSnapshot(
        _ snapshot: ContactsDomainSnapshot,
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
        try writeSnapshotGeneration(
            snapshot,
            generationIdentifier: 1,
            domainMasterKey: domainMasterKey
        )
    }

    private func writeSnapshotGeneration(
        _ snapshot: ContactsDomainSnapshot,
        generationIdentifier: Int,
        domainMasterKey: Data
    ) throws {
        try storageRoot.ensureDomainDirectoryExists(for: Self.domainID)

        var plaintext = try ContactsDomainSnapshotCodec.encodeSnapshot(snapshot)
        defer {
            plaintext.protectedDataZeroize()
        }

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let envelope = try ProtectedDomainEnvelopeCodec.seal(
            plaintext: plaintext,
            domainID: Self.domainID,
            schemaVersion: ContactsDomainSnapshot.currentSchemaVersion,
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
        defer {
            validatedPlaintext.protectedDataZeroize()
        }
        _ = try ContactsDomainSnapshotCodec.decodeSnapshot(validatedPlaintext)

        let currentURL = storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .current)
        let previousURL = storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .previous)
        if try storageRoot.managedItemExists(at: currentURL) {
            try storageRoot.promoteStagedFile(from: currentURL, to: previousURL)
        }
        try storageRoot.promoteStagedFile(from: pendingURL, to: currentURL)

        try bootstrapStore.saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: ContactsDomainSnapshot.currentSchemaVersion,
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

        let expectedCurrentGenerationIdentifier = try expectedCurrentGenerationIdentifier()
        var domainMasterKey = try domainKeyManager.unwrapDomainMasterKey(
            from: wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )
        do {
            var candidates: [OpenedSnapshot] = []
            var highestObservedGenerationIdentifier: Int?

            for slot in ProtectedDomainGenerationSlot.allCases {
                let url = storageRoot.domainEnvelopeURL(for: Self.domainID, slot: slot)
                guard try storageRoot.managedItemExists(at: url) else {
                    continue
                }

                do {
                    let data = try storageRoot.readManagedData(at: url)
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
                    let decodedSnapshot = try ContactsDomainSnapshotCodec.decodeSnapshot(plaintext)
                    candidates.append(
                        OpenedSnapshot(
                            snapshot: decodedSnapshot.snapshot,
                            generationIdentifier: envelope.generationIdentifier,
                            sourceSchemaVersion: decodedSnapshot.sourceSchemaVersion
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
                    "Contacts domain does not contain a readable authoritative generation."
                )
            }
            if selectedSnapshot.generationIdentifier < expectedCurrentGenerationIdentifier {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts expected current generation is not readable."
                )
            }
            if let highestObservedGenerationIdentifier,
               selectedSnapshot.generationIdentifier < highestObservedGenerationIdentifier {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts highest observed generation is not readable."
                )
            }

            return (selectedSnapshot, domainMasterKey)
        } catch {
            domainMasterKey.protectedDataZeroize()
            throw error
        }
    }

    private func expectedCurrentGenerationIdentifier() throws -> Int {
        guard let metadata = try bootstrapStore.loadMetadata(for: Self.domainID),
              let value = metadata.expectedCurrentGenerationIdentifier,
              let generationIdentifier = Int(value),
              generationIdentifier > 0 else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts bootstrap metadata is missing expected current generation."
            )
        }
        return generationIdentifier
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
        snapshot = nil
        unlockedGenerationIdentifier = nil
    }
}

extension ContactsDomainStore: ProtectedDomainRecoveryHandler {
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
        let stagedSnapshot: ContactsDomainSnapshot?
        switch phase {
        case .journaled, .sharedResourceProvisioned:
            stagedSnapshot = try initialSnapshotProvider()
            try stagedSnapshot?.validateContract()
        case .artifactsStaged, .validated:
            stagedSnapshot = nil
        case .membershipCommitted:
            return
        }
        let wrappingRootKey = SensitiveBytesBox(data: try currentWrappingRootKey())
        defer {
            wrappingRootKey.zeroize()
        }

        _ = try await registryStore.completePendingCreate(
            domainID: Self.domainID,
            stageArtifacts: { [self] in
                guard let stagedSnapshot else {
                    return
                }
                try stageInitialSnapshot(
                    stagedSnapshot,
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
