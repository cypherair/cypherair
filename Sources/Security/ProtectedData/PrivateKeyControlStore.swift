import Foundation
import LocalAuthentication
import Security

@Observable
final class PrivateKeyControlStore: ProtectedDataRelockParticipant, PrivateKeyControlStoreProtocol, @unchecked Sendable {
    struct Payload: Codable, Equatable, Sendable {
        struct Settings: Codable, Equatable, Sendable {
            var authMode: AuthenticationMode
        }

        static let currentSchemaVersion = 1

        var settings: Settings
        var recoveryJournal: PrivateKeyControlRecoveryJournal

        static func initial(authMode: AuthenticationMode) -> Payload {
            Payload(
                settings: Settings(authMode: authMode),
                recoveryJournal: .empty
            )
        }
    }

    static let domainID: ProtectedDataDomainID = "private-key-control"

    private struct OpenedSnapshot {
        let payload: Payload
        let generationIdentifier: Int
    }

    private let storageRoot: ProtectedDataStorageRoot
    private let registryStore: ProtectedDataRegistryStore
    private let domainKeyManager: ProtectedDomainKeyManager
    private let bootstrapStore: ProtectedDomainBootstrapStore
    private let currentWrappingRootKey: (() throws -> Data)?

    private(set) var privateKeyControlState: PrivateKeyControlState = .locked
    private(set) var payload: Payload?

    @ObservationIgnored
    private var unlockedGenerationIdentifier: Int?
    @ObservationIgnored
    private var memoryOnlySeededForTesting = false

    init(
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        bootstrapStore: ProtectedDomainBootstrapStore? = nil,
        currentWrappingRootKey: (() throws -> Data)? = nil
    ) {
        self.storageRoot = storageRoot
        self.registryStore = registryStore
        self.domainKeyManager = domainKeyManager
        self.bootstrapStore = bootstrapStore ?? ProtectedDomainBootstrapStore(storageRoot: storageRoot)
        self.currentWrappingRootKey = currentWrappingRootKey
    }

    func bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
        authenticationContext: LAContext?,
        persistSharedRight: @escaping @Sendable (Data) async throws -> Void,
        firstDomainSharedRightCleaner: ProtectedDataFirstDomainSharedRightCleaner? = nil
    ) async throws -> Bool {
        let registry = try registryStore.loadRegistry()
        if registry.committedMembership[Self.domainID] != nil {
            return false
        }

        switch registry.classifyRecoveryDisposition() {
        case .resumeSteadyState:
            break
        case .continuePendingMutation, .frameworkRecoveryNeeded:
            privateKeyControlState = .recoveryNeeded
            throw PrivateKeyControlError.recoveryNeeded
        }

        guard registry.committedMembership.isEmpty,
              registry.sharedResourceLifecycleState == .absent else {
            return false
        }
        guard authenticationContext != nil else {
            privateKeyControlState = .locked
            return false
        }
        let initialPayload = Payload.initial(authMode: .standard)
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
            cleanupJournaledFirstDomainSharedRightIfNeeded: { [self] in
                guard let firstDomainSharedRightCleaner else {
                    return
                }
                do {
                    let cleanupOutcome = try await firstDomainSharedRightCleaner
                        .cleanupJournaledFirstDomainSharedRightIfSafe(
                            expectedDomainID: Self.domainID,
                            source: Self.domainID.rawValue,
                            loadCurrentRegistry: { try registryStore.loadRegistry() }
                        )
                    if cleanupOutcome == .blockedByArtifacts {
                        privateKeyControlState = .recoveryNeeded
                        throw PrivateKeyControlError.recoveryNeeded
                    }
                } catch {
                    privateKeyControlState = .recoveryNeeded
                    throw error
                }
            },
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

        clearUnlockedState()
        privateKeyControlState = .locked
        return true
    }

    func ensureCommittedIfNeeded(wrappingRootKey: Data) async throws {
        let registry = try registryStore.loadRegistry()
        if registry.committedMembership[Self.domainID] != nil {
            return
        }
        guard !registry.committedMembership.isEmpty else {
            return
        }
        guard registry.sharedResourceLifecycleState == .ready,
              registry.pendingMutation == nil else {
            privateKeyControlState = .recoveryNeeded
            throw PrivateKeyControlError.recoveryNeeded
        }

        let initialPayload = Payload.initial(authMode: .standard)
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
                        "Private key control can only join an existing ready shared resource."
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

        clearUnlockedState()
        privateKeyControlState = .locked
    }

    func openDomainIfNeeded(wrappingRootKey: Data) async throws -> Payload {
        if let payload, case .unlocked = privateKeyControlState {
            return payload
        }

        let registry = try registryStore.loadRegistry()
        guard registry.pendingMutation == nil,
              registry.sharedResourceLifecycleState == .ready else {
            privateKeyControlState = .recoveryNeeded
            throw PrivateKeyControlError.recoveryNeeded
        }
        guard registry.committedMembership[Self.domainID] != nil else {
            privateKeyControlState = .locked
            throw PrivateKeyControlError.locked
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
            privateKeyControlState = .unlocked(openedSnapshot.payload.settings.authMode)

            if registry.committedMembership[Self.domainID] == .recoveryNeeded {
                _ = try await registryStore.updateCommittedDomainState(
                    domainID: Self.domainID,
                    to: .active
                )
            }

            return openedSnapshot.payload
        } catch {
            clearUnlockedState()
            privateKeyControlState = .recoveryNeeded
            if registry.committedMembership[Self.domainID] != .recoveryNeeded {
                _ = try? await registryStore.updateCommittedDomainState(
                    domainID: Self.domainID,
                    to: .recoveryNeeded
                )
            }
            throw error
        }
    }

    func requireUnlockedAuthMode() throws -> AuthenticationMode {
        guard case .unlocked(let mode) = privateKeyControlState,
              let payload,
              payload.settings.authMode == mode else {
            if privateKeyControlState == .recoveryNeeded {
                throw PrivateKeyControlError.recoveryNeeded
            }
            throw PrivateKeyControlError.locked
        }
        if payload.recoveryJournal.rewrapPhase == .commitRequired,
           let targetMode = payload.recoveryJournal.rewrapTargetMode,
           targetMode != mode {
            throw PrivateKeyControlError.recoveryNeeded
        }
        return mode
    }

    func recoveryJournal() throws -> PrivateKeyControlRecoveryJournal {
        guard let payload,
              privateKeyControlState.isUnlocked else {
            if privateKeyControlState == .recoveryNeeded {
                throw PrivateKeyControlError.recoveryNeeded
            }
            throw PrivateKeyControlError.locked
        }
        return payload.recoveryJournal
    }

    func seedUnlockedForTesting(_ mode: AuthenticationMode) {
        payload = .initial(authMode: mode)
        unlockedGenerationIdentifier = 1
        privateKeyControlState = .unlocked(mode)
        memoryOnlySeededForTesting = true
    }

    func beginRewrap(targetMode: AuthenticationMode) throws {
        _ = try requireUnlockedAuthMode()
        try updatePayload { payload in
            payload.recoveryJournal.rewrapTargetMode = targetMode
            payload.recoveryJournal.rewrapPhase = .preparing
        }
    }

    func markRewrapCommitRequired() throws {
        _ = try requireUnlockedAuthMode()
        try updatePayload { payload in
            guard payload.recoveryJournal.rewrapTargetMode != nil else {
                throw PrivateKeyControlError.recoveryNeeded
            }
            payload.recoveryJournal.rewrapPhase = .commitRequired
        }
    }

    func completeRewrap(targetMode: AuthenticationMode) throws {
        guard var updatedPayload = payload,
              privateKeyControlState.isUnlocked else {
            if privateKeyControlState == .recoveryNeeded {
                throw PrivateKeyControlError.recoveryNeeded
            }
            throw PrivateKeyControlError.locked
        }

        let previousPayload = updatedPayload
        updatedPayload.settings.authMode = targetMode
        updatedPayload.recoveryJournal.rewrapTargetMode = nil
        updatedPayload.recoveryJournal.rewrapPhase = nil

        if memoryOnlySeededForTesting {
            payload = updatedPayload
            unlockedGenerationIdentifier = max(unlockedGenerationIdentifier ?? 0, 0) + 1
            privateKeyControlState = .unlocked(targetMode)
            return
        }

        do {
            try persistUpdatedPayload(updatedPayload)
        } catch {
            var inMemoryPayload = previousPayload
            inMemoryPayload.settings.authMode = targetMode
            inMemoryPayload.recoveryJournal.rewrapTargetMode = targetMode
            inMemoryPayload.recoveryJournal.rewrapPhase = .commitRequired
            payload = inMemoryPayload
            privateKeyControlState = .unlocked(targetMode)
            throw error
        }
    }

    func clearRewrapJournal() throws {
        try updatePayload { payload in
            payload.recoveryJournal.rewrapTargetMode = nil
            payload.recoveryJournal.rewrapPhase = nil
        }
    }

    func beginModifyExpiry(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        try updatePayload { payload in
            payload.recoveryJournal.modifyExpiry = ModifyExpiryRecoveryEntry(fingerprint: fingerprint)
        }
    }

    func clearModifyExpiryJournal() throws {
        try updatePayload { payload in
            payload.recoveryJournal.modifyExpiry = nil
        }
    }

    func clearModifyExpiryJournalIfMatches(fingerprint: String) throws {
        try updatePayload { payload in
            guard payload.recoveryJournal.modifyExpiry?.fingerprint == fingerprint else {
                return
            }
            payload.recoveryJournal.modifyExpiry = nil
        }
    }

    func relockProtectedData() async throws {
        clearUnlockedState()
        if privateKeyControlState.isUnlocked {
            privateKeyControlState = .locked
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
        let initialPayload = Payload.initial(authMode: .standard)
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

    private func updatePayload(_ mutate: (inout Payload) throws -> Void) throws {
        guard var updatedPayload = payload,
              privateKeyControlState.isUnlocked else {
            if privateKeyControlState == .recoveryNeeded {
                throw PrivateKeyControlError.recoveryNeeded
            }
            throw PrivateKeyControlError.locked
        }

        try mutate(&updatedPayload)

        if memoryOnlySeededForTesting {
            payload = updatedPayload
            unlockedGenerationIdentifier = max(unlockedGenerationIdentifier ?? 0, 0) + 1
            privateKeyControlState = .unlocked(updatedPayload.settings.authMode)
            return
        }

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
        privateKeyControlState = .unlocked(updatedPayload.settings.authMode)
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
                "Private key control does not contain a readable authoritative generation."
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
        try domainKeyManager.deleteWrappedDomainMasterKeyRecords(for: Self.domainID)
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

extension PrivateKeyControlStore: ProtectedDomainRecoveryHandler {
    var protectedDataDomainID: ProtectedDataDomainID {
        Self.domainID
    }
}
