import Foundation
import LocalAuthentication

enum ContactsDomainStoreState: Equatable {
    case locked
    case loaded
    case recoveryNeeded
}

final class ContactsDomainStore: ProtectedDataRelockParticipant, @unchecked Sendable {
    static let domainID: ProtectedDataDomainID = "contacts"

    private let storageRoot: ProtectedDataStorageRoot
    private let registryStore: ProtectedDataRegistryStore
    private let domainKeyManager: ProtectedDomainKeyManager
    private let bootstrapStore: ProtectedDomainBootstrapStore
    private let currentWrappingRootKey: (() throws -> Data)?
    private let initialSnapshotProvider: () throws -> ContactsDomainSnapshot
    private let databaseFactory: (ProtectedDataStorageRoot, ProtectedDataDomainID) -> ContactsSQLCipherDatabase

    private(set) var snapshot: ContactsDomainSnapshot?
    private(set) var domainState: ContactsDomainStoreState = .locked

    private var database: ContactsSQLCipherDatabase?

    init(
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        bootstrapStore: ProtectedDomainBootstrapStore? = nil,
        currentWrappingRootKey: (() throws -> Data)? = nil,
        initialSnapshotProvider: @escaping () throws -> ContactsDomainSnapshot = {
            ContactsDomainSnapshot.empty()
        },
        databaseFactory: @escaping (
            ProtectedDataStorageRoot,
            ProtectedDataDomainID
        ) -> ContactsSQLCipherDatabase = { storageRoot, domainID in
            ContactsSQLCipherDatabase(storageRoot: storageRoot, domainID: domainID)
        }
    ) {
        self.storageRoot = storageRoot
        self.registryStore = registryStore
        self.domainKeyManager = domainKeyManager
        self.bootstrapStore = bootstrapStore ?? ProtectedDomainBootstrapStore(storageRoot: storageRoot)
        self.currentWrappingRootKey = currentWrappingRootKey
        self.initialSnapshotProvider = initialSnapshotProvider
        self.databaseFactory = databaseFactory
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
        try validateSnapshotForProtectedData(initialSnapshot)
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
                try validateAuthoritativeSnapshot(
                    wrappingRootKey: wrappingRootKeyBox.dataCopy()
                )
            }
        )

        clearUnlockedState()
        domainState = .locked
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
            let opened = try openAuthoritativeDatabase(
                wrappingRootKey: wrappingRootKey,
                keepDatabaseOpen: true
            )
            snapshot = opened.snapshot
            database = opened.database
            domainState = .loaded

            if registry.committedMembership[Self.domainID] == .recoveryNeeded {
                _ = try await registryStore.updateCommittedDomainState(
                    domainID: Self.domainID,
                    to: .active
                )
            }

            return opened.snapshot
        } catch {
            try? closeDatabase()
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
        guard let database else {
            throw ProtectedDataError.authorizingUnavailable
        }

        try validateSnapshotForProtectedData(updatedSnapshot)
        try database.replaceSnapshot(updatedSnapshot)
        snapshot = updatedSnapshot
        domainState = .loaded
    }

    func relockProtectedData() async throws {
        let wasLoaded = domainState == .loaded
        snapshot = nil
        do {
            try closeDatabase()
        } catch {
            if wasLoaded {
                domainState = .locked
            }
            throw error
        }
        if wasLoaded {
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

        let stagedDatabase = databaseFactory(storageRoot, Self.domainID)
        do {
            try stagedDatabase.createFresh(
                snapshot: snapshot,
                domainMasterKey: domainMasterKey
            )
            try stagedDatabase.close()
        } catch {
            try? stagedDatabase.close()
            throw error
        }

        try saveBootstrapMetadata()
    }

    private func openAuthoritativeDatabase(
        wrappingRootKey: Data,
        keepDatabaseOpen: Bool
    ) throws -> (snapshot: ContactsDomainSnapshot, database: ContactsSQLCipherDatabase?) {
        try validateBootstrapMetadata()

        guard let wrappedRecord = try domainKeyManager.loadWrappedDomainMasterKeyRecord(
            for: Self.domainID
        ) else {
            throw ProtectedDataError.missingWrappedDomainMasterKey(Self.domainID)
        }

        var domainMasterKey = try domainKeyManager.unwrapDomainMasterKey(
            from: wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )
        defer {
            domainMasterKey.protectedDataZeroize()
        }

        let openedDatabase = databaseFactory(storageRoot, Self.domainID)
        do {
            let openedSnapshot = try openedDatabase.openExisting(domainMasterKey: domainMasterKey)
            if keepDatabaseOpen {
                return (openedSnapshot, openedDatabase)
            }
            try openedDatabase.close()
            return (openedSnapshot, nil)
        } catch {
            try? openedDatabase.close()
            throw error
        }
    }

    private func validateAuthoritativeSnapshot(wrappingRootKey: Data) throws {
        _ = try openAuthoritativeDatabase(
            wrappingRootKey: wrappingRootKey,
            keepDatabaseOpen: false
        )
    }

    private func saveBootstrapMetadata() throws {
        try bootstrapStore.saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: ContactsDomainSnapshot.currentSchemaVersion,
                expectedCurrentGenerationIdentifier: nil
            ),
            for: Self.domainID
        )
    }

    private func validateBootstrapMetadata() throws {
        guard let metadata = try bootstrapStore.loadMetadata(for: Self.domainID) else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts bootstrap metadata is missing."
            )
        }
        guard metadata.schemaVersion == ContactsDomainSnapshot.currentSchemaVersion else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts bootstrap metadata schema is unsupported."
            )
        }
    }

    private func deleteDomainArtifacts() throws {
        try closeDatabase()
        clearUnlockedState()
        try storageRoot.removeContactsSQLCipherDatabaseFilesIfPresent(for: Self.domainID)
        try domainKeyManager.deleteWrappedDomainMasterKeyRecords(for: Self.domainID)
        try bootstrapStore.removeMetadata(for: Self.domainID)
        try storageRoot.removeDomainDirectoryIfPresent(for: Self.domainID)
    }

    private func closeDatabase() throws {
        guard let database else {
            return
        }
        try database.close()
        self.database = nil
    }

    private func clearUnlockedState() {
        snapshot = nil
        database = nil
    }

    private func validateSnapshotForProtectedData(_ snapshot: ContactsDomainSnapshot) throws {
        do {
            try snapshot.validateContract()
        } catch let error as ContactsDomainValidationError {
            throw ProtectedDataError.invalidEnvelope(error.reason)
        }
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
            if let stagedSnapshot {
                try validateSnapshotForProtectedData(stagedSnapshot)
            }
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
                try validateAuthoritativeSnapshot(
                    wrappingRootKey: wrappingRootKey.dataCopy()
                )
            }
        )
    }

    func deleteDomainArtifactsForRecovery() throws {
        try deleteDomainArtifacts()
    }
}
