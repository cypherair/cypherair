import Foundation
import LocalAuthentication
@testable import CypherAir

/// A neutral protected domain for framework lifecycle tests that need a second
/// domain to join, delete, or recover alongside a real product domain.
///
/// It stores a fixed marker payload and nothing else, but drives the real
/// registry store, domain-key manager, and `CPDENV5` envelope codec — so the
/// framework behavior a test observes is production behavior, not a stub's.
/// Like every real non-first domain it can only join an existing ready shared
/// resource, and that rule is enforced where the framework enforces it: in
/// `validateBeforeJournal`, before the create transaction writes anything.
final class MockPracticeProtectedDomainStore: ProtectedDomainRecoveryHandler, @unchecked Sendable {
    struct Payload: Codable, Equatable, Sendable {
        static let currentSchemaVersion = 1
        static let current = Payload(marker: "CypherAir.Tests.PracticeDomain")

        let marker: String
    }

    static let domainID: ProtectedDataDomainID = "test-practice"

    private let storageRoot: ProtectedDataStorageRoot
    private let registryStore: ProtectedDataRegistryStore
    private let domainKeyManager: ProtectedDomainKeyManager
    private let currentWrappingRootKey: (() throws -> Data)?

    private(set) var payload: Payload?

    init(
        storageRoot: ProtectedDataStorageRoot,
        registryStore: ProtectedDataRegistryStore,
        domainKeyManager: ProtectedDomainKeyManager,
        currentWrappingRootKey: (() throws -> Data)? = nil
    ) {
        self.storageRoot = storageRoot
        self.registryStore = registryStore
        self.domainKeyManager = domainKeyManager
        self.currentWrappingRootKey = currentWrappingRootKey
    }

    func ensureCommittedIfNeeded(wrappingRootKey: Data) async throws {
        let wrappingRootKey = SensitiveBytesBox(data: wrappingRootKey)
        defer {
            wrappingRootKey.zeroize()
        }

        _ = try await registryStore.performCreateDomainTransaction(
            domainID: Self.domainID,
            validateBeforeJournal: { registry in
                guard registry.sharedResourceLifecycleState == .ready,
                      registry.committedMembership.contains(where: { $0.key != Self.domainID }) else {
                    throw ProtectedDataError.invalidRegistry(
                        "The practice domain can only join an existing ready shared resource."
                    )
                }
            },
            provisionSharedResourceIfNeeded: {},
            stageArtifacts: { [self] in
                try stageInitialPayload(wrappingRootKey: wrappingRootKey.dataCopy())
            },
            validateArtifacts: { [self] in
                try withAuthoritativeSnapshot(wrappingRootKey: wrappingRootKey.dataCopy()) { _, _ in }
            }
        )
        payload = nil
    }

    @discardableResult
    func openDomainIfNeeded(wrappingRootKey: Data) async throws -> Payload {
        if let payload {
            return payload
        }

        let openedPayload = try withAuthoritativeSnapshot(
            wrappingRootKey: wrappingRootKey
        ) { snapshotPayload, domainMasterKey in
            // The cache takes its own copy, so the buffer the snapshot owns stays
            // uniquely referenced and its zeroize clears the real bytes.
            domainKeyManager.cacheUnlockedDomainMasterKey(
                Data(domainMasterKey),
                for: Self.domainID
            )
            return snapshotPayload
        }
        payload = openedPayload
        return openedPayload
    }

    func deleteDomainArtifactsForRecovery() throws {
        try domainKeyManager.deleteWrappedDomainMasterKeyRecords(for: Self.domainID)
        try storageRoot.removeDomainDirectoryIfPresent(for: Self.domainID)
        payload = nil
    }

    // MARK: - ProtectedDomainRecoveryHandler

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
        let wrappingRootKey = SensitiveBytesBox(data: try currentWrappingRootKey())
        defer {
            wrappingRootKey.zeroize()
        }

        _ = try await registryStore.completePendingCreate(
            domainID: Self.domainID,
            stageArtifacts: { [self] in
                try stageInitialPayload(wrappingRootKey: wrappingRootKey.dataCopy())
            },
            validateArtifacts: { [self] in
                try withAuthoritativeSnapshot(wrappingRootKey: wrappingRootKey.dataCopy()) { _, _ in }
            }
        )
    }

    // MARK: - Artifacts

    private func stageInitialPayload(wrappingRootKey: Data) throws {
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

        try storageRoot.ensureDomainDirectoryExists(for: Self.domainID)
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        var plaintext = try encoder.encode(Payload.current)
        defer {
            plaintext.protectedDataZeroize()
        }
        let envelope = try ProtectedDomainEnvelopeCodec.seal(
            plaintext: plaintext,
            domainID: Self.domainID,
            schemaVersion: Payload.currentSchemaVersion,
            generationIdentifier: 1,
            domainMasterKey: domainMasterKey
        )
        let envelopeData = try ProtectedDomainEnvelopeCodec.encode(envelope)
        let pendingURL = storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .pending)
        try storageRoot.writeProtectedData(envelopeData, to: pendingURL)
        try storageRoot.promoteStagedFile(
            from: pendingURL,
            to: storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .current)
        )
    }

    /// Opens the committed generation and hands the payload and the unwrapped
    /// domain master key to `body`. Both buffers are zeroized on the way out, so
    /// anything `body` keeps must be its own copy.
    private func withAuthoritativeSnapshot<T>(
        wrappingRootKey: Data,
        _ body: (Payload, Data) throws -> T
    ) throws -> T {
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

        let envelopeData = try storageRoot.readManagedData(
            at: storageRoot.domainEnvelopeURL(for: Self.domainID, slot: .current)
        )
        let envelope = try ProtectedDomainEnvelopeCodec.decode(envelopeData)
        var plaintext = try ProtectedDomainEnvelopeCodec.open(
            envelope: envelope,
            domainMasterKey: domainMasterKey
        )
        defer {
            plaintext.protectedDataZeroize()
        }
        return try body(
            try PropertyListDecoder().decode(Payload.self, from: plaintext),
            domainMasterKey
        )
    }
}
