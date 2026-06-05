import CryptoKit
import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

typealias ProtectedDataTestAppAppContainer = CypherAir.AppContainer
typealias ProtectedDataTestAppAppSessionOrchestrator = CypherAir.AppSessionOrchestrator
typealias ProtectedDataTestAppAppStartupCoordinator = CypherAir.AppStartupCoordinator
typealias ProtectedDataTestAppProtectedDataBootstrapState = CypherAir.ProtectedDataBootstrapState
typealias ProtectedDataTestAppProtectedDataAccessGateClassifier = CypherAir.ProtectedDataAccessGateClassifier
typealias ProtectedDataTestAppProtectedDataFrameworkState = CypherAir.ProtectedDataFrameworkState
typealias ProtectedDataTestAppProtectedDataPersistedRightHandle = CypherAir.ProtectedDataPersistedRightHandle
typealias ProtectedDataTestAppProtectedDataRegistryStore = CypherAir.ProtectedDataRegistryStore
typealias ProtectedDataTestAppProtectedDataRelockParticipant = CypherAir.ProtectedDataRelockParticipant
typealias ProtectedDataTestAppProtectedDataRightStoreClientProtocol = CypherAir.ProtectedDataRightStoreClientProtocol
typealias ProtectedDataTestAppProtectedDataRightIdentifiers = CypherAir.ProtectedDataRightIdentifiers
typealias ProtectedDataTestAppProtectedDataSessionCoordinator = CypherAir.ProtectedDataSessionCoordinator
typealias ProtectedDataTestAppProtectedDataSessionRelockCoordinator = CypherAir.ProtectedDataSessionRelockCoordinator
typealias ProtectedDataTestAppProtectedDataPostUnlockCoordinator = CypherAir.ProtectedDataPostUnlockCoordinator
typealias ProtectedDataTestAppProtectedDataPostUnlockDomainOpener = CypherAir.ProtectedDataPostUnlockDomainOpener
typealias ProtectedDataTestAppProtectedDataPostUnlockOutcome = CypherAir.ProtectedDataPostUnlockOutcome
typealias ProtectedDataTestAppProtectedDataFrameworkSentinelStore = CypherAir.ProtectedDataFrameworkSentinelStore
typealias ProtectedDataTestAppPrivateKeyControlStore = CypherAir.PrivateKeyControlStore
typealias ProtectedDataTestAppKeyMetadataDomainStore = CypherAir.KeyMetadataDomainStore
typealias ProtectedDataTestAppKeyMetadataStore = CypherAir.KeyMetadataStore
typealias ProtectedDataTestAppProtectedDataStorageRoot = CypherAir.ProtectedDataStorageRoot
typealias ProtectedDataTestAppProtectedDomainKeyManager = CypherAir.ProtectedDomainKeyManager
typealias ProtectedDataTestAppProtectedDomainRecoveryHandler = CypherAir.ProtectedDomainRecoveryHandler
typealias ProtectedDataTestAppProtectedDomainRecoveryCoordinator = CypherAir.ProtectedDomainRecoveryCoordinator
typealias ProtectedDataTestAppMockProtectedDataRootSecretStore = CypherAir.MockProtectedDataRootSecretStore
typealias ProtectedDataTestAppPrivacyScreenLifecycleGate = CypherAir.PrivacyScreenLifecycleGate
typealias ProtectedDataTestAppPendingRecoveryOutcome = CypherAir.PendingRecoveryOutcome
typealias ProtectedDataTestAppWrappedDomainMasterKeyRecord = CypherAir.WrappedDomainMasterKeyRecord
typealias ProtectedDataTestAppProtectedOrdinarySettingsCoordinator = CypherAir.ProtectedOrdinarySettingsCoordinator
typealias ProtectedDataTestAppLegacyOrdinarySettingsStore = CypherAir.LegacyOrdinarySettingsStore

final class ProtectedDataTestMutableDateProvider: @unchecked Sendable {
    var value: Date

    init(_ value: Date) {
        self.value = value
    }

    func now() -> Date {
        value
    }
}

final class MockProtectedDataPersistedRightHandle: ProtectedDataTestAppProtectedDataPersistedRightHandle {
    let identifier: String
    let secretData: Data
    var authorizeError: Error?
    var rawSecretError: Error?

    private(set) var authorizeCallCount = 0
    private(set) var deauthorizeCallCount = 0

    init(identifier: String, secretData: Data) {
        self.identifier = identifier
        self.secretData = secretData
    }

    func authorize(localizedReason: String) async throws {
        authorizeCallCount += 1
        if let authorizeError {
            throw authorizeError
        }
    }

    func deauthorize() async {
        deauthorizeCallCount += 1
    }

    func rawSecretData() async throws -> Data {
        if let rawSecretError {
            throw rawSecretError
        }
        return secretData
    }

    func rootSecretData() throws -> Data {
        if let rawSecretError {
            throw rawSecretError
        }
        return secretData
    }
}

final class MockProtectedDataRightStoreClient: ProtectedDataTestAppProtectedDataRightStoreClientProtocol, ProtectedDataRootSecretStoreProtocol, @unchecked Sendable {
    var persistedRightHandle: MockProtectedDataPersistedRightHandle?

    private(set) var rightLookupCallCount = 0
    private(set) var saveWithoutSecretCallCount = 0
    private(set) var saveWithSecretCallCount = 0
    private(set) var removeCallCount = 0
    private(set) var lastRemovedIdentifier: String?
    private(set) var lastAuthenticationContext: LAContext?

    func right(forIdentifier identifier: String) async throws -> any ProtectedDataTestAppProtectedDataPersistedRightHandle {
        rightLookupCallCount += 1
        guard let persistedRightHandle else {
            throw CypherAir.ProtectedDataError.missingPersistedRight(identifier)
        }
        return persistedRightHandle
    }

    func saveRight(_ right: LARight, identifier: String) async throws -> any ProtectedDataTestAppProtectedDataPersistedRightHandle {
        saveWithoutSecretCallCount += 1
        let handle = MockProtectedDataPersistedRightHandle(identifier: identifier, secretData: Data(repeating: 0x11, count: 32))
        persistedRightHandle = handle
        return handle
    }

    func saveRight(
        _ right: LARight,
        identifier: String,
        secret: Data
    ) async throws -> any ProtectedDataTestAppProtectedDataPersistedRightHandle {
        saveWithSecretCallCount += 1
        let handle = MockProtectedDataPersistedRightHandle(identifier: identifier, secretData: secret)
        persistedRightHandle = handle
        return handle
    }

    func removeRight(forIdentifier identifier: String) async throws {
        removeCallCount += 1
        lastRemovedIdentifier = identifier
        persistedRightHandle = nil
    }

    func saveRootSecret(
        _ secretData: Data,
        identifier: String,
        policy: AppSessionAuthenticationPolicy
    ) throws {
        _ = policy
        saveWithSecretCallCount += 1
        let handle = MockProtectedDataPersistedRightHandle(identifier: identifier, secretData: secretData)
        persistedRightHandle = handle
    }

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext,
        minimumEnvelopeVersion: Int?
    ) throws -> ProtectedDataRootSecretLoadResult {
        _ = minimumEnvelopeVersion
        lastAuthenticationContext = authenticationContext
        rightLookupCallCount += 1
        guard let persistedRightHandle else {
            throw MockKeychainError.itemNotFound
        }
        if let authorizeError = persistedRightHandle.authorizeError {
            throw authorizeError
        }
        return ProtectedDataRootSecretLoadResult(
            secretData: try persistedRightHandle.rootSecretData(),
            storageFormat: .envelopeV2,
            didMigrate: false
        )
    }

    func deleteRootSecret(identifier: String) throws {
        removeCallCount += 1
        lastRemovedIdentifier = identifier
        guard persistedRightHandle != nil else {
            throw MockKeychainError.itemNotFound
        }
        persistedRightHandle = nil
    }

    func rootSecretExists(identifier: String) -> Bool {
        persistedRightHandle != nil
    }

    func reprotectRootSecret(
        identifier: String,
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext
    ) throws {
        _ = identifier
        _ = currentPolicy
        _ = newPolicy
        lastAuthenticationContext = authenticationContext
        guard persistedRightHandle != nil else {
            throw MockKeychainError.itemNotFound
        }
    }
}

final class MockProtectedDataRelockParticipant: ProtectedDataTestAppProtectedDataRelockParticipant {
    var shouldThrow = false
    private(set) var relockCallCount = 0

    func relockProtectedData() async throws {
        relockCallCount += 1
        if shouldThrow {
            throw ProtectedDataError.restartRequired
        }
    }
}

/// Relock participant that parks inside `relockProtectedData()` on a gate, so a
/// resume Task suspends precisely inside `relockCurrentSession()` — the window
/// between the orchestrator's `guard !isAuthenticating` and its in-flight flag
/// set. Used to deterministically prove the double-entry race is closed.
final class SuspendingRelockParticipant: ProtectedDataTestAppProtectedDataRelockParticipant {
    let gate: AsyncSuspensionGate
    private(set) var relockCallCount = 0

    init(gate: AsyncSuspensionGate) {
        self.gate = gate
    }

    func relockProtectedData() async throws {
        relockCallCount += 1
        await gate.suspend()
    }
}

actor AsyncBooleanFlag {
    var value = false

    func setTrue() {
        value = true
    }

    func currentValue() -> Bool {
        value
    }
}

actor AsyncIntegerCounter {
    var value = 0

    func next() -> Int {
        value += 1
        return value
    }

    func currentValue() -> Int {
        value
    }
}

actor AsyncSuspensionGate {
    var continuation: CheckedContinuation<Void, Never>?
    var suspended = false

    func suspend() async {
        suspended = true
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
        suspended = false
    }

    func isSuspended() -> Bool {
        suspended
    }

    func resume() {
        continuation?.resume()
        continuation = nil
    }
}

actor AsyncDataBox {
    var value = Data()

    func set(_ data: Data) {
        value = data
    }

    func data() -> Data {
        value
    }
}

final class ProtectedDataRootSecretCleanupProbe: @unchecked Sendable {
    let lock = NSLock()
    var currentExists: Bool
    var recordedEvents: [String] = []

    init(exists: Bool = true) {
        self.currentExists = exists
    }

    func rootSecretExists() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        recordedEvents.append("exists")
        return currentExists
    }

    func removeRootSecret() {
        lock.lock()
        defer { lock.unlock() }
        recordedEvents.append("remove")
        currentExists = false
    }

    func provisionRootSecret() {
        lock.lock()
        defer { lock.unlock() }
        recordedEvents.append("provision")
        currentExists = true
    }

    func record(_ event: String) {
        lock.lock()
        defer { lock.unlock() }
        recordedEvents.append(event)
    }

    func snapshot() -> (exists: Bool, events: [String]) {
        lock.lock()
        defer { lock.unlock() }
        return (currentExists, recordedEvents)
    }
}

enum ProtectedDataTestInterruption: Error {
    case injectedPendingCreateInterruption
}

final class MockProtectedDomainRecoveryHandler: ProtectedDataTestAppProtectedDomainRecoveryHandler, @unchecked Sendable {
    let protectedDataDomainID: ProtectedDataDomainID
    private(set) var continuedCreatePhases: [CreateDomainPhase] = []
    private(set) var deleteArtifactsCallCount = 0

    init(domainID: ProtectedDataDomainID) {
        self.protectedDataDomainID = domainID
    }

    func continuePendingCreate(
        phase: CreateDomainPhase,
        authenticationContext: LAContext?
    ) async throws {
        continuedCreatePhases.append(phase)
    }

    func deleteDomainArtifactsForRecovery() throws {
        deleteArtifactsCallCount += 1
    }
}

actor ThrowingRootSecretFloorRecorder {
    private(set) var callCount = 0
    private(set) var lastVersion: Int?

    func record(_ version: Int) throws {
        callCount += 1
        lastVersion = version
        throw ProtectedDataError.internalFailure("Injected root-secret envelope floor write failure.")
    }

    func snapshot() -> (callCount: Int, lastVersion: Int?) {
        (callCount, lastVersion)
    }
}

@MainActor
class ProtectedDataFrameworkTestCase: XCTestCase {
    struct ProtectedSettingsPayloadV1: Codable {
        var clipboardNotice: Bool
    }

    struct KeyMetadataPayloadV1: Encodable {
        var schemaVersion: Int
        var identities: [KeyMetadataIdentityV1]
    }

    struct KeyMetadataIdentityV1: Encodable {
        let fingerprint: String
        let keyVersion: UInt8
        let profile: PGPKeyProfile
        let userId: String?
        let hasEncryptionSubkey: Bool
        let isRevoked: Bool
        let isExpired: Bool
        let isDefault: Bool
        let isBackedUp: Bool
        let publicKeyData: Data
        let revocationCert: Data
        let primaryAlgo: String
        let subkeyAlgo: String?
        let expiryDate: Date?

        init(_ identity: PGPKeyIdentity) {
            fingerprint = identity.fingerprint
            keyVersion = identity.keyVersion
            profile = identity.profile
            userId = identity.userId
            hasEncryptionSubkey = identity.hasEncryptionSubkey
            isRevoked = identity.isRevoked
            isExpired = identity.isExpired
            isDefault = identity.isDefault
            isBackedUp = identity.isBackedUp
            publicKeyData = identity.publicKeyData
            revocationCert = identity.revocationCert
            primaryAlgo = identity.primaryAlgo
            subkeyAlgo = identity.subkeyAlgo
            expiryDate = identity.expiryDate
        }
    }

    let envelopeTestSharedRight = "com.cypherair.tests.protected-data.envelope"

    func makeTemporaryDirectory(_ prefix: String) -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    func makeMetadataIdentity(
        fingerprint: String,
        userId: String? = nil,
        isDefault: Bool = false,
        isBackedUp: Bool = false,
        publicKeySeed: UInt8 = 0x11
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint.lowercased(),
            keyVersion: 4,
            profile: .universal,
            userId: userId,
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: isDefault,
            isBackedUp: isBackedUp,
            publicKeyData: Data([publicKeySeed, 0x42, 0x43]),
            revocationCert: Data([0x52, publicKeySeed]),
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519",
            expiryDate: nil
        )
    }

    func makeProtectedSettingsHarness(
        _ prefix: String
    ) throws -> (
        storageRoot: ProtectedDataTestAppProtectedDataStorageRoot,
        registryStore: ProtectedDataTestAppProtectedDataRegistryStore,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager,
        defaults: UserDefaults,
        defaultsSuiteName: String,
        store: ProtectedSettingsStore
    ) {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory(prefix))
        let sharedRightIdentifier = "com.cypherair.tests.protected-settings.\(UUID().uuidString)"
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: sharedRightIdentifier
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)
        let defaultsSuiteName = "com.cypherair.tests.protected-settings.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        let store = ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager
        )
        return (
            storageRoot,
            registryStore,
            domainKeyManager,
            defaults,
            defaultsSuiteName,
            store
        )
    }

    func createProtectedSettingsDomain(
        store: ProtectedSettingsStore,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager
    ) async throws -> Data {
        let capturedSharedSecret = AsyncDataBox()
        try await store.ensureCommittedAndMigrateSettingsIfNeeded(
            persistSharedRight: { secret in
                await capturedSharedSecret.set(secret)
            }
        )
        var rootSecret = await capturedSharedSecret.data()
        let wrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()
        return wrappingRootKey
    }

    func setLegacyOrdinarySettings(
        _ snapshot: ProtectedOrdinarySettingsSnapshot,
        defaults: UserDefaults
    ) {
        defaults.set(snapshot.gracePeriod, forKey: ProtectedOrdinarySettingsLegacyKeys.gracePeriod)
        defaults.set(snapshot.encryptToSelf, forKey: ProtectedOrdinarySettingsLegacyKeys.encryptToSelf)
        defaults.set(
            snapshot.hasCompletedOnboarding,
            forKey: ProtectedOrdinarySettingsLegacyKeys.onboardingComplete
        )
        defaults.set(
            snapshot.guidedTutorialCompletedVersion,
            forKey: ProtectedOrdinarySettingsLegacyKeys.guidedTutorialCompletedVersion
        )
        defaults.set(snapshot.colorTheme.rawValue, forKey: ProtectedOrdinarySettingsLegacyKeys.colorTheme)
    }

    func assertLegacyOrdinarySettingsRemoved(
        defaults: UserDefaults,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertNil(defaults.object(forKey: AppConfiguration.clipboardNoticeLegacyKey), file: file, line: line)
        for key in LegacyOrdinarySettingsStore.persistentKeys {
            XCTAssertNil(defaults.object(forKey: key), "Expected \(key) to be removed.", file: file, line: line)
        }
    }

    func writeProtectedSettingsEnvelope<P: Encodable>(
        payload: P,
        schemaVersion: Int,
        generationIdentifier: Int,
        storageRoot: ProtectedDataTestAppProtectedDataStorageRoot,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager,
        wrappingRootKey: Data
    ) throws {
        guard let wrappedRecord = try domainKeyManager.loadWrappedDomainMasterKeyRecord(
            for: ProtectedSettingsStore.domainID
        ) else {
            throw ProtectedDataError.missingWrappedDomainMasterKey(ProtectedSettingsStore.domainID)
        }
        var domainMasterKey = try domainKeyManager.unwrapDomainMasterKey(
            from: wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )
        defer {
            domainMasterKey.protectedDataZeroize()
        }

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        var plaintext = try encoder.encode(payload)
        defer {
            plaintext.protectedDataZeroize()
        }
        let envelope = try ProtectedDomainEnvelopeCodec.seal(
            plaintext: plaintext,
            domainID: ProtectedSettingsStore.domainID,
            schemaVersion: schemaVersion,
            generationIdentifier: generationIdentifier,
            domainMasterKey: domainMasterKey
        )
        let envelopeData = try encoder.encode(envelope)
        let pendingURL = storageRoot.domainEnvelopeURL(for: ProtectedSettingsStore.domainID, slot: .pending)
        try storageRoot.writeProtectedData(envelopeData, to: pendingURL)
        let currentURL = storageRoot.domainEnvelopeURL(for: ProtectedSettingsStore.domainID, slot: .current)
        let previousURL = storageRoot.domainEnvelopeURL(for: ProtectedSettingsStore.domainID, slot: .previous)
        if try storageRoot.managedItemExists(at: currentURL) {
            try storageRoot.promoteStagedFile(from: currentURL, to: previousURL)
        }
        try storageRoot.promoteStagedFile(from: pendingURL, to: currentURL)
        try ProtectedDomainBootstrapStore(storageRoot: storageRoot).saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: schemaVersion,
                expectedCurrentGenerationIdentifier: String(generationIdentifier),
                coarseRecoveryReason: nil,
                wrappedDomainMasterKeyRecordVersion: ProtectedDataTestAppWrappedDomainMasterKeyRecord.currentFormatVersion
            ),
            for: ProtectedSettingsStore.domainID
        )
    }

    func writeKeyMetadataEnvelope<P: Encodable>(
        payload: P,
        schemaVersion: Int,
        generationIdentifier: Int,
        storageRoot: ProtectedDataTestAppProtectedDataStorageRoot,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager,
        wrappingRootKey: Data
    ) throws {
        guard let wrappedRecord = try domainKeyManager.loadWrappedDomainMasterKeyRecord(
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
        ) else {
            throw ProtectedDataError.missingWrappedDomainMasterKey(ProtectedDataTestAppKeyMetadataDomainStore.domainID)
        }
        var domainMasterKey = try domainKeyManager.unwrapDomainMasterKey(
            from: wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )
        defer {
            domainMasterKey.protectedDataZeroize()
        }

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        var plaintext = try encoder.encode(payload)
        defer {
            plaintext.protectedDataZeroize()
        }
        let envelope = try ProtectedDomainEnvelopeCodec.seal(
            plaintext: plaintext,
            domainID: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
            schemaVersion: schemaVersion,
            generationIdentifier: generationIdentifier,
            domainMasterKey: domainMasterKey
        )
        let envelopeData = try encoder.encode(envelope)
        let pendingURL = storageRoot.domainEnvelopeURL(for: ProtectedDataTestAppKeyMetadataDomainStore.domainID, slot: .pending)
        try storageRoot.writeProtectedData(envelopeData, to: pendingURL)
        let currentURL = storageRoot.domainEnvelopeURL(for: ProtectedDataTestAppKeyMetadataDomainStore.domainID, slot: .current)
        let previousURL = storageRoot.domainEnvelopeURL(for: ProtectedDataTestAppKeyMetadataDomainStore.domainID, slot: .previous)
        if try storageRoot.managedItemExists(at: currentURL) {
            try storageRoot.promoteStagedFile(from: currentURL, to: previousURL)
        }
        try storageRoot.promoteStagedFile(from: pendingURL, to: currentURL)
        try ProtectedDomainBootstrapStore(storageRoot: storageRoot).saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: schemaVersion,
                expectedCurrentGenerationIdentifier: String(generationIdentifier),
                coarseRecoveryReason: nil,
                wrappedDomainMasterKeyRecordVersion: ProtectedDataTestAppWrappedDomainMasterKeyRecord.currentFormatVersion
            ),
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
        )
    }

    func writeKeyMetadataPendingEnvelope<P: Encodable>(
        payload: P,
        schemaVersion: Int,
        generationIdentifier: Int,
        storageRoot: ProtectedDataTestAppProtectedDataStorageRoot,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager,
        wrappingRootKey: Data
    ) throws {
        guard let wrappedRecord = try domainKeyManager.loadWrappedDomainMasterKeyRecord(
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
        ) else {
            throw ProtectedDataError.missingWrappedDomainMasterKey(ProtectedDataTestAppKeyMetadataDomainStore.domainID)
        }
        var domainMasterKey = try domainKeyManager.unwrapDomainMasterKey(
            from: wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )
        defer {
            domainMasterKey.protectedDataZeroize()
        }

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        var plaintext = try encoder.encode(payload)
        defer {
            plaintext.protectedDataZeroize()
        }
        let envelope = try ProtectedDomainEnvelopeCodec.seal(
            plaintext: plaintext,
            domainID: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
            schemaVersion: schemaVersion,
            generationIdentifier: generationIdentifier,
            domainMasterKey: domainMasterKey
        )
        let envelopeData = try encoder.encode(envelope)
        let pendingURL = storageRoot.domainEnvelopeURL(for: ProtectedDataTestAppKeyMetadataDomainStore.domainID, slot: .pending)
        try storageRoot.writeProtectedData(envelopeData, to: pendingURL)
    }

    func loadCurrentKeyMetadataEnvelope(
        storageRoot: ProtectedDataTestAppProtectedDataStorageRoot
    ) throws -> ProtectedDomainEnvelope {
        let url = storageRoot.domainEnvelopeURL(for: ProtectedDataTestAppKeyMetadataDomainStore.domainID, slot: .current)
        let data = try storageRoot.readManagedData(at: url)
        return try PropertyListDecoder().decode(ProtectedDomainEnvelope.self, from: data)
    }

    func makeKeyMetadataDomainHarness(
        _ prefix: String,
        keychain providedKeychain: MockKeychain? = nil
    ) async throws -> (
        storageRoot: ProtectedDataTestAppProtectedDataStorageRoot,
        registryStore: ProtectedDataTestAppProtectedDataRegistryStore,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager,
        wrappingRootKey: Data,
        keychain: MockKeychain,
        legacyStore: ProtectedDataTestAppKeyMetadataStore,
        store: ProtectedDataTestAppKeyMetadataDomainStore
    ) {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory(prefix))
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.key-metadata.\(UUID().uuidString)"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot)

        let defaultsSuiteName = "com.cypherair.tests.key-metadata.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let privateKeyControlStore = ProtectedDataTestAppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }
        let persistedSecretBox = AsyncDataBox()

        _ = try await privateKeyControlStore.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
            authenticationContext: handoffContext,
            persistSharedRight: { secret in
                await persistedSecretBox.set(secret)
            }
        )

        var rootSecret = await persistedSecretBox.data()
        let wrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()

        let keychain = providedKeychain ?? MockKeychain()
        let legacyStore = ProtectedDataTestAppKeyMetadataStore(keychain: keychain)
        let store = ProtectedDataTestAppKeyMetadataDomainStore(
            legacyMetadataStore: legacyStore,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        return (
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            wrappingRootKey: wrappingRootKey,
            keychain: keychain,
            legacyStore: legacyStore,
            store: store
        )
    }

    func leaveKeyMetadataPendingCreateAtJournaled(
        registryStore: ProtectedDataTestAppProtectedDataRegistryStore,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        do {
            _ = try await registryStore.performCreateDomainTransaction(
                domainID: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
                validateBeforeJournal: { registry in
                    guard registry.sharedResourceLifecycleState == .ready,
                          !registry.committedMembership.isEmpty else {
                        throw ProtectedDataError.invalidRegistry(
                            "Key metadata pending-create fixture requires a ready shared resource."
                        )
                    }
                },
                provisionSharedResourceIfNeeded: {},
                stageArtifacts: {
                    throw ProtectedDataTestInterruption.injectedPendingCreateInterruption
                },
                validateArtifacts: {}
            )
            XCTFail("Expected injected key metadata create interruption.", file: file, line: line)
        } catch ProtectedDataTestInterruption.injectedPendingCreateInterruption {
        }

        let registry = try registryStore.loadRegistry()
        guard case let .createDomain(domainID, phase)? = registry.pendingMutation else {
            XCTFail("Expected key metadata pending create to remain journaled.", file: file, line: line)
            return
        }
        XCTAssertEqual(domainID, ProtectedDataTestAppKeyMetadataDomainStore.domainID, file: file, line: line)
        XCTAssertEqual(phase, .journaled, file: file, line: line)
    }

    func leaveKeyMetadataPendingCreateWithStagedArtifacts(
        storageRoot: ProtectedDataTestAppProtectedDataStorageRoot,
        registryStore: ProtectedDataTestAppProtectedDataRegistryStore,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager,
        wrappingRootKey: Data,
        identity: PGPKeyIdentity,
        phase: CreateDomainPhase,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        guard phase == .artifactsStaged || phase == .validated else {
            XCTFail("Staged-artifact fixture only supports artifactsStaged or validated.", file: file, line: line)
            return
        }

        let payload = ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(identities: [identity])
        var domainMasterKey = try domainKeyManager.generateDomainMasterKey()
        defer {
            domainMasterKey.protectedDataZeroize()
        }
        let wrappedRecord = try domainKeyManager.wrapDomainMasterKey(
            domainMasterKey,
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
            wrappingRootKey: wrappingRootKey
        )
        try domainKeyManager.writeWrappedDomainMasterKeyRecordTransaction(
            wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )

        try storageRoot.ensureDomainDirectoryExists(for: ProtectedDataTestAppKeyMetadataDomainStore.domainID)
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        var plaintext = try encoder.encode(payload)
        defer {
            plaintext.protectedDataZeroize()
        }
        let envelope = try ProtectedDomainEnvelopeCodec.seal(
            plaintext: plaintext,
            domainID: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
            schemaVersion: ProtectedDataTestAppKeyMetadataDomainStore.Payload.currentSchemaVersion,
            generationIdentifier: 1,
            domainMasterKey: domainMasterKey
        )
        let envelopeData = try encoder.encode(envelope)
        let pendingURL = storageRoot.domainEnvelopeURL(
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
            slot: .pending
        )
        try storageRoot.writeProtectedData(envelopeData, to: pendingURL)
        try storageRoot.promoteStagedFile(
            from: pendingURL,
            to: storageRoot.domainEnvelopeURL(
                for: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
                slot: .current
            )
        )
        try ProtectedDomainBootstrapStore(storageRoot: storageRoot).saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: ProtectedDataTestAppKeyMetadataDomainStore.Payload.currentSchemaVersion,
                expectedCurrentGenerationIdentifier: "1",
                coarseRecoveryReason: nil,
                wrappedDomainMasterKeyRecordVersion: ProtectedDataTestAppWrappedDomainMasterKeyRecord.currentFormatVersion
            ),
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
        )

        var registry = try registryStore.loadRegistry()
        XCTAssertEqual(registry.sharedResourceLifecycleState, .ready, file: file, line: line)
        XCTAssertNil(registry.committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID], file: file, line: line)
        registry.pendingMutation = .createDomain(
            targetDomainID: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
            phase: phase
        )
        try registryStore.saveRegistry(registry)
    }

    func replacing(
        _ envelope: ProtectedDataRootSecretEnvelope,
        magic: String? = nil,
        formatVersion: Int? = nil,
        algorithmID: String? = nil,
        aadVersion: Int? = nil,
        sharedRightIdentifier: String? = nil,
        deviceBindingKeyIdentifier: String? = nil,
        deviceBindingPublicKeyX963: Data? = nil,
        ephemeralPublicKeyX963: Data? = nil,
        hkdfSalt: Data? = nil,
        nonce: Data? = nil,
        ciphertext: Data? = nil,
        tag: Data? = nil
    ) -> ProtectedDataRootSecretEnvelope {
        ProtectedDataRootSecretEnvelope(
            magic: magic ?? envelope.magic,
            formatVersion: formatVersion ?? envelope.formatVersion,
            algorithmID: algorithmID ?? envelope.algorithmID,
            aadVersion: aadVersion ?? envelope.aadVersion,
            sharedRightIdentifier: sharedRightIdentifier ?? envelope.sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier ?? envelope.deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: deviceBindingPublicKeyX963 ?? envelope.deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963 ?? envelope.ephemeralPublicKeyX963,
            hkdfSalt: hkdfSalt ?? envelope.hkdfSalt,
            nonce: nonce ?? envelope.nonce,
            ciphertext: ciphertext ?? envelope.ciphertext,
            tag: tag ?? envelope.tag
        )
    }

    func flippedFirstByte(_ data: Data) -> Data {
        var copy = data
        if !copy.isEmpty {
            copy[copy.startIndex] ^= 0xFF
        }
        return copy
    }

    func encodedEnvelopeWithUnsupportedField(
        from envelope: ProtectedDataRootSecretEnvelope
    ) throws -> Data {
        let dictionary: [String: Any] = [
            "magic": envelope.magic,
            "formatVersion": envelope.formatVersion,
            "algorithmID": envelope.algorithmID,
            "aadVersion": envelope.aadVersion,
            "sharedRightIdentifier": envelope.sharedRightIdentifier,
            "deviceBindingKeyIdentifier": envelope.deviceBindingKeyIdentifier,
            "deviceBindingPublicKeyX963": envelope.deviceBindingPublicKeyX963,
            "ephemeralPublicKeyX963": envelope.ephemeralPublicKeyX963,
            "hkdfSalt": envelope.hkdfSalt,
            "nonce": envelope.nonce,
            "ciphertext": envelope.ciphertext,
            "tag": envelope.tag,
            "unsupported": Data([0x00])
        ]
        return try PropertyListSerialization.data(
            fromPropertyList: dictionary,
            format: .binary,
            options: 0
        )
    }

    func insertLegacyRootSecret(
        _ payload: Data,
        identifier: String,
        account: String
    ) throws {
        deleteRootSecretPayload(identifier: identifier, account: account)
        var query = rootSecretQuery(identifier: identifier, account: account)
        query[kSecValueData as String] = payload
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        try handleKeychainStatus(SecItemAdd(query as CFDictionary, nil))
    }

    func replaceRootSecretPayload(
        _ payload: Data,
        identifier: String,
        account: String
    ) throws {
        try handleKeychainStatus(
            SecItemUpdate(
                rootSecretQuery(identifier: identifier, account: account) as CFDictionary,
                [kSecValueData as String: payload] as CFDictionary
            )
        )
    }

    func loadRootSecretPayload(
        identifier: String,
        account: String
    ) throws -> Data {
        var query = rootSecretQuery(identifier: identifier, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        try handleKeychainStatus(SecItemCopyMatching(query as CFDictionary, &result))
        guard let data = result as? Data else {
            throw KeychainError.unhandledError(errSecInternalError)
        }
        return data
    }

    func deleteRootSecretPayload(identifier: String, account: String) {
        let status = SecItemDelete(rootSecretQuery(identifier: identifier, account: account) as CFDictionary)
        XCTAssertTrue(
            status == errSecSuccess || status == errSecItemNotFound,
            "Unexpected Keychain delete status \(status)"
        )
    }

    func rootSecretQuery(identifier: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: identifier,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    func handleKeychainStatus(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            throw KeychainError.itemNotFound
        case errSecDuplicateItem:
            throw KeychainError.duplicateItem
        case errSecUserCanceled:
            throw KeychainError.userCancelled
        case errSecAuthFailed:
            throw KeychainError.authenticationFailed
        case errSecInteractionNotAllowed:
            throw KeychainError.interactionNotAllowed
        default:
            throw KeychainError.unhandledError(status)
        }
    }

}

func XCTAssertThrowsErrorAsync(
    _ expression: @escaping () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await expression()
        XCTFail("Expected expression to throw.", file: file, line: line)
    } catch {
    }
}
