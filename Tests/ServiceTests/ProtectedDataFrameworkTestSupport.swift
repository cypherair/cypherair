import CryptoKit
import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

typealias ProtectedDataTestAppAppSessionOrchestrator = CypherAir.AppSessionOrchestrator
typealias ProtectedDataTestAppProtectedDataAccessGateClassifier = CypherAir.ProtectedDataAccessGateClassifier
typealias ProtectedDataTestAppProtectedDataRegistryStore = CypherAir.ProtectedDataRegistryStore
typealias ProtectedDataTestAppProtectedDataRelockParticipant = CypherAir.ProtectedDataRelockParticipant
typealias ProtectedDataTestAppProtectedDataSessionCoordinator = CypherAir.ProtectedDataSessionCoordinator
typealias ProtectedDataTestAppProtectedDataSessionRelockCoordinator = CypherAir.ProtectedDataSessionRelockCoordinator
typealias ProtectedDataTestAppProtectedDataPostUnlockCoordinator = CypherAir.ProtectedDataPostUnlockCoordinator
typealias ProtectedDataTestAppProtectedDataPostUnlockDomainOpener = CypherAir.ProtectedDataPostUnlockDomainOpener
typealias ProtectedDataTestAppProtectedDataFrameworkSentinelStore = CypherAir.ProtectedDataFrameworkSentinelStore
typealias ProtectedDataTestAppPrivateKeyControlStore = CypherAir.PrivateKeyControlStore
typealias ProtectedDataTestAppKeyMetadataDomainStore = CypherAir.KeyMetadataDomainStore
typealias ProtectedDataTestAppProtectedDataStorageRoot = CypherAir.ProtectedDataStorageRoot
typealias ProtectedDataTestAppProtectedDomainKeyManager = CypherAir.ProtectedDomainKeyManager
typealias ProtectedDataTestAppProtectedDomainRecoveryHandler = CypherAir.ProtectedDomainRecoveryHandler
typealias ProtectedDataTestAppProtectedDomainRecoveryCoordinator = CypherAir.ProtectedDomainRecoveryCoordinator
typealias ProtectedDataTestAppMockProtectedDataRootSecretStore = CypherAir.MockProtectedDataRootSecretStore
typealias ProtectedDataTestAppPendingRecoveryOutcome = CypherAir.PendingRecoveryOutcome
typealias ProtectedDataTestAppWrappedDomainMasterKeyRecord = CypherAir.WrappedDomainMasterKeyRecord

final class RecordingProtectedDataRootSecretStore: ProtectedDataRootSecretStoreProtocol, @unchecked Sendable {
    private var storage: [String: Data] = [:]

    private(set) var saveCallCount = 0
    private(set) var loadCallCount = 0
    private(set) var removeCallCount = 0
    private(set) var lastRemovedIdentifier: String?
    private(set) var lastAuthenticationContext: LAContext?

    var loadError: Error?

    func seedRootSecret(_ secretData: Data, identifier: String) {
        storage[identifier] = secretData
    }

    func saveRootSecret(
        _ secretData: Data,
        identifier: String,
        policy: AppSessionAuthenticationPolicy
    ) throws {
        _ = policy
        saveCallCount += 1
        storage[identifier] = secretData
    }

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext
    ) throws -> Data {
        lastAuthenticationContext = authenticationContext
        loadCallCount += 1
        if let loadError {
            throw loadError
        }
        guard let secretData = storage[identifier] else {
            throw MockKeychainError.itemNotFound
        }
        return secretData
    }

    func deleteRootSecret(identifier: String) throws {
        removeCallCount += 1
        lastRemovedIdentifier = identifier
        guard storage.removeValue(forKey: identifier) != nil else {
            throw MockKeychainError.itemNotFound
        }
    }

    func rootSecretExists(identifier: String) -> Bool {
        storage[identifier] != nil
    }

    func reprotectRootSecret(
        identifier: String,
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext
    ) throws {
        _ = currentPolicy
        _ = newPolicy
        lastAuthenticationContext = authenticationContext
        guard storage[identifier] != nil else {
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

actor AsyncBooleanFlag {
    var value = false

    func setTrue() {
        value = true
    }

    func currentValue() -> Bool {
        value
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

@MainActor
class ProtectedDataFrameworkTestCase: XCTestCase {
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
            expiryDate: nil,
            openPGPConfigurationIdentity: .compatibleSoftwareV4,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
    }

    func makeProtectedSettingsHarness(
        _ prefix: String
    ) throws -> (
        storageRoot: ProtectedDataTestAppProtectedDataStorageRoot,
        registryStore: ProtectedDataTestAppProtectedDataRegistryStore,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager,
        keychain: MockKeychain,
        store: ProtectedSettingsStore
    ) {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory(prefix))
        let sharedRightIdentifier = "com.cypherair.tests.protected-settings.\(UUID().uuidString)"
        let keychain = MockKeychain()
        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(
            storageRoot: storageRoot,
            keychain: keychain
        )
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: sharedRightIdentifier,
            hasExternalProtectedDataArtifacts: {
                try domainKeyManager.hasAnyPersistedDomainKeyRecord()
            }
        )
        _ = try registryStore.performSynchronousBootstrap()
        let store = ProtectedSettingsStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager
        )
        return (
            storageRoot,
            registryStore,
            domainKeyManager,
            keychain,
            store
        )
    }

    func createProtectedSettingsDomain(
        store: ProtectedSettingsStore,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager
    ) async throws -> Data {
        let capturedSharedSecret = AsyncDataBox()
        try await store.ensureCommittedIfNeeded(
            persistSharedRight: { secret in
                await capturedSharedSecret.set(secret)
            }
        )
        var rootSecret = await capturedSharedSecret.data()
        let wrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()
        return wrappingRootKey
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
                expectedCurrentGenerationIdentifier: String(generationIdentifier)
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

    func makeKeyMetadataDomainHarness(
        _ prefix: String
    ) async throws -> (
        storageRoot: ProtectedDataTestAppProtectedDataStorageRoot,
        registryStore: ProtectedDataTestAppProtectedDataRegistryStore,
        domainKeyManager: ProtectedDataTestAppProtectedDomainKeyManager,
        keychain: MockKeychain,
        wrappingRootKey: Data,
        store: ProtectedDataTestAppKeyMetadataDomainStore
    ) {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory(prefix))
        let keychain = MockKeychain()
        let domainKeyManager = ProtectedDataTestAppProtectedDomainKeyManager(
            storageRoot: storageRoot,
            keychain: keychain
        )
        let registryStore = ProtectedDataTestAppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.key-metadata.\(UUID().uuidString)",
            hasExternalProtectedDataArtifacts: {
                try domainKeyManager.hasAnyPersistedDomainKeyRecord()
            }
        )
        _ = try registryStore.performSynchronousBootstrap()

        let defaultsSuiteName = "com.cypherair.tests.key-metadata.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let privateKeyControlStore = ProtectedDataTestAppPrivateKeyControlStore(
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

        let store = ProtectedDataTestAppKeyMetadataDomainStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        return (
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            keychain: keychain,
            wrappingRootKey: wrappingRootKey,
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
                expectedCurrentGenerationIdentifier: "1"
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
        deviceBindingKeyData: Data? = nil,
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
            deviceBindingKeyData: deviceBindingKeyData ?? envelope.deviceBindingKeyData,
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
            "deviceBindingKeyData": envelope.deviceBindingKeyData,
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

    func insertRootSecretPayload(
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
