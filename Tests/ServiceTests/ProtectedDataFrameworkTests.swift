import CryptoKit
import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

private typealias AppAppContainer = CypherAir.AppContainer
private typealias AppAppSessionOrchestrator = CypherAir.AppSessionOrchestrator
private typealias AppAppStartupCoordinator = CypherAir.AppStartupCoordinator
private typealias AppProtectedDataBootstrapState = CypherAir.ProtectedDataBootstrapState
private typealias AppProtectedDataAccessGateClassifier = CypherAir.ProtectedDataAccessGateClassifier
private typealias AppProtectedDataFrameworkState = CypherAir.ProtectedDataFrameworkState
private typealias AppProtectedDataPersistedRightHandle = CypherAir.ProtectedDataPersistedRightHandle
private typealias AppProtectedDataRegistryStore = CypherAir.ProtectedDataRegistryStore
private typealias AppProtectedDataRelockParticipant = CypherAir.ProtectedDataRelockParticipant
private typealias AppProtectedDataRightStoreClientProtocol = CypherAir.ProtectedDataRightStoreClientProtocol
private typealias AppProtectedDataRightIdentifiers = CypherAir.ProtectedDataRightIdentifiers
private typealias AppProtectedDataSessionCoordinator = CypherAir.ProtectedDataSessionCoordinator
private typealias AppProtectedDataSessionRelockCoordinator = CypherAir.ProtectedDataSessionRelockCoordinator
private typealias AppProtectedDataPostUnlockCoordinator = CypherAir.ProtectedDataPostUnlockCoordinator
private typealias AppProtectedDataPostUnlockDomainOpener = CypherAir.ProtectedDataPostUnlockDomainOpener
private typealias AppProtectedDataPostUnlockOutcome = CypherAir.ProtectedDataPostUnlockOutcome
private typealias AppProtectedDataFrameworkSentinelStore = CypherAir.ProtectedDataFrameworkSentinelStore
private typealias AppPrivateKeyControlStore = CypherAir.PrivateKeyControlStore
private typealias AppKeyMetadataDomainStore = CypherAir.KeyMetadataDomainStore
private typealias AppKeyMetadataStore = CypherAir.KeyMetadataStore
private typealias AppProtectedDataStorageRoot = CypherAir.ProtectedDataStorageRoot
private typealias AppProtectedDomainKeyManager = CypherAir.ProtectedDomainKeyManager
private typealias AppProtectedDomainRecoveryHandler = CypherAir.ProtectedDomainRecoveryHandler
private typealias AppProtectedDomainRecoveryCoordinator = CypherAir.ProtectedDomainRecoveryCoordinator
private typealias AppMockProtectedDataRootSecretStore = CypherAir.MockProtectedDataRootSecretStore
private typealias AppPrivacyScreenLifecycleGate = CypherAir.PrivacyScreenLifecycleGate
private typealias AppPendingRecoveryOutcome = CypherAir.PendingRecoveryOutcome
private typealias AppWrappedDomainMasterKeyRecord = CypherAir.WrappedDomainMasterKeyRecord
private typealias AppProtectedOrdinarySettingsCoordinator = CypherAir.ProtectedOrdinarySettingsCoordinator
private typealias AppLegacyOrdinarySettingsStore = CypherAir.LegacyOrdinarySettingsStore

private final class MockProtectedDataPersistedRightHandle: AppProtectedDataPersistedRightHandle {
    let identifier: String
    private let secretData: Data
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

private final class MockProtectedDataRightStoreClient: AppProtectedDataRightStoreClientProtocol, ProtectedDataRootSecretStoreProtocol, @unchecked Sendable {
    var persistedRightHandle: MockProtectedDataPersistedRightHandle?

    private(set) var rightLookupCallCount = 0
    private(set) var saveWithoutSecretCallCount = 0
    private(set) var saveWithSecretCallCount = 0
    private(set) var removeCallCount = 0
    private(set) var lastRemovedIdentifier: String?
    private(set) var lastAuthenticationContext: LAContext?

    func right(forIdentifier identifier: String) async throws -> any AppProtectedDataPersistedRightHandle {
        rightLookupCallCount += 1
        guard let persistedRightHandle else {
            throw CypherAir.ProtectedDataError.missingPersistedRight(identifier)
        }
        return persistedRightHandle
    }

    func saveRight(_ right: LARight, identifier: String) async throws -> any AppProtectedDataPersistedRightHandle {
        saveWithoutSecretCallCount += 1
        let handle = MockProtectedDataPersistedRightHandle(identifier: identifier, secretData: Data(repeating: 0x11, count: 32))
        persistedRightHandle = handle
        return handle
    }

    func saveRight(
        _ right: LARight,
        identifier: String,
        secret: Data
    ) async throws -> any AppProtectedDataPersistedRightHandle {
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
            throw KeychainError.itemNotFound
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
            throw KeychainError.itemNotFound
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
            throw KeychainError.itemNotFound
        }
    }
}

private final class MockProtectedDataRelockParticipant: AppProtectedDataRelockParticipant {
    var shouldThrow = false
    private(set) var relockCallCount = 0

    func relockProtectedData() async throws {
        relockCallCount += 1
        if shouldThrow {
            throw ProtectedDataError.restartRequired
        }
    }
}

private actor AsyncBooleanFlag {
    private var value = false

    func setTrue() {
        value = true
    }

    func currentValue() -> Bool {
        value
    }
}

private actor AsyncIntegerCounter {
    private var value = 0

    func next() -> Int {
        value += 1
        return value
    }
}

private actor AsyncDataBox {
    private var value = Data()

    func set(_ data: Data) {
        value = data
    }

    func data() -> Data {
        value
    }
}

private enum ProtectedDataTestInterruption: Error {
    case injectedPendingCreateInterruption
}

private final class MockProtectedDomainRecoveryHandler: AppProtectedDomainRecoveryHandler, @unchecked Sendable {
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

private actor ThrowingRootSecretFloorRecorder {
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
final class ProtectedDataFrameworkTests: XCTestCase {
    private struct ProtectedSettingsPayloadV1: Codable {
        var clipboardNotice: Bool
    }

    private let envelopeTestSharedRight = "com.cypherair.tests.protected-data.envelope"

    private func makeTemporaryDirectory(_ prefix: String) -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func makeMetadataIdentity(
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

    private func makeProtectedSettingsHarness(
        _ prefix: String
    ) throws -> (
        storageRoot: AppProtectedDataStorageRoot,
        registryStore: AppProtectedDataRegistryStore,
        domainKeyManager: AppProtectedDomainKeyManager,
        defaults: UserDefaults,
        defaultsSuiteName: String,
        store: ProtectedSettingsStore
    ) {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory(prefix))
        let sharedRightIdentifier = "com.cypherair.tests.protected-settings.\(UUID().uuidString)"
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: sharedRightIdentifier
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
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

    private func createProtectedSettingsDomain(
        store: ProtectedSettingsStore,
        domainKeyManager: AppProtectedDomainKeyManager
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

    private func setLegacyOrdinarySettings(
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

    private func assertLegacyOrdinarySettingsRemoved(
        defaults: UserDefaults,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertNil(defaults.object(forKey: AppConfiguration.clipboardNoticeLegacyKey), file: file, line: line)
        for key in LegacyOrdinarySettingsStore.persistentKeys {
            XCTAssertNil(defaults.object(forKey: key), "Expected \(key) to be removed.", file: file, line: line)
        }
    }

    private func writeProtectedSettingsEnvelope<P: Encodable>(
        payload: P,
        schemaVersion: Int,
        generationIdentifier: Int,
        storageRoot: AppProtectedDataStorageRoot,
        domainKeyManager: AppProtectedDomainKeyManager,
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
                wrappedDomainMasterKeyRecordVersion: AppWrappedDomainMasterKeyRecord.currentFormatVersion
            ),
            for: ProtectedSettingsStore.domainID
        )
    }

    private func makeKeyMetadataDomainHarness(
        _ prefix: String,
        keychain providedKeychain: MockKeychain? = nil
    ) async throws -> (
        storageRoot: AppProtectedDataStorageRoot,
        registryStore: AppProtectedDataRegistryStore,
        domainKeyManager: AppProtectedDomainKeyManager,
        wrappingRootKey: Data,
        keychain: MockKeychain,
        legacyStore: AppKeyMetadataStore,
        store: AppKeyMetadataDomainStore
    ) {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory(prefix))
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.key-metadata.\(UUID().uuidString)"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)

        let defaultsSuiteName = "com.cypherair.tests.key-metadata.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let privateKeyControlStore = AppPrivateKeyControlStore(
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
        let legacyStore = AppKeyMetadataStore(keychain: keychain)
        let store = AppKeyMetadataDomainStore(
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

    private func leaveKeyMetadataPendingCreateAtJournaled(
        registryStore: AppProtectedDataRegistryStore,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        do {
            _ = try await registryStore.performCreateDomainTransaction(
                domainID: AppKeyMetadataDomainStore.domainID,
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
        XCTAssertEqual(domainID, AppKeyMetadataDomainStore.domainID, file: file, line: line)
        XCTAssertEqual(phase, .journaled, file: file, line: line)
    }

    private func leaveKeyMetadataPendingCreateWithStagedArtifacts(
        storageRoot: AppProtectedDataStorageRoot,
        registryStore: AppProtectedDataRegistryStore,
        domainKeyManager: AppProtectedDomainKeyManager,
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

        let payload = AppKeyMetadataDomainStore.Payload.initial(identities: [identity])
        var domainMasterKey = try domainKeyManager.generateDomainMasterKey()
        defer {
            domainMasterKey.protectedDataZeroize()
        }
        let wrappedRecord = try domainKeyManager.wrapDomainMasterKey(
            domainMasterKey,
            for: AppKeyMetadataDomainStore.domainID,
            wrappingRootKey: wrappingRootKey
        )
        try domainKeyManager.writeWrappedDomainMasterKeyRecordTransaction(
            wrappedRecord,
            wrappingRootKey: wrappingRootKey
        )

        try storageRoot.ensureDomainDirectoryExists(for: AppKeyMetadataDomainStore.domainID)
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        var plaintext = try encoder.encode(payload)
        defer {
            plaintext.protectedDataZeroize()
        }
        let envelope = try ProtectedDomainEnvelopeCodec.seal(
            plaintext: plaintext,
            domainID: AppKeyMetadataDomainStore.domainID,
            schemaVersion: AppKeyMetadataDomainStore.Payload.currentSchemaVersion,
            generationIdentifier: 1,
            domainMasterKey: domainMasterKey
        )
        let envelopeData = try encoder.encode(envelope)
        let pendingURL = storageRoot.domainEnvelopeURL(
            for: AppKeyMetadataDomainStore.domainID,
            slot: .pending
        )
        try storageRoot.writeProtectedData(envelopeData, to: pendingURL)
        try storageRoot.promoteStagedFile(
            from: pendingURL,
            to: storageRoot.domainEnvelopeURL(
                for: AppKeyMetadataDomainStore.domainID,
                slot: .current
            )
        )
        try ProtectedDomainBootstrapStore(storageRoot: storageRoot).saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: AppKeyMetadataDomainStore.Payload.currentSchemaVersion,
                expectedCurrentGenerationIdentifier: "1",
                coarseRecoveryReason: nil,
                wrappedDomainMasterKeyRecordVersion: AppWrappedDomainMasterKeyRecord.currentFormatVersion
            ),
            for: AppKeyMetadataDomainStore.domainID
        )

        var registry = try registryStore.loadRegistry()
        XCTAssertEqual(registry.sharedResourceLifecycleState, .ready, file: file, line: line)
        XCTAssertNil(registry.committedMembership[AppKeyMetadataDomainStore.domainID], file: file, line: line)
        registry.pendingMutation = .createDomain(
            targetDomainID: AppKeyMetadataDomainStore.domainID,
            phase: phase
        )
        try registryStore.saveRegistry(registry)
    }

    private func replacing(
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

    private func flippedFirstByte(_ data: Data) -> Data {
        var copy = data
        if !copy.isEmpty {
            copy[copy.startIndex] ^= 0xFF
        }
        return copy
    }

    private func encodedEnvelopeWithUnsupportedField(
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

    private func insertLegacyRootSecret(
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

    private func replaceRootSecretPayload(
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

    private func loadRootSecretPayload(
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

    private func deleteRootSecretPayload(identifier: String, account: String) {
        let status = SecItemDelete(rootSecretQuery(identifier: identifier, account: account) as CFDictionary)
        XCTAssertTrue(
            status == errSecSuccess || status == errSecItemNotFound,
            "Unexpected Keychain delete status \(status)"
        )
    }

    private func rootSecretQuery(identifier: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: identifier,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    private func handleKeychainStatus(_ status: OSStatus) throws {
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

    func test_rootSecretEnvelope_roundTripsWithMockDeviceBindingProvider() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x42, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)
        let encoded = try ProtectedDataRootSecretEnvelopeCodec.encode(envelope)
        let decoded = try ProtectedDataRootSecretEnvelopeCodec.decode(
            encoded,
            expectedSharedRightIdentifier: envelopeTestSharedRight
        )

        var openedSecret = try provider.openRootSecret(
            envelope: decoded,
            expectedSharedRightIdentifier: envelopeTestSharedRight
        )
        defer {
            openedSecret.protectedDataZeroize()
        }

        XCTAssertEqual(decoded.magic, ProtectedDataRootSecretEnvelope.magic)
        XCTAssertEqual(decoded.formatVersion, ProtectedDataRootSecretEnvelope.currentFormatVersion)
        XCTAssertEqual(decoded.aadVersion, ProtectedDataRootSecretEnvelope.currentAADVersion)
        XCTAssertEqual(ProtectedDataRootSecretEnvelope.currentAADVersion, 2)
        XCTAssertEqual(decoded.algorithmID, ProtectedDataRootSecretEnvelope.algorithmID)
        XCTAssertEqual(decoded.hkdfSalt.count, ProtectedDataRootSecretEnvelope.expectedSaltLength)
        XCTAssertEqual(decoded.nonce.count, ProtectedDataRootSecretEnvelope.expectedNonceLength)
        XCTAssertEqual(decoded.tag.count, ProtectedDataRootSecretEnvelope.expectedAuthenticationTagLength)
        XCTAssertEqual(decoded.ciphertext.count, ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        XCTAssertEqual(openedSecret, rootSecret)
    }

    func test_rootSecretEnvelope_rejectsTamperedAuthenticatedFields() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x24, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)

        let tamperedEnvelopes = [
            replacing(envelope, hkdfSalt: flippedFirstByte(envelope.hkdfSalt)),
            replacing(envelope, nonce: flippedFirstByte(envelope.nonce)),
            replacing(envelope, ciphertext: flippedFirstByte(envelope.ciphertext)),
            replacing(envelope, tag: flippedFirstByte(envelope.tag)),
            replacing(envelope, deviceBindingPublicKeyX963: flippedFirstByte(envelope.deviceBindingPublicKeyX963)),
            replacing(envelope, ephemeralPublicKeyX963: flippedFirstByte(envelope.ephemeralPublicKeyX963))
        ]

        for tamperedEnvelope in tamperedEnvelopes {
            XCTAssertThrowsError(
                try provider.openRootSecret(
                    envelope: tamperedEnvelope,
                    expectedSharedRightIdentifier: envelopeTestSharedRight
                )
            )
        }
    }

    func test_rootSecretEnvelope_aadV2BindsEphemeralPublicKeyAndRejectsAADV1() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x26, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)
        let substituteEphemeralPublicKey = P256.KeyAgreement.PrivateKey().publicKey.x963Representation

        let originalAAD = try ProtectedDataRootSecretEnvelopeCodec.rootSecretEnvelopeAAD(
            sharedRightIdentifier: envelope.sharedRightIdentifier,
            deviceBindingKeyIdentifier: envelope.deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: envelope.deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: envelope.ephemeralPublicKeyX963,
            rootSecretLength: envelope.ciphertext.count
        )
        let substitutedAAD = try ProtectedDataRootSecretEnvelopeCodec.rootSecretEnvelopeAAD(
            sharedRightIdentifier: envelope.sharedRightIdentifier,
            deviceBindingKeyIdentifier: envelope.deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: envelope.deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: substituteEphemeralPublicKey,
            rootSecretLength: envelope.ciphertext.count
        )

        XCTAssertNotEqual(originalAAD, substitutedAAD)

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let aadV1Payload = try encoder.encode(replacing(envelope, aadVersion: 1))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.decode(
            aadV1Payload,
            expectedSharedRightIdentifier: envelopeTestSharedRight
        ))
    }

    func test_rootSecretEnvelope_rejectsMalformedContractAndUnsupportedFields() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x35, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)

        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, magic: "CAPDSEV1")))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, formatVersion: 1)))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, algorithmID: "other")))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, hkdfSalt: Data(repeating: 0x00, count: 31))))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, nonce: Data(repeating: 0x00, count: 11))))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, tag: Data(repeating: 0x00, count: 15))))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, ciphertext: Data(repeating: 0x00, count: 31))))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.decode(
            try encodedEnvelopeWithUnsupportedField(from: envelope),
            expectedSharedRightIdentifier: envelopeTestSharedRight
        ))
    }

    func test_rootSecretEnvelope_rejectsWrongSharedRightIdentifier() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x53, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)

        XCTAssertThrowsError(
            try ProtectedDataRootSecretEnvelopeCodec.decode(
                try ProtectedDataRootSecretEnvelopeCodec.encode(envelope),
                expectedSharedRightIdentifier: "\(envelopeTestSharedRight).wrong"
            )
        )
        XCTAssertThrowsError(
            try provider.openRootSecret(
                envelope: envelope,
                expectedSharedRightIdentifier: "\(envelopeTestSharedRight).wrong"
            )
        )
    }

    func test_rootSecretStore_migratesLegacyRawPayloadAndWritesFormatFloor() throws {
        let account = "ProtectedDataFrameworkTests.\(#function).\(UUID().uuidString)"
        let identifier = "\(envelopeTestSharedRight).migration.\(UUID().uuidString)"
        let legacySecret = Data(repeating: 0x61, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        try insertLegacyRootSecret(legacySecret, identifier: identifier, account: account)
        defer {
            deleteRootSecretPayload(identifier: identifier, account: account)
        }

        let floorKeychain = MockKeychain()
        try floorKeychain.save(
            Data([0x91]),
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            account: account,
            accessControl: nil
        )
        let floorStore = ProtectedDataRootSecretFormatFloorStore(keychain: floorKeychain, account: account)
        let store = KeychainProtectedDataRootSecretStore(
            account: account,
            supportKeychain: floorKeychain,
            deviceBindingProvider: MockProtectedDataDeviceBindingProvider(),
            formatFloorStore: floorStore
        )

        var result = try store.loadRootSecret(
            identifier: identifier,
            authenticationContext: LAContext(),
            minimumEnvelopeVersion: nil
        )
        defer {
            result.secretData.protectedDataZeroize()
        }

        XCTAssertEqual(result.secretData, legacySecret)
        XCTAssertEqual(result.storageFormat, .envelopeV2)
        XCTAssertTrue(result.didMigrate)
        XCTAssertEqual(
            try floorStore.readMinimumEnvelopeVersion(sharedRightIdentifier: identifier),
            ProtectedDataRootSecretEnvelope.currentFormatVersion
        )
        XCTAssertFalse(floorKeychain.exists(
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            account: account
        ))

        let migratedPayload = try loadRootSecretPayload(identifier: identifier, account: account)
        XCTAssertNotEqual(migratedPayload.count, ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        XCTAssertNoThrow(try ProtectedDataRootSecretEnvelopeCodec.decode(
            migratedPayload,
            expectedSharedRightIdentifier: identifier
        ))
    }

    func test_rootSecretStore_legacyMigrationFloorWriteFailureThrowsAfterMigratingPayload() throws {
        let account = "ProtectedDataFrameworkTests.\(#function).\(UUID().uuidString)"
        let identifier = "\(envelopeTestSharedRight).migration-floor-failure.\(UUID().uuidString)"
        let legacySecret = Data(repeating: 0x63, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        try insertLegacyRootSecret(legacySecret, identifier: identifier, account: account)
        defer {
            deleteRootSecretPayload(identifier: identifier, account: account)
        }

        let floorKeychain = MockKeychain()
        try floorKeychain.save(
            Data([0x91]),
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            account: account,
            accessControl: nil
        )
        floorKeychain.failOnSaveNumber = 2
        let floorStore = ProtectedDataRootSecretFormatFloorStore(keychain: floorKeychain, account: account)
        let store = KeychainProtectedDataRootSecretStore(
            account: account,
            supportKeychain: floorKeychain,
            deviceBindingProvider: MockProtectedDataDeviceBindingProvider(),
            formatFloorStore: floorStore
        )

        XCTAssertThrowsError(try store.loadRootSecret(
            identifier: identifier,
            authenticationContext: LAContext(),
            minimumEnvelopeVersion: nil
        ))
        XCTAssertNil(try floorStore.readMinimumEnvelopeVersion(sharedRightIdentifier: identifier))
        let migratedPayload = try loadRootSecretPayload(identifier: identifier, account: account)
        XCTAssertNotEqual(migratedPayload.count, ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
    }

    func test_rootSecretStore_rejectsLegacyDowngradeAfterFormatFloor() throws {
        let account = "ProtectedDataFrameworkTests.\(#function).\(UUID().uuidString)"
        let identifier = "\(envelopeTestSharedRight).downgrade.\(UUID().uuidString)"
        let legacySecret = Data(repeating: 0x72, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        try insertLegacyRootSecret(legacySecret, identifier: identifier, account: account)
        defer {
            deleteRootSecretPayload(identifier: identifier, account: account)
        }

        let floorKeychain = MockKeychain()
        let floorStore = ProtectedDataRootSecretFormatFloorStore(keychain: floorKeychain, account: account)
        let store = KeychainProtectedDataRootSecretStore(
            account: account,
            supportKeychain: floorKeychain,
            deviceBindingProvider: MockProtectedDataDeviceBindingProvider(),
            formatFloorStore: floorStore
        )

        var migratedResult = try store.loadRootSecret(
            identifier: identifier,
            authenticationContext: LAContext(),
            minimumEnvelopeVersion: nil
        )
        migratedResult.secretData.protectedDataZeroize()

        try replaceRootSecretPayload(legacySecret, identifier: identifier, account: account)

        XCTAssertThrowsError(
            try store.loadRootSecret(
                identifier: identifier,
                authenticationContext: LAContext(),
                minimumEnvelopeVersion: nil
            )
        )
    }

    func test_registryBootstrap_withoutRootOrArtifacts_bootstrapsEmptySteadyState() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataBootstrap")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let store = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.bootstrap"
        )

        let result = try store.performSynchronousBootstrap()
        let registry = try store.loadRegistry()

        guard case .emptySteadyState(let bootstrappedRegistry, let didBootstrap) = result.bootstrapOutcome else {
            return XCTFail("Expected empty steady-state bootstrap outcome, got \(result.bootstrapOutcome)")
        }
        XCTAssertEqual(result.frameworkState, .sessionLocked)
        XCTAssertTrue(didBootstrap)
        XCTAssertTrue(FileManager.default.fileExists(atPath: storageRoot.registryURL.path))
        XCTAssertEqual(bootstrappedRegistry, registry)
        XCTAssertEqual(registry.committedMembership, [:])
        XCTAssertEqual(registry.sharedResourceLifecycleState, .absent)
        XCTAssertNil(registry.pendingMutation)
    }

    func test_registryBootstrap_missingRegistryWithArtifacts_entersFrameworkRecoveryNeeded() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataArtifacts")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        try FileManager.default.createDirectory(at: storageRoot.rootURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: storageRoot.domainDirectory(for: "synthetic-domain"),
            withIntermediateDirectories: true
        )

        let store = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.artifacts"
        )

        let result = try store.performSynchronousBootstrap()

        XCTAssertEqual(result.bootstrapOutcome, .frameworkRecoveryNeeded)
        XCTAssertEqual(result.frameworkState, .frameworkRecoveryNeeded)
        XCTAssertFalse(FileManager.default.fileExists(atPath: storageRoot.registryURL.path))
    }

    func test_registryBootstrap_loadedRegistry_preservesContinuePendingMutationDisposition() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataPendingMutation")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let store = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.pending"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.pending",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(targetDomainID: "contacts", phase: .journaled)
        )
        try store.saveRegistry(registry)

        let result = try store.performSynchronousBootstrap()

        guard case .loadedRegistry(let loadedRegistry, let recoveryDisposition) = result.bootstrapOutcome else {
            return XCTFail("Expected loaded registry bootstrap outcome, got \(result.bootstrapOutcome)")
        }
        XCTAssertEqual(loadedRegistry, registry)
        XCTAssertEqual(recoveryDisposition, .continuePendingMutation)
        XCTAssertEqual(result.frameworkState, .sessionLocked)
    }

    func test_domainKeyManager_deriveWrappingRootKey_zeroizesInputAndWrapsDeterministicallyPerDomain() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataKeys")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        var rawSecret = Data(repeating: 0x7A, count: 32)
        let domainMasterKey = Data(repeating: 0x42, count: 32)

        let wrappingRootKey = try keyManager.deriveWrappingRootKey(from: &rawSecret)
        let firstDomainWrappingKey = try keyManager.deriveDomainWrappingKey(
            from: wrappingRootKey,
            domainID: "contacts"
        )
        let secondDomainWrappingKey = try keyManager.deriveDomainWrappingKey(
            from: wrappingRootKey,
            domainID: "settings"
        )
        let record = try keyManager.wrapDomainMasterKey(
            domainMasterKey,
            for: "contacts",
            wrappingRootKey: wrappingRootKey
        )
        let unwrappedDomainMasterKey = try keyManager.unwrapDomainMasterKey(
            from: record,
            wrappingRootKey: wrappingRootKey
        )

        XCTAssertTrue(rawSecret.allSatisfy { $0 == 0 })
        XCTAssertNotEqual(firstDomainWrappingKey, secondDomainWrappingKey)
        XCTAssertEqual(record.nonce.count, 12)
        XCTAssertEqual(record.tag.count, 16)
        XCTAssertEqual(record.ciphertext.count, 32)
        XCTAssertEqual(unwrappedDomainMasterKey, domainMasterKey)
    }

    func test_domainKeyManager_unwrapRejectsMalformedRecordLengths() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataMalformedRecord")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        var rawSecret = Data(repeating: 0x33, count: 32)
        let wrappingRootKey = try keyManager.deriveWrappingRootKey(from: &rawSecret)
        let malformedRecord = AppWrappedDomainMasterKeyRecord(
            formatVersion: 1,
            domainID: "contacts",
            nonce: Data(repeating: 0x01, count: 8),
            ciphertext: Data(repeating: 0x02, count: 31),
            tag: Data(repeating: 0x03, count: 15)
        )

        XCTAssertThrowsError(
            try keyManager.unwrapDomainMasterKey(
                from: malformedRecord,
                wrappingRootKey: wrappingRootKey
            )
        )
    }

    func test_sensitiveBytes_zeroize_clearsOwnedStorage() {
        var sensitiveBytes = CypherAir.SensitiveBytes(data: Data(repeating: 0xAB, count: 8))

        sensitiveBytes.zeroize()

        XCTAssertEqual(sensitiveBytes.dataCopy(), Data(repeating: 0x00, count: 8))
    }

    func test_sessionCoordinator_authorizeAndRelockClearsWrappingRootKeyAndUnlockedDomainKeys() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSession")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.session",
            secretData: Data(repeating: 0xAB, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.session"
        )
        let participant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(participant)

        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.session",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test authorization"
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xCD, count: 32), for: "contacts")

        XCTAssertEqual(authorizationResult, .authorized)
        XCTAssertEqual(coordinator.frameworkState, .sessionAuthorized)
        XCTAssertTrue(coordinator.hasActiveWrappingRootKey)
        XCTAssertTrue(keyManager.hasUnlockedDomainMasterKeys)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 1)

        await coordinator.relockCurrentSession()

        XCTAssertEqual(participant.relockCallCount, 1)
        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
    }

    func test_sessionRelockCoordinatorDeduplicatesParticipantsAndReportsFailures() async throws {
        let relockCoordinator = AppProtectedDataSessionRelockCoordinator()
        let successfulParticipant = MockProtectedDataRelockParticipant()
        let failingParticipant = MockProtectedDataRelockParticipant()
        failingParticipant.shouldThrow = true

        relockCoordinator.register(successfulParticipant)
        relockCoordinator.register(successfulParticipant)
        relockCoordinator.register(failingParticipant)

        let participantErrorOccurred = await relockCoordinator.relockParticipants()

        XCTAssertTrue(participantErrorOccurred)
        XCTAssertEqual(successfulParticipant.relockCallCount, 1)
        XCTAssertEqual(failingParticipant.relockCallCount, 1)
    }

    func test_sessionCoordinator_removePersistedSharedRightClearsWrappingRootKeyAndUnlockedDomainKeys() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSessionRemoveSharedRight")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let identifier = "com.cypherair.tests.protected-data.session-remove-shared-right"
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: identifier,
            secretData: Data(repeating: 0xA1, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: identifier
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: identifier,
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test authorization"
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xC1, count: 32), for: "contacts")

        XCTAssertEqual(authorizationResult, .authorized)
        XCTAssertTrue(coordinator.hasActiveWrappingRootKey)
        XCTAssertTrue(keyManager.hasUnlockedDomainMasterKeys)

        try await coordinator.removePersistedSharedRight(identifier: identifier)

        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
        XCTAssertFalse(coordinator.hasPersistedRootSecret(identifier: identifier))
        XCTAssertEqual(rightStoreClient.removeCallCount, 1)
        XCTAssertEqual(rightStoreClient.lastRemovedIdentifier, identifier)
    }

    func test_sessionCoordinator_reauthorizationClearsUnlockedDomainKeys() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSessionReauthorization")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let identifier = "com.cypherair.tests.protected-data.session-reauthorization"
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: identifier,
            secretData: Data(repeating: 0xA2, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: identifier
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: identifier,
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        let firstAuthorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test first authorization"
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xC2, count: 32), for: "contacts")
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: identifier,
            secretData: Data(repeating: 0xA3, count: 32)
        )

        let secondAuthorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test second authorization"
        )

        XCTAssertEqual(firstAuthorizationResult, .authorized)
        XCTAssertEqual(secondAuthorizationResult, .authorized)
        XCTAssertEqual(coordinator.frameworkState, .sessionAuthorized)
        XCTAssertTrue(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 2)
    }

    func test_sessionCoordinator_authorizationFloorRecordFailureReturnsRecoveryWithoutSessionKey() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSessionFloorFailure")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.session-floor-failure",
            secretData: Data(repeating: 0xA7, count: 32)
        )
        let floorRecorder = ThrowingRootSecretFloorRecorder()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.session-floor-failure",
            recordRootSecretEnvelopeMinimumVersion: { version in
                try await floorRecorder.record(version)
            }
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.session-floor-failure",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test floor failure"
        )
        let floorSnapshot = await floorRecorder.snapshot()

        XCTAssertEqual(authorizationResult, .frameworkRecoveryNeeded)
        XCTAssertEqual(coordinator.frameworkState, .frameworkRecoveryNeeded)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
        XCTAssertEqual(floorSnapshot.callCount, 1)
        XCTAssertEqual(floorSnapshot.lastVersion, ProtectedDataRootSecretEnvelope.currentFormatVersion)
    }

    func test_sessionCoordinator_authorizationUsesProvidedAppSessionContext() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSessionHandoff")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rootSecretStore = MockProtectedDataRightStoreClient()
        rootSecretStore.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.session-handoff",
            secretData: Data(repeating: 0xBC, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.session-handoff"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.session-handoff",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        let context = LAContext()
        defer { context.invalidate() }

        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test handoff",
            authenticationContext: context
        )

        XCTAssertEqual(authorizationResult, .authorized)
        XCTAssertTrue(rootSecretStore.lastAuthenticationContext === context)
        XCTAssertTrue(context.interactionNotAllowed)
        XCTAssertEqual(rootSecretStore.rightLookupCallCount, 1)
    }

    func test_sessionCoordinator_reprotectRootSecretDisallowsSecondInteraction() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataReprotectInteractionDisallowed")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rootSecretStore = MockProtectedDataRightStoreClient()
        rootSecretStore.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.reprotect",
            secretData: Data(repeating: 0xB7, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.reprotect"
        )
        let context = LAContext()
        defer { context.invalidate() }

        let didReprotect = try coordinator.reprotectPersistedRootSecretIfPresent(
            from: .userPresence,
            to: .biometricsOnly,
            authenticationContext: context
        )

        XCTAssertTrue(didReprotect)
        XCTAssertTrue(rootSecretStore.lastAuthenticationContext === context)
        XCTAssertTrue(context.interactionNotAllowed)
    }

    func test_sessionCoordinator_relockParticipantFailure_entersRestartRequired() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataRestartRequired")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.restart",
            secretData: Data(repeating: 0xAC, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.restart"
        )
        let participant = MockProtectedDataRelockParticipant()
        participant.shouldThrow = true
        coordinator.registerRelockParticipant(participant)

        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.restart",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test authorization"
        )
        await coordinator.relockCurrentSession()

        XCTAssertEqual(authorizationResult, .authorized)
        XCTAssertEqual(participant.relockCallCount, 1)
        XCTAssertEqual(coordinator.frameworkState, .restartRequired)
        let blockedResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Blocked after restartRequired"
        )
        XCTAssertEqual(blockedResult, .frameworkRecoveryNeeded)
    }

    func test_preAuthBootstrap_doesNotTouchRightStoreClient() throws {
        let engine = PgpEngine()
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let defaultsSuiteName = "com.cypherair.tests.protected-data.startup.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let config = AppConfiguration(defaults: defaults)
        let protectedDataBaseDirectory = makeTemporaryDirectory("ProtectedDataStartup")
        let documentDirectory = makeTemporaryDirectory("ProtectedDataStartupDocuments")
        let contactsDirectory = documentDirectory.appendingPathComponent("contacts", isDirectory: true)
        let legacySelfTestReportsDirectory = documentDirectory.appendingPathComponent("self-test", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: protectedDataBaseDirectory) }
        defer { try? FileManager.default.removeItem(at: documentDirectory) }
        try FileManager.default.createDirectory(at: contactsDirectory, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: legacySelfTestReportsDirectory, withIntermediateDirectories: true)
        try Data("legacy self-test report".utf8).write(
            to: legacySelfTestReportsDirectory.appendingPathComponent("self-test-legacy.txt")
        )

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: protectedDataBaseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: AppProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let recoveryCoordinator = AppProtectedDomainRecoveryCoordinator(registryStore: registryStore)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let protectedDataSessionCoordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: AppProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let protectedSettingsStore = ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let protectedOrdinarySettingsCoordinator = AppProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: protectedSettingsStore
            )
        )
        let protectedDataFrameworkSentinelStore = AppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let privateKeyControlStore = AppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        authManager.configurePrivateKeyControlStore(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedSettingsStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedDataFrameworkSentinelStore)
        let appSessionOrchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                try recoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: {
                protectedOrdinarySettingsCoordinator.gracePeriodForSession
            },
            evaluateAppAuthentication: { reason in
                try await authManager.evaluateAppSession(
                    policy: config.appSessionAuthenticationPolicy,
                    reason: reason
                )
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore
        )
        let contactService = ContactService(engine: engine, contactsDirectory: contactsDirectory)
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let encryptionService = EncryptionService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let decryptionService = DecryptionService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let passwordMessageService = PasswordMessageService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let signingService = SigningService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let certificateSignatureService = CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let qrService = QRService(engine: engine)
        let selfTestService = SelfTestService(engine: engine)
        let localDataResetService = LocalDataResetService(
            keychain: keychain,
            protectedDataStorageRoot: storageRoot,
            contactsDirectory: contactsDirectory,
            defaults: defaults,
            defaultsDomainName: defaultsSuiteName,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            authManager: authManager,
            keyManagement: keyManagement,
            contactService: contactService,
            selfTestService: selfTestService,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator,
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory
        )
        let container = AppAppContainer(
            authLifecycleTraceStore: nil,
            authenticationShieldCoordinator: CypherAir.AuthenticationShieldCoordinator(),
            authPromptCoordinator: authPromptCoordinator,
            secureEnclave: secureEnclave,
            keychain: keychain,
            authManager: authManager,
            config: config,
            protectedOrdinarySettingsCoordinator: protectedOrdinarySettingsCoordinator,
            protectedDataStorageRoot: storageRoot,
            protectedDataRegistryStore: registryStore,
            protectedDomainKeyManager: domainKeyManager,
            protectedDomainRecoveryCoordinator: recoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            protectedSettingsStore: protectedSettingsStore,
            protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore,
            appSessionOrchestrator: appSessionOrchestrator,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            encryptionService: encryptionService,
            decryptionService: decryptionService,
            passwordMessageService: passwordMessageService,
            signingService: signingService,
            certificateSignatureService: certificateSignatureService,
            qrService: qrService,
            selfTestService: selfTestService,
            localDataResetService: localDataResetService,
            contactsDirectory: contactsDirectory,
            legacySelfTestReportsDirectory: legacySelfTestReportsDirectory,
            defaultsSuiteName: defaultsSuiteName
        )

        let snapshot = AppAppStartupCoordinator().performPreAuthBootstrap(using: container)

        guard case .emptySteadyState(_, let didBootstrap) = snapshot.bootstrapOutcome else {
            return XCTFail("Expected empty steady-state startup snapshot, got \(snapshot.bootstrapOutcome)")
        }
        XCTAssertEqual(snapshot.protectedDataFrameworkState, AppProtectedDataFrameworkState.sessionLocked)
        XCTAssertTrue(didBootstrap)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
        XCTAssertEqual(rightStoreClient.saveWithoutSecretCallCount, 0)
        XCTAssertEqual(rightStoreClient.saveWithSecretCallCount, 0)
        XCTAssertEqual(keychain.listItemsCallCount, 0)
        XCTAssertEqual(keychain.loadCallCount, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacySelfTestReportsDirectory.path))
        XCTAssertEqual(protectedDataSessionCoordinator.frameworkState, AppProtectedDataFrameworkState.sessionLocked)
    }

    func test_handleInitialAppearance_nonBypassAlwaysAuthenticates() async throws {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataInitialAppearance")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.initial-appearance",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleInitialAppearance(
            localizedReason: "Initial appearance should authenticate"
        )
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertTrue(didEvaluate)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(relockParticipant.relockCallCount, 1)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleInitialAppearance_uiTestBypassSkipsAuthentication() async throws {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataInitialAppearanceBypass")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.initial-appearance-bypass",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { true },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleInitialAppearance(
            localizedReason: "UI test bypass should skip authentication"
        )
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication)
        XCTAssertFalse(didEvaluate)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_externalAuthenticationPromptInProgress_skipsRelockAndAuthentication() async throws {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResumeSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resume-suppression",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        defer { authPromptCoordinator.endOperationPrompt() }

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "External prompt in progress"
        )
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
    }

    func test_handleSceneDidResignActive_externalAuthenticationPromptInProgress_doesNotBlurPrivacyScreen() {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResignSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resign-suppression",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        defer { authPromptCoordinator.endOperationPrompt() }

        orchestrator.handleSceneDidResignActive()

        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_lateLifecycleAfterOperationPromptEnds_doesNotTriggerPrivacyResumeAuthentication() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataLateLifecycleSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.late-lifecycle",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        var gate = AppPrivacyScreenLifecycleGate()

        authPromptCoordinator.beginOperationPrompt()
        authPromptCoordinator.endOperationPrompt()

        gate.syncOperationAuthenticationAttemptGeneration(
            orchestrator.operationAuthenticationAttemptGeneration
        )
        if gate.shouldHandleInactive(
            isAuthenticating: orchestrator.isAuthenticating,
            isOperationPromptInProgress: orchestrator.isOperationAuthenticationPromptInProgress
        ) == .handle {
            orchestrator.handleSceneDidResignActive()
        }

        gate.syncOperationAuthenticationAttemptGeneration(
            orchestrator.operationAuthenticationAttemptGeneration
        )
        let attemptedAuthentication: Bool
        if gate.shouldHandleBecomeActive(
            isAuthenticating: orchestrator.isAuthenticating,
            isOperationPromptInProgress: orchestrator.isOperationAuthenticationPromptInProgress
        ) == .handle {
            attemptedAuthentication = await orchestrator.handleResume(
                localizedReason: "Late lifecycle after operation prompt"
            )
        } else {
            attemptedAuthentication = false
        }

        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(attemptedAuthentication)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_authenticationSettleInactive_blursWithoutRelockOrAuthentication() async throws {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataAuthenticationSettleInactive")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.auth-settle-inactive",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        orchestrator.handleAuthenticationSettleInactive(source: "unit.authSettleInactive")
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
    }

    func test_authenticationSettleActive_hidesTransientBlurWithoutAuthentication() async throws {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataAuthenticationSettleActive")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.auth-settle-active",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        orchestrator.handleAuthenticationSettleInactive(source: "unit.authSettleInactive")
        orchestrator.handleAuthenticationSettleActive(source: "unit.authSettleActive")
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertEqual(relockParticipant.relockCallCount, 0)
        XCTAssertFalse(didEvaluate)
    }

    func test_authenticationSettleActive_keepsRetryOverlayAfterAuthFailure() async throws {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataAuthenticationSettleFailure")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.auth-settle-failure",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        orchestrator.authFailed = true
        orchestrator.handleAuthenticationSettleInactive(source: "unit.authSettleInactive")
        orchestrator.handleAuthenticationSettleActive(source: "unit.authSettleActive")
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
        XCTAssertTrue(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.contentClearGeneration, 0)
        XCTAssertFalse(didEvaluate)
    }

    func test_realResignClearsTransientSettleBlurAndRemainsBlurred() {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataAuthenticationSettleRealResign")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.auth-settle-real-resign",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        orchestrator.handleAuthenticationSettleInactive(source: "unit.authSettleInactive")
        orchestrator.handleSceneDidResignActive()
        orchestrator.handleAuthenticationSettleActive(source: "unit.authSettleActive")

        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
        XCTAssertFalse(orchestrator.authFailed)
    }

    func test_handleSceneDidEnterBackground_duringExternalAuthenticationPrompt_blursPrivacyScreen() {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataBackgroundSuppression")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.background-suppression",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        defer { authPromptCoordinator.endOperationPrompt() }

        orchestrator.handleSceneDidEnterBackground()

        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_successfulAuthentication_doesNotActivateProtectedDataSession() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResumeNoWarmUp")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let handoffContext = LAContext()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resume-no-warmup",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .authenticated(context: handoffContext) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Successful privacy unlock should not warm protected settings"
        )

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
        XCTAssertTrue(orchestrator.consumeAuthenticatedContextForProtectedData() === handoffContext)
        XCTAssertNil(orchestrator.consumeAuthenticatedContextForProtectedData())
        handoffContext.invalidate()
    }

    func test_handleResume_successfulAuthenticationIncrementsPostAuthenticationGenerationAfterHandler() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataPostAuthenticationGeneration")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-auth-generation",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didRunPostAuthenticationHandler = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            postAuthenticationHandler: { _, _ in
                await didRunPostAuthenticationHandler.setTrue()
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 0)

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Successful privacy unlock should publish post-auth generation"
        )
        let didRunHandler = await didRunPostAuthenticationHandler.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertTrue(didRunHandler)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 1)
    }

    func test_handleResume_failedAuthenticationDoesNotIncrementPostAuthenticationGeneration() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataFailedPostAuthenticationGeneration")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.failed-post-auth-generation",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didRunPostAuthenticationHandler = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .failed },
            postAuthenticationHandler: { _, _ in
                await didRunPostAuthenticationHandler.setTrue()
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Failed privacy unlock should not publish post-auth generation"
        )
        let didRunHandler = await didRunPostAuthenticationHandler.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertFalse(didRunHandler)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 0)
        XCTAssertTrue(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.authenticationFailureReason, .authenticationFailed)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_biometricsLockoutSetsFailureReasonAndKeepsPrivacyOverlay() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataBiometricsLockout")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.biometrics-lockout",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let didRunPostAuthenticationHandler = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                throw AuthenticationError.appAccessBiometricsLockedOut
            },
            postAuthenticationHandler: { _, _ in
                await didRunPostAuthenticationHandler.setTrue()
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Locked out privacy unlock should keep content hidden"
        )
        let didRunHandler = await didRunPostAuthenticationHandler.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertFalse(didRunHandler)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 0)
        XCTAssertNil(orchestrator.lastAuthenticationDate)
        XCTAssertTrue(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.authenticationFailureReason, .biometricsLockedOut)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
    }

    func test_handleResume_successfulAuthenticationClearsPreviousFailureReason() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataClearsFailureReason")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: MockProtectedDataRightStoreClient(),
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.clears-failure-reason",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let authenticationAttempts = AsyncIntegerCounter()
        let didRunPostAuthenticationHandler = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                if await authenticationAttempts.next() == 1 {
                    throw AuthenticationError.appAccessBiometricsLockedOut
                }
                return .authenticated(context: nil)
            },
            postAuthenticationHandler: { _, _ in
                await didRunPostAuthenticationHandler.setTrue()
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        let firstAttempt = await orchestrator.handleResume(
            localizedReason: "First privacy unlock attempt is locked out"
        )

        XCTAssertTrue(firstAttempt)
        XCTAssertTrue(orchestrator.authFailed)
        XCTAssertEqual(orchestrator.authenticationFailureReason, .biometricsLockedOut)
        XCTAssertTrue(orchestrator.isPrivacyScreenBlurred)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 0)

        let secondAttempt = await orchestrator.handleResume(
            localizedReason: "Second privacy unlock succeeds"
        )
        let didRunHandler = await didRunPostAuthenticationHandler.currentValue()

        XCTAssertTrue(secondAttempt)
        XCTAssertTrue(didRunHandler)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertNil(orchestrator.authenticationFailureReason)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertEqual(orchestrator.postAuthenticationGeneration, 1)
    }

    func test_appAccessPolicyChange_discardsPendingProtectedDataHandoffContext() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataPolicyChangeHandoff")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let handoffContext = LAContext()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.policy-change-handoff",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in .authenticated(context: handoffContext) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        defer {
            if orchestrator.hasProtectedDataAuthorizationHandoffContext {
                handoffContext.invalidate()
            }
        }

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Successful privacy unlock stores handoff before policy change"
        )

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertTrue(orchestrator.hasProtectedDataAuthorizationHandoffContext)

        orchestrator.discardProtectedDataAuthorizationHandoffContextForPolicyChange()

        XCTAssertFalse(orchestrator.hasProtectedDataAuthorizationHandoffContext)
        XCTAssertNil(orchestrator.consumeAuthenticatedContextForProtectedData())
    }

    func test_handleResume_afterBackgroundFollowingOperationPrompt_treatsReturnAsRealResume() async {
        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("ProtectedDataResumeAfterBackground")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.resume-after-background",
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let relockParticipant = MockProtectedDataRelockParticipant()
        coordinator.registerRelockParticipant(relockParticipant)
        let didEvaluateAuthentication = AsyncBooleanFlag()
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Not used in this test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            evaluateAppAuthentication: { _ in
                await didEvaluateAuthentication.setTrue()
                return .authenticated(context: nil)
            },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )

        authPromptCoordinator.beginOperationPrompt()
        orchestrator.handleSceneDidEnterBackground()
        authPromptCoordinator.endOperationPrompt()

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Resume after a real background should still re-authenticate"
        )
        let didEvaluate = await didEvaluateAuthentication.currentValue()

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertTrue(didEvaluate)
        XCTAssertEqual(orchestrator.contentClearGeneration, 1)
        XCTAssertEqual(relockParticipant.relockCallCount, 1)
        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.authFailed)
        XCTAssertFalse(orchestrator.isPrivacyScreenBlurred)
    }

    func test_accessGateClassifier_classifiesBootstrapAndSessionStates() throws {
        let sharedRightIdentifier = "com.cypherair.tests.protected-data.gate.classifier"
        let emptyRegistry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: sharedRightIdentifier
        )
        let pendingRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: sharedRightIdentifier,
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(targetDomainID: "contacts", phase: .journaled)
        )
        let readyRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: sharedRightIdentifier,
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        XCTAssertEqual(
            AppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .emptySteadyState(registry: emptyRegistry, didBootstrap: false),
                frameworkState: .sessionLocked
            ),
            .noProtectedDomainPresent
        )
        XCTAssertEqual(
            AppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: pendingRegistry, recoveryDisposition: .continuePendingMutation),
                frameworkState: .sessionLocked
            ),
            .pendingMutationRecoveryRequired
        )
        XCTAssertEqual(
            AppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: readyRegistry, recoveryDisposition: .frameworkRecoveryNeeded),
                frameworkState: .sessionLocked
            ),
            .frameworkRecoveryNeeded
        )
        XCTAssertEqual(
            AppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: readyRegistry, recoveryDisposition: .resumeSteadyState),
                frameworkState: .sessionLocked
            ),
            .authorizationRequired(registry: readyRegistry)
        )
        XCTAssertEqual(
            AppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: readyRegistry, recoveryDisposition: .resumeSteadyState),
                frameworkState: .sessionAuthorized
            ),
            .alreadyAuthorized(registry: readyRegistry)
        )
        XCTAssertEqual(
            AppProtectedDataAccessGateClassifier.evaluate(
                bootstrapOutcome: .loadedRegistry(registry: readyRegistry, recoveryDisposition: .resumeSteadyState),
                frameworkState: .restartRequired
            ),
            .frameworkRecoveryNeeded
        )
    }

    func test_accessGateClassifier_afterFirstAccessReloadsCurrentRegistry() throws {
        let sharedRightIdentifier = "com.cypherair.tests.protected-data.gate.classifier-reload"
        let startupRegistry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: sharedRightIdentifier
        )
        let currentRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: sharedRightIdentifier,
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        var currentRegistryLookupCount = 0
        let classifier = AppProtectedDataAccessGateClassifier(
            currentRegistryProvider: {
                currentRegistryLookupCount += 1
                return currentRegistry
            },
            frameworkStateProvider: { .sessionLocked }
        )

        let decision = classifier.evaluate(
            startupBootstrapOutcome: .emptySteadyState(registry: startupRegistry, didBootstrap: true),
            isFirstProtectedAccessInCurrentProcess: false
        )

        XCTAssertEqual(currentRegistryLookupCount, 1)
        XCTAssertEqual(decision, .authorizationRequired(registry: currentRegistry))
    }

    func test_accessGateClassifier_currentRegistryLookupFailureFailsClosed() throws {
        let sharedRightIdentifier = "com.cypherair.tests.protected-data.gate.classifier-failure"
        let startupRegistry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: sharedRightIdentifier
        )
        let classifier = AppProtectedDataAccessGateClassifier(
            currentRegistryProvider: {
                throw ProtectedDataError.invalidRegistry("Registry unavailable")
            },
            frameworkStateProvider: { .sessionAuthorized }
        )

        let decision = classifier.evaluate(
            startupBootstrapOutcome: .emptySteadyState(registry: startupRegistry, didBootstrap: true),
            isFirstProtectedAccessInCurrentProcess: false
        )

        XCTAssertEqual(decision, .frameworkRecoveryNeeded)
    }

    func test_accessGate_emptySteadyState_returnsNoProtectedDomainPresent() throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessEmpty"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.empty"
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("Should not be called") },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator
        )
        let registry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.empty"
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .emptySteadyState(registry: registry, didBootstrap: false),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .noProtectedDomainPresent)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
    }

    func test_accessGate_continuePendingMutation_returnsPendingMutationRecoveryRequired() throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessPending"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.pending"
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("Should not be called") },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.pending",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(targetDomainID: "contacts", phase: .journaled)
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .continuePendingMutation),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .pendingMutationRecoveryRequired)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
    }

    func test_accessGate_readyRegistryWithoutAuthorization_requiresAuthorization() throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessAuth"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.auth"
        )
        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("Should not be called") },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.auth",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        guard case .authorizationRequired(let authorizationRegistry) = decision else {
            return XCTFail("Expected authorizationRequired gate decision, got \(decision)")
        }
        XCTAssertEqual(authorizationRegistry, registry)
    }

    func test_accessGate_readyRegistryWithAuthorizedSession_returnsAlreadyAuthorized() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessAlreadyAuthorized"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.gate.reuse",
            secretData: Data(repeating: 0xAD, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.reuse"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.reuse",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )
        XCTAssertEqual(authorizationResult, .authorized)

        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { registry },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        guard case .alreadyAuthorized(let reusedRegistry) = decision else {
            return XCTFail("Expected alreadyAuthorized gate decision, got \(decision)")
        }
        XCTAssertEqual(reusedRegistry, registry)
    }

    func test_accessGate_readyRegistryWithLatchedFrameworkRecovery_returnsFrameworkRecoveryNeeded() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessFrameworkRecovery"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.framework-recovery"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.framework-recovery",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Trigger framework recovery"
        )
        XCTAssertEqual(authorizationResult, .frameworkRecoveryNeeded)
        XCTAssertEqual(coordinator.frameworkState, .frameworkRecoveryNeeded)

        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { registry },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .frameworkRecoveryNeeded)
    }

    func test_accessGate_readyRegistryWithRestartRequired_returnsFrameworkRecoveryNeeded() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAccessRestartRequired"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.gate.restart-required",
            secretData: Data(repeating: 0xB0, count: 32)
        )
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.restart-required"
        )
        let participant = MockProtectedDataRelockParticipant()
        participant.shouldThrow = true
        coordinator.registerRelockParticipant(participant)
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.gate.restart-required",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        let authorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )
        XCTAssertEqual(authorizationResult, .authorized)
        await coordinator.relockCurrentSession()
        XCTAssertEqual(coordinator.frameworkState, .restartRequired)

        let orchestrator = AppAppSessionOrchestrator(
            currentRegistryProvider: { registry },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 180 },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator
        )

        let decision = orchestrator.evaluateProtectedDataAccessGate(
            startupBootstrapOutcome: .loadedRegistry(registry: registry, recoveryDisposition: .resumeSteadyState),
            isFirstProtectedAccessInCurrentProcess: true
        )

        XCTAssertEqual(decision, .frameworkRecoveryNeeded)
    }

    func test_postUnlockCoordinator_opensCommittedRegisteredDomainWithHandoffContext() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockOpen"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        rightStoreClient.persistedRightHandle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.post-unlock.open",
            secretData: Data(repeating: 0xCA, count: 32)
        )
        let sessionCoordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.open"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.open",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: nil
        )
        let openCalled = AsyncBooleanFlag()
        let coordinator = AppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                AppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { wrappingRootKey in
                        XCTAssertEqual(wrappingRootKey.count, 32)
                        await openCalled.setTrue()
                    }
                )
            ]
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }

        let outcome = await coordinator.openRegisteredDomains(
            authenticationContext: handoffContext,
            localizedReason: "Open protected domains",
            source: "unitTest"
        )

        XCTAssertEqual(outcome, .opened([CypherAir.ProtectedSettingsStore.domainID]))
        let didOpen = await openCalled.currentValue()
        XCTAssertTrue(didOpen)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionAuthorized)
        XCTAssertTrue(rightStoreClient.lastAuthenticationContext === handoffContext)
        XCTAssertTrue(handoffContext.interactionNotAllowed)
    }

    func test_postUnlockCoordinator_withoutContextDoesNotAuthorize() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockNoContext"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let rightStoreClient = MockProtectedDataRightStoreClient()
        let sessionCoordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.no-context"
        )
        let coordinator = AppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: {
                XCTFail("Registry should not load without an authenticated context.")
                return ProtectedDataRegistry.emptySteadyState(sharedRightIdentifier: "unused")
            },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                AppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { _ in XCTFail("Domain should not open without an authenticated context.") }
                )
            ]
        )

        let outcome = await coordinator.openRegisteredDomains(
            authenticationContext: nil,
            localizedReason: "Open protected domains",
            source: "unitTest"
        )

        XCTAssertEqual(outcome, .noAuthenticatedContext)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionLocked)
    }

    func test_postUnlockCoordinator_pendingMutationDoesNotOpenDomain() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockPending"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let rightStoreClient = MockProtectedDataRightStoreClient()
        let sessionCoordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.pending"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.pending",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .journaled
            )
        )
        let openCalled = AsyncBooleanFlag()
        let coordinator = AppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                AppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { _ in await openCalled.setTrue() }
                )
            ]
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }

        let outcome = await coordinator.openRegisteredDomains(
            authenticationContext: handoffContext,
            localizedReason: "Open protected domains",
            source: "unitTest"
        )

        XCTAssertEqual(outcome, .pendingMutationRecoveryRequired)
        let didOpen = await openCalled.currentValue()
        XCTAssertFalse(didOpen)
        XCTAssertEqual(rightStoreClient.rightLookupCallCount, 0)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionLocked)
    }

    func test_postUnlockCoordinator_defersLegacyMigrationWithoutSecondPrompt() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockLegacy"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let legacyRightStoreClient = MockProtectedDataRightStoreClient()
        let legacyRight = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.post-unlock.legacy",
            secretData: Data(repeating: 0xC9, count: 32)
        )
        legacyRightStoreClient.persistedRightHandle = legacyRight
        let rootSecretStore = AppMockProtectedDataRootSecretStore()
        let sessionCoordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            legacyRightStoreClient: legacyRightStoreClient,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.legacy"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.post-unlock.legacy",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: nil
        )
        let openCalled = AsyncBooleanFlag()
        let coordinator = AppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                AppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { _ in await openCalled.setTrue() }
                )
            ]
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }

        let outcome = await coordinator.openRegisteredDomains(
            authenticationContext: handoffContext,
            localizedReason: "Open protected domains",
            source: "unitTest"
        )

        XCTAssertEqual(outcome, .authorizationDenied)
        XCTAssertEqual(rootSecretStore.loadCallCount, 1)
        XCTAssertTrue(rootSecretStore.lastAuthenticationContext === handoffContext)
        XCTAssertTrue(handoffContext.interactionNotAllowed)
        XCTAssertEqual(legacyRightStoreClient.rightLookupCallCount, 0)
        XCTAssertEqual(legacyRight.authorizeCallCount, 0)
        let didOpen = await openCalled.currentValue()
        XCTAssertFalse(didOpen)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionLocked)
    }

    func test_postUnlockCoordinator_createsAndOpensFrameworkSentinelAsSecondDomain() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataPostUnlockSentinel"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let sharedRightIdentifier = "com.cypherair.tests.protected-data.post-unlock.sentinel"
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: sharedRightIdentifier
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rootSecretStore = MockProtectedDataRightStoreClient()
        let sessionCoordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: sharedRightIdentifier
        )
        let defaultsSuiteName = "com.cypherair.tests.protected-data.post-unlock.sentinel.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        let protectedSettingsStore = ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try sessionCoordinator.wrappingRootKeyData()
            }
        )
        let sentinelStore = AppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try sessionCoordinator.wrappingRootKeyData()
            }
        )
        try await protectedSettingsStore.ensureCommittedAndMigrateSettingsIfNeeded(
            persistSharedRight: { secret in
                try rootSecretStore.saveRootSecret(
                    secret,
                    identifier: sharedRightIdentifier,
                    policy: .userPresence
                )
            }
        )

        let coordinator = AppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { try registryStore.loadRegistry() },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                AppProtectedDataPostUnlockDomainOpener(
                    domainID: CypherAir.ProtectedSettingsStore.domainID,
                    open: { wrappingRootKey in
                        _ = try await protectedSettingsStore.openDomainIfNeeded(
                            wrappingRootKey: wrappingRootKey
                        )
                    }
                ),
                AppProtectedDataPostUnlockDomainOpener(
                    domainID: AppProtectedDataFrameworkSentinelStore.domainID,
                    ensureCommittedIfNeeded: { wrappingRootKey in
                        try await sentinelStore.ensureCommittedIfNeeded(
                            wrappingRootKey: wrappingRootKey
                        )
                    },
                    open: { wrappingRootKey in
                        _ = try await sentinelStore.openDomainIfNeeded(
                            wrappingRootKey: wrappingRootKey
                        )
                    }
                )
            ]
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }

        let outcome = await coordinator.openRegisteredDomains(
            authenticationContext: handoffContext,
            localizedReason: "Open protected domains",
            source: "unitTest"
        )
        let registry = try registryStore.loadRegistry()

        XCTAssertEqual(
            outcome,
            .opened([
                CypherAir.ProtectedSettingsStore.domainID,
                AppProtectedDataFrameworkSentinelStore.domainID
            ])
        )
        XCTAssertEqual(registry.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertEqual(registry.committedMembership[AppProtectedDataFrameworkSentinelStore.domainID], .active)
        XCTAssertEqual(registry.pendingMutation, nil)
        XCTAssertEqual(sentinelStore.payload, .current)
        XCTAssertEqual(rootSecretStore.rightLookupCallCount, 1)
        XCTAssertTrue(rootSecretStore.lastAuthenticationContext === handoffContext)
        XCTAssertTrue(handoffContext.interactionNotAllowed)
    }

    func test_privateKeyControl_emptyRegistryRequiresHandoffContext() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("PrivateKeyControlNoHandoff"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.private-key-control.no-handoff"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let defaultsSuiteName = "com.cypherair.tests.private-key-control.no-handoff.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        defaults.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.authModeKey)
        let store = AppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot)
        )

        let created = try await store.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
            authenticationContext: nil,
            persistSharedRight: { _ in XCTFail("Root secret must not be persisted without a handoff context") }
        )

        XCTAssertFalse(created)
        XCTAssertNil(try registryStore.loadRegistry().committedMembership[AppPrivateKeyControlStore.domainID])
        XCTAssertEqual(defaults.string(forKey: AuthPreferences.authModeKey), AuthenticationMode.highSecurity.rawValue)
        XCTAssertEqual(store.privateKeyControlState, .locked)
    }

    func test_privateKeyControl_emptyRegistryCreatesFirstDomainAndMigratesLegacyJournal() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("PrivateKeyControlFirstDomain"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.private-key-control.first"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let defaultsSuiteName = "com.cypherair.tests.private-key-control.first.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        defaults.set(AuthenticationMode.highSecurity.rawValue, forKey: AuthPreferences.authModeKey)
        defaults.set(true, forKey: AuthPreferences.rewrapInProgressKey)
        defaults.set(AuthenticationMode.standard.rawValue, forKey: AuthPreferences.rewrapTargetModeKey)
        defaults.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        defaults.set("abc123", forKey: AuthPreferences.modifyExpiryFingerprintKey)
        let store = AppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }
        let persistedSecretBox = AsyncDataBox()

        let created = try await store.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
            authenticationContext: handoffContext,
            persistSharedRight: { secret in await persistedSecretBox.set(secret) }
        )

        XCTAssertTrue(created)
        XCTAssertEqual(try registryStore.loadRegistry().committedMembership[AppPrivateKeyControlStore.domainID], .active)
        XCTAssertNil(defaults.string(forKey: AuthPreferences.authModeKey))
        XCTAssertFalse(defaults.bool(forKey: AuthPreferences.rewrapInProgressKey))
        XCTAssertNil(defaults.string(forKey: AuthPreferences.rewrapTargetModeKey))
        XCTAssertFalse(defaults.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))
        XCTAssertNil(defaults.string(forKey: AuthPreferences.modifyExpiryFingerprintKey))

        var rootSecret = await persistedSecretBox.data()
        XCTAssertFalse(rootSecret.isEmpty)
        let wrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()
        let payload = try await store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)

        XCTAssertEqual(payload.settings.authMode, .highSecurity)
        XCTAssertEqual(payload.recoveryJournal.rewrapTargetMode, .standard)
        XCTAssertEqual(payload.recoveryJournal.modifyExpiry?.fingerprint, "abc123")
        XCTAssertEqual(try store.requireUnlockedAuthMode(), .highSecurity)
    }

    func test_realComponents_privateKeyControlFirstLeavesSettingsMigrationNeedingAuthorizedSessionAfterRestart() async throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave is required for the real ProtectedData root-secret store.")
        }

        let baseDirectory = makeTemporaryDirectory("RealProtectedDataPrivateKeyControlFirst")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }
        let account = "com.cypherair.tests.real-components.\(UUID().uuidString)"
        let sharedRightIdentifier = "com.cypherair.tests.real-components.shared-right.\(UUID().uuidString)"
        let systemKeychain = SystemKeychain()
        let formatFloorStore = ProtectedDataRootSecretFormatFloorStore(
            keychain: systemKeychain,
            account: account
        )
        let deviceBindingProvider = HardwareProtectedDataDeviceBindingProvider(
            keychain: systemKeychain,
            account: account
        )
        let rootSecretStore = KeychainProtectedDataRootSecretStore(
            account: account,
            supportKeychain: systemKeychain,
            deviceBindingProvider: deviceBindingProvider,
            formatFloorStore: formatFloorStore
        )
        defer {
            try? rootSecretStore.deleteRootSecret(identifier: sharedRightIdentifier)
            try? formatFloorStore.deleteMarker()
            try? systemKeychain.delete(
                service: KeychainConstants.protectedDataDeviceBindingKeyService,
                account: account,
                authenticationContext: nil
            )
        }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: sharedRightIdentifier
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)

        let defaultsSuiteName = "com.cypherair.tests.real-components.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        let privateKeyControlStore = AppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager
        )
        let initialSessionCoordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: sharedRightIdentifier
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }

        let created = try await privateKeyControlStore.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
            authenticationContext: handoffContext,
            persistSharedRight: { secret in
                try await initialSessionCoordinator.persistSharedRight(secretData: secret)
            }
        )

        XCTAssertTrue(created)
        XCTAssertTrue(initialSessionCoordinator.hasPersistedRootSecret(identifier: sharedRightIdentifier))
        XCTAssertEqual(
            try registryStore.loadRegistry().committedMembership[AppPrivateKeyControlStore.domainID],
            .active
        )

        let restartedSessionCoordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: sharedRightIdentifier
        )
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: {
                try restartedSessionCoordinator.wrappingRootKeyData()
            }
        )

        XCTAssertEqual(settingsStore.migrationAuthorizationRequirement(), .wrappingRootKeyRequired)
        do {
            try await settingsStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("A second ProtectedData domain must reuse the existing shared root.")
                }
            )
            XCTFail("Expected migration to require an authorized wrapping root key after restart.")
        } catch ProtectedDataError.missingWrappingRootKey {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func test_privateKeyControl_pendingMutationFailsClosed() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("PrivateKeyControlPending"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.private-key-control.pending"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.private-key-control.pending",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: AppProtectedDataFrameworkSentinelStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)
        let defaultsSuiteName = "com.cypherair.tests.private-key-control.pending.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        let store = AppPrivateKeyControlStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot)
        )

        do {
            try await store.ensureCommittedIfNeeded(wrappingRootKey: Data(repeating: 0xC1, count: 32))
            XCTFail("Expected pending mutation to block private-key-control creation.")
        } catch PrivateKeyControlError.recoveryNeeded {
        } catch {
            XCTFail("Expected recoveryNeeded, got \(error)")
        }
        XCTAssertEqual(store.privateKeyControlState, .recoveryNeeded)
    }

    func test_frameworkSentinel_doesNotCreateFirstDomainFromEmptyRegistry() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataSentinelEmpty"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.sentinel.empty"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let sentinelStore = AppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot)
        )

        try await sentinelStore.ensureCommittedIfNeeded(
            wrappingRootKey: Data(repeating: 0xE1, count: 32)
        )

        let registry = try registryStore.loadRegistry()
        XCTAssertTrue(registry.committedMembership.isEmpty)
        XCTAssertNil(registry.pendingMutation)
        XCTAssertEqual(registry.sharedResourceLifecycleState, .absent)
    }

    func test_postUnlockCoordinator_emptyRegistryWithSentinelOpenerDoesNotReadRootSecret() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataSentinelEmptyPostUnlock"))
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let registry = ProtectedDataRegistry.emptySteadyState(
            sharedRightIdentifier: "com.cypherair.tests.protected-data.sentinel.empty-post-unlock"
        )
        let rootSecretStore = MockProtectedDataRightStoreClient()
        let sessionCoordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: registry.sharedRightIdentifier
        )
        let coordinator = AppProtectedDataPostUnlockCoordinator(
            currentRegistryProvider: { registry },
            protectedDataSessionCoordinator: sessionCoordinator,
            domainOpeners: [
                AppProtectedDataPostUnlockDomainOpener(
                    domainID: AppProtectedDataFrameworkSentinelStore.domainID,
                    ensureCommittedIfNeeded: { _ in XCTFail("Sentinel should not be created for an empty registry.") },
                    open: { _ in XCTFail("Sentinel should not open for an empty registry.") }
                )
            ]
        )
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }

        let outcome = await coordinator.openRegisteredDomains(
            authenticationContext: handoffContext,
            localizedReason: "Open protected domains",
            source: "unitTest"
        )

        XCTAssertEqual(outcome, .noProtectedDomainPresent)
        XCTAssertEqual(rootSecretStore.rightLookupCallCount, 0)
        XCTAssertEqual(sessionCoordinator.frameworkState, .sessionLocked)
    }

    func test_authorization_missingRight_returnsFrameworkRecoveryNeeded() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationMissingRight"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.missing"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.missing",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xD1, count: 32), for: "contacts")

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )

        XCTAssertEqual(result, .frameworkRecoveryNeeded)
        XCTAssertEqual(coordinator.frameworkState, .frameworkRecoveryNeeded)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
    }

    func test_authorization_legacyMigrationDeferredClearsUnlockedDomainKeys() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationDeferredMigration"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.deferred-migration"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.deferred-migration",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xD3, count: 32), for: "contacts")

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data",
            allowLegacyMigration: false
        )

        XCTAssertEqual(result, .cancelledOrDenied)
        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
    }

    func test_authorization_secretUnreadable_returnsFrameworkRecoveryNeededAndDeauthorizes() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationUnreadableSecret"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let handle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.authorization.secret",
            secretData: Data(repeating: 0xAE, count: 32)
        )
        handle.rawSecretError = ProtectedDataError.internalFailure("secret unreadable")
        rightStoreClient.persistedRightHandle = handle
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.secret"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.secret",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )
        keyManager.cacheUnlockedDomainMasterKey(Data(repeating: 0xD2, count: 32), for: "contacts")

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )

        XCTAssertEqual(result, .frameworkRecoveryNeeded)
        XCTAssertEqual(coordinator.frameworkState, .frameworkRecoveryNeeded)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
    }

    func test_authorization_userCancelled_returnsCancelledOrDenied() async throws {
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory("ProtectedDataAuthorizationCancelled"))
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let rightStoreClient = MockProtectedDataRightStoreClient()
        let handle = MockProtectedDataPersistedRightHandle(
            identifier: "com.cypherair.tests.protected-data.authorization.cancelled",
            secretData: Data(repeating: 0xAF, count: 32)
        )
        handle.authorizeError = AuthenticationError.cancelled
        rightStoreClient.persistedRightHandle = handle
        let coordinator = AppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.cancelled"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.authorization.cancelled",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["contacts": .active],
            pendingMutation: nil
        )

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Authorize protected data"
        )

        XCTAssertEqual(result, .cancelledOrDenied)
        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
    }

    func test_pendingRecovery_firstDomainCreateWithoutReady_returnsResetRequired() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataPendingCreateReset")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.pending-create"
        )
        let recoveryCoordinator = AppProtectedDomainRecoveryCoordinator(registryStore: registryStore)
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.pending-create",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .artifactsStaged
            )
        )
        try registryStore.saveRegistry(registry)

        XCTAssertEqual(recoveryCoordinator.pendingRecoveryAuthorizationRequirement(), .notRequired)

        let outcome = try await registryStore.recoverPendingMutation(
            targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
            continueDelete: { _ in }
        )

        XCTAssertEqual(outcome, AppPendingRecoveryOutcome.resetRequired)
    }

    func test_recoveryCoordinator_dispatchesPendingDeleteToDomainHandler() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataGenericRecoveryDelete")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let domainID: ProtectedDataDomainID = "generic-domain"
        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.generic-recovery"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.generic-recovery",
            sharedResourceLifecycleState: .cleanupPending,
            committedMembership: [:],
            pendingMutation: .deleteDomain(
                targetDomainID: domainID,
                phase: .membershipRemoved
            )
        )
        try registryStore.saveRegistry(registry)

        let handler = MockProtectedDomainRecoveryHandler(domainID: domainID)
        let cleanupCalled = AsyncBooleanFlag()
        let recoveryCoordinator = AppProtectedDomainRecoveryCoordinator(registryStore: registryStore)

        let outcome = try await recoveryCoordinator.recoverPendingMutation(
            handler: handler,
            removeSharedRight: { identifier in
                XCTAssertEqual(identifier, registry.sharedRightIdentifier)
                await cleanupCalled.setTrue()
            }
        )

        XCTAssertEqual(outcome, .resumedToSteadyState)
        XCTAssertEqual(handler.deleteArtifactsCallCount, 1)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertTrue(didCleanup)
        XCTAssertNil(try registryStore.loadRegistry().pendingMutation)
    }

    func test_recoveryCoordinator_targetMismatchReturnsFrameworkRecoveryNeeded() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataGenericRecoveryMismatch")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.generic-recovery-mismatch"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.generic-recovery-mismatch",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: "other-domain",
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)

        let handler = MockProtectedDomainRecoveryHandler(domainID: "generic-domain")
        let recoveryCoordinator = AppProtectedDomainRecoveryCoordinator(registryStore: registryStore)

        let outcome = try await recoveryCoordinator.recoverPendingMutation(
            handler: handler,
            removeSharedRight: { _ in }
        )

        XCTAssertEqual(outcome, .frameworkRecoveryNeeded)
        XCTAssertEqual(handler.deleteArtifactsCallCount, 0)
        XCTAssertTrue(handler.continuedCreatePhases.isEmpty)
    }

    func test_protectedSettings_surfacesSentinelPendingCreateAsRetryable() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSettingsSentinelPending")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-sentinel-pending"
        )
        let defaultsSuiteName = "com.cypherair.tests.protected-data.settings-sentinel-pending.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }
        let protectedSettingsStore = ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot)
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-sentinel-pending",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: AppProtectedDataFrameworkSentinelStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)

        protectedSettingsStore.syncPreAuthorizationState()

        XCTAssertEqual(protectedSettingsStore.domainState, .pendingRetryRequired)
        do {
            _ = try await protectedSettingsStore.openDomainIfNeeded(
                wrappingRootKey: Data(repeating: 0xC1, count: 32)
            )
            XCTFail("Protected settings must not open while sentinel recovery is pending.")
        } catch {
            XCTAssertEqual(protectedSettingsStore.domainState, .pendingRetryRequired)
        }
    }

    func test_recoveryCoordinator_handlerListDispatchesByPendingDomainID() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataHandlerListRecovery")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.handler-list"
        )
        let wrappingRootKey = Data(repeating: 0xA4, count: 32)
        let sentinelStore = AppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot),
            currentWrappingRootKey: { wrappingRootKey }
        )
        let mismatchedHandler = MockProtectedDomainRecoveryHandler(domainID: "other-domain")
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.handler-list",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: AppProtectedDataFrameworkSentinelStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)
        let recoveryCoordinator = AppProtectedDomainRecoveryCoordinator(registryStore: registryStore)

        XCTAssertEqual(
            recoveryCoordinator.pendingRecoveryAuthorizationRequirement(),
            .wrappingRootKeyRequired
        )

        let outcome = try await recoveryCoordinator.recoverPendingMutation(
            handlers: [
                mismatchedHandler,
                sentinelStore
            ],
            removeSharedRight: { _ in
                XCTFail("Second-domain create recovery must not remove the shared root.")
            }
        )
        let recoveredRegistry = try registryStore.loadRegistry()

        XCTAssertEqual(outcome, .resumedToSteadyState)
        XCTAssertEqual(recoveredRegistry.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertEqual(recoveredRegistry.committedMembership[AppProtectedDataFrameworkSentinelStore.domainID], .active)
        XCTAssertNil(recoveredRegistry.pendingMutation)
        XCTAssertEqual(mismatchedHandler.deleteArtifactsCallCount, 0)
        XCTAssertTrue(mismatchedHandler.continuedCreatePhases.isEmpty)
        XCTAssertTrue(try storageRoot.managedItemExists(
            at: storageRoot.committedWrappedDomainMasterKeyURL(
                for: AppProtectedDataFrameworkSentinelStore.domainID
            )
        ))
    }

    func test_secondDomainDeletePreservesSharedRootUntilLastDomainIsRemoved() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSecondDomainDelete")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.second-domain-delete"
        )
        let domainKeyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let wrappingRootKey = Data(repeating: 0xB4, count: 32)
        let sentinelStore = AppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.second-domain-delete",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: nil
        )
        try registryStore.saveRegistry(registry)
        try await sentinelStore.ensureCommittedIfNeeded(wrappingRootKey: wrappingRootKey)

        let secondDomainCleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.performDeleteDomainTransaction(
            domainID: AppProtectedDataFrameworkSentinelStore.domainID,
            deleteArtifacts: {
                try sentinelStore.deleteDomainArtifactsForRecovery()
            },
            cleanupSharedResourceIfNeeded: {
                await secondDomainCleanupCalled.setTrue()
            }
        )
        let afterSecondDomainDelete = try registryStore.loadRegistry()

        XCTAssertEqual(afterSecondDomainDelete.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertNil(afterSecondDomainDelete.committedMembership[AppProtectedDataFrameworkSentinelStore.domainID])
        XCTAssertEqual(afterSecondDomainDelete.sharedResourceLifecycleState, .ready)
        XCTAssertNil(afterSecondDomainDelete.pendingMutation)
        let didRunSecondDomainCleanup = await secondDomainCleanupCalled.currentValue()
        XCTAssertFalse(didRunSecondDomainCleanup)

        let lastDomainCleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.performDeleteDomainTransaction(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {},
            cleanupSharedResourceIfNeeded: {
                await lastDomainCleanupCalled.setTrue()
            }
        )
        let afterLastDomainDelete = try registryStore.loadRegistry()

        XCTAssertTrue(afterLastDomainDelete.committedMembership.isEmpty)
        XCTAssertEqual(afterLastDomainDelete.sharedResourceLifecycleState, .absent)
        XCTAssertNil(afterLastDomainDelete.pendingMutation)
        let didRunLastDomainCleanup = await lastDomainCleanupCalled.currentValue()
        XCTAssertTrue(didRunLastDomainCleanup)
    }

    func test_protectedSettingsResetRequiresWrappingKeyBeforeDeletingWhenSentinelRemains() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSettingsResetPreflight")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.settings-reset-preflight.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-reset-preflight"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager
        )
        let capturedSharedSecret = AsyncDataBox()
        try await settingsStore.ensureCommittedAndMigrateSettingsIfNeeded(
            persistSharedRight: { secret in
                await capturedSharedSecret.set(secret)
            }
        )
        var rootSecret = await capturedSharedSecret.data()
        let wrappingRootKey = try keyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()

        let sentinelStore = AppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        try await sentinelStore.ensureCommittedIfNeeded(wrappingRootKey: wrappingRootKey)
        let currentEnvelopeURL = storageRoot.domainEnvelopeURL(
            for: CypherAir.ProtectedSettingsStore.domainID,
            slot: .current
        )

        XCTAssertEqual(settingsStore.resetAuthorizationRequirement(), .wrappingRootKeyRequired)
        do {
            try await settingsStore.resetDomain(
                persistSharedRight: { _ in
                    XCTFail("Second-domain settings reset must not create a new shared root.")
                },
                removeSharedRight: { _ in
                    XCTFail("Second-domain settings reset must not remove the shared root.")
                },
                currentWrappingRootKey: {
                    throw ProtectedDataError.missingWrappingRootKey
                }
            )
            XCTFail("Expected reset to fail before deleting settings without a wrapping key.")
        } catch ProtectedDataError.missingWrappingRootKey {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        let retainedRegistry = try registryStore.loadRegistry()
        XCTAssertEqual(retainedRegistry.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertEqual(retainedRegistry.committedMembership[AppProtectedDataFrameworkSentinelStore.domainID], .active)
        XCTAssertNil(retainedRegistry.pendingMutation)
        XCTAssertTrue(try storageRoot.managedItemExists(at: currentEnvelopeURL))
    }

    func test_protectedSettingsMigrationAuthorizationRequirementReflectsRegistryShape() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedSettingsMigrationRequirement")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-settings-migration-requirement.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-settings-migration-requirement"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot)
        )

        XCTAssertEqual(settingsStore.migrationAuthorizationRequirement(), .notRequired)

        let privateKeyControlOnlyRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-settings-migration-requirement",
            sharedResourceLifecycleState: .ready,
            committedMembership: [AppPrivateKeyControlStore.domainID: .active],
            pendingMutation: nil
        )
        try registryStore.saveRegistry(privateKeyControlOnlyRegistry)

        XCTAssertEqual(settingsStore.migrationAuthorizationRequirement(), .wrappingRootKeyRequired)

        let pendingRegistry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-settings-migration-requirement",
            sharedResourceLifecycleState: .ready,
            committedMembership: [AppPrivateKeyControlStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: AppProtectedDataFrameworkSentinelStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(pendingRegistry)

        XCTAssertEqual(settingsStore.migrationAuthorizationRequirement(), .frameworkRecoveryNeeded)
    }

    func test_protectedSettingsFreshInstallCreatesSchemaV2OrdinarySettingsPayload() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsFreshV2")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let payload = try await harness.store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let metadata = try ProtectedDomainBootstrapStore(
            storageRoot: harness.storageRoot
        ).loadMetadata(for: ProtectedSettingsStore.domainID)

        XCTAssertEqual(metadata?.schemaVersion, ProtectedSettingsStore.Payload.currentSchemaVersion)
        XCTAssertEqual(payload.ordinarySettings, .firstRunDefaults)

        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: harness.store
            )
        )
        coordinator.loadAfterAppAuthentication(protectedSettingsDomainState: .unlocked)

        XCTAssertEqual(coordinator.snapshot, .firstRunDefaults)
    }

    func test_protectedSettingsV1PayloadMigratesOrdinarySettingsAndCleansLegacyAfterVerifiedReadback() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsV1Migration")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let expectedSnapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: 300,
            hasCompletedOnboarding: true,
            colorTheme: .teal,
            encryptToSelf: false,
            guidedTutorialCompletedVersion: GuidedTutorialVersion.current
        )
        setLegacyOrdinarySettings(expectedSnapshot, defaults: harness.defaults)
        harness.defaults.set(true, forKey: AppConfiguration.clipboardNoticeLegacyKey)
        try writeProtectedSettingsEnvelope(
            payload: ProtectedSettingsPayloadV1(clipboardNotice: false),
            schemaVersion: 1,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: wrappingRootKey
        )

        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        let payload = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let metadata = try ProtectedDomainBootstrapStore(
            storageRoot: harness.storageRoot
        ).loadMetadata(for: ProtectedSettingsStore.domainID)

        XCTAssertEqual(metadata?.schemaVersion, ProtectedSettingsStore.Payload.currentSchemaVersion)
        XCTAssertEqual(payload.clipboardNotice, false)
        XCTAssertEqual(payload.ordinarySettings, expectedSnapshot)
        assertLegacyOrdinarySettingsRemoved(defaults: harness.defaults)
    }

    func test_protectedSettingsV2PayloadWinsOverConflictingLegacyOrdinarySettings() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsV2Authority")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        _ = try await harness.store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let protectedSnapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: 60,
            hasCompletedOnboarding: true,
            colorTheme: .pink,
            encryptToSelf: false,
            guidedTutorialCompletedVersion: GuidedTutorialVersion.current
        )
        try harness.store.updateOrdinarySettingsSnapshot(protectedSnapshot)
        try await harness.store.relockProtectedData()

        setLegacyOrdinarySettings(
            ProtectedOrdinarySettingsSnapshot(
                gracePeriod: 300,
                hasCompletedOnboarding: false,
                colorTheme: .orange,
                encryptToSelf: true,
                guidedTutorialCompletedVersion: 0
            ),
            defaults: harness.defaults
        )
        harness.defaults.set(false, forKey: AppConfiguration.clipboardNoticeLegacyKey)

        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        let payload = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)

        XCTAssertEqual(payload.clipboardNotice, true)
        XCTAssertEqual(payload.ordinarySettings, protectedSnapshot)
        assertLegacyOrdinarySettingsRemoved(defaults: harness.defaults)
    }

    func test_protectedSettingsCommittedUpgradeMissingWrappingKeyDoesNotPersistRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedMissingWrappingKey")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        _ = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: {
                throw ProtectedDataError.missingWrappingRootKey
            }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected committed settings upgrade to require the wrapping root key.")
        } catch ProtectedDataError.missingWrappingRootKey {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(reopenedStore.domainState, .locked)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .active
        )
    }

    func test_protectedSettingsCommittedUpgradePendingMutationDoesNotPersistRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedPendingMutation")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        var registry = try harness.registryStore.loadRegistry()
        registry.pendingMutation = .createDomain(
            targetDomainID: AppProtectedDataFrameworkSentinelStore.domainID,
            phase: .journaled
        )
        try harness.registryStore.saveRegistry(registry)
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected committed settings upgrade to stop for pending mutation.")
        } catch ProtectedDataError.invalidRegistry(_) {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(reopenedStore.domainState, .pendingRetryRequired)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .active
        )
    }

    func test_protectedSettingsCommittedUpgradeStorageReadFailureDoesNotPersistRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedStorageReadFailure")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        try writeProtectedSettingsEnvelope(
            payload: ProtectedSettingsStore.Payload(
                clipboardNotice: true,
                ordinarySettings: .firstRunDefaults
            ),
            schemaVersion: ProtectedSettingsStore.Payload.currentSchemaVersion,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: wrappingRootKey
        )
        let currentURL = harness.storageRoot.domainEnvelopeURL(
            for: ProtectedSettingsStore.domainID,
            slot: .current
        )
        let previousURL = harness.storageRoot.domainEnvelopeURL(
            for: ProtectedSettingsStore.domainID,
            slot: .previous
        )
        XCTAssertTrue(try harness.storageRoot.managedItemExists(at: previousURL))
        try FileManager.default.removeItem(at: currentURL)
        try FileManager.default.createDirectory(at: currentURL, withIntermediateDirectories: false)
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected committed settings upgrade to fail on storage read.")
        } catch ProtectedDataError.invalidEnvelope(_) {
            XCTFail("Storage read failure must not be folded into invalidEnvelope.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .frameworkUnavailable)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .active
        )
    }

    func test_protectedSettingsCommittedUpgradeWrappedDMKStorageReadFailureDoesNotPersistRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedWrappedDMKStorageReadFailure")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let wrappedDMKURL = harness.storageRoot.committedWrappedDomainMasterKeyURL(
            for: ProtectedSettingsStore.domainID
        )
        try FileManager.default.removeItem(at: wrappedDMKURL)
        try FileManager.default.createDirectory(at: wrappedDMKURL, withIntermediateDirectories: false)
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected committed settings upgrade to fail on wrapped DMK storage read.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .frameworkUnavailable)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .active
        )
    }

    func test_protectedSettingsCommittedUpgradeCorruptWrappedDMKPersistsRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedCorruptWrappedDMK")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        try harness.storageRoot.writeProtectedData(
            Data("not a plist wrapped DMK".utf8),
            to: harness.storageRoot.committedWrappedDomainMasterKeyURL(
                for: ProtectedSettingsStore.domainID
            )
        )
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected corrupt committed wrapped DMK to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .recoveryNeeded
        )
    }

    func test_protectedSettingsCommittedUpgradeCorruptPayloadPersistsRecovery() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCommittedCorruptUpgrade")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }
        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        try writeProtectedSettingsEnvelope(
            payload: ProtectedSettingsPayloadV1(clipboardNotice: true),
            schemaVersion: ProtectedSettingsStore.Payload.currentSchemaVersion,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: wrappingRootKey
        )
        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )

        do {
            try await reopenedStore.ensureCommittedAndMigrateSettingsIfNeeded(
                persistSharedRight: { _ in
                    XCTFail("Committed settings upgrade must not provision a new shared right.")
                }
            )
            XCTFail("Expected corrupt committed settings payload to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .recoveryNeeded
        )
    }

    func test_protectedSettingsCorruptCommittedPayloadRequiresRecoveryAndLeavesLegacySources() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsCorrupt")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        let legacySnapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: 180,
            hasCompletedOnboarding: true,
            colorTheme: .graphite,
            encryptToSelf: false,
            guidedTutorialCompletedVersion: GuidedTutorialVersion.current
        )
        setLegacyOrdinarySettings(legacySnapshot, defaults: harness.defaults)
        harness.defaults.set(false, forKey: AppConfiguration.clipboardNoticeLegacyKey)
        try writeProtectedSettingsEnvelope(
            payload: ProtectedSettingsPayloadV1(clipboardNotice: true),
            schemaVersion: ProtectedSettingsStore.Payload.currentSchemaVersion,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: wrappingRootKey
        )

        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        do {
            _ = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
            XCTFail("Expected corrupt protected settings payload to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedSettingsStore.domainID],
            .recoveryNeeded
        )
        XCTAssertNotNil(harness.defaults.object(forKey: AppConfiguration.clipboardNoticeLegacyKey))
        XCTAssertNotNil(harness.defaults.object(forKey: ProtectedOrdinarySettingsLegacyKeys.gracePeriod))
    }

    func test_protectedSettingsOrdinaryMutationsPersistAcrossRelockAndReopen() async throws {
        let harness = try makeProtectedSettingsHarness("ProtectedSettingsMutationPersistence")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        defer { harness.defaults.removePersistentDomain(forName: harness.defaultsSuiteName) }

        let wrappingRootKey = try await createProtectedSettingsDomain(
            store: harness.store,
            domainKeyManager: harness.domainKeyManager
        )
        _ = try await harness.store.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: harness.store
            )
        )
        coordinator.loadAfterAppAuthentication(protectedSettingsDomainState: .unlocked)

        coordinator.setGracePeriod(300)
        coordinator.setHasCompletedOnboarding(true)
        coordinator.setColorTheme(.teal)
        coordinator.setEncryptToSelf(false)
        coordinator.markGuidedTutorialCompletedCurrentVersion()
        let expectedSnapshot = ProtectedOrdinarySettingsSnapshot(
            gracePeriod: 300,
            hasCompletedOnboarding: true,
            colorTheme: .teal,
            encryptToSelf: false,
            guidedTutorialCompletedVersion: GuidedTutorialVersion.current
        )
        XCTAssertEqual(coordinator.snapshot, expectedSnapshot)

        try await harness.store.relockProtectedData()
        harness.domainKeyManager.clearUnlockedDomainMasterKeys()
        coordinator.relock()

        XCTAssertNil(harness.store.payload)
        XCTAssertNil(coordinator.snapshot)
        XCTAssertFalse(harness.domainKeyManager.hasUnlockedDomainMasterKeys)

        let reopenedStore = ProtectedSettingsStore(
            defaults: harness.defaults,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        _ = try await reopenedStore.openDomainIfNeeded(wrappingRootKey: wrappingRootKey)
        let reloadedCoordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: ProtectedSettingsOrdinarySettingsPersistence(
                protectedSettingsStore: reopenedStore
            )
        )
        reloadedCoordinator.loadAfterAppAuthentication(protectedSettingsDomainState: .unlocked)

        XCTAssertEqual(reloadedCoordinator.snapshot, expectedSnapshot)
    }

    func test_protectedSettingsResetRecreatesWithWrappingKeyWhenSentinelRemains() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSettingsResetWithKey")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.settings-reset-with-key.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.settings-reset-with-key"
        )
        _ = try registryStore.performSynchronousBootstrap()
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager,
            currentWrappingRootKey: {
                throw ProtectedDataError.missingWrappingRootKey
            }
        )
        let capturedSharedSecret = AsyncDataBox()
        try await settingsStore.ensureCommittedAndMigrateSettingsIfNeeded(
            persistSharedRight: { secret in
                await capturedSharedSecret.set(secret)
            }
        )
        var rootSecret = await capturedSharedSecret.data()
        let wrappingRootKey = try keyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()

        let sentinelStore = AppProtectedDataFrameworkSentinelStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        try await sentinelStore.ensureCommittedIfNeeded(wrappingRootKey: wrappingRootKey)

        try await settingsStore.resetDomain(
            persistSharedRight: { _ in
                XCTFail("Second-domain settings reset must not create a new shared root.")
            },
            removeSharedRight: { _ in
                XCTFail("Second-domain settings reset must not remove the shared root.")
            },
            currentWrappingRootKey: {
                wrappingRootKey
            }
        )

        let resetRegistry = try registryStore.loadRegistry()
        XCTAssertEqual(resetRegistry.committedMembership[CypherAir.ProtectedSettingsStore.domainID], .active)
        XCTAssertEqual(resetRegistry.committedMembership[AppProtectedDataFrameworkSentinelStore.domainID], .active)
        XCTAssertNil(resetRegistry.pendingMutation)
        XCTAssertTrue(try storageRoot.managedItemExists(
            at: storageRoot.domainEnvelopeURL(
                for: CypherAir.ProtectedSettingsStore.domainID,
                slot: .current
            )
        ))
    }

    func test_abandonPendingCreate_clearsPendingMutationAndArtifacts() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonPendingCreate")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.abandon-create.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-create"
        )
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager
        )

        try storageRoot.ensureDomainDirectoryExists(for: CypherAir.ProtectedSettingsStore.domainID)
        try storageRoot.writeProtectedData(
            Data("staged".utf8),
            to: storageRoot.domainEnvelopeURL(
                for: CypherAir.ProtectedSettingsStore.domainID,
                slot: .pending
            )
        )

        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-create",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .artifactsStaged
            )
        )
        try registryStore.saveRegistry(registry)

        _ = try await registryStore.abandonPendingCreate(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {
                try settingsStore.deleteDomainArtifactsForRecovery()
            },
            cleanupSharedResourceIfNeeded: {}
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        XCTAssertFalse(
            try storageRoot.managedItemExists(
                at: storageRoot.domainEnvelopeURL(
                    for: CypherAir.ProtectedSettingsStore.domainID,
                    slot: .pending
                )
            )
        )
    }

    func test_abandonPendingCreate_membershipCommittedLastDomainCleansSharedResource() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonCommittedCreate")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-committed-create"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-committed-create",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .membershipCommitted
            )
        )
        try registryStore.saveRegistry(registry)

        let cleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.abandonPendingCreate(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {},
            cleanupSharedResourceIfNeeded: {
                await cleanupCalled.setTrue()
            }
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertTrue(clearedRegistry.committedMembership.isEmpty)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertTrue(didCleanup)
    }

    func test_abandonPendingCreate_cleanupFailureLeavesPendingMutation() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonCleanupFailure")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.abandon-cleanup-failure.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-cleanup-failure"
        )
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot)
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-cleanup-failure",
            sharedResourceLifecycleState: .ready,
            committedMembership: [CypherAir.ProtectedSettingsStore.domainID: .active],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .membershipCommitted
            )
        )
        try registryStore.saveRegistry(registry)
        try storageRoot.ensureDomainDirectoryExists(for: CypherAir.ProtectedSettingsStore.domainID)
        let currentEnvelopeURL = storageRoot.domainEnvelopeURL(
            for: CypherAir.ProtectedSettingsStore.domainID,
            slot: .current
        )
        try storageRoot.writeProtectedData(Data("current".utf8), to: currentEnvelopeURL)

        do {
            _ = try await registryStore.abandonPendingCreate(
                domainID: CypherAir.ProtectedSettingsStore.domainID,
                deleteArtifacts: {
                    try settingsStore.deleteDomainArtifactsForRecovery()
                },
                cleanupSharedResourceIfNeeded: {
                    throw ProtectedDataError.internalFailure("Injected cleanup failure.")
                }
            )
            XCTFail("Expected shared-resource cleanup failure to fail closed.")
        } catch ProtectedDataError.internalFailure {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        let retainedRegistry = try registryStore.loadRegistry()
        XCTAssertEqual(
            retainedRegistry.pendingMutation,
            .deleteDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .sharedResourceCleanupStarted
            )
        )
        XCTAssertEqual(retainedRegistry.sharedResourceLifecycleState, .cleanupPending)
        XCTAssertTrue(retainedRegistry.committedMembership.isEmpty)
        XCTAssertFalse(try storageRoot.managedItemExists(at: currentEnvelopeURL))

        let cleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.completePendingDelete(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {
                try settingsStore.deleteDomainArtifactsForRecovery()
            },
            cleanupSharedResourceIfNeeded: {
                await cleanupCalled.setTrue()
            }
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        XCTAssertTrue(clearedRegistry.committedMembership.isEmpty)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertTrue(didCleanup)
    }

    func test_abandonPendingCreate_preMembershipCleanupFailurePreservesArtifacts() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonPreMembershipCleanupFailure")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.abandon-pre-membership-cleanup-failure.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-pre-membership-cleanup-failure"
        )
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: AppProtectedDomainKeyManager(storageRoot: storageRoot)
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-pre-membership-cleanup-failure",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .artifactsStaged
            )
        )
        try registryStore.saveRegistry(registry)
        try storageRoot.ensureDomainDirectoryExists(for: CypherAir.ProtectedSettingsStore.domainID)
        let pendingEnvelopeURL = storageRoot.domainEnvelopeURL(
            for: CypherAir.ProtectedSettingsStore.domainID,
            slot: .pending
        )
        try storageRoot.writeProtectedData(Data("pending".utf8), to: pendingEnvelopeURL)
        let deleteCalled = AsyncBooleanFlag()

        do {
            _ = try await registryStore.abandonPendingCreate(
                domainID: CypherAir.ProtectedSettingsStore.domainID,
                deleteArtifacts: {
                    await deleteCalled.setTrue()
                    try settingsStore.deleteDomainArtifactsForRecovery()
                },
                cleanupSharedResourceIfNeeded: {
                    throw ProtectedDataError.internalFailure("Injected cleanup failure.")
                }
            )
            XCTFail("Expected shared-resource cleanup failure to fail closed.")
        } catch ProtectedDataError.internalFailure {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        let retainedRegistry = try registryStore.loadRegistry()
        XCTAssertEqual(retainedRegistry.pendingMutation, registry.pendingMutation)
        XCTAssertEqual(retainedRegistry.sharedResourceLifecycleState, .absent)
        XCTAssertTrue(retainedRegistry.committedMembership.isEmpty)
        XCTAssertTrue(try storageRoot.managedItemExists(at: pendingEnvelopeURL))
        let didDelete = await deleteCalled.currentValue()
        XCTAssertFalse(didDelete)
    }

    func test_abandonPendingCreate_journaledFirstDomainDoesNotRequireSharedCleanup() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataAbandonJournaledCreate")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-journaled-create"
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.abandon-journaled-create",
            sharedResourceLifecycleState: .absent,
            committedMembership: [:],
            pendingMutation: .createDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .journaled
            )
        )
        try registryStore.saveRegistry(registry)

        let cleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.abandonPendingCreate(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {},
            cleanupSharedResourceIfNeeded: {
                await cleanupCalled.setTrue()
            }
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertFalse(didCleanup)
    }

    func test_keyMetadataDomain_freshInstallCreatesEmptyPayloadAndRelockClearsMemory() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataFresh")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }

        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        let payload = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )

        XCTAssertEqual(payload.schemaVersion, AppKeyMetadataDomainStore.Payload.currentSchemaVersion)
        XCTAssertEqual(payload.identities, [])
        XCTAssertEqual(try harness.store.loadAll(), [])
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[AppKeyMetadataDomainStore.domainID],
            .active
        )

        try await harness.store.relockProtectedData()

        XCTAssertEqual(harness.store.domainState, .locked)
        XCTAssertNil(harness.store.payload)
        XCTAssertThrowsError(try harness.store.loadAll())
    }

    func test_keyMetadataDomain_migratesDedicatedMetadataAccountAndCleansSource() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataDedicatedMigration")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            userId: "Dedicated <dedicated@example.invalid>",
            isDefault: true
        )
        try harness.legacyStore.save(identity)

        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )

        XCTAssertEqual(try harness.store.loadAll(), [identity])
        XCTAssertFalse(harness.keychain.exists(
            service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
            account: KeychainConstants.metadataAccount
        ))
        XCTAssertNil(harness.store.migrationWarning)
    }

    func test_keyMetadataDomain_cleanupFailureKeepsMigratedSourceForRetry() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataCleanupFailure")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "abababababababababababababababababababab",
            userId: "Cleanup Retry <cleanup@example.invalid>"
        )
        try harness.legacyStore.save(identity)
        harness.keychain.failOnDeleteNumber = 1

        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )

        XCTAssertTrue(harness.keychain.exists(
            service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
            account: KeychainConstants.metadataAccount
        ))
        XCTAssertEqual(harness.store.migrationWarning, AppKeyMetadataDomainStore.migrationWarningMessage())

        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )

        XCTAssertEqual(try harness.store.loadAll(), [identity])
        XCTAssertFalse(harness.keychain.exists(
            service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
            account: KeychainConstants.metadataAccount
        ))
        XCTAssertNil(harness.store.migrationWarning)
    }

    func test_keyMetadataDomain_cleanupRetryDeletesSameFingerprintLegacyDuplicate() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataDuplicateCleanupRetry")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let legacyDuplicate = makeMetadataIdentity(
            fingerprint: "acacacacacacacacacacacacacacacacacacacac",
            userId: "Default Duplicate <default-duplicate@example.invalid>",
            publicKeySeed: 0x21
        )
        let dedicatedDuplicate = makeMetadataIdentity(
            fingerprint: legacyDuplicate.fingerprint,
            userId: "Dedicated Duplicate <dedicated-duplicate@example.invalid>",
            isBackedUp: true,
            publicKeySeed: 0x22
        )
        try harness.legacyStore.save(legacyDuplicate, account: KeychainConstants.defaultAccount)
        try harness.legacyStore.save(dedicatedDuplicate, account: KeychainConstants.metadataAccount)
        harness.keychain.failOnDeleteNumber = 1

        let authenticationContext = LAContext()
        defer { authenticationContext.invalidate() }
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: authenticationContext
        )

        XCTAssertEqual(harness.store.migrationWarning, AppKeyMetadataDomainStore.migrationWarningMessage())
        XCTAssertTrue(harness.keychain.exists(
            service: KeychainConstants.metadataService(fingerprint: legacyDuplicate.fingerprint),
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(harness.keychain.exists(
            service: KeychainConstants.metadataService(fingerprint: dedicatedDuplicate.fingerprint),
            account: KeychainConstants.metadataAccount
        ))

        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: authenticationContext
        )

        XCTAssertEqual(try harness.store.loadAll(), [dedicatedDuplicate])
        XCTAssertFalse(harness.keychain.exists(
            service: KeychainConstants.metadataService(fingerprint: legacyDuplicate.fingerprint),
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertNil(harness.store.migrationWarning)
    }

    func test_keyMetadataDomain_migratesDefaultAccountWithAuthenticatedContextAndCleansSource() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataDefaultMigration")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            userId: "Default <default@example.invalid>"
        )
        try harness.legacyStore.save(identity, account: KeychainConstants.defaultAccount)
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }

        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: handoffContext
        )
        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: handoffContext
        )

        XCTAssertEqual(try harness.store.loadAll(), [identity])
        XCTAssertFalse(harness.keychain.exists(
            service: KeychainConstants.metadataService(fingerprint: identity.fingerprint),
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertTrue(harness.keychain.listItemsCalls.contains { call in
            call.account == KeychainConstants.defaultAccount && call.hasAuthenticationContext
        })
    }

    func test_keyMetadataDomain_pendingCreateRecoveryUsesAuthenticationContextForDefaultAccount() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataRecoveryContext")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc",
            userId: "Recovered Default <recovered-default@example.invalid>"
        )
        try harness.legacyStore.save(identity, account: KeychainConstants.defaultAccount)
        try await leaveKeyMetadataPendingCreateAtJournaled(registryStore: harness.registryStore)
        harness.keychain.resetCallHistory()

        let authenticationContext = LAContext()
        defer { authenticationContext.invalidate() }
        let recoveryCoordinator = ProtectedDomainRecoveryCoordinator(registryStore: harness.registryStore)
        let outcome = try await recoveryCoordinator.recoverPendingMutation(
            handler: harness.store,
            authenticationContext: authenticationContext,
            removeSharedRight: { _ in
                XCTFail("Key metadata recovery must not remove the shared right.")
            }
        )

        XCTAssertEqual(outcome, .resumedToSteadyState)
        XCTAssertNil(try harness.registryStore.loadRegistry().pendingMutation)

        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: authenticationContext
        )

        XCTAssertEqual(try harness.store.loadAll(), [identity])
        XCTAssertTrue(harness.keychain.listItemsCalls.contains { call in
            call.account == KeychainConstants.defaultAccount && call.hasAuthenticationContext
        })
        XCTAssertTrue(harness.keychain.loadCalls.contains { call in
            call.account == KeychainConstants.defaultAccount && call.hasAuthenticationContext
        })
    }

    func test_keyMetadataDomain_pendingCreateRecoveryWithoutContextKeepsRetryableWhenSourcesFail() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataRecoveryNoContext")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let corruptFingerprint = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        try harness.keychain.save(
            Data("not-valid-key-metadata".utf8),
            service: KeychainConstants.metadataService(fingerprint: corruptFingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try await leaveKeyMetadataPendingCreateAtJournaled(registryStore: harness.registryStore)

        let recoveryCoordinator = ProtectedDomainRecoveryCoordinator(registryStore: harness.registryStore)
        let outcome = try await recoveryCoordinator.recoverPendingMutation(
            handler: harness.store,
            authenticationContext: nil,
            removeSharedRight: { _ in
                XCTFail("Retryable key metadata recovery must not remove the shared right.")
            }
        )

        XCTAssertEqual(outcome, .retryablePending)
        let registry = try harness.registryStore.loadRegistry()
        XCTAssertEqual(registry.committedMembership[AppKeyMetadataDomainStore.domainID], nil)
        guard case let .createDomain(domainID, phase)? = registry.pendingMutation else {
            XCTFail("Expected key metadata pending create to remain retryable.")
            return
        }
        XCTAssertEqual(domainID, AppKeyMetadataDomainStore.domainID)
        XCTAssertEqual(phase, .journaled)
        XCTAssertThrowsError(try harness.store.loadAll())
    }

    func test_keyMetadataDomain_pendingCreateRecoveryFromStagedArtifactsSkipsLegacySourcesWithoutContext() async throws {
        for (index, phase) in [CreateDomainPhase.artifactsStaged, .validated].enumerated() {
            let harness = try await makeKeyMetadataDomainHarness("KeyMetadataRecoveryStaged\(index)")
            defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
            let identity = makeMetadataIdentity(
                fingerprint: index == 0
                    ? "dededededededededededededededededededede"
                    : "efefefefefefefefefefefefefefefefefefefef",
                userId: "Staged \(index) <staged-\(index)@example.invalid>",
                publicKeySeed: UInt8(0x30 + index)
            )
            try leaveKeyMetadataPendingCreateWithStagedArtifacts(
                storageRoot: harness.storageRoot,
                registryStore: harness.registryStore,
                domainKeyManager: harness.domainKeyManager,
                wrappingRootKey: harness.wrappingRootKey,
                identity: identity,
                phase: phase
            )
            try harness.keychain.save(
                Data("not-valid-key-metadata".utf8),
                service: KeychainConstants.metadataService(
                    fingerprint: index == 0
                        ? "fdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfd"
                        : "fefefefefefefefefefefefefefefefefefefefe"
                ),
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
            harness.keychain.resetCallHistory()

            let recoveryCoordinator = ProtectedDomainRecoveryCoordinator(registryStore: harness.registryStore)
            let outcome = try await recoveryCoordinator.recoverPendingMutation(
                handler: harness.store,
                authenticationContext: nil,
                removeSharedRight: { _ in
                    XCTFail("Key metadata recovery must not remove the shared right.")
                }
            )

            XCTAssertEqual(outcome, .resumedToSteadyState)
            XCTAssertNil(try harness.registryStore.loadRegistry().pendingMutation)
            XCTAssertEqual(harness.keychain.listItemsCallCount, 0)
            XCTAssertEqual(harness.keychain.loadCallCount, 0)

            let openContext = LAContext()
            defer { openContext.invalidate() }
            _ = try await harness.store.openDomainIfNeeded(
                wrappingRootKey: harness.wrappingRootKey,
                authenticationContext: openContext
            )
            XCTAssertEqual(try harness.store.loadAll(), [identity])
        }
    }

    func test_keyMetadataDomain_deduplicatesDualSourcesWithDedicatedAccountPriority() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataDualSource")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let defaultOnly = makeMetadataIdentity(
            fingerprint: "1111111111111111111111111111111111111111",
            userId: "Default Only <default-only@example.invalid>",
            publicKeySeed: 0x01
        )
        let legacyDuplicate = makeMetadataIdentity(
            fingerprint: "2222222222222222222222222222222222222222",
            userId: "Legacy Duplicate <legacy@example.invalid>",
            publicKeySeed: 0x02
        )
        let dedicatedDuplicate = makeMetadataIdentity(
            fingerprint: legacyDuplicate.fingerprint,
            userId: "Dedicated Duplicate <dedicated@example.invalid>",
            isBackedUp: true,
            publicKeySeed: 0x03
        )
        try harness.legacyStore.save(defaultOnly, account: KeychainConstants.defaultAccount)
        try harness.legacyStore.save(legacyDuplicate, account: KeychainConstants.defaultAccount)
        try harness.legacyStore.save(dedicatedDuplicate, account: KeychainConstants.metadataAccount)

        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        let migrated = try harness.store.loadAll()

        XCTAssertEqual(migrated.map(\.fingerprint), [
            defaultOnly.fingerprint,
            dedicatedDuplicate.fingerprint
        ])
        XCTAssertEqual(migrated.first(where: { $0.fingerprint == dedicatedDuplicate.fingerprint }), dedicatedDuplicate)
    }

    func test_keyMetadataDomain_corruptLegacyRowsDoNotBlockReadableRowsAndRemainForRetry() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataCorruptLegacy")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let readable = makeMetadataIdentity(
            fingerprint: "cccccccccccccccccccccccccccccccccccccccc",
            userId: "Readable <readable@example.invalid>"
        )
        let corruptFingerprint = "dddddddddddddddddddddddddddddddddddddddd"
        let corruptService = KeychainConstants.metadataService(fingerprint: corruptFingerprint)
        try harness.legacyStore.save(readable)
        try harness.keychain.save(
            Data("not-valid-key-metadata".utf8),
            service: corruptService,
            account: KeychainConstants.metadataAccount,
            accessControl: nil
        )

        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )

        XCTAssertEqual(try harness.store.loadAll(), [readable])
        XCTAssertFalse(harness.keychain.exists(
            service: KeychainConstants.metadataService(fingerprint: readable.fingerprint),
            account: KeychainConstants.metadataAccount
        ))
        XCTAssertTrue(harness.keychain.exists(
            service: corruptService,
            account: KeychainConstants.metadataAccount
        ))
        XCTAssertEqual(harness.store.migrationWarning, AppKeyMetadataDomainStore.migrationWarningMessage())
    }

    func test_keyMetadataDomain_committedCorruptionEntersRecoveryWithoutLegacyRebuild() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataCommittedCorruption")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let domainIdentity = makeMetadataIdentity(
            fingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            userId: "Domain <domain@example.invalid>"
        )
        let legacyIdentity = makeMetadataIdentity(
            fingerprint: "ffffffffffffffffffffffffffffffffffffffff",
            userId: "Legacy <legacy@example.invalid>"
        )
        try harness.legacyStore.save(domainIdentity)
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        try harness.legacyStore.save(legacyIdentity)
        try harness.storageRoot.writeProtectedData(
            Data("corrupt-current-key-metadata".utf8),
            to: harness.storageRoot.domainEnvelopeURL(
                for: AppKeyMetadataDomainStore.domainID,
                slot: .current
            )
        )
        let reopenedStore = AppKeyMetadataDomainStore(
            legacyMetadataStore: harness.legacyStore,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        do {
            _ = try await reopenedStore.openDomainIfNeeded(
                wrappingRootKey: harness.wrappingRootKey,
                authenticationContext: LAContext()
            )
            XCTFail("Expected corrupt committed key metadata to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertNil(reopenedStore.payload)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[AppKeyMetadataDomainStore.domainID],
            .recoveryNeeded
        )
        XCTAssertTrue(harness.keychain.exists(
            service: KeychainConstants.metadataService(fingerprint: legacyIdentity.fingerprint),
            account: KeychainConstants.metadataAccount
        ))
    }

    func test_keyMetadataDomain_mutationsPersistWithoutEnumeratingPrivateKeychainRows() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataMutations")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        harness.keychain.resetCallHistory()

        var identity = makeMetadataIdentity(
            fingerprint: "9999999999999999999999999999999999999999",
            userId: "Mutable <mutable@example.invalid>"
        )
        try harness.store.save(identity)
        identity.isBackedUp = true
        try harness.store.update(identity)
        XCTAssertEqual(try harness.store.loadAll(), [identity])
        try harness.store.delete(fingerprint: identity.fingerprint)

        XCTAssertEqual(try harness.store.loadAll(), [])
        XCTAssertEqual(harness.keychain.listItemsCallCount, 0)
        XCTAssertEqual(harness.keychain.loadCallCount, 0)
        XCTAssertEqual(harness.keychain.saveCallCount, 0)
        XCTAssertEqual(harness.keychain.deleteCallCount, 0)
    }

    func test_completePendingDelete_clearsCleanupPendingAndPendingMutation() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataCompletePendingDelete")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let defaultsSuiteName = "com.cypherair.tests.protected-data.complete-delete.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defer { defaults.removePersistentDomain(forName: defaultsSuiteName) }

        let storageRoot = AppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let registryStore = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.complete-delete"
        )
        let keyManager = AppProtectedDomainKeyManager(storageRoot: storageRoot)
        let settingsStore = CypherAir.ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: keyManager
        )

        try storageRoot.ensureDomainDirectoryExists(for: CypherAir.ProtectedSettingsStore.domainID)
        try storageRoot.writeProtectedData(
            Data("current".utf8),
            to: storageRoot.domainEnvelopeURL(
                for: CypherAir.ProtectedSettingsStore.domainID,
                slot: .current
            )
        )

        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.complete-delete",
            sharedResourceLifecycleState: .cleanupPending,
            committedMembership: [:],
            pendingMutation: .deleteDomain(
                targetDomainID: CypherAir.ProtectedSettingsStore.domainID,
                phase: .membershipRemoved
            )
        )
        try registryStore.saveRegistry(registry)

        let cleanupCalled = AsyncBooleanFlag()
        _ = try await registryStore.completePendingDelete(
            domainID: CypherAir.ProtectedSettingsStore.domainID,
            deleteArtifacts: {
                try settingsStore.deleteDomainArtifactsForRecovery()
            },
            cleanupSharedResourceIfNeeded: {
                await cleanupCalled.setTrue()
            }
        )

        let clearedRegistry = try registryStore.loadRegistry()
        XCTAssertNil(clearedRegistry.pendingMutation)
        XCTAssertEqual(clearedRegistry.sharedResourceLifecycleState, .absent)
        let didCleanup = await cleanupCalled.currentValue()
        XCTAssertTrue(didCleanup)
        XCTAssertFalse(
            try storageRoot.managedItemExists(
                at: storageRoot.domainEnvelopeURL(
                    for: CypherAir.ProtectedSettingsStore.domainID,
                    slot: .current
                )
            )
        )
    }
}

private func XCTAssertThrowsErrorAsync(
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
