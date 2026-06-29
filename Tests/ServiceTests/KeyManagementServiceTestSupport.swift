import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

final class PromptObservingSecureEnclave: SecureEnclaveManageable, @unchecked Sendable {
    let base: MockSecureEnclave
    let coordinator: CypherAir.AuthenticationPromptCoordinator
    private let observationLock = NSLock()
    private var sawOperationPromptInProgressDuringGenerateStorage = false
    private var sawOperationPromptInProgressDuringWrapStorage = false
    private var sawOperationPromptInProgressDuringReconstructStorage = false

    var sawOperationPromptInProgressDuringGenerateWrappingKey: Bool {
        observationLock.lock()
        defer { observationLock.unlock() }
        return sawOperationPromptInProgressDuringGenerateStorage
    }

    var sawOperationPromptInProgressDuringWrap: Bool {
        observationLock.lock()
        defer { observationLock.unlock() }
        return sawOperationPromptInProgressDuringWrapStorage
    }

    /// Whether the operation-prompt depth was > 0 when `reconstructKey` ran.
    /// `reconstructKey` now runs off the main actor (the SE unwrap is hopped off-main
    /// in `PrivateKeyAccessService`), so this is written off-main and read on the main
    /// actor by tests; guard it with a lock.
    var sawOperationPromptInProgressDuringReconstruct: Bool {
        observationLock.lock()
        defer { observationLock.unlock() }
        return sawOperationPromptInProgressDuringReconstructStorage
    }

    init(
        base: MockSecureEnclave,
        coordinator: CypherAir.AuthenticationPromptCoordinator
    ) {
        self.base = base
        self.coordinator = coordinator
    }

    static var isAvailable: Bool { MockSecureEnclave.isAvailable }

    func generateWrappingKey(
        accessControl: SecAccessControl?,
        authenticationContext: LAContext?
    ) throws -> any SEKeyHandle {
        let inProgress = coordinator.isOperationPromptInProgress
        observationLock.lock()
        sawOperationPromptInProgressDuringGenerateStorage = inProgress
        observationLock.unlock()
        return try base.generateWrappingKey(
            accessControl: accessControl,
            authenticationContext: authenticationContext
        )
    }

    func wrap(
        privateKey: Data,
        using handle: any SEKeyHandle,
        fingerprint: String
    ) throws -> WrappedKeyBundle {
        let inProgress = coordinator.isOperationPromptInProgress
        observationLock.lock()
        sawOperationPromptInProgressDuringWrapStorage = inProgress
        observationLock.unlock()
        return try base.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint)
    }

    func unwrap(
        bundle: WrappedKeyBundle,
        using handle: any SEKeyHandle,
        fingerprint: String
    ) throws -> Data {
        try base.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
    }

    func deleteKey(_ handle: any SEKeyHandle) throws {
        try base.deleteKey(handle)
    }

    func reconstructKey(
        from data: Data,
        authenticationContext: LAContext?
    ) throws -> any SEKeyHandle {
        let inProgress = coordinator.isOperationPromptInProgress
        observationLock.lock()
        sawOperationPromptInProgressDuringReconstructStorage = inProgress
        observationLock.unlock()
        return try base.reconstructKey(
            from: data,
            authenticationContext: authenticationContext
        )
    }
}

/// SE mock whose `reconstructKey` blocks (synchronously) until released. Used to prove
/// that `PrivateKeyAccessService` runs the SE reconstruct OFF the main actor, so the
/// main actor stays free during the (blocking) Secure Enclave biometric — the property
/// that lets the app-session lifecycle gate observe the operation prompt in-progress.
final class BlockingReconstructSecureEnclave: SecureEnclaveManageable, @unchecked Sendable {
    let base: MockSecureEnclave
    private let lock = NSLock()
    private var didStartReconstructStorage = false
    private let releaseGate = DispatchSemaphore(value: 0)

    /// Set (off-main) when `reconstructKey` begins; read on the main actor by the test.
    var didStartReconstruct: Bool {
        lock.lock()
        defer { lock.unlock() }
        return didStartReconstructStorage
    }

    init(base: MockSecureEnclave) {
        self.base = base
    }

    /// Unblocks the in-flight `reconstructKey`.
    func releaseReconstruct() {
        releaseGate.signal()
    }

    static var isAvailable: Bool { MockSecureEnclave.isAvailable }

    func generateWrappingKey(
        accessControl: SecAccessControl?,
        authenticationContext: LAContext?
    ) throws -> any SEKeyHandle {
        try base.generateWrappingKey(
            accessControl: accessControl,
            authenticationContext: authenticationContext
        )
    }

    func wrap(
        privateKey: Data,
        using handle: any SEKeyHandle,
        fingerprint: String
    ) throws -> WrappedKeyBundle {
        try base.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint)
    }

    func unwrap(
        bundle: WrappedKeyBundle,
        using handle: any SEKeyHandle,
        fingerprint: String
    ) throws -> Data {
        try base.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
    }

    func deleteKey(_ handle: any SEKeyHandle) throws {
        try base.deleteKey(handle)
    }

    func reconstructKey(
        from data: Data,
        authenticationContext: LAContext?
    ) throws -> any SEKeyHandle {
        lock.lock()
        didStartReconstructStorage = true
        lock.unlock()
        // Block this thread until the test releases. If reconstruct ran on the main
        // actor (the bug), this would stall the main thread; the fix runs it off-main.
        releaseGate.wait()
        return try base.reconstructKey(
            from: data,
            authenticationContext: authenticationContext
        )
    }
}

enum KeyManagementPrivateKeyControlTestError: Error {
    case delayedFailure
}

enum RecordingKeyMetadataPersistenceError: Error {
    case duplicateIdentity
    case loadFailed
    case saveFailed
    case updateFailed
    case deleteFailed
}

final class FailingModifyExpiryPrivateKeyControlStore: PrivateKeyControlStoreProtocol, @unchecked Sendable {
    var mode: AuthenticationMode?
    var journal = PrivateKeyControlRecoveryJournal.empty
    var failNextBeginModifyExpiry = false
    var failNextClearModifyExpiry = false

    init(mode: AuthenticationMode? = .standard) {
        self.mode = mode
    }

    var privateKeyControlState: PrivateKeyControlState {
        guard let mode else {
            return .locked
        }
        return .unlocked(mode)
    }

    func requireUnlockedAuthMode() throws -> AuthenticationMode {
        guard let mode else {
            throw PrivateKeyControlError.locked
        }
        if journal.rewrapPhase == .commitRequired,
           let targetMode = journal.rewrapTargetMode,
           targetMode != mode {
            throw PrivateKeyControlError.recoveryNeeded
        }
        return mode
    }

    func recoveryJournal() throws -> PrivateKeyControlRecoveryJournal {
        guard mode != nil else {
            throw PrivateKeyControlError.locked
        }
        return journal
    }

    func beginRewrap(targetMode: AuthenticationMode) throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapTargetMode = targetMode
        journal.rewrapPhase = .preparing
    }

    func markRewrapCommitRequired() throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapPhase = .commitRequired
    }

    func completeRewrap(targetMode: AuthenticationMode) throws {
        guard mode != nil else {
            throw PrivateKeyControlError.locked
        }
        mode = targetMode
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func clearRewrapJournal() throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func beginModifyExpiry(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        if failNextBeginModifyExpiry {
            failNextBeginModifyExpiry = false
            throw KeyManagementPrivateKeyControlTestError.delayedFailure
        }
        journal.modifyExpiry = ModifyExpiryRecoveryEntry(fingerprint: fingerprint)
    }

    func clearModifyExpiryJournal() throws {
        _ = try requireUnlockedAuthMode()
        if failNextClearModifyExpiry {
            failNextClearModifyExpiry = false
            throw KeyManagementPrivateKeyControlTestError.delayedFailure
        }
        journal.modifyExpiry = nil
    }

    func clearModifyExpiryJournalIfMatches(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        if journal.modifyExpiry?.fingerprint == fingerprint {
            journal.modifyExpiry = nil
        }
    }
}

final class RecordingKeyMetadataPersistence: KeyMetadataPersistence {
    private(set) var identities: [PGPKeyIdentity] = []
    private(set) var loadAllCallCount = 0
    private(set) var saveCallCount = 0
    private(set) var updateCallCount = 0
    private(set) var deleteCallCount = 0
    var failNextLoadAll = false
    var failNextSave = false
    var failNextUpdate = false
    var failNextDelete = false
    var throwOnDuplicate = true
    var deleteCheckpoint: (() -> Void)?

    func seed(_ identities: [PGPKeyIdentity]) {
        self.identities = identities.sorted { $0.fingerprint < $1.fingerprint }
    }

    func loadAll() throws -> [PGPKeyIdentity] {
        loadAllCallCount += 1
        if failNextLoadAll {
            failNextLoadAll = false
            throw RecordingKeyMetadataPersistenceError.loadFailed
        }
        return identities.sorted { $0.fingerprint < $1.fingerprint }
    }

    func save(_ identity: PGPKeyIdentity) throws {
        saveCallCount += 1
        if failNextSave {
            failNextSave = false
            throw RecordingKeyMetadataPersistenceError.saveFailed
        }
        if throwOnDuplicate && identities.contains(where: { $0.fingerprint == identity.fingerprint }) {
            throw RecordingKeyMetadataPersistenceError.duplicateIdentity
        }
        identities.append(identity)
        identities.sort { $0.fingerprint < $1.fingerprint }
    }

    func update(_ identity: PGPKeyIdentity) throws {
        updateCallCount += 1
        if failNextUpdate {
            failNextUpdate = false
            throw RecordingKeyMetadataPersistenceError.updateFailed
        }
        if let index = identities.firstIndex(where: { $0.fingerprint == identity.fingerprint }) {
            identities[index] = identity
        } else {
            identities.append(identity)
        }
        identities.sort { $0.fingerprint < $1.fingerprint }
    }

    func delete(fingerprint: String) throws {
        deleteCallCount += 1
        deleteCheckpoint?()
        if failNextDelete {
            failNextDelete = false
            throw RecordingKeyMetadataPersistenceError.deleteFailed
        }
        identities.removeAll { $0.fingerprint == fingerprint }
    }
}

actor ProvisioningCheckpointGate {
    var continuation: CheckedContinuation<Void, Never>?
    var didResume = false

    func suspend() async {
        await withCheckedContinuation { continuation in
            if didResume {
                continuation.resume()
            } else {
                self.continuation = continuation
            }
        }
    }

    func isSuspended() -> Bool {
        continuation != nil
    }

    func resume() {
        didResume = true
        let continuation = continuation
        self.continuation = nil
        continuation?.resume()
    }
}

actor CapturedDataBox {
    var value = Data()

    func set(_ value: Data) {
        self.value = value
    }

    func data() -> Data {
        value
    }

    func clear() {
        value.protectedDataZeroize()
        value.removeAll(keepingCapacity: false)
    }
}

actor AsyncFlag {
    var value = false

    func set() {
        value = true
    }

    func isSet() -> Bool {
        value
    }
}

final class HiddenGenerationTestCertificateBuilder: SecureEnclaveCustodyCertificateBuilding, @unchecked Sendable {
    let result: PGPSecureEnclaveCustodyGeneratedMaterial

    init(result: PGPSecureEnclaveCustodyGeneratedMaterial) {
        self.result = result
    }

    func generatePublicCertificate(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        configuration: PGPKeyConfiguration,
        handlePair: SecureEnclaveCustodyLoadedHandlePair,
        digestSigner: any SecureEnclaveCustodyDigestSigning
    ) async throws -> PGPSecureEnclaveCustodyGeneratedMaterial {
        result
    }
}

struct HiddenGenerationTestDigestSigner: SecureEnclaveCustodyDigestSigning {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        try SecureEnclaveP256RawSignature(
            r: Data(repeating: 1, count: 32),
            s: Data(repeating: 2, count: 32)
        )
    }
}

final class RecordingSecureEnclaveCustodyRecoveryClassifier: SecureEnclaveCustodyGenerationRecoveryClassifying, @unchecked Sendable {
    let reportProvider: @Sendable ([PGPKeyIdentity]) -> SecureEnclaveCustodyGenerationRecoveryReport
    private(set) var requestedIdentitySnapshots: [[PGPKeyIdentity]] = []
    var requestedIdentityFingerprints: [String] {
        requestedIdentitySnapshots.last?.map(\.fingerprint) ?? []
    }

    init(report: SecureEnclaveCustodyGenerationRecoveryReport) {
        self.reportProvider = { _ in report }
    }

    init(
        _ reportProvider: @escaping @Sendable ([PGPKeyIdentity]) -> SecureEnclaveCustodyGenerationRecoveryReport
    ) {
        self.reportProvider = reportProvider
    }

    func classify(
        identities: [PGPKeyIdentity]
    ) -> SecureEnclaveCustodyGenerationRecoveryReport {
        requestedIdentitySnapshots.append(identities)
        return reportProvider(identities)
    }
}

/// Tests for KeyManagementService — full key lifecycle with mock SE/Keychain/Auth.

class KeyManagementServiceTestCase: XCTestCase {
    var engine: PgpEngine!
    var service: KeyManagementService!
    var mockSE: MockSecureEnclave!
    var mockKC: MockKeychain!
    var mockAuth: MockAuthenticator!
    var privateKeyControlStore: InMemoryPrivateKeyControlStore!
    var metadataPersistence: RecordingKeyMetadataPersistence!

    struct ProtectedKeyMetadataProvisioningTarget {
        let baseDirectory: URL
        let defaultsSuiteName: String
        let wrappingRootKey: Data
        let keychain: MockKeychain
        let keyMetadataStore: KeyMetadataDomainStore
        let keyManagement: KeyManagementService
        let protectedDataSessionCoordinator: ProtectedDataSessionCoordinator
    }

    override func setUp() {
        super.setUp()
        engine = PgpEngine()
        privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        metadataPersistence = RecordingKeyMetadataPersistence()
        let result = TestHelpers.makeKeyManagement(
            engine: engine,
            privateKeyControlStore: privateKeyControlStore,
            metadataPersistence: metadataPersistence
        )
        service = result.service
        mockSE = result.mockSE
        mockKC = result.mockKC
        mockAuth = result.mockAuth
    }

    override func tearDown() {
        service = nil
        mockSE = nil
        mockKC = nil
        mockAuth = nil
        privateKeyControlStore = nil
        metadataPersistence = nil
        engine = nil
        super.tearDown()
    }

    func copyPermanentBundleToPending(fingerprint: String) throws {
        let account = KeychainConstants.defaultAccount
        let envelope = try mockKC.load(
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: account
        )

        try mockKC.save(
            envelope,
            service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
    }

    func makeFreshService() -> KeyManagementService {
        KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: mockAuth,
            privateKeyControlStore: privateKeyControlStore,
            metadataPersistence: metadataPersistence
        )
    }

    func makeTemporaryDirectory(_ prefix: String) throws -> URL {
        let url = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CypherAirTests", isDirectory: true)
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    func supportsCompleteProtectedFileCreation() throws -> Bool {
        let probeDirectory = try makeTemporaryDirectory("ProtectedFileCreationProbe")
        defer {
            try? FileManager.default.removeItem(at: probeDirectory)
        }

        let probeURL = probeDirectory.appendingPathComponent("probe.dat")
        guard FileManager.default.createFile(
            atPath: probeURL.path,
            contents: Data([0]),
            attributes: [.protectionKey: FileProtectionType.complete]
        ) else {
            return false
        }

        let attributes = try FileManager.default.attributesOfItem(atPath: probeURL.path)
        return attributes[.protectionKey] as? FileProtectionType == .complete
    }

    func makeCheckpointedProvisioningService(
        checkpoint: @escaping KeyProvisioningService.ProvisioningCheckpoint
    ) -> (
        service: KeyManagementService,
        keychain: MockKeychain,
        metadataPersistence: RecordingKeyMetadataPersistence
    ) {
        let localSE = MockSecureEnclave()
        let localKeychain = MockKeychain()
        let localAuthenticator = MockAuthenticator()
        let localPrivateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        let metadataPersistence = RecordingKeyMetadataPersistence()
        let service = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: localSE,
            keychain: localKeychain,
            authenticator: localAuthenticator,
            privateKeyControlStore: localPrivateKeyControlStore,
            metadataPersistence: metadataPersistence,
            provisioningCheckpoint: checkpoint
        )
        return (service, localKeychain, metadataPersistence)
    }

    func makePostProvisioningCheckpointedService(
        checkpoint: @escaping KeyProvisioningService.ProvisioningCheckpoint
    ) -> (
        service: KeyManagementService,
        keychain: MockKeychain,
        metadataPersistence: RecordingKeyMetadataPersistence
    ) {
        let localSE = MockSecureEnclave()
        let localKeychain = MockKeychain()
        let localAuthenticator = MockAuthenticator()
        let localPrivateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        let metadataPersistence = RecordingKeyMetadataPersistence()
        let service = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: localSE,
            keychain: localKeychain,
            authenticator: localAuthenticator,
            privateKeyControlStore: localPrivateKeyControlStore,
            metadataPersistence: metadataPersistence,
            postProvisioningCheckpoint: checkpoint
        )
        return (service, localKeychain, metadataPersistence)
    }

    func makeRecordingMetadataService(
        metadataPersistence: RecordingKeyMetadataPersistence = RecordingKeyMetadataPersistence(),
        beforeAuthModeReadCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        afterImportOffMainActorCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        afterPermanentBundleStoreCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        identityStoreCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        commitDrainWaiterRegisteredCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil,
        relockInvalidationCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil
    ) -> (
        service: KeyManagementService,
        keychain: MockKeychain,
        metadataPersistence: RecordingKeyMetadataPersistence
    ) {
        let localSE = MockSecureEnclave()
        let localKeychain = MockKeychain()
        let localAuthenticator = MockAuthenticator()
        let localPrivateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        let service = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: localSE,
            keychain: localKeychain,
            authenticator: localAuthenticator,
            privateKeyControlStore: localPrivateKeyControlStore,
            metadataPersistence: metadataPersistence,
            beforeAuthModeReadCheckpoint: beforeAuthModeReadCheckpoint,
            afterImportOffMainActorCheckpoint: afterImportOffMainActorCheckpoint,
            afterPermanentBundleStoreCheckpoint: afterPermanentBundleStoreCheckpoint,
            identityStoreCheckpoint: identityStoreCheckpoint,
            commitDrainWaiterRegisteredCheckpoint: commitDrainWaiterRegisteredCheckpoint,
            relockInvalidationCheckpoint: relockInvalidationCheckpoint
        )
        return (service, localKeychain, metadataPersistence)
    }

    func makeHiddenSecureEnclaveGenerationService(
        metadataPersistence: RecordingKeyMetadataPersistence = RecordingKeyMetadataPersistence(),
        keyStore: MockSecureEnclaveCustodyKeyStore = MockSecureEnclaveCustodyKeyStore(),
        authenticationPromptCoordinator: AuthenticationPromptCoordinator? = nil,
        custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator? = nil,
        afterIdentityCommitCheckpoint: SecureEnclaveCustodyGenerationService.GenerationCheckpoint? = nil,
        commitDrainWaiterRegisteredCheckpoint: KeyProvisioningService.ProvisioningCheckpoint? = nil
    ) -> (
        service: KeyManagementService,
        keyStore: MockSecureEnclaveCustodyKeyStore,
        metadataPersistence: RecordingKeyMetadataPersistence
    ) {
        let localSE = MockSecureEnclave()
        let localKeychain = MockKeychain()
        let localAuthenticator = MockAuthenticator()
        let localPrivateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        let service = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: localSE,
            keychain: localKeychain,
            authenticator: localAuthenticator,
            authenticationPromptCoordinator: authenticationPromptCoordinator ?? AuthenticationPromptCoordinator(),
            privateKeyControlStore: localPrivateKeyControlStore,
            metadataPersistence: metadataPersistence,
            commitDrainWaiterRegisteredCheckpoint: commitDrainWaiterRegisteredCheckpoint,
            secureEnclaveCustodyGenerationServiceFactory: { catalogStore, invalidationGate, commitCoordinator in
                SecureEnclaveCustodyGenerationService(
                    certificateBuilder: HiddenGenerationTestCertificateBuilder(
                        result: Self.hiddenGenerationMaterial(
                            fingerprint: "hidden-drain",
                            keyVersion: 4
                        )
                    ),
                    handleStore: SecureEnclaveCustodyHandleStore(
                        keyStore: keyStore,
                        handleSetIdentifierGenerator: { "hidden-drain" }
                    ),
                    digestSigner: HiddenGenerationTestDigestSigner(),
                    catalogStore: catalogStore,
                    resolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
                    invalidationGate: invalidationGate,
                    commitCoordinator: commitCoordinator,
                    authenticationPromptCoordinator: authenticationPromptCoordinator,
                    custodyOperationAuthenticator: custodyOperationAuthenticator,
                    afterIdentityCommitCheckpoint: afterIdentityCommitCheckpoint
                )
            }
        )
        return (service, keyStore, metadataPersistence)
    }

    func makeProtectedKeyMetadataProvisioningTarget(
        identityStoreCheckpoint: @escaping KeyProvisioningService.ProvisioningCheckpoint,
        relockInvalidationCheckpoint: @escaping KeyProvisioningService.ProvisioningCheckpoint
    ) async throws -> ProtectedKeyMetadataProvisioningTarget {
        let baseDirectory = try makeTemporaryDirectory("KeyMetadataProvisioningRelock")
        let storageRoot = ProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let sharedRightIdentifier = "com.cypherair.tests.key-metadata-provisioning.\(UUID().uuidString)"
        let registryStore = ProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: sharedRightIdentifier
        )
        _ = try registryStore.performSynchronousBootstrap()
        let domainKeyManager = ProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let defaultsSuiteName = "com.cypherair.tests.key-metadata-provisioning.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)

        let privateKeyControlStore = PrivateKeyControlStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager
        )
        let persistedSecretBox = CapturedDataBox()
        let handoffContext = LAContext()
        defer { handoffContext.invalidate() }
        _ = try await privateKeyControlStore.bootstrapFirstDomainAfterAppAuthenticationIfNeeded(
            authenticationContext: handoffContext,
            persistSharedRight: { secret in
                await persistedSecretBox.set(secret)
            }
        )

        var rootSecret = await persistedSecretBox.data()
        let wrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rootSecret)
        rootSecret.protectedDataZeroize()
        await persistedSecretBox.clear()

        let keychain = MockKeychain()
        let keyMetadataStore = KeyMetadataDomainStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey }
        )
        try await keyMetadataStore.ensureCommittedIfNeeded(
            wrappingRootKey: wrappingRootKey
        )
        _ = try await keyMetadataStore.openDomainIfNeeded(
            wrappingRootKey: wrappingRootKey
        )
        _ = try await privateKeyControlStore.openDomainIfNeeded(
            wrappingRootKey: wrappingRootKey
        )

        let protectedDataSessionCoordinator = ProtectedDataSessionCoordinator(
            domainKeyManager: domainKeyManager,
            sharedRightIdentifier: sharedRightIdentifier
        )
        let keyManagement = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: MockSecureEnclave(),
            keychain: keychain,
            authenticator: MockAuthenticator(),
            privateKeyControlStore: privateKeyControlStore,
            metadataPersistence: keyMetadataStore,
            identityStoreCheckpoint: identityStoreCheckpoint,
            relockInvalidationCheckpoint: relockInvalidationCheckpoint
        )
        protectedDataSessionCoordinator.registerRelockParticipant(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(keyManagement)
        protectedDataSessionCoordinator.registerRelockParticipant(keyMetadataStore)

        return ProtectedKeyMetadataProvisioningTarget(
            baseDirectory: baseDirectory,
            defaultsSuiteName: defaultsSuiteName,
            wrappingRootKey: wrappingRootKey,
            keychain: keychain,
            keyMetadataStore: keyMetadataStore,
            keyManagement: keyManagement,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator
        )
    }

    func assertNoProvisionedKeyMaterial(
        in keychain: MockKeychain,
        metadataPersistence: RecordingKeyMetadataPersistence,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let privateKeyServices = try keychain.listItems(
            servicePrefix: KeychainConstants.prefix,
            account: KeychainConstants.defaultAccount
        )

        XCTAssertTrue(privateKeyServices.isEmpty, file: file, line: line)
        XCTAssertTrue(metadataPersistence.identities.isEmpty, file: file, line: line)
        XCTAssertEqual(metadataPersistence.saveCallCount, 0, file: file, line: line)
    }

    func assertNoPrivateKeyMaterial(
        in keychain: MockKeychain,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let privateKeyServices = try keychain.listItems(
            servicePrefix: KeychainConstants.prefix,
            account: KeychainConstants.defaultAccount
        )

        XCTAssertTrue(privateKeyServices.isEmpty, file: file, line: line)
    }

    func copyPermanentBundle(
        fingerprint: String,
        from source: MockKeychain,
        to destination: MockKeychain
    ) throws {
        let account = KeychainConstants.defaultAccount
        let service = KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint)
        let data = try source.load(service: service, account: account)
        try destination.save(data, service: service, account: account, accessControl: nil)
    }

    func recoveryJournal() throws -> PrivateKeyControlRecoveryJournal {
        try privateKeyControlStore.recoveryJournal()
    }

    func loadStoredIdentity(fingerprint: String) throws -> PGPKeyIdentity {
        try loadStoredIdentity(fingerprint: fingerprint, persistence: metadataPersistence)
    }

    func loadStoredIdentity(
        fingerprint: String,
        persistence: RecordingKeyMetadataPersistence
    ) throws -> PGPKeyIdentity {
        guard let identity = persistence.identities.first(
            where: { $0.fingerprint == fingerprint }
        ) else {
            throw CypherAirError.noMatchingKey
        }
        return identity
    }

    func overwriteStoredIdentity(_ identity: PGPKeyIdentity) throws {
        try metadataPersistence.update(identity)
    }

    func storeIdentity(_ identity: PGPKeyIdentity) throws {
        try metadataPersistence.save(identity)
    }

    static func hiddenGenerationMaterial(
        fingerprint: String,
        keyVersion: UInt8
    ) -> PGPSecureEnclaveCustodyGeneratedMaterial {
        PGPSecureEnclaveCustodyGeneratedMaterial(
            publicKeyData: Data("public-\(fingerprint)".utf8),
            revocationCert: Data("revocation-\(fingerprint)".utf8),
            metadata: PGPKeyMetadata(
                fingerprint: fingerprint,
                keyVersion: keyVersion,
                userId: "Hidden Relock Drain <hidden-drain@example.com>",
                hasEncryptionSubkey: true,
                isRevoked: false,
                isExpired: false,
                profile: keyVersion == 4 ? .universal : .advanced,
                primaryAlgo: "ECDSA P-256",
                subkeyAlgo: "ECDH P-256",
                expiryTimestamp: nil
            ),
            signingKeyFingerprint: "\(fingerprint)-signing",
            keyAgreementSubkeyFingerprint: "\(fingerprint)-agreement"
        )
    }

    static func hiddenCustodyIdentity(
        fingerprint: String,
        keyVersion: UInt8,
        isDefault: Bool = true,
        isBackedUp: Bool = false
    ) -> PGPKeyIdentity {
        let material = hiddenGenerationMaterial(fingerprint: fingerprint, keyVersion: keyVersion)
        return PGPKeyIdentity(
            fingerprint: material.metadata.fingerprint,
            keyVersion: material.metadata.keyVersion,
            profile: material.metadata.profile,
            userId: material.metadata.userId,
            hasEncryptionSubkey: material.metadata.hasEncryptionSubkey,
            isRevoked: false,
            isExpired: false,
            isDefault: isDefault,
            isBackedUp: isBackedUp,
            publicKeyData: material.publicKeyData,
            revocationCert: material.revocationCert,
            primaryAlgo: material.metadata.primaryAlgo,
            subkeyAlgo: material.metadata.subkeyAlgo,
            expiryDate: nil,
            openPGPConfigurationIdentity: keyVersion == 4 ? .compatibleP256V4 : .modernP256V6,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
    }

    struct HiddenCustodyExportFixture {
        let identity: PGPKeyIdentity
        let signingPublicKeyX963: Data
        let keyAgreementPublicKeyX963: Data
    }

    func generatedHiddenCustodyExportFixture(
        configurationIdentity: PGPKeyConfiguration.Identity
    ) async throws -> HiddenCustodyExportFixture {
        let signingPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let keyAgreementPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let signingPublicKeyX963 = try Self.publicKeyX963(from: signingPrivateKey)
        let keyAgreementPublicKeyX963 = try Self.publicKeyX963(from: keyAgreementPrivateKey)
        let handleSetIdentifier = "export-\(UUID().uuidString.lowercased())"
        let signingReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .signing
        )
        let keyAgreementReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .keyAgreement
        )
        let handlePair = try SecureEnclaveCustodyLoadedHandlePair(
            signing: SecureEnclaveCustodyLoadedHandle(
                binding: SecureEnclaveCustodyHandlePublicBinding(
                    reference: signingReference,
                    publicKeyX963: signingPublicKeyX963
                ),
                privateKey: signingPrivateKey
            ),
            keyAgreement: SecureEnclaveCustodyLoadedHandle(
                binding: SecureEnclaveCustodyHandlePublicBinding(
                    reference: keyAgreementReference,
                    publicKeyX963: keyAgreementPublicKeyX963
                ),
                privateKey: nil
            )
        )
        let adapter = PGPSecureEnclaveCustodyGenerationAdapter(engine: engine)
        let material = try await adapter.generatePublicCertificate(
            name: "Hidden Export \(configurationIdentity.rawValue)",
            email: "hidden-export@example.invalid",
            expirySeconds: 3600,
            configuration: configurationIdentity.configuration,
            handlePair: handlePair,
            digestSigner: SystemSecureEnclaveCustodyDigestSigner()
        )
        let metadata = material.metadata
        let identity = PGPKeyIdentity(
            fingerprint: metadata.fingerprint,
            keyVersion: metadata.keyVersion,
            profile: metadata.profile,
            userId: metadata.userId,
            hasEncryptionSubkey: metadata.hasEncryptionSubkey,
            isRevoked: metadata.isRevoked,
            isExpired: metadata.isExpired,
            isDefault: true,
            isBackedUp: false,
            publicKeyData: material.publicKeyData,
            revocationCert: material.revocationCert,
            primaryAlgo: metadata.primaryAlgo,
            subkeyAlgo: metadata.subkeyAlgo,
            expiryDate: metadata.expiryDate,
            openPGPConfigurationIdentity: configurationIdentity,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
        return HiddenCustodyExportFixture(
            identity: identity,
            signingPublicKeyX963: signingPublicKeyX963,
            keyAgreementPublicKeyX963: keyAgreementPublicKeyX963
        )
    }

    static func makeEphemeralP256PrivateKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw CypherAirError.keyGenerationFailed(
                reason: error.map { CFErrorCopyDescription($0.takeRetainedValue()) as String }
                    ?? "Failed to create test P-256 key."
            )
        }
        return key
    }

    static func publicKeyX963(from privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CypherAirError.keyGenerationFailed(reason: "Failed to derive test P-256 public key.")
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw CypherAirError.keyGenerationFailed(
                reason: error.map { CFErrorCopyDescription($0.takeRetainedValue()) as String }
                    ?? "Failed to export test P-256 public key."
            )
        }
        return data
    }

    static func hiddenRecoveryReport(
        identities: [PGPKeyIdentity],
        handleAvailability: (PGPKeyIdentity) -> SecureEnclaveCustodyHandleAvailability = { _ in
            .unavailable(.privateHandleMissing)
        }
    ) -> SecureEnclaveCustodyGenerationRecoveryReport {
        let assessments = identities
            .filter { $0.privateKeyCustodyKind == .appleSecureEnclavePrivateOperations }
            .enumerated()
            .map { ordinal, identity in
                SecureEnclaveCustodyGenerationRecoveryAssessment(
                    identityOrdinal: ordinal,
                    configurationIdentity: identity.openPGPConfigurationIdentity,
                    publicMaterialAvailability: .available,
                    revocationArtifactAvailability: identity.revocationCert.isEmpty
                        ? .unavailable(.revocationArtifactUnavailable)
                        : .available,
                    handleAvailability: handleAvailability(identity)
                )
            }
        return SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: assessments,
            inventorySummary: .empty,
            inventoryFailureCategory: nil
        )
    }

    func provisionFixtureBackedIdentity(secretCertData: Data) throws -> PGPKeyIdentity {
        let info = try engine.parseKeyInfo(keyData: secretCertData)
        let metadata = PGPKeyMetadataAdapter.metadata(from: info)
        let handle = try mockSE.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try mockSE.wrap(
            privateKey: secretCertData,
            using: handle,
            fingerprint: info.fingerprint
        )
        let bundleStore = KeyBundleStore(keychain: mockKC)
        try bundleStore.saveBundle(bundle, fingerprint: info.fingerprint)

        // Test-only fixture path: retain the exact fixture bytes on the identity so
        // selector discovery sees the same duplicate-occurrence structure already
        // exercised by `test_selectionCatalog_duplicateSameBytesFixture_preservesPerOccurrenceState`.
        let identity = PGPKeyIdentity(
            fingerprint: metadata.fingerprint,
            keyVersion: metadata.keyVersion,
            profile: metadata.profile,
            userId: metadata.userId,
            hasEncryptionSubkey: metadata.hasEncryptionSubkey,
            isRevoked: metadata.isRevoked,
            isExpired: metadata.isExpired,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: secretCertData,
            revocationCert: Data(),
            primaryAlgo: metadata.primaryAlgo,
            subkeyAlgo: metadata.subkeyAlgo,
            expiryDate: metadata.expiryDate,
            openPGPConfigurationIdentity: metadata.profile.openPGPConfiguration.identity,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
        try storeIdentity(identity)
        return identity
    }

    func waitUntil(
        _ description: String,
        timeout: TimeInterval = 5,
        condition: @escaping () async -> Bool
    ) async {
        let deadline = Date().addingTimeInterval(timeout)

        while Date() < deadline {
            if await condition() {
                return
            }
            await Task.yield()
        }

        XCTFail("Timed out waiting for \(description)")
    }
}
