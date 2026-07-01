import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class ProtectedDataDomainKeySessionTests: ProtectedDataFrameworkTestCase {
    func test_domainKeyManager_deriveWrappingRootKey_zeroizesInputAndWrapsDeterministicallyPerDomain() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataKeys")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
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

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        var rawSecret = Data(repeating: 0x33, count: 32)
        let wrappingRootKey = try keyManager.deriveWrappingRootKey(from: &rawSecret)
        let malformedRecord = ProtectedDataTestAppWrappedDomainMasterKeyRecord(
            magic: ProtectedDataTestAppWrappedDomainMasterKeyRecord.magic,
            formatVersion: ProtectedDataTestAppWrappedDomainMasterKeyRecord.currentFormatVersion,
            algorithmID: ProtectedDataTestAppWrappedDomainMasterKeyRecord.algorithmID,
            aadVersion: ProtectedDataTestAppWrappedDomainMasterKeyRecord.currentAADVersion,
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

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        rightStoreClient.seedRootSecret(Data(repeating: 0xAB, count: 32), identifier: "com.cypherair.tests.protected-data.session")
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
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
        XCTAssertEqual(rightStoreClient.loadCallCount, 1)

        await coordinator.relockCurrentSession()

        XCTAssertEqual(participant.relockCallCount, 1)
        XCTAssertEqual(coordinator.frameworkState, .sessionLocked)
        XCTAssertFalse(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
    }

    func test_sessionRelockCoordinatorDeduplicatesParticipantsAndReportsFailures() async throws {
        let relockCoordinator = ProtectedDataTestAppProtectedDataSessionRelockCoordinator()
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
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        rightStoreClient.seedRootSecret(Data(repeating: 0xA1, count: 32), identifier: identifier)
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
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
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        rightStoreClient.seedRootSecret(Data(repeating: 0xA2, count: 32), identifier: identifier)
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
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
        rightStoreClient.seedRootSecret(Data(repeating: 0xA3, count: 32), identifier: identifier)

        let secondAuthorizationResult = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "ProtectedData unit test second authorization"
        )

        XCTAssertEqual(firstAuthorizationResult, .authorized)
        XCTAssertEqual(secondAuthorizationResult, .authorized)
        XCTAssertEqual(coordinator.frameworkState, .sessionAuthorized)
        XCTAssertTrue(coordinator.hasActiveWrappingRootKey)
        XCTAssertFalse(keyManager.hasUnlockedDomainMasterKeys)
        XCTAssertEqual(rightStoreClient.loadCallCount, 2)
    }

    func test_sessionCoordinator_authorizationUsesProvidedAppSessionContext() async throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataSessionHandoff")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let rootSecretStore = RecordingProtectedDataRootSecretStore()
        rootSecretStore.seedRootSecret(Data(repeating: 0xBC, count: 32), identifier: "com.cypherair.tests.protected-data.session-handoff")
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
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
        XCTAssertEqual(rootSecretStore.loadCallCount, 1)
    }

    func test_sessionCoordinator_reprotectRootSecretDisallowsSecondInteraction() throws {
        let baseDirectory = makeTemporaryDirectory("ProtectedDataReprotectInteractionDisallowed")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let rootSecretStore = RecordingProtectedDataRootSecretStore()
        rootSecretStore.seedRootSecret(Data(repeating: 0xB7, count: 32), identifier: "com.cypherair.tests.protected-data.reprotect")
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
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

        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        rightStoreClient.seedRootSecret(Data(repeating: 0xAC, count: 32), identifier: "com.cypherair.tests.protected-data.restart")
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
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
}
