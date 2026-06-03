import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class KeyMetadataProtectedDomainTests: ProtectedDataFrameworkTestCase {
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

        XCTAssertEqual(payload.schemaVersion, ProtectedDataTestAppKeyMetadataDomainStore.Payload.currentSchemaVersion)
        XCTAssertEqual(payload.identities, [])
        XCTAssertEqual(try harness.store.loadAll(), [])
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
            .active
        )

        try await harness.store.relockProtectedData()

        XCTAssertEqual(harness.store.domainState, .locked)
        XCTAssertNil(harness.store.payload)
        XCTAssertThrowsError(try harness.store.loadAll())
    }

    func test_keyMetadataDomain_committedSchemaV1MigratesAndWritesSchemaV2() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataSchemaV1Migration")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let legacyIdentity = makeMetadataIdentity(
            fingerprint: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            userId: "Legacy V1 <legacy-v1@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        try writeKeyMetadataEnvelope(
            payload: KeyMetadataPayloadV1(
                schemaVersion: 1,
                identities: [KeyMetadataIdentityV1(legacyIdentity)]
            ),
            schemaVersion: 1,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: harness.wrappingRootKey
        )

        let payload = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )

        XCTAssertEqual(payload.schemaVersion, 2)
        XCTAssertEqual(payload.identities.count, 1)
        XCTAssertEqual(payload.identities.first?.openPGPConfigurationIdentity, .compatibleSoftwareV4)
        XCTAssertEqual(payload.identities.first?.privateKeyCustodyKind, .softwareSecretCertificate)

        let currentEnvelope = try loadCurrentKeyMetadataEnvelope(storageRoot: harness.storageRoot)
        XCTAssertEqual(currentEnvelope.schemaVersion, 2)
        XCTAssertEqual(currentEnvelope.generationIdentifier, 3)
        let bootstrap = try ProtectedDomainBootstrapStore(storageRoot: harness.storageRoot)
            .loadMetadata(for: ProtectedDataTestAppKeyMetadataDomainStore.domainID)
        XCTAssertEqual(bootstrap?.schemaVersion, 2)
        XCTAssertEqual(bootstrap?.expectedCurrentGenerationIdentifier, "3")
    }

    func test_keyMetadataDomain_v2MismatchedConfigurationCustodyRequiresRecovery() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataMismatchedConfigCustody")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let invalidIdentity = PGPKeyIdentity(
            fingerprint: "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
            keyVersion: 4,
            profile: .universal,
            userId: "Invalid <invalid@example.invalid>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data([0x10, 0x11]),
            revocationCert: Data([0x12]),
            primaryAlgo: "P-256",
            subkeyAlgo: "P-256",
            expiryDate: nil,
            openPGPConfigurationIdentity: .compatibleP256V4,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        try writeKeyMetadataEnvelope(
            payload: ProtectedDataTestAppKeyMetadataDomainStore.Payload(
                schemaVersion: 2,
                identities: [invalidIdentity]
            ),
            schemaVersion: 2,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: harness.wrappingRootKey
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
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
            XCTFail("Expected mismatched key metadata configuration and custody to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertNil(reopenedStore.payload)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
            .recoveryNeeded
        )
    }

    func test_keyMetadataDomain_corruptCurrentGenerationDoesNotFallbackToPrevious() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataCorruptCurrentNoFallback")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
            userId: "Readable Previous <previous@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        try writeKeyMetadataEnvelope(
            payload: ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(identities: [identity]),
            schemaVersion: 2,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: harness.wrappingRootKey
        )
        try harness.storageRoot.writeProtectedData(
            Data("corrupt-current-key-metadata".utf8),
            to: harness.storageRoot.domainEnvelopeURL(
                for: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
                slot: .current
            )
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
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
            XCTFail("Expected corrupt current key metadata to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
            .recoveryNeeded
        )
    }

    func test_keyMetadataDomain_missingCurrentGenerationDoesNotFallbackToPrevious() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataMissingCurrentNoFallback")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6",
            userId: "Readable Previous <previous@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        try writeKeyMetadataEnvelope(
            payload: ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(identities: [identity]),
            schemaVersion: 2,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: harness.wrappingRootKey
        )
        try harness.storageRoot.removeItemIfPresent(
            at: harness.storageRoot.domainEnvelopeURL(
                for: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
                slot: .current
            )
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
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
            XCTFail("Expected missing current key metadata to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
            .recoveryNeeded
        )
    }

    func test_keyMetadataDomain_expectedCurrentGenerationMismatchRequiresRecovery() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataExpectedCurrentMismatch")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
            userId: "Mismatch <mismatch@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        try writeKeyMetadataEnvelope(
            payload: ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(identities: [identity]),
            schemaVersion: 2,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: harness.wrappingRootKey
        )
        try ProtectedDomainBootstrapStore(storageRoot: harness.storageRoot).saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: 2,
                expectedCurrentGenerationIdentifier: "3",
                coarseRecoveryReason: nil,
                wrappedDomainMasterKeyRecordVersion: ProtectedDataTestAppWrappedDomainMasterKeyRecord.currentFormatVersion
            ),
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
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
            XCTFail("Expected mismatched expected current key metadata generation to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
            .recoveryNeeded
        )
    }

    func test_keyMetadataDomain_stalePendingGenerationDoesNotOverrideCurrent() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataStalePendingNoOverride")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let currentIdentity = makeMetadataIdentity(
            fingerprint: "a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9",
            userId: "Current <current@example.invalid>"
        )
        let pendingIdentity = makeMetadataIdentity(
            fingerprint: "b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9",
            userId: "Pending <pending@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        try writeKeyMetadataEnvelope(
            payload: ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(identities: [currentIdentity]),
            schemaVersion: 2,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: harness.wrappingRootKey
        )
        try writeKeyMetadataPendingEnvelope(
            payload: ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(identities: [pendingIdentity]),
            schemaVersion: 2,
            generationIdentifier: 3,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: harness.wrappingRootKey
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
            legacyMetadataStore: harness.legacyStore,
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        let payload = try await reopenedStore.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )

        XCTAssertEqual(reopenedStore.domainState, .loaded)
        XCTAssertEqual(payload.identities.map(\.fingerprint), [currentIdentity.fingerprint])
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
            .active
        )
    }

    func test_keyMetadataDomain_unsupportedFutureSchemaFailsClosed() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataFutureSchema")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4",
            userId: "Future <future@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey,
            authenticationContext: LAContext()
        )
        try writeKeyMetadataEnvelope(
            payload: ProtectedDataTestAppKeyMetadataDomainStore.Payload(
                schemaVersion: 99,
                identities: [identity]
            ),
            schemaVersion: 99,
            generationIdentifier: 2,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: harness.wrappingRootKey
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
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
            XCTFail("Expected unsupported key metadata schema to require recovery.")
        } catch {
        }

        XCTAssertEqual(reopenedStore.domainState, .recoveryNeeded)
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
            .recoveryNeeded
        )
    }

    func test_keyMetadataPayloadValidationRejectsProfileKeyVersionMismatch() throws {
        let identity = PGPKeyIdentity(
            fingerprint: "a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
            keyVersion: 4,
            profile: .advanced,
            userId: "Mismatched Profile <mismatched-profile@example.invalid>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data([0x30, 0x31]),
            revocationCert: Data([0x32]),
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519",
            expiryDate: nil,
            openPGPConfigurationIdentity: .compatibleSoftwareV4,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
        let payload = ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(identities: [identity])

        XCTAssertThrowsError(try payload.validateContract())
    }

    func test_keyMetadataPayloadValidationAcceptsRepresentableSecureEnclaveP256() throws {
        let identity = PGPKeyIdentity(
            fingerprint: "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
            keyVersion: 4,
            profile: .universal,
            userId: "P-256 <p256@example.invalid>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data([0x20, 0x21]),
            revocationCert: Data([0x22]),
            primaryAlgo: "P-256",
            subkeyAlgo: "P-256",
            expiryDate: nil,
            openPGPConfigurationIdentity: .compatibleP256V4,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
        let payload = ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(identities: [identity])

        XCTAssertNoThrow(try payload.validateContract())
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
        XCTAssertEqual(harness.store.migrationWarning, ProtectedDataTestAppKeyMetadataDomainStore.migrationWarningMessage())

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

        XCTAssertEqual(harness.store.migrationWarning, ProtectedDataTestAppKeyMetadataDomainStore.migrationWarningMessage())
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
        XCTAssertEqual(registry.committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID], nil)
        guard case let .createDomain(domainID, phase)? = registry.pendingMutation else {
            XCTFail("Expected key metadata pending create to remain retryable.")
            return
        }
        XCTAssertEqual(domainID, ProtectedDataTestAppKeyMetadataDomainStore.domainID)
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
        XCTAssertEqual(harness.store.migrationWarning, ProtectedDataTestAppKeyMetadataDomainStore.migrationWarningMessage())
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
                for: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
                slot: .current
            )
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
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
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
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
}
