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
            wrappingRootKey: harness.wrappingRootKey
        )
        let payload = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
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

    func test_keyMetadataDomain_v2MismatchedConfigurationCustodyRequiresRecovery() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataMismatchedConfigCustody")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let invalidIdentity = PGPKeyIdentity(
            fingerprint: "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
            keyVersion: 4,
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
            wrappingRootKey: harness.wrappingRootKey
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
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        do {
            _ = try await reopenedStore.openDomainIfNeeded(
                wrappingRootKey: harness.wrappingRootKey
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
            wrappingRootKey: harness.wrappingRootKey
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
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        do {
            _ = try await reopenedStore.openDomainIfNeeded(
                wrappingRootKey: harness.wrappingRootKey
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
            wrappingRootKey: harness.wrappingRootKey
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
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        do {
            _ = try await reopenedStore.openDomainIfNeeded(
                wrappingRootKey: harness.wrappingRootKey
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
            wrappingRootKey: harness.wrappingRootKey
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
                expectedCurrentGenerationIdentifier: "3"
            ),
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        do {
            _ = try await reopenedStore.openDomainIfNeeded(
                wrappingRootKey: harness.wrappingRootKey
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

    func test_keyMetadataDomain_bootstrapLagFromInterruptedCommitHealsForward() async throws {
        // Simulates a kill between the pending→current promotion and the
        // bootstrap write: current holds sealed generation N+1 while the
        // bootstrap watermark still reads N. The open must accept the
        // authenticated next generation and heal the watermark forward
        // instead of bricking the domain.
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataBootstrapLagHeals")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1",
            userId: "Healed <healed@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )
        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )
        try harness.store.save(identity)
        try ProtectedDomainBootstrapStore(storageRoot: harness.storageRoot).saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: 2,
                expectedCurrentGenerationIdentifier: "1"
            ),
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        let payload = try await reopenedStore.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )

        XCTAssertEqual(reopenedStore.domainState, .loaded)
        XCTAssertEqual(payload.identities, [identity])
        let healedMetadata = try XCTUnwrap(
            ProtectedDomainBootstrapStore(storageRoot: harness.storageRoot).loadMetadata(
                for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
            )
        )
        XCTAssertEqual(healedMetadata.expectedCurrentGenerationIdentifier, "2")
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
            .active
        )
    }

    func test_keyMetadataDomain_missingCurrentWithSealedNextPendingCompletesCommit() async throws {
        // Simulates a kill between the current→previous and pending→current
        // promotions: the current slot is gone but a fully sealed
        // next-generation pending envelope exists. The open must complete
        // the interrupted commit and land on the new generation.
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataPendingCompletesCommit")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let committedIdentity = makeMetadataIdentity(
            fingerprint: "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2",
            userId: "Committed <committed@example.invalid>"
        )
        let pendingIdentity = makeMetadataIdentity(
            fingerprint: "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
            userId: "Pending <pending-commit@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )
        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )
        try harness.store.save(committedIdentity)
        try writeKeyMetadataPendingEnvelope(
            payload: ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(
                identities: [committedIdentity, pendingIdentity]
            ),
            schemaVersion: 2,
            generationIdentifier: 3,
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
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        let payload = try await reopenedStore.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )

        XCTAssertEqual(reopenedStore.domainState, .loaded)
        XCTAssertEqual(
            payload.identities.map(\.fingerprint),
            [committedIdentity.fingerprint, pendingIdentity.fingerprint]
        )
        XCTAssertTrue(
            try harness.storageRoot.managedItemExists(
                at: harness.storageRoot.domainEnvelopeURL(
                    for: ProtectedDataTestAppKeyMetadataDomainStore.domainID,
                    slot: .current
                )
            )
        )
        let healedMetadata = try XCTUnwrap(
            ProtectedDomainBootstrapStore(storageRoot: harness.storageRoot).loadMetadata(
                for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
            )
        )
        XCTAssertEqual(healedMetadata.expectedCurrentGenerationIdentifier, "3")
    }

    func test_keyMetadataDomain_currentGenerationTooFarAheadRequiresRecovery() async throws {
        // Exactly one generation ahead of the bootstrap watermark is the only
        // healable state; a wider gap cannot come from a single interrupted
        // commit and must stay fail-closed.
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataTooFarAhead")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2",
            userId: "Too Far <too-far@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )
        try writeKeyMetadataEnvelope(
            payload: ProtectedDataTestAppKeyMetadataDomainStore.Payload.initial(identities: [identity]),
            schemaVersion: 2,
            generationIdentifier: 4,
            storageRoot: harness.storageRoot,
            domainKeyManager: harness.domainKeyManager,
            wrappingRootKey: harness.wrappingRootKey
        )
        try ProtectedDomainBootstrapStore(storageRoot: harness.storageRoot).saveMetadata(
            ProtectedDomainBootstrapMetadata(
                schemaVersion: 2,
                expectedCurrentGenerationIdentifier: "2"
            ),
            for: ProtectedDataTestAppKeyMetadataDomainStore.domainID
        )
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        do {
            _ = try await reopenedStore.openDomainIfNeeded(
                wrappingRootKey: harness.wrappingRootKey
            )
            XCTFail("Expected a current generation two ahead of bootstrap metadata to require recovery.")
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
            wrappingRootKey: harness.wrappingRootKey
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
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        let payload = try await reopenedStore.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )

        XCTAssertEqual(reopenedStore.domainState, .loaded)
        XCTAssertEqual(payload.identities.map(\.fingerprint), [currentIdentity.fingerprint])
        XCTAssertEqual(
            try harness.registryStore.loadRegistry().committedMembership[ProtectedDataTestAppKeyMetadataDomainStore.domainID],
            .active
        )
    }

    func test_keyMetadataDomain_unsupportedSchemaFailsClosed() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataUnsupportedSchema")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        let identity = makeMetadataIdentity(
            fingerprint: "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4",
            userId: "Future <future@example.invalid>"
        )
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
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
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )

        do {
            _ = try await reopenedStore.openDomainIfNeeded(
                wrappingRootKey: harness.wrappingRootKey
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

    func test_keyMetadataPayloadValidationRejectsConfigurationKeyVersionMismatch() throws {
        // The persisted keyVersion must match the authoritative configuration
        // identity's key version (a v6 record claiming the v4 Legacy family).
        let identity = PGPKeyIdentity(
            fingerprint: "a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
            keyVersion: 6,
            userId: "Mismatched Configuration <mismatched-configuration@example.invalid>",
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

    func test_keyMetadataDomain_pendingCreateRecoveryFromJournaledCreatesEmptyPayload() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataRecoveryJournaled")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        try await leaveKeyMetadataPendingCreateAtJournaled(registryStore: harness.registryStore)

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

        let payload = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )
        XCTAssertEqual(payload.identities, [])
    }

    func test_keyMetadataDomain_pendingCreateRecoveryFromStagedArtifactsPreservesStagedPayload() async throws {
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

            _ = try await harness.store.openDomainIfNeeded(
                wrappingRootKey: harness.wrappingRootKey
            )
            XCTAssertEqual(try harness.store.loadAll(), [identity])
        }
    }

    func test_keyMetadataDomain_mutationsPersistAcrossRelockAndReopen() async throws {
        let harness = try await makeKeyMetadataDomainHarness("KeyMetadataMutations")
        defer { try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent()) }
        try await harness.store.ensureCommittedIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )
        _ = try await harness.store.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )

        var identity = makeMetadataIdentity(
            fingerprint: "9999999999999999999999999999999999999999",
            userId: "Mutable <mutable@example.invalid>"
        )
        try harness.store.save(identity)
        identity.isBackedUp = true
        try harness.store.update(identity)
        XCTAssertEqual(try harness.store.loadAll(), [identity])

        try await harness.store.relockProtectedData()
        let reopenedStore = ProtectedDataTestAppKeyMetadataDomainStore(
            storageRoot: harness.storageRoot,
            registryStore: harness.registryStore,
            domainKeyManager: harness.domainKeyManager,
            currentWrappingRootKey: { harness.wrappingRootKey }
        )
        _ = try await reopenedStore.openDomainIfNeeded(
            wrappingRootKey: harness.wrappingRootKey
        )
        XCTAssertEqual(try reopenedStore.loadAll(), [identity])

        try reopenedStore.delete(fingerprint: identity.fingerprint)
        XCTAssertEqual(try reopenedStore.loadAll(), [])
    }
}
