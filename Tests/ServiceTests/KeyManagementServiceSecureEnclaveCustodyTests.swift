import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceSecureEnclaveCustodyTests: KeyManagementServiceTestCase {

    func test_hiddenSecureEnclaveGeneration_relockWaitsForIdentityCommitAndRollsBackHandles() async throws {
        let identityCommitGate = ProvisioningCheckpointGate()
        let waiterRegisteredGate = ProvisioningCheckpointGate()
        let deleteStarted = expectation(description: "hidden generation metadata rollback delete started")
        let allowDelete = DispatchSemaphore(value: 0)
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.deleteCheckpoint = {
            deleteStarted.fulfill()
            allowDelete.wait()
        }
        defer {
            allowDelete.signal()
        }
        let target = makeHiddenSecureEnclaveGenerationService(
            metadataPersistence: metadataPersistence,
            afterIdentityCommitCheckpoint: {
                await identityCommitGate.suspend()
            },
            commitDrainWaiterRegisteredCheckpoint: {
                await waiterRegisteredGate.suspend()
            }
        )
        let targetService = target.service

        let generationTask = Task { [targetService] in
            try await targetService.generateSecureEnclaveCustodyKey(
                name: "Hidden Relock Drain",
                email: "hidden-drain@example.com",
                expirySeconds: nil,
                configurationIdentity: .compatibleP256V4
            )
        }

        await waitUntil("hidden generation identity-store checkpoint") {
            await identityCommitGate.isSuspended()
        }
        XCTAssertEqual(target.metadataPersistence.saveCallCount, 1)
        XCTAssertEqual(target.metadataPersistence.identities.map(\.fingerprint), ["hidden-drain"])
        XCTAssertEqual(target.keyStore.storedHandleCount(), 2)

        let relockTask = Task { [targetService] in
            try await targetService.relockProtectedData()
        }
        let relockFinished = AsyncFlag()
        let observedRelockTask = Task {
            try await relockTask.value
            await relockFinished.set()
        }
        await waitUntil("hidden generation commit-drain waiter") {
            await waiterRegisteredGate.isSuspended()
        }

        await waiterRegisteredGate.resume()
        await identityCommitGate.resume()
        await fulfillment(of: [deleteStarted], timeout: 2)
        for _ in 0..<10 {
            await Task.yield()
        }
        let didRelockFinishWhileRollbackWasBlocked = await relockFinished.isSet()
        XCTAssertFalse(
            didRelockFinishWhileRollbackWasBlocked,
            "Relock must stay inside the shared commit drain until hidden rollback finishes."
        )
        allowDelete.signal()

        do {
            _ = try await generationTask.value
            XCTFail("Expected invalidated hidden generation to cancel during identity commit")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }
        try await observedRelockTask.value

        XCTAssertEqual(targetService.metadataLoadState, .locked)
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertTrue(target.metadataPersistence.identities.isEmpty)
        XCTAssertEqual(target.metadataPersistence.deleteCallCount, 1)
        XCTAssertEqual(target.keyStore.storedHandleCount(), 0)
        XCTAssertEqual(target.keyStore.deleteRequests.map(\.role), [.signing, .keyAgreement])
    }

    func test_loadKeysRefreshesSecureEnclaveCustodyRecoveryReportAndRelockClearsIt() async throws {
        let metadataPersistence = RecordingKeyMetadataPersistence()
        let identity = Self.hiddenCustodyIdentity(fingerprint: "hidden-recovery", keyVersion: 4)
        metadataPersistence.seed([identity])
        let expectedReport = SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: [
                SecureEnclaveCustodyGenerationRecoveryAssessment(
                    identityOrdinal: 0,
                    publicMaterialAvailability: .available,
                    revocationArtifactAvailability: .available,
                    handleAvailability: .unavailable(.privateHandleMissing)
                )
            ],
            inventorySummary: .empty,
            inventoryFailureCategory: nil
        )
        let recoveryClassifier = RecordingSecureEnclaveCustodyRecoveryClassifier(
            report: expectedReport
        )
        let targetService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            privateKeyControlStore: InMemoryPrivateKeyControlStore(mode: .standard),
            metadataPersistence: metadataPersistence,
            secureEnclaveCustodyRecoveryService: recoveryClassifier
        )

        try targetService.loadKeys()

        XCTAssertEqual(recoveryClassifier.requestedIdentityFingerprints, ["hidden-recovery"])
        XCTAssertEqual(targetService.secureEnclaveCustodyRecoveryReport, expectedReport)

        try await targetService.relockProtectedData()

        XCTAssertEqual(targetService.secureEnclaveCustodyRecoveryReport, .empty)
        XCTAssertEqual(targetService.metadataLoadState, .locked)
    }

    func test_deleteHiddenSecureEnclaveCustodyKeyRefreshesRecoveryReport() throws {
        let metadataPersistence = RecordingKeyMetadataPersistence()
        let hiddenIdentity = Self.hiddenCustodyIdentity(fingerprint: "hidden-delete", keyVersion: 4)
        metadataPersistence.seed([hiddenIdentity])
        let recoveryClassifier = RecordingSecureEnclaveCustodyRecoveryClassifier { identities in
            Self.hiddenRecoveryReport(identities: identities)
        }
        let targetService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            privateKeyControlStore: InMemoryPrivateKeyControlStore(mode: .standard),
            metadataPersistence: metadataPersistence,
            secureEnclaveCustodyRecoveryService: recoveryClassifier
        )

        try targetService.loadKeys()
        XCTAssertEqual(targetService.secureEnclaveCustodyRecoveryReport.assessments.count, 1)

        try targetService.deleteKey(fingerprint: hiddenIdentity.fingerprint)

        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertTrue(targetService.secureEnclaveCustodyRecoveryReport.assessments.isEmpty)
        XCTAssertEqual(recoveryClassifier.requestedIdentitySnapshots.map { $0.map(\.fingerprint) }, [
            ["hidden-delete"],
            []
        ])
    }

    func test_deleteSecureEnclaveCustodyKeyDeletesHandlesAndMetadata() async throws {
        let fixture = try await generatedHiddenCustodyExportFixture(
            configurationIdentity: .compatibleP256V4
        )
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let pair = try seedCustodyHandles(
            fixture: fixture,
            keyStore: keyStore,
            handleSetIdentifier: "delete-success"
        )
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.seed([fixture.identity])
        let targetService = makeSecureEnclaveCustodyDeletionTarget(
            metadataPersistence: metadataPersistence,
            keyStore: keyStore
        )
        try targetService.loadKeys()

        try targetService.deleteKey(fingerprint: fixture.identity.fingerprint)

        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertTrue(metadataPersistence.identities.isEmpty)
        XCTAssertEqual(keyStore.storedHandleCount(), 0)
        XCTAssertEqual(keyStore.deleteRequests, pair.references)
    }

    func test_deleteSecureEnclaveCustodyKeyHandleFailureStillRemovesMetadataAndReportsPartialDeletion() async throws {
        let fixture = try await generatedHiddenCustodyExportFixture(
            configurationIdentity: .compatibleP256V4
        )
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let pair = try seedCustodyHandles(
            fixture: fixture,
            keyStore: keyStore,
            handleSetIdentifier: "delete-failure"
        )
        keyStore.failDeleteRole = .signing
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.seed([fixture.identity])
        let targetService = makeSecureEnclaveCustodyDeletionTarget(
            metadataPersistence: metadataPersistence,
            keyStore: keyStore
        )
        try targetService.loadKeys()

        // A non-missing Secure Enclave handle-delete failure still surfaces a
        // partial-deletion error to the caller…
        XCTAssertThrowsError(try targetService.deleteKey(fingerprint: fixture.identity.fingerprint)) { error in
            // Partial deletion surfaces as the typed .keychainError case; the
            // guarded behavior is the catalog-metadata removal and handle state
            // asserted below, not the human-readable message text.
            guard case CypherAirError.keychainError = error else {
                return XCTFail("Expected keychainError, got \(error)")
            }
        }

        // …but the catalog metadata is REMOVED, so the device-bound key is no longer
        // trapped in the catalog. (The bug: it used to survive and recur on every retry,
        // clearable only by a full data reset.)
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertTrue(metadataPersistence.identities.isEmpty)
        // Secure Enclave deletion is genuinely partial: the failing signing handle is
        // stranded while the key-agreement handle was already removed.
        XCTAssertTrue(keyStore.contains(reference: pair.signing.reference))
        XCTAssertFalse(keyStore.contains(reference: pair.keyAgreement.reference))

        // Idempotency: a second delete does not crash and the key stays gone. It routes
        // through the catalog-miss orphan path (no resurrection); the stranded signing
        // handle is left for the inventory-based full-reset cleanup, not re-targeted here.
        keyStore.failDeleteRole = nil
        XCTAssertNoThrow(try targetService.deleteKey(fingerprint: fixture.identity.fingerprint))
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertTrue(metadataPersistence.identities.isEmpty)
    }

    func test_deleteSecureEnclaveCustodyKeyMetadataAssociationMismatchStillRemovesMetadataAndReportsPartialDeletion() async throws {
        let fixture = try await generatedHiddenCustodyExportFixture(
            configurationIdentity: .compatibleP256V4
        )
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        _ = try seedCustodyHandles(
            fixture: fixture,
            keyStore: keyStore,
            handleSetIdentifier: "delete-mismatch"
        )
        // Desync the stored identity from its public-binding inspection: same public-key
        // bytes and fingerprint, but a key version the inspector will not match → the
        // handle-deletion guard returns .metadataAssociationMismatch before any delete.
        let desyncedIdentity = makeIdentity(
            from: fixture.identity,
            keyVersion: fixture.identity.keyVersion == 4 ? 6 : 4
        )
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.seed([desyncedIdentity])
        let targetService = makeSecureEnclaveCustodyDeletionTarget(
            metadataPersistence: metadataPersistence,
            keyStore: keyStore
        )
        try targetService.loadKeys()

        XCTAssertThrowsError(try targetService.deleteKey(fingerprint: desyncedIdentity.fingerprint)) { error in
            // Partial deletion surfaces as the typed .keychainError case; the
            // guarded behavior is the catalog-metadata removal and handle state
            // asserted below, not the human-readable message text.
            guard case CypherAirError.keychainError = error else {
                return XCTFail("Expected keychainError, got \(error)")
            }
        }

        // The desync no longer makes the key permanently undeletable.
        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertTrue(metadataPersistence.identities.isEmpty)
        // No handle was touched — the mismatch guard tripped before deleteHandlePair.
        XCTAssertTrue(keyStore.deleteRequests.isEmpty)
        XCTAssertEqual(keyStore.storedHandleCount(), 2)
    }

    func test_deleteSecureEnclaveCustodyKeyMissingHandlesIsCleanDeletion() async throws {
        let fixture = try await generatedHiddenCustodyExportFixture(
            configurationIdentity: .compatibleP256V4
        )
        let keyStore = MockSecureEnclaveCustodyKeyStore() // no handles seeded → already missing
        let metadataPersistence = RecordingKeyMetadataPersistence()
        metadataPersistence.seed([fixture.identity])
        let targetService = makeSecureEnclaveCustodyDeletionTarget(
            metadataPersistence: metadataPersistence,
            keyStore: keyStore
        )
        try targetService.loadKeys()

        // Handles already gone is a benign, error-free deletion — not a partial-deletion throw.
        XCTAssertNoThrow(try targetService.deleteKey(fingerprint: fixture.identity.fingerprint))

        XCTAssertTrue(targetService.keys.isEmpty)
        XCTAssertTrue(metadataPersistence.identities.isEmpty)
        XCTAssertEqual(keyStore.storedHandleCount(), 0)
    }

    func test_confirmKeyBackupExportedRefreshesRecoveryReportWithCurrentSnapshot() throws {
        let metadataPersistence = RecordingKeyMetadataPersistence()
        let hiddenIdentity = Self.hiddenCustodyIdentity(
            fingerprint: "hidden-backup",
            keyVersion: 4,
            isBackedUp: false
        )
        metadataPersistence.seed([hiddenIdentity])
        let recoveryClassifier = RecordingSecureEnclaveCustodyRecoveryClassifier { identities in
            Self.hiddenRecoveryReport(identities: identities) { identity in
                identity.isBackedUp ? .available : .unavailable(.privateHandleMissing)
            }
        }
        let targetService = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            privateKeyControlStore: InMemoryPrivateKeyControlStore(mode: .standard),
            metadataPersistence: metadataPersistence,
            secureEnclaveCustodyRecoveryService: recoveryClassifier
        )

        try targetService.loadKeys()
        XCTAssertEqual(
            targetService.secureEnclaveCustodyRecoveryReport.assessments.first?.handleAvailability,
            .unavailable(.privateHandleMissing)
        )

        targetService.confirmKeyBackupExported(fingerprint: hiddenIdentity.fingerprint)

        XCTAssertEqual(
            recoveryClassifier.requestedIdentitySnapshots.last?.first?.isBackedUp,
            true
        )
        XCTAssertEqual(
            targetService.secureEnclaveCustodyRecoveryReport.assessments.first?.handleAvailability,
            .available
        )
    }

    func test_exportPublicKey_hiddenSecureEnclaveCustody_returnsStoredPublicCertificate() async throws {
        for configurationIdentity in [
            PGPKeyConfiguration.Identity.compatibleP256V4,
            .modernP256V6
        ] {
            let fixture = try await generatedHiddenCustodyExportFixture(
                configurationIdentity: configurationIdentity
            )
            try storeIdentity(fixture.identity)
            try service.loadKeys()
            let unwrapCountBefore = mockSE.unwrapCallCount

            let armored = try service.exportPublicKey(fingerprint: fixture.identity.fingerprint)
            let binary = try engine.dearmor(armored: armored)

            XCTAssertEqual(binary, fixture.identity.publicKeyData)
            XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore)
            let inspection = try PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine)
                .inspectPublicBindings(publicKeyData: binary)
            XCTAssertEqual(inspection.fingerprint, fixture.identity.fingerprint)
            XCTAssertEqual(inspection.keyVersion, fixture.identity.keyVersion)
            XCTAssertEqual(inspection.signingPublicKeyX963, fixture.signingPublicKeyX963)
            XCTAssertEqual(inspection.keyAgreementPublicKeyX963, fixture.keyAgreementPublicKeyX963)
        }
    }

    func test_exportKey_hiddenSecureEnclaveCustody_isUnsupportedAndDoesNotUnwrapOrMarkBackedUp() async throws {
        let fixture = try await generatedHiddenCustodyExportFixture(
            configurationIdentity: .compatibleP256V4
        )
        try storeIdentity(fixture.identity)
        try service.loadKeys()
        XCTAssertFalse(try XCTUnwrap(service.keys.first).isBackedUp)
        let unwrapCountBefore = mockSE.unwrapCallCount

        do {
            _ = try await service.exportKeyBackupData(
                fingerprint: fixture.identity.fingerprint,
                passphrase: "backup-pass"
            )
            XCTFail("Expected Secure Enclave custody backup export to be unsupported")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnsupportedForCustody)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        do {
            _ = try await service.exportKey(
                fingerprint: fixture.identity.fingerprint,
                passphrase: "backup-pass"
            )
            XCTFail("Expected Secure Enclave custody private export to be unsupported")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnsupportedForCustody)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore)
        XCTAssertFalse(try loadStoredIdentity(fingerprint: fixture.identity.fingerprint).isBackedUp)
        XCTAssertFalse(try XCTUnwrap(service.keys.first).isBackedUp)
    }

    func test_exportRevocationCertificate_hiddenSecureEnclaveCustody_returnsStoredRevocationArtifact() async throws {
        for configurationIdentity in [
            PGPKeyConfiguration.Identity.compatibleP256V4,
            .modernP256V6
        ] {
            let fixture = try await generatedHiddenCustodyExportFixture(
                configurationIdentity: configurationIdentity
            )
            try storeIdentity(fixture.identity)
            try service.loadKeys()
            let unwrapCountBefore = mockSE.unwrapCallCount
            let saveCountBefore = mockKC.saveCallCount

            let armored = try await service.exportRevocationCertificate(
                fingerprint: fixture.identity.fingerprint
            )
            let binary = try engine.dearmor(armored: armored)

            XCTAssertEqual(binary, fixture.identity.revocationCert)
            XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore)
            XCTAssertEqual(mockKC.saveCallCount, saveCountBefore)
            let validation = try engine.parseRevocationCert(
                revData: binary,
                certData: fixture.identity.publicKeyData
            )
            XCTAssertTrue(validation.lowercased().contains(fixture.identity.fingerprint.lowercased()))
        }
    }

    func test_exportRevocationCertificate_hiddenSecureEnclaveCustody_missingArtifactFailsClosed() async throws {
        let fixture = try await generatedHiddenCustodyExportFixture(
            configurationIdentity: .modernP256V6
        )
        var identity = fixture.identity
        identity.revocationCert = Data()
        try storeIdentity(identity)
        try service.loadKeys()
        let unwrapCountBefore = mockSE.unwrapCallCount
        let saveCountBefore = mockKC.saveCallCount

        do {
            _ = try await service.exportRevocationCertificate(fingerprint: identity.fingerprint)
            XCTFail("Expected missing Secure Enclave revocation artifact to fail closed")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .revocationArtifactUnavailable)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore)
        XCTAssertEqual(mockKC.saveCallCount, saveCountBefore)
        XCTAssertTrue(try loadStoredIdentity(fingerprint: identity.fingerprint).revocationCert.isEmpty)
    }

    func test_modifyExpiry_secureEnclaveCustodyWithoutRoutingService_staysBlockedUnderExposedPolicy() async throws {
        // The exposed production policy approves SE modify-expiry at the
        // resolver, but a container without the expiry-mutation routing service
        // must still fail closed (never fall back to software custody paths).
        let fixture = try await generatedHiddenCustodyExportFixture(
            configurationIdentity: .compatibleP256V4
        )
        try storeIdentity(fixture.identity)
        try service.loadKeys()
        let unwrapCountBefore = mockSE.unwrapCallCount

        do {
            _ = try await service.modifyExpiry(
                fingerprint: fixture.identity.fingerprint,
                newExpirySeconds: 60 * 60 * 24
            )
            XCTFail("Expected unrouted Secure Enclave modify-expiry to fail closed")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore)
    }

    func test_selectiveRevocation_secureEnclaveCustodyWithoutRoutingService_staysBlockedUnderExposedPolicy() async throws {
        // Post-flip, the resolver approves SE revocation, so the unrouted
        // custody arm in SelectiveRevocationService is the load-bearing
        // fail-closed barrier — pin it (mirror of the modify-expiry case).
        let fixture = try await generatedHiddenCustodyExportFixture(
            configurationIdentity: .compatibleP256V4
        )
        try storeIdentity(fixture.identity)
        try service.loadKeys()
        let catalog = try service.selectionCatalog(fingerprint: fixture.identity.fingerprint)
        let subkey = try XCTUnwrap(catalog.subkeys.first)
        let unwrapCountBefore = mockSE.unwrapCallCount

        do {
            _ = try await service.exportSubkeyRevocationCertificate(
                fingerprint: fixture.identity.fingerprint,
                subkeySelection: subkey
            )
            XCTFail("Expected unrouted Secure Enclave selective revocation to fail closed")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }

        XCTAssertEqual(mockSE.unwrapCallCount, unwrapCountBefore)
    }

    func test_generateSecureEnclaveCustodyKey_withoutWiredService_failsClosedWithPerCategoryError() async {
        // Containers without the generation factory (UI-test container, or any
        // device without a Secure Enclave) must fail closed with the sanitized
        // category so the per-category presentation copy survives — never a
        // generic reason string.
        do {
            _ = try await service.generateSecureEnclaveCustodyKey(
                name: "Unwired",
                email: nil,
                expirySeconds: nil,
                configurationIdentity: .compatibleP256V4
            )
            XCTFail("Expected unwired Secure Enclave custody generation to fail closed")
        } catch CypherAirError.keyOperationUnavailable(let category) {
            XCTAssertEqual(category, .operationUnavailableByPolicy)
        } catch {
            XCTFail("Expected keyOperationUnavailable, got \(error)")
        }
    }

    private func makeSecureEnclaveCustodyDeletionTarget(
        metadataPersistence: RecordingKeyMetadataPersistence,
        keyStore: MockSecureEnclaveCustodyKeyStore
    ) -> KeyManagementService {
        KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            privateKeyControlStore: InMemoryPrivateKeyControlStore(mode: .standard),
            secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: SecureEnclaveCustodyHandleStore(keyStore: keyStore)
            ),
            metadataPersistence: metadataPersistence
        )
    }

    private func seedCustodyHandles(
        fixture: HiddenCustodyExportFixture,
        keyStore: MockSecureEnclaveCustodyKeyStore,
        handleSetIdentifier: String
    ) throws -> SecureEnclaveCustodyHandlePair {
        let signingReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .signing
        )
        let keyAgreementReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .keyAgreement
        )
        let signingBinding = try SecureEnclaveCustodyHandlePublicBinding(
            reference: signingReference,
            publicKeyX963: fixture.signingPublicKeyX963
        )
        let keyAgreementBinding = try SecureEnclaveCustodyHandlePublicBinding(
            reference: keyAgreementReference,
            publicKeyX963: fixture.keyAgreementPublicKeyX963
        )
        keyStore.insert(SecureEnclaveCustodyLoadedHandle(binding: signingBinding, privateKey: nil))
        keyStore.insert(SecureEnclaveCustodyLoadedHandle(binding: keyAgreementBinding, privateKey: nil))
        return try SecureEnclaveCustodyHandlePair(
            signing: signingBinding,
            keyAgreement: keyAgreementBinding
        )
    }

    /// Rebuilds an identity with a different key version to simulate a stored
    /// metadata ↔ public-binding desync. The inspector derives the real version from
    /// `publicKeyData`, so the altered `keyVersion` forces the deletion mismatch guard.
    private func makeIdentity(from base: PGPKeyIdentity, keyVersion: UInt8) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: base.fingerprint,
            keyVersion: keyVersion,
            userId: base.userId,
            hasEncryptionSubkey: base.hasEncryptionSubkey,
            isRevoked: base.isRevoked,
            isExpired: base.isExpired,
            isDefault: base.isDefault,
            isBackedUp: base.isBackedUp,
            publicKeyData: base.publicKeyData,
            revocationCert: base.revocationCert,
            primaryAlgo: base.primaryAlgo,
            subkeyAlgo: base.subkeyAlgo,
            expiryDate: base.expiryDate,
            openPGPConfigurationIdentity: base.openPGPConfigurationIdentity,
            privateKeyCustodyKind: base.privateKeyCustodyKind
        )
    }

}
