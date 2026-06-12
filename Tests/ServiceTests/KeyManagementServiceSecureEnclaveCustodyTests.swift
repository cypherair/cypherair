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
                    configurationIdentity: .compatibleP256V4,
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
            authenticator: MockAuthenticator(),
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
            authenticator: MockAuthenticator(),
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
            authenticator: MockAuthenticator(),
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

}
