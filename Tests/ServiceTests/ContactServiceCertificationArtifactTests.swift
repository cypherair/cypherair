import XCTest
@testable import CypherAir

final class ContactServiceCertificationArtifactTests: ContactServiceTestCase {
    func test_pr6ProtectedCertificationArtifactSaveDeduplicatesExportsAndPersists() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR6CertificationSave")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "PR6 Certified Contact",
            email: "pr6-certified@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let keyRecord = try XCTUnwrap(
            service.availableContactKeyRecord(contactId: contactId, preferredKeyId: nil)
        )
        let (artifact, duplicateArtifact) = try await makeVerifiedCertificationArtifacts(
            service: service,
            keyRecord: keyRecord,
            exportFilenames: ("artifact-pr6-save.asc", "artifact-pr6-duplicate.asc")
        )

        let saved = try service.saveCertificationArtifact(artifact)
        let duplicate = try service.saveCertificationArtifact(duplicateArtifact)
        let export = try service.exportCertificationArtifact(artifactId: saved.artifactId)
        let snapshot = try service.currentContactsDomainSnapshot()
        let projectedKey = try XCTUnwrap(
            snapshot.keyRecords.first { $0.keyId == keyRecord.keyId }
        )

        XCTAssertEqual(duplicate.artifactId, saved.artifactId)
        XCTAssertEqual(service.certificationArtifacts(for: keyRecord.keyId).map(\.artifactId), [saved.artifactId])
        XCTAssertEqual(projectedKey.certificationProjection.status, .certified)
        XCTAssertEqual(projectedKey.certificationProjection.artifactIds, [saved.artifactId])
        XCTAssertTrue(String(data: export.data, encoding: .utf8)?.contains("BEGIN PGP SIGNATURE") == true)
        XCTAssertEqual(export.filename, "artifact-pr6-save.asc")

        XCTAssertThrowsError(
            try service.updateCertificationArtifactValidation(
                artifactId: saved.artifactId,
                status: .valid
            )
        )

        try await service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        let reopenedArtifacts = reopened.service.certificationArtifacts(for: keyRecord.keyId)

        XCTAssertEqual(reopenedArtifacts.map(\.artifactId), [saved.artifactId])
        XCTAssertEqual(
            reopened.service.availableKey(keyId: keyRecord.keyId)?.certificationProjection.status,
            .certified
        )
    }

    func test_pr6CertificationProjectionDoesNotChangeManualVerification() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR6ManualSeparate")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "PR6 Manual Separate",
            email: "pr6-manual@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .unverified
        )
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let keyRecord = try XCTUnwrap(
            service.availableContactKeyRecord(contactId: contactId, preferredKeyId: nil)
        )

        _ = try service.saveCertificationArtifact(
            try await makeVerifiedCertificationArtifact(
                service: service,
                keyRecord: keyRecord,
                exportFilename: "artifact-pr6-manual-separate.asc"
            )
        )
        let summary = try XCTUnwrap(service.availableKey(keyId: keyRecord.keyId))

        XCTAssertEqual(summary.manualVerificationState, .unverified)
        XCTAssertEqual(summary.certificationProjection.status, .certified)
    }

    func test_pr6CertificationArtifactSaveRejectsStaleTargetDigest() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR6StaleDigest")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "PR6 Stale Digest",
            email: "pr6-stale-digest@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let keyRecord = try XCTUnwrap(
            service.availableContactKeyRecord(contactId: contactId, preferredKeyId: nil)
        )
        let before = try service.currentContactsDomainSnapshot()
        var snapshot = before
        let staleArtifact = makeValidCertificationArtifact(
            artifactId: "artifact-pr6-stale-target",
            keyRecord: keyRecord,
            signatureData: Data([0xde, 0xad])
        ) {
            $0.targetCertificateDigest = ContactCertificationArtifactReference.sha256Hex(
                for: Data("different target certificate".utf8)
            )
        }

        XCTAssertThrowsError(
            try ContactSnapshotMutator(engine: engine).saveCertificationArtifact(
                staleArtifact,
                in: &snapshot
            )
        )
        XCTAssertEqual(snapshot, before)
    }

    func test_pr6CertificationArtifactSaveBackfillsMissingTargetDigest() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR6BackfillDigest")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "PR6 Backfill Digest",
            email: "pr6-backfill@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let keyRecord = try XCTUnwrap(
            service.availableContactKeyRecord(contactId: contactId, preferredKeyId: nil)
        )
        var snapshot = try service.currentContactsDomainSnapshot()
        let artifact = makeValidCertificationArtifact(
            artifactId: "artifact-pr6-backfilled-target",
            keyRecord: keyRecord,
            signatureData: Data([0xca, 0xfe])
        ) {
            $0.targetCertificateDigest = nil
        }

        let mutation = try ContactSnapshotMutator(engine: engine).saveCertificationArtifact(
            artifact,
            in: &snapshot
        )
        let projectedKey = try XCTUnwrap(
            snapshot.keyRecords.first { $0.keyId == keyRecord.keyId }
        )

        XCTAssertEqual(
            mutation.output.targetCertificateDigest,
            ContactCertificationArtifactReference.sha256Hex(for: keyRecord.publicKeyData)
        )
    }

    func test_pr6CertificationArtifactDedupeRefreshesValidatedMetadata() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR6DedupeRefresh")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "PR6 Dedupe Refresh",
            email: "pr6-dedupe@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let keyRecord = try XCTUnwrap(
            service.availableContactKeyRecord(contactId: contactId, preferredKeyId: nil)
        )
        var snapshot = try service.currentContactsDomainSnapshot()
        let oldCreatedAt = Date(timeIntervalSince1970: 1_000)
        let signatureData = Data([0x5a, 0x5b])
        let staleArtifact = makeValidCertificationArtifact(
            artifactId: "artifact-pr6-refresh-existing",
            keyRecord: keyRecord,
            signatureData: signatureData
        ) {
            $0.createdAt = oldCreatedAt
            $0.validationStatus = .invalidOrStale
            $0.targetCertificateDigest = ContactCertificationArtifactReference.sha256Hex(
                for: Data("old certificate".utf8)
            )
            $0.signerPrimaryFingerprint = "1111111111111111111111111111111111111111"
            $0.signingKeyFingerprint = "1111111111111111111111111111111111111111"
            $0.certificationKind = .generic
            $0.exportFilename = "existing.asc"
        }
        snapshot.certificationArtifacts.append(staleArtifact)
        _ = try ContactSnapshotMutator(engine: engine).recomputeCertificationProjections(
            in: &snapshot
        )
        let refreshedCandidate = makeValidCertificationArtifact(
            artifactId: "artifact-pr6-refresh-candidate",
            keyRecord: keyRecord,
            signatureData: signatureData
        ) {
            $0.signerPrimaryFingerprint = "2222222222222222222222222222222222222222"
            $0.signingKeyFingerprint = "3333333333333333333333333333333333333333"
            $0.certificationKind = .positive
            $0.targetCertificateDigest = ContactCertificationArtifactReference.sha256Hex(
                for: keyRecord.publicKeyData
            )
            $0.exportFilename = "candidate.asc"
        }

        let mutation = try ContactSnapshotMutator(engine: engine).saveCertificationArtifact(
            refreshedCandidate,
            in: &snapshot
        )

        XCTAssertEqual(mutation.output.artifactId, "artifact-pr6-refresh-existing")
        XCTAssertEqual(mutation.output.createdAt, oldCreatedAt)
        XCTAssertEqual(mutation.output.validationStatus, .valid)
        XCTAssertEqual(
            mutation.output.targetCertificateDigest,
            ContactCertificationArtifactReference.sha256Hex(for: keyRecord.publicKeyData)
        )
        XCTAssertEqual(mutation.output.signerPrimaryFingerprint, "2222222222222222222222222222222222222222")
        XCTAssertEqual(mutation.output.signingKeyFingerprint, "3333333333333333333333333333333333333333")
        XCTAssertEqual(mutation.output.certificationKind, .positive)
        XCTAssertEqual(mutation.output.exportFilename, "existing.asc")
        XCTAssertEqual(snapshot.certificationArtifacts.count, 1)
    }

    func test_pr6CertificationProjectionRecomputeMarksStaleDigestInvalidOrStale() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR6RecomputeStaleDigest")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "PR6 Recompute Stale Digest",
            email: "pr6-recompute-stale@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let keyRecord = try XCTUnwrap(
            service.availableContactKeyRecord(contactId: contactId, preferredKeyId: nil)
        )
        var snapshot = try service.currentContactsDomainSnapshot()
        let lastValidatedAt = Date(timeIntervalSince1970: 10)
        let updatedAt = Date(timeIntervalSince1970: 20)
        let artifact = makeValidCertificationArtifact(
            artifactId: "artifact-pr6-recompute-stale-digest",
            keyRecord: keyRecord,
            signatureData: Data([0x44, 0x55])
        ) {
            $0.targetCertificateDigest = ContactCertificationArtifactReference.sha256Hex(
                for: Data("old target certificate".utf8)
            )
            $0.lastValidatedAt = lastValidatedAt
        }
        snapshot.certificationArtifacts.append(artifact)

        let didMutate = try ContactSnapshotMutator(engine: engine).recomputeCertificationProjections(
            in: &snapshot,
            updatedAt: updatedAt
        )

        let normalizedArtifact = try XCTUnwrap(
            snapshot.certificationArtifacts.first { $0.artifactId == artifact.artifactId }
        )
        let projectedKey = try XCTUnwrap(
            snapshot.keyRecords.first { $0.keyId == keyRecord.keyId }
        )
        XCTAssertTrue(didMutate)
        XCTAssertEqual(normalizedArtifact.validationStatus, .invalidOrStale)
        XCTAssertEqual(normalizedArtifact.updatedAt, updatedAt)
        XCTAssertEqual(normalizedArtifact.lastValidatedAt, lastValidatedAt)
        XCTAssertEqual(projectedKey.certificationProjection.status, .invalidOrStale)
        XCTAssertEqual(projectedKey.certificationProjection.artifactIds, [artifact.artifactId])
    }

    func test_pr6CertificationProjectionRecomputeReturnsTrueWhenOnlyArtifactStatusChanges() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR6RecomputeArtifactOnly")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "PR6 Recompute Artifact Only",
            email: "pr6-recompute-artifact@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let keyRecord = try XCTUnwrap(
            service.availableContactKeyRecord(contactId: contactId, preferredKeyId: nil)
        )
        var snapshot = try service.currentContactsDomainSnapshot()
        let lastValidatedAt = Date(timeIntervalSince1970: 30)
        let updatedAt = Date(timeIntervalSince1970: 40)
        let artifact = makeValidCertificationArtifact(
            artifactId: "artifact-pr6-recompute-artifact-only",
            keyRecord: keyRecord,
            signatureData: Data([0x66, 0x77])
        ) {
            $0.targetCertificateDigest = ContactCertificationArtifactReference.sha256Hex(
                for: Data("previous target certificate".utf8)
            )
            $0.lastValidatedAt = lastValidatedAt
        }
        snapshot.certificationArtifacts.append(artifact)
        let keyIndex = try XCTUnwrap(snapshot.keyRecords.firstIndex { $0.keyId == keyRecord.keyId })
        snapshot.keyRecords[keyIndex].certificationArtifactIds = [artifact.artifactId]
        snapshot.keyRecords[keyIndex].certificationProjection = ContactCertificationProjection(
            status: .invalidOrStale,
            artifactIds: [artifact.artifactId],
            lastValidatedAt: lastValidatedAt
        )
        let keyRecordsBefore = snapshot.keyRecords

        let didMutate = try ContactSnapshotMutator(engine: engine).recomputeCertificationProjections(
            in: &snapshot,
            updatedAt: updatedAt
        )

        XCTAssertTrue(didMutate)
        XCTAssertEqual(snapshot.keyRecords, keyRecordsBefore)
        XCTAssertEqual(snapshot.certificationArtifacts.first?.validationStatus, .invalidOrStale)
        XCTAssertEqual(snapshot.certificationArtifacts.first?.updatedAt, updatedAt)
    }

    func test_pr6CertificationProjectionRecomputeKeepsCurrentDigestValidCertified() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR6RecomputeValidDigest")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "PR6 Recompute Valid Digest",
            email: "pr6-recompute-valid@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(service.contactId(forFingerprint: generated.fingerprint))
        let keyRecord = try XCTUnwrap(
            service.availableContactKeyRecord(contactId: contactId, preferredKeyId: nil)
        )
        var snapshot = try service.currentContactsDomainSnapshot()
        let artifact = makeValidCertificationArtifact(
            artifactId: "artifact-pr6-recompute-valid-digest",
            keyRecord: keyRecord,
            signatureData: Data([0x88, 0x99])
        )
        snapshot.certificationArtifacts.append(artifact)

        let didMutate = try ContactSnapshotMutator(engine: engine).recomputeCertificationProjections(
            in: &snapshot
        )

        let normalizedArtifact = try XCTUnwrap(
            snapshot.certificationArtifacts.first { $0.artifactId == artifact.artifactId }
        )
        let projectedKey = try XCTUnwrap(
            snapshot.keyRecords.first { $0.keyId == keyRecord.keyId }
        )
        XCTAssertTrue(didMutate)
        XCTAssertEqual(normalizedArtifact.validationStatus, .valid)
        XCTAssertEqual(projectedKey.certificationProjection.status, .certified)
        XCTAssertEqual(projectedKey.certificationProjection.artifactIds, [artifact.artifactId])
    }
}
