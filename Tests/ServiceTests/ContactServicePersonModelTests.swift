import XCTest
@testable import CypherAir

final class ContactServicePersonModelTests: ContactServiceTestCase {
    // MARK: - PR5 Contact Identities

    func test_pr5ImportMatcher_sameFingerprintDoesNotReturnCandidate() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let matcher = ContactImportMatcher()
        let generated = try engine.generateKey(
            name: "Matcher Same Fingerprint",
            email: "matcher-same@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        _ = try mutator.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        let validation = try PGPContactImportAdapter(engine: engine)
            .validateImportablePublicCertificate(generated.publicKeyData)

        XCTAssertNil(matcher.candidateMatch(for: validation, in: snapshot))
    }

    func test_pr5SnapshotMutator_sameFingerprintUpdatePreservesCanonicalIds() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let generated = try engine.generateKey(
            name: "Mutator Stable Key",
            email: "mutator-stable@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try mutator.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        let beforeRecord = try XCTUnwrap(snapshot.keyRecords.first)

        let update = try mutator.addContact(
            publicKeyData: refreshed.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )

        guard case .updated(let fingerprint) = update.output else {
            return XCTFail("Expected .updated, got \(update.output)")
        }
        let afterRecord = try XCTUnwrap(snapshot.keyRecords.first)
        XCTAssertEqual(fingerprint, beforeRecord.fingerprint)
        XCTAssertEqual(afterRecord.contactId, beforeRecord.contactId)
        XCTAssertEqual(afterRecord.keyId, beforeRecord.keyId)
    }

    func test_pr5SnapshotMutator_removeKeyPrunesOwnedCertificationArtifacts() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let generated = try engine.generateKey(
            name: "Artifact Removed Key",
            email: "artifact-removed@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        _ = try mutator.addContact(
            publicKeyData: generated.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        try attachCertificationArtifact(
            artifactId: "artifact-remove-key",
            toKeyWithFingerprint: generated.fingerprint,
            in: &snapshot
        )
        try snapshot.validateContract()

        let mutation = try mutator.removeKey(
            fingerprint: generated.fingerprint,
            in: &snapshot
        )

        XCTAssertTrue(mutation.didMutate)
        XCTAssertTrue(snapshot.identities.isEmpty)
        XCTAssertTrue(snapshot.keyRecords.isEmpty)
        XCTAssertTrue(snapshot.certificationArtifacts.isEmpty)
        XCTAssertNoThrow(try snapshot.validateContract())
    }

    func test_pr5SnapshotMutator_removeContactIdentityPrunesOnlyOwnedCertificationArtifacts() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let firstKey = try engine.generateKey(
            name: "Artifact Target One",
            email: "artifact-target-one@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let secondKey = try engine.generateKey(
            name: "Artifact Target Two",
            email: "artifact-target-two@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )
        let retainedKey = try engine.generateKey(
            name: "Artifact Retained",
            email: "artifact-retained@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        _ = try mutator.addContact(
            publicKeyData: firstKey.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        _ = try mutator.addContact(
            publicKeyData: secondKey.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        _ = try mutator.addContact(
            publicKeyData: retainedKey.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        let targetContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == firstKey.fingerprint }?.contactId
        )
        let sourceContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == secondKey.fingerprint }?.contactId
        )
        _ = try mutator.mergeContact(
            sourceContactId: sourceContactId,
            into: targetContactId,
            in: &snapshot
        )

        try attachCertificationArtifact(
            artifactId: "artifact-target-one",
            toKeyWithFingerprint: firstKey.fingerprint,
            in: &snapshot
        )
        try attachCertificationArtifact(
            artifactId: "artifact-target-two",
            toKeyWithFingerprint: secondKey.fingerprint,
            in: &snapshot
        )
        try attachCertificationArtifact(
            artifactId: "artifact-retained",
            toKeyWithFingerprint: retainedKey.fingerprint,
            in: &snapshot
        )
        try snapshot.validateContract()

        let mutation = try mutator.removeContactIdentity(
            contactId: targetContactId,
            in: &snapshot
        )

        XCTAssertTrue(mutation.didMutate)
        XCTAssertFalse(snapshot.identities.contains { $0.contactId == targetContactId })
        XCTAssertFalse(snapshot.keyRecords.contains { $0.contactId == targetContactId })
        XCTAssertEqual(snapshot.certificationArtifacts.map(\.artifactId), ["artifact-retained"])
        XCTAssertTrue(snapshot.keyRecords.contains { $0.fingerprint == retainedKey.fingerprint })
        XCTAssertNoThrow(try snapshot.validateContract())
    }

    func test_pr5RecipientResolver_usesPreferredKeyAndRejectsRemovedContactId() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let resolver = ContactRecipientResolver()
        let firstKey = try engine.generateKey(
            name: "Resolver One",
            email: "resolver-one@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let secondKey = try engine.generateKey(
            name: "Resolver Two",
            email: "resolver-two@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        _ = try mutator.addContact(
            publicKeyData: firstKey.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        _ = try mutator.addContact(
            publicKeyData: secondKey.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        let targetContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == firstKey.fingerprint }?.contactId
        )
        let sourceContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == secondKey.fingerprint }?.contactId
        )
        _ = try mutator.mergeContact(
            sourceContactId: sourceContactId,
            into: targetContactId,
            in: &snapshot
        )

        XCTAssertEqual(
            try resolver.publicKeysForRecipientContactIDs([targetContactId], in: snapshot),
            [firstKey.publicKeyData]
        )
        XCTAssertThrowsError(
            try resolver.publicKeysForRecipientContactIDs([sourceContactId], in: snapshot)
        ) { error in
            guard case .invalidKeyData = error as? CypherAirError else {
                return XCTFail("Expected invalidKeyData for removed contact ID, got \(error)")
            }
        }
    }

    func test_pr5SummaryProjector_recipientRowsUsePreferredKeyVerificationOnly() throws {
        var snapshot = ContactsDomainSnapshot.empty()
        let mutator = ContactSnapshotMutator(engine: engine)
        let projector = ContactSummaryProjector()
        let preferredKey = try engine.generateKey(
            name: "Projector Preferred",
            email: "projector-preferred@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let historicalKey = try engine.generateKey(
            name: "Projector Historical",
            email: "projector-historical@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        _ = try mutator.addContact(
            publicKeyData: preferredKey.publicKeyData,
            verificationState: .verified,
            in: &snapshot
        )
        _ = try mutator.addContact(
            publicKeyData: historicalKey.publicKeyData,
            verificationState: .unverified,
            in: &snapshot
        )
        let targetContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == preferredKey.fingerprint }?.contactId
        )
        let sourceContactId = try XCTUnwrap(
            snapshot.keyRecords.first { $0.fingerprint == historicalKey.fingerprint }?.contactId
        )
        _ = try mutator.mergeContact(
            sourceContactId: sourceContactId,
            into: targetContactId,
            in: &snapshot
        )
        _ = try mutator.setKeyUsageState(
            .historical,
            fingerprint: historicalKey.fingerprint,
            in: &snapshot
        )

        let identity = try XCTUnwrap(projector.identitySummary(contactId: targetContactId, in: snapshot))
        let recipient = try XCTUnwrap(
            projector.recipientSummaries(from: snapshot).first { $0.contactId == targetContactId }
        )
        XCTAssertTrue(identity.hasUnverifiedKeys)
        XCTAssertEqual(recipient.preferredKey.fingerprint, preferredKey.fingerprint)
        XCTAssertTrue(recipient.isPreferredKeyVerified)
    }

    func test_pr5ProtectedImport_sameEmailDifferentFingerprintCreatesNewIdentityAndStrongCandidate() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5StrongCandidate")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let firstKey = try engine.generateKey(
            name: "Strong Candidate",
            email: "candidate@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let secondKey = try engine.generateKey(
            name: "Strong Candidate",
            email: "candidate@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        let firstResult = try service.importContact(publicKeyData: firstKey.publicKeyData)
        guard case .added(let firstContact, _) = firstResult else {
            return XCTFail("Expected .added, got \(firstResult)")
        }

        let secondResult = try service.importContact(publicKeyData: secondKey.publicKeyData)
        guard case .addedWithCandidate(let secondContact, _, let candidate) = secondResult else {
            return XCTFail("Expected .addedWithCandidate, got \(secondResult)")
        }

        XCTAssertEqual(candidate.strength, .strong)
        XCTAssertEqual(candidate.contactIds, [try XCTUnwrap(firstContact.contactId)])
        XCTAssertNotEqual(firstContact.contactId, secondContact.contactId)
        XCTAssertEqual(service.availableContactIdentities.count, 2)
        XCTAssertEqual(service.testContactFingerprints.sorted(), [
            firstKey.fingerprint,
            secondKey.fingerprint,
        ].sorted())
    }

    func test_pr5ProtectedImport_sameUserIdWithoutEmailCreatesWeakCandidateAndNeverAutoLinks() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5WeakCandidate")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let firstKey = try engine.generateKey(
            name: "Weak Candidate",
            email: nil,
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let secondKey = try engine.generateKey(
            name: "Weak Candidate",
            email: nil,
            expirySeconds: nil,
            suite: .ed448X448
        )

        let firstResult = try service.importContact(publicKeyData: firstKey.publicKeyData)
        guard case .added(let firstContact, _) = firstResult else {
            return XCTFail("Expected .added, got \(firstResult)")
        }

        let secondResult = try service.importContact(publicKeyData: secondKey.publicKeyData)
        guard case .addedWithCandidate(let secondContact, _, let candidate) = secondResult else {
            return XCTFail("Expected .addedWithCandidate, got \(secondResult)")
        }

        XCTAssertEqual(candidate.strength, .weak)
        XCTAssertEqual(candidate.contactIds, [try XCTUnwrap(firstContact.contactId)])
        XCTAssertNotEqual(firstContact.contactId, secondContact.contactId)
        XCTAssertEqual(service.availableContactIdentities.count, 2)
    }

    func test_pr5ProtectedSameFingerprintUpdatePreservesCanonicalIdentityAndKeyIds() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5SameFingerprintUpdate")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let generated = try engine.generateKey(
            name: "Stable Key",
            email: "stable@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let refreshed = try engine.modifyExpiry(
            certData: generated.certData,
            newExpirySeconds: 60 * 60 * 24 * 365
        )

        _ = try service.importContact(publicKeyData: generated.publicKeyData)
        let beforeSnapshot = try service.currentContactsDomainSnapshot()
        let beforeRecord = try XCTUnwrap(beforeSnapshot.keyRecords.first)

        let updateResult = try service.importContact(publicKeyData: refreshed.publicKeyData)
        guard case .updated(let updatedContact, _) = updateResult else {
            return XCTFail("Expected .updated, got \(updateResult)")
        }

        let afterSnapshot = try service.currentContactsDomainSnapshot()
        let afterRecord = try XCTUnwrap(afterSnapshot.keyRecords.first)
        XCTAssertEqual(updatedContact.contactId, beforeRecord.contactId)
        XCTAssertEqual(afterRecord.contactId, beforeRecord.contactId)
        XCTAssertEqual(afterRecord.keyId, beforeRecord.keyId)
        XCTAssertEqual(afterRecord.fingerprint, beforeRecord.fingerprint)
    }

    func test_pr5ProtectedMergePreservesKeyStateAndHistoricalSignerRecognition() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5MergeState")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let targetKey = try engine.generateKey(
            name: "Merge Target",
            email: "merge-target@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let sourceKey = try engine.generateKey(
            name: "Merge Source",
            email: "merge-source@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        _ = try service.importContact(publicKeyData: targetKey.publicKeyData, verificationState: .verified)
        _ = try service.importContact(publicKeyData: sourceKey.publicKeyData, verificationState: .unverified)
        let targetContactId = try XCTUnwrap(service.contactId(forFingerprint: targetKey.fingerprint))
        let sourceContactId = try XCTUnwrap(service.contactId(forFingerprint: sourceKey.fingerprint))

        let mergeResult = try service.mergeContact(sourceContactId: sourceContactId, into: targetContactId)

        XCTAssertEqual(mergeResult.survivingContact.contactId, targetContactId)
        XCTAssertFalse(mergeResult.preferredKeyNeedsSelection)

        let summary = try XCTUnwrap(service.availableContactIdentity(forContactID: targetContactId))
        XCTAssertEqual(summary.keys.count, 2)
        XCTAssertEqual(summary.preferredKey?.fingerprint, targetKey.fingerprint)
        let incomingKey = try XCTUnwrap(summary.keys.first { $0.fingerprint == sourceKey.fingerprint })
        XCTAssertEqual(incomingKey.usageState, .additionalActive)
        XCTAssertEqual(incomingKey.manualVerificationState, .unverified)

        let recipientKeys = try service.publicKeysForRecipientContactIDs([targetContactId])
        XCTAssertEqual(recipientKeys, [targetKey.publicKeyData])

        try service.setKeyUsageState(.historical, fingerprint: sourceKey.fingerprint)
        let historicalSummary = try XCTUnwrap(service.availableContactIdentity(forContactID: targetContactId))
        XCTAssertEqual(historicalSummary.historicalKeys.map(\.fingerprint), [sourceKey.fingerprint])
        XCTAssertEqual(try service.publicKeysForRecipientContactIDs([targetContactId]), [targetKey.publicKeyData])

        let verificationContext = service.contactsVerificationContext()
        XCTAssertEqual(verificationContext.availability, .availableProtectedDomain)
        XCTAssertTrue(verificationContext.contactKeys.contains { $0.fingerprint == sourceKey.fingerprint })
        XCTAssertTrue(verificationContext.contactKeys.contains { $0.fingerprint == targetKey.fingerprint })
    }

    func test_pr5ProtectedMergeUnionsTags() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5MergeMembership")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let targetKey = try engine.generateKey(
            name: "Tagged Target",
            email: "tagged-target@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let sourceKey = try engine.generateKey(
            name: "Tagged Source",
            email: "tagged-source@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        _ = try service.importContact(publicKeyData: targetKey.publicKeyData)
        _ = try service.importContact(publicKeyData: sourceKey.publicKeyData)
        let targetContactId = try XCTUnwrap(service.contactId(forFingerprint: targetKey.fingerprint))
        let sourceContactId = try XCTUnwrap(service.contactId(forFingerprint: sourceKey.fingerprint))

        let now = Date()
        var snapshot = try service.currentContactsDomainSnapshot()
        snapshot.tags = [
            ContactTag(
                tagId: "tag-target",
                displayName: "Target Tag",
                normalizedName: ContactTag.normalizedName(for: "Target Tag"),
                createdAt: now,
                updatedAt: now
            ),
            ContactTag(
                tagId: "tag-source",
                displayName: "Source Tag",
                normalizedName: ContactTag.normalizedName(for: "Source Tag"),
                createdAt: now,
                updatedAt: now
            ),
        ]
        let targetIdentityIndex = try XCTUnwrap(
            snapshot.identities.firstIndex { $0.contactId == targetContactId }
        )
        let sourceIdentityIndex = try XCTUnwrap(
            snapshot.identities.firstIndex { $0.contactId == sourceContactId }
        )
        snapshot.identities[targetIdentityIndex].tagIds = ["tag-target"]
        snapshot.identities[sourceIdentityIndex].tagIds = ["tag-source"]
        try opened.harness.store.replaceSnapshot(snapshot)
        try await service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        let reopenedService = reopened.service

        _ = try reopenedService.mergeContact(sourceContactId: sourceContactId, into: targetContactId)

        let mergedSnapshot = try reopenedService.currentContactsDomainSnapshot()
        let mergedIdentity = try XCTUnwrap(
            mergedSnapshot.identities.first { $0.contactId == targetContactId }
        )
        XCTAssertEqual(Set(mergedIdentity.tagIds), Set(["tag-target", "tag-source"]))
        XCTAssertFalse(mergedSnapshot.identities.contains { $0.contactId == sourceContactId })
    }

    func test_pr5ProtectedPreferredKeySelectionPersistsAndMissingPreferredFailsClosed() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsPR5PreferredPersistence")
        defer {
            try? FileManager.default.removeItem(at: opened.harness.storageRoot.rootURL.deletingLastPathComponent())
        }
        let service = opened.service
        let firstKey = try engine.generateKey(
            name: "Preferred One",
            email: "preferred-one@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let secondKey = try engine.generateKey(
            name: "Preferred Two",
            email: "preferred-two@example.invalid",
            expirySeconds: nil,
            suite: .ed448X448
        )

        _ = try service.importContact(publicKeyData: firstKey.publicKeyData)
        _ = try service.importContact(publicKeyData: secondKey.publicKeyData)
        let targetContactId = try XCTUnwrap(service.contactId(forFingerprint: firstKey.fingerprint))
        let sourceContactId = try XCTUnwrap(service.contactId(forFingerprint: secondKey.fingerprint))
        _ = try service.mergeContact(sourceContactId: sourceContactId, into: targetContactId)

        try service.setPreferredKey(fingerprint: secondKey.fingerprint, for: targetContactId)
        try await service.relockProtectedData()
        let reopened = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        let reopenedService = reopened.service
        XCTAssertEqual(
            reopenedService.availableContactIdentity(forContactID: targetContactId)?.preferredKey?.fingerprint,
            secondKey.fingerprint
        )
        XCTAssertEqual(try reopenedService.publicKeysForRecipientContactIDs([targetContactId]), [secondKey.publicKeyData])

        var unresolvedSnapshot = try reopenedService.currentContactsDomainSnapshot()
        for index in unresolvedSnapshot.keyRecords.indices
            where unresolvedSnapshot.keyRecords[index].contactId == targetContactId {
            unresolvedSnapshot.keyRecords[index].usageState = .additionalActive
        }
        try reopened.store.replaceSnapshot(unresolvedSnapshot)
        try await reopenedService.relockProtectedData()
        let unresolved = await reopenProtectedContactService(
            harness: opened.harness,
            contactsDirectory: opened.contactsDirectory
        )
        let unresolvedService = unresolved.service

        XCTAssertNil(unresolvedService.availableContactIdentity(forContactID: targetContactId)?.preferredKey)
        XCTAssertThrowsError(try unresolvedService.publicKeysForRecipientContactIDs([targetContactId])) { error in
            guard case .invalidKeyData = error as? CypherAirError else {
                return XCTFail("Expected invalidKeyData for missing preferred key, got \(error)")
            }
        }
    }
}
