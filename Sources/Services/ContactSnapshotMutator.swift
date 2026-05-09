import Foundation

struct ContactSnapshotMutator {
    struct Mutation<Output> {
        let output: Output
        let didMutate: Bool
    }

    enum AddOutcome {
        case duplicate(fingerprint: String)
        case updated(fingerprint: String)
        case added(fingerprint: String, candidate: ContactCandidateMatch?)
    }

    struct MergeOutcome {
        let sourceContactId: String
        let targetContactId: String
    }

    private let engine: PgpEngine
    private let importMatcher: ContactImportMatcher

    init(
        engine: PgpEngine,
        importMatcher: ContactImportMatcher = ContactImportMatcher()
    ) {
        self.engine = engine
        self.importMatcher = importMatcher
    }

    func addContact(
        publicKeyData: Data,
        verificationState: ContactVerificationState,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<AddOutcome> {
        let validation = try ContactImportPublicCertificateValidator.validate(
            publicKeyData,
            using: engine
        )
        let binaryData = validation.publicCertData
        let now = Date()

        if let existingIndex = snapshot.keyRecords.firstIndex(where: {
            $0.fingerprint == validation.keyInfo.fingerprint
        }) {
            let existingRecord = snapshot.keyRecords[existingIndex]
            let mergedResult: CertificateMergeResult
            do {
                mergedResult = try engine.mergePublicCertificateUpdate(
                    existingCert: existingRecord.publicKeyData,
                    incomingCertOrUpdate: binaryData
                )
            } catch {
                throw ContactImportPublicCertificateValidator.mapError(error)
            }

            let resolvedVerificationState: ContactVerificationState =
                (existingRecord.manualVerificationState.isVerified || verificationState == .verified)
                ? .verified
                : existingRecord.manualVerificationState

            switch mergedResult.outcome {
            case .noOp:
                if snapshot.keyRecords[existingIndex].manualVerificationState != resolvedVerificationState {
                    snapshot.keyRecords[existingIndex].manualVerificationState = resolvedVerificationState
                    snapshot.keyRecords[existingIndex].updatedAt = now
                    snapshot.updatedAt = now
                    try normalizeKeyUsage(in: &snapshot, updatedAt: now)
                    return Mutation(
                        output: .duplicate(fingerprint: existingRecord.fingerprint),
                        didMutate: true
                    )
                }
                return Mutation(
                    output: .duplicate(fingerprint: existingRecord.fingerprint),
                    didMutate: false
                )

            case .updated:
                let updatedValidation = try ContactImportPublicCertificateValidator.validate(
                    mergedResult.mergedCertData,
                    using: engine
                )
                snapshot.keyRecords[existingIndex] = updatedKeyRecord(
                    preserving: existingRecord,
                    from: updatedValidation,
                    publicKeyData: mergedResult.mergedCertData,
                    verificationState: resolvedVerificationState,
                    now: now
                )
                markCertificationArtifactsStaleIfTargetChanged(
                    keyId: existingRecord.keyId,
                    newPublicKeyData: mergedResult.mergedCertData,
                    in: &snapshot,
                    now: now
                )
                _ = try recomputeCertificationProjections(in: &snapshot, updatedAt: now)
                updateIdentityDisplayIfNeeded(
                    contactId: existingRecord.contactId,
                    from: snapshot.keyRecords[existingIndex],
                    in: &snapshot,
                    now: now
                )
                snapshot.updatedAt = now
                try normalizeKeyUsage(in: &snapshot, updatedAt: now)
                return Mutation(
                    output: .updated(fingerprint: updatedValidation.keyInfo.fingerprint),
                    didMutate: true
                )
            }
        }

        let candidateMatch = importMatcher.candidateMatch(for: validation, in: snapshot)
        let identity = makeIdentity(from: validation, now: now)
        let keyRecord = makeKeyRecord(
            from: validation,
            contactId: identity.contactId,
            verificationState: verificationState,
            usageState: validation.keyInfo.hasEncryptionSubkey
                && !validation.keyInfo.isRevoked
                && !validation.keyInfo.isExpired
                ? .preferred
                : .historical,
            now: now
        )
        snapshot.identities.append(identity)
        snapshot.keyRecords.append(keyRecord)
        snapshot.updatedAt = now
        try normalizeKeyUsage(in: &snapshot, updatedAt: now)
        return Mutation(
            output: .added(fingerprint: validation.keyInfo.fingerprint, candidate: candidateMatch),
            didMutate: true
        )
    }

    func setVerificationState(
        _ verificationState: ContactVerificationState,
        for fingerprint: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<Void> {
        guard let index = snapshot.keyRecords.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        let now = Date()
        snapshot.keyRecords[index].manualVerificationState = verificationState
        snapshot.keyRecords[index].updatedAt = now
        snapshot.updatedAt = now
        return Mutation(output: (), didMutate: true)
    }

    func removeKey(
        fingerprint: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<Void> {
        guard let keyRecord = snapshot.keyRecords.first(where: { $0.fingerprint == fingerprint }) else {
            return Mutation(output: (), didMutate: false)
        }

        let now = Date()
        let removedKeyIds = Set([keyRecord.keyId])
        snapshot.keyRecords.removeAll { $0.fingerprint == fingerprint }
        pruneCertificationArtifacts(forRemovedKeyIds: removedKeyIds, in: &snapshot)
        if !snapshot.keyRecords.contains(where: { $0.contactId == keyRecord.contactId }) {
            snapshot.identities.removeAll { $0.contactId == keyRecord.contactId }
            for listIndex in snapshot.recipientLists.indices {
                snapshot.recipientLists[listIndex].memberContactIds.removeAll { $0 == keyRecord.contactId }
                snapshot.recipientLists[listIndex].updatedAt = now
            }
        }
        snapshot.updatedAt = now
        try normalizeKeyUsage(in: &snapshot, updatedAt: now)
        return Mutation(output: (), didMutate: true)
    }

    func removeContactIdentity(
        contactId: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<Void> {
        guard snapshot.identities.contains(where: { $0.contactId == contactId }) else {
            return Mutation(output: (), didMutate: false)
        }

        let now = Date()
        let removedKeyIds = Set(
            snapshot.keyRecords
                .filter { $0.contactId == contactId }
                .map(\.keyId)
        )
        snapshot.identities.removeAll { $0.contactId == contactId }
        snapshot.keyRecords.removeAll { $0.contactId == contactId }
        pruneCertificationArtifacts(forRemovedKeyIds: removedKeyIds, in: &snapshot)
        for listIndex in snapshot.recipientLists.indices {
            snapshot.recipientLists[listIndex].memberContactIds.removeAll { $0 == contactId }
            snapshot.recipientLists[listIndex].updatedAt = now
        }
        snapshot.updatedAt = now
        try snapshot.validateContract()
        return Mutation(output: (), didMutate: true)
    }

    func setPreferredKey(
        fingerprint: String,
        for contactId: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<Void> {
        guard let preferredIndex = snapshot.keyRecords.firstIndex(where: {
            $0.contactId == contactId && $0.fingerprint == fingerprint
        }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        guard snapshot.keyRecords[preferredIndex].canEncryptTo else {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contacts.preferredKey.notEncryptable",
                    defaultValue: "The selected key cannot receive encrypted messages."
                )
            )
        }

        let now = Date()
        for index in snapshot.keyRecords.indices where snapshot.keyRecords[index].contactId == contactId {
            if index == preferredIndex {
                snapshot.keyRecords[index].usageState = .preferred
            } else if snapshot.keyRecords[index].usageState == .preferred {
                snapshot.keyRecords[index].usageState = snapshot.keyRecords[index].canEncryptTo
                    ? .additionalActive
                    : .historical
            }
            snapshot.keyRecords[index].updatedAt = now
        }
        snapshot.updatedAt = now
        try normalizeKeyUsage(in: &snapshot, updatedAt: now)
        return Mutation(output: (), didMutate: true)
    }

    func setKeyUsageState(
        _ usageState: ContactKeyUsageState,
        fingerprint: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<Void> {
        guard let index = snapshot.keyRecords.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        if usageState != .historical && !snapshot.keyRecords[index].canEncryptTo {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contacts.activeKey.notEncryptable",
                    defaultValue: "The selected key cannot be active because it cannot receive encrypted messages."
                )
            )
        }

        let now = Date()
        snapshot.keyRecords[index].usageState = usageState
        snapshot.keyRecords[index].updatedAt = now
        snapshot.updatedAt = now
        try normalizeKeyUsage(in: &snapshot, updatedAt: now)
        return Mutation(output: (), didMutate: true)
    }

    func mergeContact(
        sourceContactId: String,
        into targetContactId: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<MergeOutcome> {
        guard sourceContactId != targetContactId else {
            throw CypherAirError.internalError(
                reason: String(
                    localized: "contacts.merge.sameContact",
                    defaultValue: "Choose two different contacts to merge."
                )
            )
        }
        guard snapshot.identities.contains(where: { $0.contactId == sourceContactId }),
              snapshot.identities.contains(where: { $0.contactId == targetContactId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }

        let now = Date()
        let sourceIdentity = snapshot.identities.first { $0.contactId == sourceContactId }
        if let targetIndex = snapshot.identities.firstIndex(where: { $0.contactId == targetContactId }),
           let sourceIdentity {
            snapshot.identities[targetIndex].tagIds = Array(
                Set(snapshot.identities[targetIndex].tagIds)
                    .union(sourceIdentity.tagIds)
            ).sorted()
            snapshot.identities[targetIndex].updatedAt = now
        }

        for index in snapshot.keyRecords.indices where snapshot.keyRecords[index].contactId == sourceContactId {
            snapshot.keyRecords[index].contactId = targetContactId
            if snapshot.keyRecords[index].usageState == .preferred {
                snapshot.keyRecords[index].usageState = snapshot.keyRecords[index].canEncryptTo
                    ? .additionalActive
                    : .historical
            }
            snapshot.keyRecords[index].updatedAt = now
        }
        for listIndex in snapshot.recipientLists.indices {
            if snapshot.recipientLists[listIndex].memberContactIds.contains(sourceContactId),
               !snapshot.recipientLists[listIndex].memberContactIds.contains(targetContactId) {
                snapshot.recipientLists[listIndex].memberContactIds.append(targetContactId)
            }
            snapshot.recipientLists[listIndex].memberContactIds.removeAll { $0 == sourceContactId }
            snapshot.recipientLists[listIndex].updatedAt = now
        }
        snapshot.identities.removeAll { $0.contactId == sourceContactId }
        snapshot.updatedAt = now
        try normalizeKeyUsage(in: &snapshot, updatedAt: now)
        return Mutation(
            output: MergeOutcome(
                sourceContactId: sourceContactId,
                targetContactId: targetContactId
            ),
            didMutate: true
        )
    }

    func saveCertificationArtifact(
        _ candidateArtifact: ContactCertificationArtifactReference,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<ContactCertificationArtifactReference> {
        let before = snapshot
        let now = Date()

        guard let keyRecord = snapshot.keyRecords.first(where: { $0.keyId == candidateArtifact.keyId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        guard candidateArtifact.validationStatus == .valid else {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contactcertification.save.invalid",
                    defaultValue: "Only valid certification signatures can be saved."
                )
            )
        }

        let currentTargetDigest = ContactCertificationArtifactReference.sha256Hex(
            for: keyRecord.publicKeyData
        )

        if let targetKeyFingerprint = candidateArtifact.targetKeyFingerprint,
           targetKeyFingerprint.lowercased() != keyRecord.fingerprint.lowercased() {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contactcertification.save.wrongKey",
                    defaultValue: "The certification signature belongs to a different contact key."
                )
            )
        }

        if let targetCertificateDigest = candidateArtifact.targetCertificateDigest,
           !targetCertificateDigest.isEmpty,
           targetCertificateDigest != currentTargetDigest {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contactcertification.save.staleTarget",
                    defaultValue: "The certification signature was validated for a different version of this contact key."
                )
            )
        }

        var artifact = candidateArtifact
        artifact.targetKeyFingerprint = keyRecord.fingerprint
        artifact.targetCertificateDigest = currentTargetDigest
        artifact.userId = artifact.userId ?? artifact.targetSelector.legacyUserIdDisplayText
        artifact.updatedAt = now
        artifact.lastValidatedAt = artifact.lastValidatedAt ?? now
        artifact.storageHint = "protected-contacts-domain"
        artifact = try artifact.validatedForPersistence(now: now)

        if let deduplicationKey = artifact.deduplicationKey,
           let existingIndex = snapshot.certificationArtifacts.firstIndex(where: {
               $0.deduplicationKey == deduplicationKey
           }) {
            let existing = snapshot.certificationArtifacts[existingIndex]
            let exportFilename = existing.exportFilename?.isEmpty == false
                ? existing.exportFilename
                : artifact.exportFilename
            let refreshedArtifact = ContactCertificationArtifactReference(
                artifactId: existing.artifactId,
                keyId: existing.keyId,
                userId: artifact.userId,
                createdAt: existing.createdAt,
                storageHint: "protected-contacts-domain",
                canonicalSignatureData: artifact.canonicalSignatureData,
                signatureDigest: artifact.signatureDigest,
                source: artifact.source,
                targetKeyFingerprint: artifact.targetKeyFingerprint,
                targetSelector: artifact.targetSelector,
                signerPrimaryFingerprint: artifact.signerPrimaryFingerprint,
                signingKeyFingerprint: artifact.signingKeyFingerprint,
                certificationKind: artifact.certificationKind,
                validationStatus: .valid,
                targetCertificateDigest: artifact.targetCertificateDigest,
                lastValidatedAt: now,
                updatedAt: now,
                exportFilename: exportFilename
            )
            snapshot.certificationArtifacts[existingIndex] = try refreshedArtifact
                .validatedForPersistence(now: now)
            _ = try recomputeCertificationProjections(in: &snapshot, updatedAt: now)
            snapshot.updatedAt = now
            try snapshot.validateContract()
            return Mutation(output: snapshot.certificationArtifacts[existingIndex], didMutate: snapshot != before)
        }

        snapshot.certificationArtifacts.append(artifact)
        _ = try recomputeCertificationProjections(in: &snapshot, updatedAt: now)
        snapshot.updatedAt = now
        try snapshot.validateContract()
        return Mutation(output: artifact, didMutate: true)
    }

    func updateCertificationArtifactValidation(
        artifactId: String,
        status: ContactCertificationValidationStatus,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<ContactCertificationArtifactReference> {
        let before = snapshot
        let now = Date()
        guard status != .valid else {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contactcertification.update.validRequiresVerification",
                    defaultValue: "Certification signatures must be revalidated before they can be marked valid."
                )
            )
        }
        guard let index = snapshot.certificationArtifacts.firstIndex(where: { $0.artifactId == artifactId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }

        snapshot.certificationArtifacts[index].validationStatus = status
        snapshot.certificationArtifacts[index].updatedAt = now
        snapshot.certificationArtifacts[index].lastValidatedAt = status == .valid
            ? now
            : snapshot.certificationArtifacts[index].lastValidatedAt
        snapshot.certificationArtifacts[index] = try snapshot.certificationArtifacts[index]
            .validatedForPersistence(now: now)
        _ = try recomputeCertificationProjections(in: &snapshot, updatedAt: now)
        snapshot.updatedAt = now
        try snapshot.validateContract()
        return Mutation(output: snapshot.certificationArtifacts[index], didMutate: snapshot != before)
    }

    @discardableResult
    func recomputeCertificationProjections(
        in snapshot: inout ContactsDomainSnapshot,
        updatedAt: Date = Date()
    ) throws -> Bool {
        let before = snapshot.keyRecords
        let artifactsByKeyId = Dictionary(grouping: snapshot.certificationArtifacts, by: \.keyId)

        for index in snapshot.keyRecords.indices {
            let keyId = snapshot.keyRecords[index].keyId
            let artifacts = (artifactsByKeyId[keyId] ?? [])
                .sorted { lhs, rhs in
                    if lhs.createdAt != rhs.createdAt {
                        return lhs.createdAt < rhs.createdAt
                    }
                    return lhs.artifactId < rhs.artifactId
                }
            let artifactIds = artifacts.map(\.artifactId)
            let status = certificationProjectionStatus(for: artifacts)
            let projection = ContactCertificationProjection(
                status: status,
                artifactIds: artifactIds,
                lastValidatedAt: artifacts.compactMap(\.lastValidatedAt).max(),
                reconciliationMetadata: nil
            )

            if snapshot.keyRecords[index].certificationArtifactIds != artifactIds ||
                snapshot.keyRecords[index].certificationProjection != projection {
                snapshot.keyRecords[index].certificationArtifactIds = artifactIds
                snapshot.keyRecords[index].certificationProjection = projection
                snapshot.keyRecords[index].updatedAt = updatedAt
            }
        }

        try snapshot.validateContract()
        return snapshot.keyRecords != before
    }

    private func makeIdentity(
        from validation: PublicCertificateValidationResult,
        now: Date
    ) -> ContactIdentity {
        ContactIdentity(
            contactId: "contact-\(UUID().uuidString)",
            displayName: IdentityPresentation.displayName(from: validation.keyInfo.userId),
            primaryEmail: IdentityPresentation.email(from: validation.keyInfo.userId),
            tagIds: [],
            notes: nil,
            createdAt: now,
            updatedAt: now
        )
    }

    private func makeKeyRecord(
        from validation: PublicCertificateValidationResult,
        contactId: String,
        verificationState: ContactVerificationState,
        usageState: ContactKeyUsageState,
        now: Date
    ) -> ContactKeyRecord {
        ContactKeyRecord(
            keyId: "key-\(UUID().uuidString)",
            contactId: contactId,
            fingerprint: validation.keyInfo.fingerprint,
            primaryUserId: validation.keyInfo.userId,
            displayName: IdentityPresentation.displayName(from: validation.keyInfo.userId),
            email: IdentityPresentation.email(from: validation.keyInfo.userId),
            keyVersion: validation.keyInfo.keyVersion,
            profile: validation.profile,
            primaryAlgo: validation.keyInfo.primaryAlgo,
            subkeyAlgo: validation.keyInfo.subkeyAlgo,
            hasEncryptionSubkey: validation.keyInfo.hasEncryptionSubkey,
            isRevoked: validation.keyInfo.isRevoked,
            isExpired: validation.keyInfo.isExpired,
            manualVerificationState: verificationState,
            usageState: usageState,
            certificationProjection: .empty,
            certificationArtifactIds: [],
            publicKeyData: validation.publicCertData,
            createdAt: now,
            updatedAt: now
        )
    }

    private func updatedKeyRecord(
        preserving existingRecord: ContactKeyRecord,
        from validation: PublicCertificateValidationResult,
        publicKeyData: Data,
        verificationState: ContactVerificationState,
        now: Date
    ) -> ContactKeyRecord {
        var updatedRecord = existingRecord
        updatedRecord.primaryUserId = validation.keyInfo.userId
        updatedRecord.displayName = IdentityPresentation.displayName(from: validation.keyInfo.userId)
        updatedRecord.email = IdentityPresentation.email(from: validation.keyInfo.userId)
        updatedRecord.keyVersion = validation.keyInfo.keyVersion
        updatedRecord.profile = validation.profile
        updatedRecord.primaryAlgo = validation.keyInfo.primaryAlgo
        updatedRecord.subkeyAlgo = validation.keyInfo.subkeyAlgo
        updatedRecord.hasEncryptionSubkey = validation.keyInfo.hasEncryptionSubkey
        updatedRecord.isRevoked = validation.keyInfo.isRevoked
        updatedRecord.isExpired = validation.keyInfo.isExpired
        updatedRecord.manualVerificationState = verificationState
        updatedRecord.publicKeyData = publicKeyData
        updatedRecord.updatedAt = now
        if !updatedRecord.canEncryptTo {
            updatedRecord.usageState = .historical
        }
        return updatedRecord
    }

    private func updateIdentityDisplayIfNeeded(
        contactId: String,
        from keyRecord: ContactKeyRecord,
        in snapshot: inout ContactsDomainSnapshot,
        now: Date
    ) {
        guard let identityIndex = snapshot.identities.firstIndex(where: {
            $0.contactId == contactId
        }) else {
            return
        }
        if snapshot.identities[identityIndex].displayName.isEmpty ||
            snapshot.identities[identityIndex].displayName == IdentityPresentation.displayName(from: nil) {
            snapshot.identities[identityIndex].displayName = keyRecord.displayName
        }
        if snapshot.identities[identityIndex].primaryEmail == nil {
            snapshot.identities[identityIndex].primaryEmail = keyRecord.email
        }
        snapshot.identities[identityIndex].updatedAt = now
    }

    private func pruneCertificationArtifacts(
        forRemovedKeyIds removedKeyIds: Set<String>,
        in snapshot: inout ContactsDomainSnapshot
    ) {
        guard !removedKeyIds.isEmpty else {
            return
        }
        snapshot.certificationArtifacts.removeAll {
            removedKeyIds.contains($0.keyId)
        }
    }

    private func markCertificationArtifactsStaleIfTargetChanged(
        keyId: String,
        newPublicKeyData: Data,
        in snapshot: inout ContactsDomainSnapshot,
        now: Date
    ) {
        let newDigest = ContactCertificationArtifactReference.sha256Hex(for: newPublicKeyData)
        for index in snapshot.certificationArtifacts.indices
            where snapshot.certificationArtifacts[index].keyId == keyId {
            guard snapshot.certificationArtifacts[index].targetCertificateDigest != nil,
                  snapshot.certificationArtifacts[index].targetCertificateDigest != newDigest else {
                continue
            }
            snapshot.certificationArtifacts[index].validationStatus = .invalidOrStale
            snapshot.certificationArtifacts[index].updatedAt = now
        }
    }

    private func certificationProjectionStatus(
        for artifacts: [ContactCertificationArtifactReference]
    ) -> ContactCertificationProjection.Status {
        guard !artifacts.isEmpty else {
            return .notCertified
        }
        if artifacts.contains(where: { $0.validationStatus == .valid }) {
            return .certified
        }
        if artifacts.contains(where: { $0.validationStatus == .invalidOrStale }) {
            return .invalidOrStale
        }
        return .revalidationNeeded
    }

    private func normalizeKeyUsage(
        in snapshot: inout ContactsDomainSnapshot,
        updatedAt: Date
    ) throws {
        let contactIds = snapshot.identities.map(\.contactId)
        for contactId in contactIds {
            let keyIndices = snapshot.keyRecords.indices.filter {
                snapshot.keyRecords[$0].contactId == contactId
            }
            for index in keyIndices where snapshot.keyRecords[index].usageState != .historical
                && !snapshot.keyRecords[index].canEncryptTo {
                snapshot.keyRecords[index].usageState = .historical
                snapshot.keyRecords[index].updatedAt = updatedAt
            }

            let preferredIndices = keyIndices.filter {
                snapshot.keyRecords[$0].usageState == .preferred
            }
            if preferredIndices.count > 1 {
                for index in preferredIndices.dropFirst() {
                    snapshot.keyRecords[index].usageState = snapshot.keyRecords[index].canEncryptTo
                        ? .additionalActive
                        : .historical
                    snapshot.keyRecords[index].updatedAt = updatedAt
                }
            }

            let hasPreferred = keyIndices.contains {
                snapshot.keyRecords[$0].usageState == .preferred &&
                snapshot.keyRecords[$0].canEncryptTo
            }
            if !hasPreferred {
                let activeEncryptable = keyIndices.filter {
                    snapshot.keyRecords[$0].usageState == .additionalActive &&
                    snapshot.keyRecords[$0].canEncryptTo
                }
                if activeEncryptable.count == 1, let index = activeEncryptable.first {
                    snapshot.keyRecords[index].usageState = .preferred
                    snapshot.keyRecords[index].updatedAt = updatedAt
                }
            }
        }
        try snapshot.validateContract()
    }
}
