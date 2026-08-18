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

    private let contactImportAdapter: PGPContactImportAdapter
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let importMatcher: ContactImportMatcher

    init(
        contactImportAdapter: PGPContactImportAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        importMatcher: ContactImportMatcher = ContactImportMatcher()
    ) {
        self.contactImportAdapter = contactImportAdapter
        self.certificateAdapter = certificateAdapter
        self.importMatcher = importMatcher
    }

    func addContact(
        publicKeyData: Data,
        verificationState: ContactVerificationState,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<AddOutcome> {
        let validation = try contactImportAdapter.validateImportablePublicCertificate(publicKeyData)
        let binaryData = validation.publicCertData
        let now = Date()

        if let existingIndex = snapshot.keyRecords.firstIndex(where: {
            $0.fingerprint == validation.metadata.fingerprint
        }) {
            let existingRecord = snapshot.keyRecords[existingIndex]
            let mergedResult = try contactImportAdapter.mergePublicCertificateUpdate(
                existingCert: existingRecord.publicKeyData,
                incomingCertOrUpdate: binaryData
            )

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
                let updatedValidation = try contactImportAdapter.validateImportablePublicCertificate(
                    mergedResult.mergedCertData
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
                    output: .updated(fingerprint: updatedValidation.metadata.fingerprint),
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
            usageState: validation.metadata.hasEncryptionSubkey
                && !validation.metadata.isRevoked
                && !validation.metadata.isExpired
                ? .preferred
                : .historical,
            now: now
        )
        snapshot.identities.append(identity)
        snapshot.keyRecords.append(keyRecord)
        snapshot.updatedAt = now
        try normalizeKeyUsage(in: &snapshot, updatedAt: now)
        return Mutation(
            output: .added(fingerprint: validation.metadata.fingerprint, candidate: candidateMatch),
            didMutate: true
        )
    }

    func importCandidateMatch(
        publicKeyData: Data,
        in snapshot: ContactsDomainSnapshot
    ) throws -> ContactCandidateMatch? {
        let validation = try contactImportAdapter.validateImportablePublicCertificate(publicKeyData)
        guard !snapshot.keyRecords.contains(where: {
            $0.fingerprint == validation.metadata.fingerprint
        }) else {
            return nil
        }
        return importMatcher.candidateMatch(for: validation, in: snapshot)
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

    @discardableResult
    func createTag(
        named rawName: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<ContactTag> {
        let displayName = ContactTag.displayName(for: rawName)
        guard !displayName.isEmpty else {
            throw CypherAirError.invalidKeyData(
                reason: String(localized: "contacts.tag.empty", defaultValue: "Enter a tag name.")
            )
        }

        let normalizedName = ContactTag.normalizedName(for: displayName)
        guard !snapshot.tags.contains(where: { $0.normalizedName == normalizedName }) else {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contacts.tag.duplicate",
                    defaultValue: "A tag with this name already exists."
                )
            )
        }

        let now = Date()
        let tag = ContactTag(
            tagId: "tag-\(UUID().uuidString)",
            displayName: displayName,
            normalizedName: normalizedName,
            createdAt: now,
            updatedAt: now
        )
        snapshot.tags.append(tag)
        snapshot.updatedAt = now
        try snapshot.validateContract()
        return Mutation(output: tag, didMutate: true)
    }

    @discardableResult
    func renameTag(
        tagId: String,
        to rawName: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<ContactTag> {
        let displayName = ContactTag.displayName(for: rawName)
        guard !displayName.isEmpty else {
            throw CypherAirError.invalidKeyData(
                reason: String(localized: "contacts.tag.empty", defaultValue: "Enter a tag name.")
            )
        }
        guard let tagIndex = snapshot.tags.firstIndex(where: { $0.tagId == tagId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.tag.notFound", defaultValue: "The selected tag could not be found.")
            )
        }

        let normalizedName = ContactTag.normalizedName(for: displayName)
        let duplicateExists = snapshot.tags.contains {
            $0.tagId != tagId && $0.normalizedName == normalizedName
        }
        guard !duplicateExists else {
            throw CypherAirError.invalidKeyData(
                reason: String(
                    localized: "contacts.tag.duplicate",
                    defaultValue: "A tag with this name already exists."
                )
            )
        }

        guard snapshot.tags[tagIndex].displayName != displayName ||
            snapshot.tags[tagIndex].normalizedName != normalizedName else {
            return Mutation(output: snapshot.tags[tagIndex], didMutate: false)
        }

        let now = Date()
        snapshot.tags[tagIndex].displayName = displayName
        snapshot.tags[tagIndex].normalizedName = normalizedName
        snapshot.tags[tagIndex].updatedAt = now
        snapshot.updatedAt = now
        try snapshot.validateContract()
        return Mutation(output: snapshot.tags[tagIndex], didMutate: true)
    }

    @discardableResult
    func deleteTag(
        tagId: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<Void> {
        guard snapshot.tags.contains(where: { $0.tagId == tagId }) else {
            return Mutation(output: (), didMutate: false)
        }

        let now = Date()
        snapshot.tags.removeAll { $0.tagId == tagId }
        for index in snapshot.identities.indices where snapshot.identities[index].tagIds.contains(tagId) {
            snapshot.identities[index].tagIds.removeAll { $0 == tagId }
            snapshot.identities[index].updatedAt = now
        }
        snapshot.updatedAt = now
        try snapshot.validateContract()
        return Mutation(output: (), didMutate: true)
    }

    @discardableResult
    func addTag(
        named rawName: String,
        toContactId contactId: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<ContactTag> {
        let displayName = ContactTag.displayName(for: rawName)
        guard !displayName.isEmpty else {
            throw CypherAirError.invalidKeyData(
                reason: String(localized: "contacts.tag.empty", defaultValue: "Enter a tag name.")
            )
        }

        guard let contactIndex = snapshot.identities.firstIndex(where: { $0.contactId == contactId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }

        let now = Date()
        let normalizedName = ContactTag.normalizedName(for: displayName)
        if let existingTag = snapshot.tags.first(where: { $0.normalizedName == normalizedName }) {
            guard !snapshot.identities[contactIndex].tagIds.contains(existingTag.tagId) else {
                return Mutation(output: existingTag, didMutate: false)
            }
            snapshot.identities[contactIndex].tagIds.append(existingTag.tagId)
            snapshot.identities[contactIndex].tagIds.sort()
            snapshot.identities[contactIndex].updatedAt = now
            snapshot.updatedAt = now
            try snapshot.validateContract()
            return Mutation(output: existingTag, didMutate: true)
        }

        let tag = ContactTag(
            tagId: "tag-\(UUID().uuidString)",
            displayName: displayName,
            normalizedName: normalizedName,
            createdAt: now,
            updatedAt: now
        )
        snapshot.tags.append(tag)
        snapshot.identities[contactIndex].tagIds.append(tag.tagId)
        snapshot.identities[contactIndex].tagIds.sort()
        snapshot.identities[contactIndex].updatedAt = now
        snapshot.updatedAt = now
        try snapshot.validateContract()
        return Mutation(output: tag, didMutate: true)
    }

    @discardableResult
    func assignTag(
        tagId: String,
        toContactId contactId: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<ContactTag> {
        guard let tag = snapshot.tags.first(where: { $0.tagId == tagId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.tag.notFound", defaultValue: "The selected tag could not be found.")
            )
        }
        guard let contactIndex = snapshot.identities.firstIndex(where: { $0.contactId == contactId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        guard !snapshot.identities[contactIndex].tagIds.contains(tagId) else {
            return Mutation(output: tag, didMutate: false)
        }

        let now = Date()
        snapshot.identities[contactIndex].tagIds.append(tagId)
        snapshot.identities[contactIndex].tagIds.sort()
        snapshot.identities[contactIndex].updatedAt = now
        snapshot.updatedAt = now
        try snapshot.validateContract()
        return Mutation(output: tag, didMutate: true)
    }

    @discardableResult
    func removeTag(
        tagId: String,
        fromContactId contactId: String,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<Void> {
        guard let contactIndex = snapshot.identities.firstIndex(where: { $0.contactId == contactId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }
        guard snapshot.identities[contactIndex].tagIds.contains(tagId) else {
            return Mutation(output: (), didMutate: false)
        }

        let now = Date()
        snapshot.identities[contactIndex].tagIds.removeAll { $0 == tagId }
        snapshot.identities[contactIndex].updatedAt = now
        snapshot.updatedAt = now
        try snapshot.validateContract()
        return Mutation(output: (), didMutate: true)
    }

    @discardableResult
    func replaceTagMembership(
        tagId: String,
        contactIds: Set<String>,
        in snapshot: inout ContactsDomainSnapshot
    ) throws -> Mutation<Void> {
        guard snapshot.tags.contains(where: { $0.tagId == tagId }) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.tag.notFound", defaultValue: "The selected tag could not be found.")
            )
        }
        let availableContactIds = Set(snapshot.identities.map(\.contactId))
        guard contactIds.isSubset(of: availableContactIds) else {
            throw CypherAirError.internalError(
                reason: String(localized: "contacts.notFound", defaultValue: "The selected contact could not be found.")
            )
        }

        let now = Date()
        var didMutate = false
        for index in snapshot.identities.indices {
            let shouldContainTag = contactIds.contains(snapshot.identities[index].contactId)
            let containsTag = snapshot.identities[index].tagIds.contains(tagId)
            guard shouldContainTag != containsTag else {
                continue
            }

            if shouldContainTag {
                snapshot.identities[index].tagIds.append(tagId)
                snapshot.identities[index].tagIds.sort()
            } else {
                snapshot.identities[index].tagIds.removeAll { $0 == tagId }
            }
            snapshot.identities[index].updatedAt = now
            didMutate = true
        }

        guard didMutate else {
            return Mutation(output: (), didMutate: false)
        }
        snapshot.updatedAt = now
        try snapshot.validateContract()
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
        artifact.updatedAt = now
        artifact.lastValidatedAt = artifact.lastValidatedAt ?? now
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
                createdAt: existing.createdAt,
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

    @discardableResult
    func recomputeCertificationProjections(
        in snapshot: inout ContactsDomainSnapshot,
        updatedAt: Date = Date()
    ) throws -> Bool {
        let beforeKeyRecords = snapshot.keyRecords
        let beforeCertificationArtifacts = snapshot.certificationArtifacts
        markValidCertificationArtifactsStaleIfTargetDigestChanged(
            in: &snapshot,
            updatedAt: updatedAt
        )
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
            let projection = ContactCertificationProjection(
                signatureState: certificationSignatureState(for: artifacts),
                artifactIds: artifactIds,
                lastValidatedAt: artifacts.compactMap(\.lastValidatedAt).max()
            )

            if snapshot.keyRecords[index].certificationArtifactIds != artifactIds ||
                snapshot.keyRecords[index].certificationProjection != projection {
                snapshot.keyRecords[index].certificationArtifactIds = artifactIds
                snapshot.keyRecords[index].certificationProjection = projection
                snapshot.keyRecords[index].updatedAt = updatedAt
            }
        }

        try snapshot.validateContract()
        return snapshot.keyRecords != beforeKeyRecords ||
            snapshot.certificationArtifacts != beforeCertificationArtifacts
    }

    /// Re-derive the certificate lifecycle flags cached on every key record.
    ///
    /// `hasEncryptionSubkey`, `isRevoked` and `isExpired` are written once, at
    /// import, and then read for the life of the record. Each is an answer about
    /// a certificate under a policy at a moment in time, so a key whose expiry
    /// passed afterwards keeps reading as usable and the app keeps offering it as
    /// a recipient. Key usage is re-normalized after the refresh, so a key that
    /// can no longer receive messages also stops being presented as a live one.
    ///
    /// All three are refreshed rather than the two whose staleness shows first:
    /// they are the three inputs to one boolean, `canEncryptTo`, and re-deriving
    /// a subset would leave that boolean an incoherent mixture of fresh and
    /// import-time answers. `hasEncryptionSubkey` also earns it on its own — it
    /// depends on a subkey binding signature still being valid at the current
    /// time, and on `.supported()` under the engine's standard policy, which
    /// drifts between Sequoia releases.
    ///
    /// This does *not* cover an encryption subkey whose own expiry has passed.
    /// The engine computes `hasEncryptionSubkey` without the aliveness check the
    /// encrypt path applies, so re-parsing recomputes the same `true`; that gap is
    /// engine-side and tracked separately (issue #808).
    ///
    /// A record whose stored certificate cannot be re-parsed keeps the values it
    /// has: this runs on the Contacts unlock path, and one unreadable record must
    /// not take the whole domain down with it.
    @discardableResult
    func refreshCertificateLifecycleState(
        in snapshot: inout ContactsDomainSnapshot,
        updatedAt: Date = Date()
    ) throws -> Bool {
        let beforeKeyRecords = snapshot.keyRecords

        for index in snapshot.keyRecords.indices {
            guard let metadata = try? contactImportAdapter
                .validateImportablePublicCertificate(snapshot.keyRecords[index].publicKeyData)
                .metadata
            else {
                continue
            }

            let record = snapshot.keyRecords[index]
            guard record.hasEncryptionSubkey != metadata.hasEncryptionSubkey ||
                record.isRevoked != metadata.isRevoked ||
                record.isExpired != metadata.isExpired
            else {
                continue
            }

            snapshot.keyRecords[index].hasEncryptionSubkey = metadata.hasEncryptionSubkey
            snapshot.keyRecords[index].isRevoked = metadata.isRevoked
            snapshot.keyRecords[index].isExpired = metadata.isExpired
            snapshot.keyRecords[index].updatedAt = updatedAt
        }

        guard snapshot.keyRecords != beforeKeyRecords else {
            return false
        }

        snapshot.updatedAt = updatedAt
        try normalizeKeyUsage(in: &snapshot, updatedAt: updatedAt)
        return true
    }

    /// Retake the engine's verdict on every stored certification.
    ///
    /// Whether a certification still vouches for anything is not a property of
    /// the bytes it was made over. The engine also weighs the signer's
    /// revocation status, the certification signature's own expiry, and the
    /// current policy's hash rules — so a stored verdict answers only for the
    /// moment it was taken, and a signer revoked since then leaves a certified
    /// badge standing on nothing. This retakes the verdict at unlock, on the
    /// same cadence as the lifecycle refresh, and lets the fresh answer decide.
    /// A cached `valid` is never carried forward on the strength of the target
    /// certificate's bytes being unchanged.
    ///
    /// Each certification is checked against the single certificate it names as
    /// its signer, resolved from the contact key records or from
    /// `ownSignerCertificates` — the user's own keys, which the contacts domain
    /// does not hold. That is exactly the claim the badge makes, and it keeps
    /// the cost proportional to the number of certifications rather than to the
    /// size of the contact list.
    ///
    /// A verdict that cannot be taken at all — the signer is no longer held, the
    /// User ID it certified is gone from the target, the signature bytes no
    /// longer parse — demotes to `revalidationNeeded` rather than failing the
    /// unlock: one unreadable certification must not take the whole domain down
    /// with it, and "we could not check" is a different statement from "it is
    /// invalid". Signer fingerprints survive every demotion, so a later unlock
    /// that can resolve the signer again restores the badge.
    ///
    /// Non-throwing by construction; the contract check for the whole reconcile
    /// sequence belongs to `recomputeCertificationProjections`, which runs next
    /// and turns these verdicts into the badge the UI reads.
    @discardableResult
    func revalidateCertificationArtifacts(
        in snapshot: inout ContactsDomainSnapshot,
        ownSignerCertificates: [String: Data],
        updatedAt: Date = Date()
    ) async -> Bool {
        guard !snapshot.certificationArtifacts.isEmpty else {
            return false
        }

        let beforeArtifacts = snapshot.certificationArtifacts
        let targetCertificatesByKeyId = Dictionary(
            snapshot.keyRecords.map { ($0.keyId, $0.publicKeyData) },
            uniquingKeysWith: { first, _ in first }
        )
        let contactCertificatesByFingerprint = Dictionary(
            snapshot.keyRecords.map { ($0.fingerprint.lowercased(), $0.publicKeyData) },
            uniquingKeysWith: { first, _ in first }
        )
        let ownCertificatesByFingerprint = Dictionary(
            ownSignerCertificates.map { ($0.key.lowercased(), $0.value) },
            uniquingKeysWith: { first, _ in first }
        )

        for index in snapshot.certificationArtifacts.indices {
            let artifact = snapshot.certificationArtifacts[index]
            let signerCertificate = artifact.signerPrimaryFingerprint
                .map { $0.lowercased() }
                .flatMap {
                    contactCertificatesByFingerprint[$0] ?? ownCertificatesByFingerprint[$0]
                }

            switch await certificationVerdict(
                for: artifact,
                targetCertificate: targetCertificatesByKeyId[artifact.keyId],
                signerCertificate: signerCertificate
            ) {
            case .valid(let targetCertificateDigest):
                guard artifact.validationStatus != .valid ||
                    artifact.targetCertificateDigest != targetCertificateDigest else {
                    continue
                }
                snapshot.certificationArtifacts[index].validationStatus = .valid
                snapshot.certificationArtifacts[index].targetCertificateDigest = targetCertificateDigest
                snapshot.certificationArtifacts[index].lastValidatedAt = updatedAt
            case .invalid:
                guard artifact.validationStatus != .invalidOrStale else {
                    continue
                }
                snapshot.certificationArtifacts[index].validationStatus = .invalidOrStale
            case .unavailable:
                guard artifact.validationStatus != .revalidationNeeded else {
                    continue
                }
                snapshot.certificationArtifacts[index].validationStatus = .revalidationNeeded
            }
            snapshot.certificationArtifacts[index].updatedAt = updatedAt
        }

        guard snapshot.certificationArtifacts != beforeArtifacts else {
            return false
        }

        snapshot.updatedAt = updatedAt
        return true
    }

    /// The engine's current answer for one stored certification. `valid` carries
    /// the digest of the exact target bytes the answer was given for, so the
    /// artifact records what it was checked against rather than what it was
    /// created against.
    private enum CertificationVerdict {
        case valid(targetCertificateDigest: String)
        case invalid
        case unavailable
    }

    private func certificationVerdict(
        for artifact: ContactCertificationArtifactReference,
        targetCertificate: Data?,
        signerCertificate: Data?
    ) async -> CertificationVerdict {
        guard let targetCertificate, let signerCertificate else {
            return .unavailable
        }

        do {
            let status: CertificateSignatureVerificationStatus
            switch artifact.targetSelector.kind {
            case .directKey:
                status = try await certificateAdapter.directKeySignatureStatus(
                    signature: artifact.canonicalSignatureData,
                    targetCert: targetCertificate,
                    candidateSigners: [signerCertificate]
                )
            case .userId:
                guard let userIdData = artifact.targetSelector.userIdData,
                      let occurrenceIndex = artifact.targetSelector.occurrenceIndex,
                      occurrenceIndex >= 0 else {
                    return .unavailable
                }
                status = try await certificateAdapter.userIdBindingSignatureStatus(
                    signature: artifact.canonicalSignatureData,
                    targetCert: targetCertificate,
                    userIdData: userIdData,
                    occurrenceIndex: occurrenceIndex,
                    candidateSigners: [signerCertificate]
                )
            }

            switch status {
            case .valid:
                return .valid(
                    targetCertificateDigest: ContactCertificationArtifactReference.sha256Hex(
                        for: targetCertificate
                    )
                )
            case .invalid:
                return .invalid
            case .signerMissing:
                return .unavailable
            }
        } catch {
            return .unavailable
        }
    }

    private func makeIdentity(
        from validation: PGPValidatedPublicCertificate,
        now: Date
    ) -> ContactIdentity {
        let metadata = validation.metadata
        return ContactIdentity(
            contactId: "contact-\(UUID().uuidString)",
            displayName: Self.domainDisplayName(from: metadata.userId),
            primaryEmail: IdentityPresentation.email(from: metadata.userId),
            tagIds: [],
            notes: nil,
            createdAt: now,
            updatedAt: now
        )
    }

    private func makeKeyRecord(
        from validation: PGPValidatedPublicCertificate,
        contactId: String,
        verificationState: ContactVerificationState,
        usageState: ContactKeyUsageState,
        now: Date
    ) -> ContactKeyRecord {
        let metadata = validation.metadata
        return ContactKeyRecord(
            keyId: "key-\(UUID().uuidString)",
            contactId: contactId,
            fingerprint: metadata.fingerprint,
            primaryUserId: metadata.userId,
            displayName: Self.domainDisplayName(from: metadata.userId),
            email: IdentityPresentation.email(from: metadata.userId),
            keyVersion: metadata.keyVersion,
            suite: validation.suite,
            primaryAlgo: metadata.primaryAlgo,
            subkeyAlgo: metadata.subkeyAlgo,
            hasEncryptionSubkey: metadata.hasEncryptionSubkey,
            isRevoked: metadata.isRevoked,
            isExpired: metadata.isExpired,
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
        from validation: PGPValidatedPublicCertificate,
        publicKeyData: Data,
        verificationState: ContactVerificationState,
        now: Date
    ) -> ContactKeyRecord {
        let metadata = validation.metadata
        var updatedRecord = existingRecord
        updatedRecord.primaryUserId = metadata.userId
        updatedRecord.displayName = Self.domainDisplayName(from: metadata.userId)
        updatedRecord.email = IdentityPresentation.email(from: metadata.userId)
        updatedRecord.keyVersion = metadata.keyVersion
        updatedRecord.suite = validation.suite
        updatedRecord.primaryAlgo = metadata.primaryAlgo
        updatedRecord.subkeyAlgo = metadata.subkeyAlgo
        updatedRecord.hasEncryptionSubkey = metadata.hasEncryptionSubkey
        updatedRecord.isRevoked = metadata.isRevoked
        updatedRecord.isExpired = metadata.isExpired
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
        if snapshot.identities[identityIndex].displayName.isEmpty {
            snapshot.identities[identityIndex].displayName = keyRecord.displayName
        }
        if snapshot.identities[identityIndex].primaryEmail == nil {
            snapshot.identities[identityIndex].primaryEmail = keyRecord.email
        }
        snapshot.identities[identityIndex].updatedAt = now
    }

    private static func domainDisplayName(from userId: String?) -> String {
        IdentityPresentation.parsedDisplayName(from: userId) ?? ""
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

    private func markValidCertificationArtifactsStaleIfTargetDigestChanged(
        in snapshot: inout ContactsDomainSnapshot,
        updatedAt: Date
    ) {
        let keyRecordsById = Dictionary(uniqueKeysWithValues: snapshot.keyRecords.map { ($0.keyId, $0) })
        for index in snapshot.certificationArtifacts.indices
            where snapshot.certificationArtifacts[index].validationStatus == .valid {
            guard let keyRecord = keyRecordsById[snapshot.certificationArtifacts[index].keyId] else {
                continue
            }
            let currentDigest = ContactCertificationArtifactReference.sha256Hex(
                for: keyRecord.publicKeyData
            )
            guard snapshot.certificationArtifacts[index].targetCertificateDigest != currentDigest else {
                continue
            }
            snapshot.certificationArtifacts[index].validationStatus = .invalidOrStale
            snapshot.certificationArtifacts[index].updatedAt = updatedAt
        }
    }

    /// The signature state of one key's stored certifications, worst-case first
    /// where it matters: a signature that has gone bad is reported even when
    /// others alongside it still verify, because that is the fact the user needs
    /// to see. Nothing here weighs *who* signed — that belongs to
    /// `ContactCertificationTrustWeb`, which derives it live.
    private func certificationSignatureState(
        for artifacts: [ContactCertificationArtifactReference]
    ) -> ContactCertificationProjection.SignatureState {
        guard !artifacts.isEmpty else {
            return .absent
        }
        if artifacts.contains(where: { $0.validationStatus == .invalidOrStale }) {
            return .invalidOrStale
        }
        if artifacts.contains(where: { $0.validationStatus == .valid }) {
            return .valid
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
