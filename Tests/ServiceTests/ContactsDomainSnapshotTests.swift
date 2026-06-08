import Foundation
import XCTest
@testable import CypherAir

final class ContactsDomainSnapshotTests: XCTestCase {
    private let referenceDate = Date(timeIntervalSince1970: 1_774_000_000)

    func test_emptySnapshot_validatesAndRoundTripsAsBinaryPlist() throws {
        let snapshot = ContactsDomainSnapshot.empty(now: referenceDate)

        let encoded = try ContactsDomainSnapshotCodec.encodeSnapshot(snapshot)
        XCTAssertEqual(String(data: encoded.prefix(6), encoding: .utf8), "bplist")

        let decoded = try ContactsDomainSnapshotCodec.decodeSnapshot(encoded)
        XCTAssertEqual(decoded.snapshot, snapshot)
        XCTAssertEqual(decoded.sourceSchemaVersion, ContactsDomainSnapshot.currentSchemaVersion)
        try decoded.snapshot.validateContract()
    }

    func test_unsupportedSchemaVersion_isRejected() throws {
        var snapshot = try makeValidSnapshot()
        snapshot.schemaVersion = ContactsDomainSnapshot.currentSchemaVersion + 1

        XCTAssertThrowsError(try snapshot.validateContract()) { error in
            XCTAssertTrue(error is ContactsDomainValidationError)
        }
        XCTAssertThrowsError(try ContactsDomainSnapshotCodec.encodeSnapshot(snapshot)) { error in
            XCTAssertEqual(
                error as? ProtectedDataError,
                .invalidEnvelope("Contacts payload has an unsupported schema version.")
            )
        }
    }

    func test_duplicateIdentifiersAndFingerprints_areRejected() throws {
        var duplicateContactID = try makeValidSnapshot()
        duplicateContactID.identities.append(duplicateContactID.identities[0])
        XCTAssertThrowsError(try duplicateContactID.validateContract())

        var duplicateKeyID = try makeValidSnapshot()
        duplicateKeyID.keyRecords.append(duplicateKeyID.keyRecords[0])
        duplicateKeyID.keyRecords[1].fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        XCTAssertThrowsError(try duplicateKeyID.validateContract())

        var duplicateFingerprint = try makeValidSnapshot()
        duplicateFingerprint.keyRecords.append(
            try makeKeyRecord(
                keyId: "key-2",
                contactId: "contact-1",
                fingerprint: duplicateFingerprint.keyRecords[0].fingerprint
            )
        )
        XCTAssertThrowsError(try duplicateFingerprint.validateContract())
    }

    func test_missingForeignKeys_areRejected() throws {
        var missingKeyContact = try makeValidSnapshot()
        missingKeyContact.keyRecords[0].contactId = "missing-contact"
        XCTAssertThrowsError(try missingKeyContact.validateContract())

        var missingArtifactKey = try makeValidSnapshot()
        missingArtifactKey.certificationArtifacts = [
            ContactCertificationArtifactReference(
                artifactId: "artifact-1",
                keyId: "missing-key",
                userId: nil,
                createdAt: referenceDate,
                storageHint: nil
            )
        ]
        XCTAssertThrowsError(try missingArtifactKey.validateContract())
    }

    func test_preferredKeyInvariants_areEnforced() throws {
        var twoPreferred = try makeValidSnapshot()
        var secondKey = try makeKeyRecord(
            keyId: "key-2",
            contactId: "contact-1",
            fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        secondKey.usageState = .preferred
        twoPreferred.keyRecords.append(secondKey)
        XCTAssertThrowsError(try twoPreferred.validateContract())

        var preferredCannotEncrypt = try makeValidSnapshot()
        preferredCannotEncrypt.keyRecords[0].hasEncryptionSubkey = false
        preferredCannotEncrypt.keyRecords[0].usageState = .preferred
        XCTAssertThrowsError(try preferredCannotEncrypt.validateContract())

        var additionalCannotEncrypt = try makeValidSnapshot()
        additionalCannotEncrypt.keyRecords[0].hasEncryptionSubkey = false
        additionalCannotEncrypt.keyRecords[0].usageState = .additionalActive
        XCTAssertThrowsError(try additionalCannotEncrypt.validateContract())

        var historicalCannotEncrypt = try makeValidSnapshot()
        historicalCannotEncrypt.keyRecords[0].hasEncryptionSubkey = false
        historicalCannotEncrypt.keyRecords[0].usageState = .historical
        XCTAssertNoThrow(try historicalCannotEncrypt.validateContract())
    }

    func test_zeroPreferredKeyIsValidAsUnresolvedRuntimeState() throws {
        var snapshot = try makeValidSnapshotWithTwoKeys()
        snapshot.keyRecords[0].usageState = .additionalActive
        snapshot.keyRecords[1].usageState = .additionalActive

        XCTAssertNoThrow(try snapshot.validateContract())
    }

    func test_validSnapshotWithTagsAndArtifacts_validates() throws {
        var snapshot = try makeValidSnapshot()
        snapshot.tags = [
            ContactTag(
                tagId: "tag-1",
                displayName: "Close Friend",
                normalizedName: ContactTag.normalizedName(for: "Close Friend"),
                createdAt: referenceDate,
                updatedAt: referenceDate
            )
        ]
        snapshot.identities[0].tagIds = ["tag-1"]
        snapshot.certificationArtifacts = [
            ContactCertificationArtifactReference(
                artifactId: "artifact-1",
                keyId: "key-1",
                userId: "Alice <alice@example.com>",
                createdAt: referenceDate,
                storageHint: "placeholder"
            )
        ]
        snapshot.keyRecords[0].certificationArtifactIds = ["artifact-1"]
        snapshot.keyRecords[0].certificationProjection = ContactCertificationProjection(
            status: .revalidationNeeded,
            artifactIds: ["artifact-1"],
            lastValidatedAt: nil,
            reconciliationMetadata: "placeholder"
        )

        XCTAssertNoThrow(try snapshot.validateContract())
    }

    func test_legacyCertificationArtifactDecodesWithRevalidationDefaults() throws {
        var snapshot = try makeValidSnapshot()
        snapshot.keyRecords[0].certificationArtifactIds = ["artifact-legacy"]
        snapshot.keyRecords[0].certificationProjection = ContactCertificationProjection(
            status: .revalidationNeeded,
            artifactIds: ["artifact-legacy"],
            lastValidatedAt: nil,
            reconciliationMetadata: "legacy"
        )
        let legacySnapshot = LegacyCertificationArtifactSnapshot(
            schemaVersion: snapshot.schemaVersion,
            identities: snapshot.identities,
            keyRecords: snapshot.keyRecords,
            tags: snapshot.tags,
            certificationArtifacts: [
                LegacyCertificationArtifactReference(
                    artifactId: "artifact-legacy",
                    keyId: "key-1",
                    userId: "Alice <alice@example.com>",
                    createdAt: referenceDate,
                    storageHint: "legacy-placeholder"
                )
            ],
            createdAt: snapshot.createdAt,
            updatedAt: snapshot.updatedAt
        )
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary

        let decoded = try ContactsDomainSnapshotCodec.decodeSnapshot(
            try encoder.encode(legacySnapshot)
        )
        let artifact = try XCTUnwrap(decoded.snapshot.certificationArtifacts.first)

        XCTAssertEqual(artifact.validationStatus, .revalidationNeeded)
        XCTAssertEqual(artifact.source, .imported)
        XCTAssertTrue(artifact.canonicalSignatureData.isEmpty)
        XCTAssertEqual(artifact.targetSelector.kind, .userId)
        XCTAssertEqual(artifact.targetSelector.occurrenceIndex, 0)
        XCTAssertEqual(artifact.targetSelector.userIdDisplayText, "Alice <alice@example.com>")
    }

    func test_v1Snapshot_failsClosedAsUnsupportedAfterCutoff() throws {
        // The contacts schema v1→v2 migration was removed under the 2026-06-08 support cutoff.
        // A v1 payload (the same fields as v2, but schemaVersion 1) must now fail closed via the
        // unsupported-version `default` branch — routing the domain to recovery instead of migrating.
        var v1ShapedSnapshot = try makeValidSnapshot()
        v1ShapedSnapshot.schemaVersion = 1
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let v1Payload = try encoder.encode(v1ShapedSnapshot)

        XCTAssertThrowsError(try ContactsDomainSnapshotCodec.decodeSnapshot(v1Payload)) { error in
            XCTAssertEqual(
                error as? ProtectedDataError,
                .invalidEnvelope("Contacts payload has an unsupported schema version.")
            )
        }
    }

    func test_certificationArtifactDigestMismatch_isRejected() throws {
        var snapshot = try makeValidSnapshot()
        snapshot.certificationArtifacts = [
            makePersistedArtifact(
                artifactId: "artifact-digest-mismatch",
                signatureData: Data([0x01, 0x02, 0x03]),
                signatureDigest: "not-the-digest"
            )
        ]

        XCTAssertThrowsError(try snapshot.validateContract())
    }

    func test_duplicateCertificationArtifactPayloads_areRejected() throws {
        var snapshot = try makeValidSnapshot()
        let signatureData = Data([0x10, 0x20, 0x30])
        snapshot.certificationArtifacts = [
            makePersistedArtifact(
                artifactId: "artifact-1",
                signatureData: signatureData
            ),
            makePersistedArtifact(
                artifactId: "artifact-2",
                signatureData: signatureData
            ),
        ]

        XCTAssertThrowsError(try snapshot.validateContract())
    }

    func test_keyRecordCertificationArtifactsMustBelongToSameKey() throws {
        var snapshot = try makeValidSnapshotWithTwoKeys()
        snapshot.certificationArtifacts = [
            ContactCertificationArtifactReference(
                artifactId: "artifact-for-key-2",
                keyId: "key-2",
                userId: "Alice <alice@example.com>",
                createdAt: referenceDate,
                storageHint: "placeholder"
            )
        ]
        snapshot.keyRecords[0].certificationArtifactIds = ["artifact-for-key-2"]

        XCTAssertThrowsError(try snapshot.validateContract())
    }

    func test_keyRecordCertificationProjectionArtifactsMustBelongToSameKey() throws {
        var snapshot = try makeValidSnapshotWithTwoKeys()
        snapshot.certificationArtifacts = [
            ContactCertificationArtifactReference(
                artifactId: "artifact-for-key-2",
                keyId: "key-2",
                userId: "Alice <alice@example.com>",
                createdAt: referenceDate,
                storageHint: "placeholder"
            )
        ]
        snapshot.keyRecords[0].certificationProjection = ContactCertificationProjection(
            status: .revalidationNeeded,
            artifactIds: ["artifact-for-key-2"],
            lastValidatedAt: nil,
            reconciliationMetadata: "placeholder"
        )

        XCTAssertThrowsError(try snapshot.validateContract())
    }

    private func makeValidSnapshot() throws -> ContactsDomainSnapshot {
        let snapshot = ContactsDomainSnapshot(
            schemaVersion: ContactsDomainSnapshot.currentSchemaVersion,
            identities: [
                ContactIdentity(
                    contactId: "contact-1",
                    displayName: "Alice",
                    primaryEmail: "alice@example.com",
                    tagIds: [],
                    notes: nil,
                    createdAt: referenceDate,
                    updatedAt: referenceDate
                )
            ],
            keyRecords: [
                try makeKeyRecord(
                    keyId: "key-1",
                    contactId: "contact-1",
                    fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
            ],
            tags: [],
            certificationArtifacts: [],
            createdAt: referenceDate,
            updatedAt: referenceDate
        )
        try snapshot.validateContract()
        return snapshot
    }

    private func makeValidSnapshotWithTwoKeys() throws -> ContactsDomainSnapshot {
        var snapshot = try makeValidSnapshot()
        var secondKey = try makeKeyRecord(
            keyId: "key-2",
            contactId: "contact-1",
            fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        secondKey.usageState = .additionalActive
        snapshot.keyRecords.append(secondKey)
        try snapshot.validateContract()
        return snapshot
    }

    private func makeKeyRecord(
        keyId: String,
        contactId: String,
        fingerprint: String
    ) throws -> ContactKeyRecord {
        ContactKeyRecord(
            keyId: keyId,
            contactId: contactId,
            fingerprint: fingerprint,
            primaryUserId: "Alice <alice@example.com>",
            displayName: "Alice",
            email: "alice@example.com",
            keyVersion: 4,
            profile: .universal,
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            manualVerificationState: .verified,
            usageState: .preferred,
            certificationProjection: .empty,
            certificationArtifactIds: [],
            publicKeyData: Data([0x01, 0x02, 0x03]),
            createdAt: referenceDate,
            updatedAt: referenceDate
        )
    }

    private func makePersistedArtifact(
        artifactId: String,
        signatureData: Data,
        signatureDigest: String? = nil
    ) -> ContactCertificationArtifactReference {
        ContactCertificationArtifactReference(
            artifactId: artifactId,
            keyId: "key-1",
            userId: nil,
            createdAt: referenceDate,
            storageHint: "test",
            canonicalSignatureData: signatureData,
            signatureDigest: signatureDigest ?? ContactCertificationArtifactReference.sha256Hex(
                for: signatureData
            ),
            source: .imported,
            targetKeyFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            targetSelector: .directKey,
            signerPrimaryFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            signingKeyFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            certificationKind: nil,
            validationStatus: .valid,
            targetCertificateDigest: ContactCertificationArtifactReference.sha256Hex(
                for: Data([0x01, 0x02, 0x03])
            ),
            lastValidatedAt: referenceDate,
            updatedAt: referenceDate,
            exportFilename: "artifact.asc"
        )
    }
}

private struct LegacyCertificationArtifactSnapshot: Encodable {
    let schemaVersion: Int
    let identities: [ContactIdentity]
    let keyRecords: [ContactKeyRecord]
    let tags: [ContactTag]
    let certificationArtifacts: [LegacyCertificationArtifactReference]
    let createdAt: Date
    let updatedAt: Date
}

private struct LegacyCertificationArtifactReference: Encodable {
    let artifactId: String
    let keyId: String
    let userId: String?
    let createdAt: Date
    let storageHint: String?
}
