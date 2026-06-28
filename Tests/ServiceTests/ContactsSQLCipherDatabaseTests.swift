import Foundation
import XCTest
@testable import CypherAir

final class ContactsSQLCipherDatabaseTests: XCTestCase {
    private let referenceDate = Date(timeIntervalSince1970: 1_774_000_000)
    private let domainMasterKey = Data((0..<32).map { UInt8($0) })

    func test_createFreshAndOpenExisting_roundTripsRichContactsSnapshot() throws {
        let baseDirectory = makeTemporaryDirectory("ContactsSQLCipherRoundTrip")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }
        let storageRoot = ProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let snapshot = try makeRichSnapshot()

        let database = ContactsSQLCipherDatabase(storageRoot: storageRoot, domainID: ContactsDomainStore.domainID)
        try database.createFresh(snapshot: snapshot, domainMasterKey: domainMasterKey)
        try database.close()

        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: storageRoot.contactsSQLCipherDatabaseURL(for: ContactsDomainStore.domainID).path
            )
        )
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: storageRoot.domainEnvelopeURL(for: ContactsDomainStore.domainID, slot: .current).path
            )
        )

        let reopenedDatabase = ContactsSQLCipherDatabase(
            storageRoot: storageRoot,
            domainID: ContactsDomainStore.domainID
        )
        let reopenedSnapshot = try reopenedDatabase.openExisting(domainMasterKey: domainMasterKey)
        try reopenedDatabase.close()

        XCTAssertEqual(reopenedSnapshot, snapshot)
    }

    func test_openExistingWithWrongDomainMasterKey_failsClosed() throws {
        let baseDirectory = makeTemporaryDirectory("ContactsSQLCipherWrongKey")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }
        let storageRoot = ProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let database = ContactsSQLCipherDatabase(storageRoot: storageRoot, domainID: ContactsDomainStore.domainID)
        try database.createFresh(snapshot: try makeRichSnapshot(), domainMasterKey: domainMasterKey)
        try database.close()

        let reopenedDatabase = ContactsSQLCipherDatabase(
            storageRoot: storageRoot,
            domainID: ContactsDomainStore.domainID
        )
        XCTAssertThrowsError(
            try reopenedDatabase.openExisting(domainMasterKey: Data(repeating: 0xA5, count: 32))
        )
        try? reopenedDatabase.close()
    }

    func test_openExistingMissingDatabase_failsWithoutCreatingAuthority() throws {
        let baseDirectory = makeTemporaryDirectory("ContactsSQLCipherMissing")
        defer { try? FileManager.default.removeItem(at: baseDirectory) }
        let storageRoot = ProtectedDataStorageRoot(baseDirectory: baseDirectory)
        let database = ContactsSQLCipherDatabase(storageRoot: storageRoot, domainID: ContactsDomainStore.domainID)

        XCTAssertThrowsError(try database.openExisting(domainMasterKey: domainMasterKey)) { error in
            XCTAssertEqual(
                error as? ProtectedDataError,
                .invalidEnvelope("Contacts SQLCipher database is missing.")
            )
        }
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: storageRoot.contactsSQLCipherDatabaseURL(for: ContactsDomainStore.domainID).path
            )
        )
    }

    private func makeTemporaryDirectory(_ prefix: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
    }

    private func makeRichSnapshot() throws -> ContactsDomainSnapshot {
        let tag = ContactTag(
            tagId: "tag-1",
            displayName: "Close Friend",
            normalizedName: ContactTag.normalizedName(for: "Close Friend"),
            createdAt: referenceDate,
            updatedAt: referenceDate
        )
        let identity = ContactIdentity(
            contactId: "contact-1",
            displayName: "Alice",
            primaryEmail: "alice@example.com",
            tagIds: [tag.tagId],
            notes: "Met at the key-signing table.\u{0000}Preserve exact notes.",
            createdAt: referenceDate,
            updatedAt: referenceDate
        )
        var keyRecord = ContactKeyRecord(
            keyId: "key-1",
            contactId: identity.contactId,
            fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
        let artifact = ContactCertificationArtifactReference(
            artifactId: "artifact-1",
            keyId: keyRecord.keyId,
            createdAt: referenceDate,
            canonicalSignatureData: Data([0x51, 0x52, 0x53]),
            signatureDigest: ContactCertificationArtifactReference.sha256Hex(for: Data([0x51, 0x52, 0x53])),
            source: .imported,
            targetKeyFingerprint: keyRecord.fingerprint,
            targetSelector: .userId(
                data: Data("Alice <alice@example.com>".utf8),
                displayText: "Alice <alice@example.com>",
                occurrenceIndex: 0
            ),
            signerPrimaryFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            signingKeyFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            certificationKind: .generic,
            validationStatus: .valid,
            targetCertificateDigest: ContactCertificationArtifactReference.sha256Hex(for: keyRecord.publicKeyData),
            lastValidatedAt: referenceDate,
            updatedAt: referenceDate,
            exportFilename: "alice-certification.asc"
        )
        keyRecord.certificationArtifactIds = [artifact.artifactId]
        keyRecord.certificationProjection = ContactCertificationProjection(
            status: .certified,
            artifactIds: [artifact.artifactId],
            lastValidatedAt: referenceDate
        )

        let snapshot = ContactsDomainSnapshot(
            schemaVersion: ContactsDomainSnapshot.currentSchemaVersion,
            identities: [identity],
            keyRecords: [keyRecord],
            tags: [tag],
            certificationArtifacts: [artifact],
            createdAt: referenceDate,
            updatedAt: referenceDate
        )
        try snapshot.validateContract()
        return snapshot
    }
}
