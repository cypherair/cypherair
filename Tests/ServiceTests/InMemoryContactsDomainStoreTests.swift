import Foundation
import XCTest
@testable import CypherAir

/// The shared-validation property behind the contacts persistence seam
/// (#961 constraint): the RAM store must reject exactly the states the
/// SQLCipher-backed store rejects, because both run
/// `ContactsDomainSnapshot.validateContract()` at their persistence
/// boundaries. If a later change gives the in-memory store its own weaker
/// checks — or none — the sandbox could reach states production refuses,
/// and these tests fail.
final class InMemoryContactsDomainStoreTests: XCTestCase {
    private let referenceDate = Date(timeIntervalSince1970: 1_774_000_000)

    // MARK: - Lifecycle parity with the production store

    func test_lifecycle_commitOpenReplaceRelockReopen() async throws {
        let store = InMemoryContactsDomainStore()
        XCTAssertNil(store.snapshot)

        try await store.ensureCommittedIfNeeded(
            wrappingRootKey: Data(),
            initialSnapshotProvider: { ContactsDomainSnapshot.empty(now: self.referenceDate) }
        )
        XCTAssertNil(store.snapshot, "Committing must not open the domain.")

        let opened = try await store.openDomainIfNeeded(wrappingRootKey: Data())
        XCTAssertTrue(opened.identities.isEmpty)
        XCTAssertNotNil(store.snapshot)

        let replacement = try makeValidSnapshot()
        try store.replaceSnapshot(replacement)
        XCTAssertEqual(store.snapshot, replacement)

        try await store.relockProtectedData()
        XCTAssertNil(store.snapshot, "Relock must drop the open payload.")

        let reopened = try await store.openDomainIfNeeded(wrappingRootKey: Data())
        XCTAssertEqual(reopened, replacement, "Reopen must restore the committed payload.")
    }

    func test_openWithoutCommit_failsClosed() async {
        let store = InMemoryContactsDomainStore()
        do {
            _ = try await store.openDomainIfNeeded(wrappingRootKey: Data())
            XCTFail("Opening an uncommitted domain must fail.")
        } catch {
            XCTAssertTrue(error is InMemoryContactsDomainStoreError)
        }
    }

    func test_replaceWithoutOpen_failsClosed() throws {
        let store = InMemoryContactsDomainStore()
        XCTAssertThrowsError(try store.replaceSnapshot(try makeValidSnapshot()))
    }

    // MARK: - The three contact invariants, enforced at every boundary

    func test_replaceSnapshot_rejectsSecondPreferredKeyPerContact() async throws {
        let store = try await makeOpenStore()
        var snapshot = try makeValidSnapshot()
        var secondKey = makeKeyRecord(
            keyId: "key-2",
            contactId: "contact-1",
            fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        secondKey.usageState = .preferred
        snapshot.keyRecords.append(secondKey)

        XCTAssertThrowsError(try store.replaceSnapshot(snapshot)) { error in
            XCTAssertTrue(error is ContactsDomainValidationError)
        }
        XCTAssertEqual(store.snapshot?.keyRecords.count, 0, "A rejected write must not land.")
    }

    func test_replaceSnapshot_rejectsActiveKeyThatCannotEncrypt() async throws {
        let store = try await makeOpenStore()
        var snapshot = try makeValidSnapshot()
        snapshot.keyRecords[0].hasEncryptionSubkey = false
        snapshot.keyRecords[0].usageState = .additionalActive

        XCTAssertThrowsError(try store.replaceSnapshot(snapshot)) { error in
            XCTAssertTrue(error is ContactsDomainValidationError)
        }
    }

    func test_replaceSnapshot_rejectsArtifactWithStaleKeyFingerprint() async throws {
        let store = try await makeOpenStore()
        var snapshot = try makeValidSnapshot()
        let signatureData = Data([0x51, 0x52, 0x53])
        snapshot.certificationArtifacts = [
            ContactCertificationArtifactReference(
                artifactId: "artifact-1",
                keyId: "key-1",
                createdAt: referenceDate,
                canonicalSignatureData: signatureData,
                signatureDigest: ContactCertificationArtifactReference.sha256Hex(for: signatureData),
                source: .imported,
                // Stale: does not match key-1's fingerprint.
                targetKeyFingerprint: "cccccccccccccccccccccccccccccccccccccccc",
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
        ]
        snapshot.keyRecords[0].certificationArtifactIds = ["artifact-1"]

        XCTAssertThrowsError(try store.replaceSnapshot(snapshot)) { error in
            XCTAssertTrue(error is ContactsDomainValidationError)
        }
    }

    func test_initialCommit_runsTheSameValidation() async {
        let store = InMemoryContactsDomainStore()
        var invalid = ContactsDomainSnapshot.empty(now: referenceDate)
        invalid.schemaVersion = ContactsDomainSnapshot.currentSchemaVersion + 1

        do {
            try await store.ensureCommittedIfNeeded(
                wrappingRootKey: Data(),
                initialSnapshotProvider: { invalid }
            )
            XCTFail("An invalid initial snapshot must not commit.")
        } catch {
            XCTAssertTrue(error is ContactsDomainValidationError)
        }
    }

    // MARK: - Helpers

    private func makeOpenStore() async throws -> InMemoryContactsDomainStore {
        let store = InMemoryContactsDomainStore()
        try await store.ensureCommittedIfNeeded(
            wrappingRootKey: Data(),
            initialSnapshotProvider: { ContactsDomainSnapshot.empty(now: self.referenceDate) }
        )
        _ = try await store.openDomainIfNeeded(wrappingRootKey: Data())
        return store
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
                makeKeyRecord(
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

    private func makeKeyRecord(
        keyId: String,
        contactId: String,
        fingerprint: String
    ) -> ContactKeyRecord {
        ContactKeyRecord(
            keyId: keyId,
            contactId: contactId,
            fingerprint: fingerprint,
            primaryUserId: "Alice <alice@example.com>",
            displayName: "Alice",
            email: "alice@example.com",
            keyVersion: 4,
            suite: .ed25519LegacyCurve25519Legacy,
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
}
