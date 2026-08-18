import XCTest
@testable import CypherAir

/// The trust web is the only thing in the app that decides whether a
/// certification counts for anything, so these tests pin the policy directly:
/// who gets weight, who does not, and — the property the whole design exists for
/// — that withdrawing a verification takes the weight away without anything
/// being recomputed, invalidated or migrated.
final class ContactCertificationTrustWebTests: XCTestCase {

    private let target = "target-key"
    private let targetFingerprint = "AAAA0000AAAA0000AAAA0000AAAA0000AAAA0000"
    private let signerFingerprint = "BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111"

    func test_verifiedSignerVouchesForTheKeyTheyCertified() {
        let trust = derivedTrust(records: [targetRecord(), signerRecord(verified: true)])

        XCTAssertEqual(trust.vouchers.map(\.displayName), ["Verified Signer"])
        XCTAssertEqual(trust.anchor, .vouched(by: trust.vouchers[0], otherVoucherCount: 0))
    }

    func test_withdrawingSignerVerificationImmediatelyRemovesTheVouch() {
        var records = [targetRecord(), signerRecord(verified: true)]
        XCTAssertFalse(derivedTrust(records: records).vouchers.isEmpty)

        // Exactly the mutation the withdraw button makes, and nothing else: no
        // artifact is touched, no projection recomputed, no cache invalidated.
        records[1].manualVerificationState = .unverified

        let trust = derivedTrust(records: records)
        XCTAssertTrue(trust.vouchers.isEmpty)
        XCTAssertEqual(trust.anchor, .unanchored)
    }

    func test_unverifiedSignerCarriesNoWeight() {
        let trust = derivedTrust(records: [targetRecord(), signerRecord(verified: false)])

        XCTAssertTrue(trust.vouchers.isEmpty)
        XCTAssertEqual(trust.anchor, .unanchored)
    }

    func test_revokedSignerCarriesNoWeightEvenWhenVerified() {
        let signer = signerRecord(verified: true, isRevoked: true)

        XCTAssertTrue(derivedTrust(records: [targetRecord(), signer]).vouchers.isEmpty)
    }

    /// Pins the provisional ruling on issue #956 so that reversing it is a
    /// deliberate change to `ContactVouchingPolicy` and this expectation, rather
    /// than something that drifts.
    func test_expiredSignerKeepsTheWeightOfWhatItAlreadyCertified() {
        let signer = signerRecord(verified: true, isExpired: true)

        XCTAssertEqual(
            derivedTrust(records: [targetRecord(), signer]).vouchers.map(\.fingerprint),
            [signerFingerprint]
        )
    }

    func test_selfSignatureNeverVouchesForItsOwnKey() {
        let selfCertification = artifact(signerFingerprint: targetFingerprint)

        let trust = ContactCertificationTrustWeb(
            keyRecords: [targetRecord()],
            certificationArtifacts: [selfCertification]
        )
        .trust(for: targetRecord())

        XCTAssertTrue(trust.vouchers.isEmpty)
        XCTAssertEqual(trust.anchor, .unanchored)
    }

    func test_signatureThatNoLongerVerifiesCarriesNoWeight() {
        var stale = artifact(signerFingerprint: signerFingerprint)
        stale.validationStatus = .invalidOrStale

        let trust = ContactCertificationTrustWeb(
            keyRecords: [targetRecord(), signerRecord(verified: true)],
            certificationArtifacts: [stale]
        )
        .trust(for: targetRecord())

        XCTAssertTrue(trust.vouchers.isEmpty)
    }

    /// Vouching is one hop. A contact vouched for by someone the user verified
    /// does not thereby become able to vouch for others.
    func test_vouchingDoesNotChainBeyondOneHop() {
        let middleFingerprint = "CCCC2222CCCC2222CCCC2222CCCC2222CCCC2222"
        let middle = makeRecord(
            keyId: "middle-key",
            fingerprint: middleFingerprint,
            displayName: "Middle",
            verified: false
        )
        let anchorRecord = makeRecord(
            keyId: "anchor-key",
            fingerprint: signerFingerprint,
            displayName: "Anchor",
            verified: true
        )

        let web = ContactCertificationTrustWeb(
            keyRecords: [targetRecord(), middle, anchorRecord],
            certificationArtifacts: [
                // The user's anchor vouches for Middle.
                artifact(
                    id: "anchor-vouches-middle",
                    keyId: middle.keyId,
                    signerFingerprint: signerFingerprint
                ),
                // Middle certifies the target, but the user never verified Middle.
                artifact(
                    id: "middle-certifies-target",
                    signerFingerprint: middleFingerprint
                ),
            ]
        )

        XCTAssertEqual(web.trust(for: middle).vouchers.map(\.displayName), ["Anchor"])
        XCTAssertTrue(web.trust(for: targetRecord()).vouchers.isEmpty)
    }

    func test_userOwnVerificationIsReportedSeparatelyFromVouching() {
        var verifiedTarget = targetRecord()
        verifiedTarget.manualVerificationState = .verified

        let trust = ContactCertificationTrustWeb(
            keyRecords: [verifiedTarget, signerRecord(verified: true)],
            certificationArtifacts: [artifact(signerFingerprint: signerFingerprint)]
        )
        .trust(for: verifiedTarget)

        // Both facts survive: the headline is the user's own check, and the
        // vouch is still listed rather than being absorbed into it.
        XCTAssertEqual(trust.anchor, .verifiedByUser)
        XCTAssertTrue(trust.isVerifiedByUser)
        XCTAssertEqual(trust.vouchers.map(\.fingerprint), [signerFingerprint])
    }

    func test_repeatedCertificationsFromOneSignerNameThatSignerOnce() {
        let web = ContactCertificationTrustWeb(
            keyRecords: [targetRecord(), signerRecord(verified: true)],
            certificationArtifacts: [
                artifact(id: "first", signerFingerprint: signerFingerprint),
                artifact(id: "second", signerFingerprint: signerFingerprint.lowercased()),
            ]
        )

        XCTAssertEqual(web.trust(for: targetRecord()).vouchers.count, 1)
    }

    // MARK: - Fixtures

    private func derivedTrust(records: [ContactKeyRecord]) -> ContactKeyTrust {
        ContactCertificationTrustWeb(
            keyRecords: records,
            certificationArtifacts: [artifact(signerFingerprint: signerFingerprint)]
        )
        .trust(for: targetRecord())
    }

    private func targetRecord() -> ContactKeyRecord {
        makeRecord(
            keyId: target,
            fingerprint: targetFingerprint,
            displayName: "Target",
            verified: false
        )
    }

    private func signerRecord(
        verified: Bool,
        isRevoked: Bool = false,
        isExpired: Bool = false
    ) -> ContactKeyRecord {
        makeRecord(
            keyId: "signer-key",
            fingerprint: signerFingerprint,
            displayName: verified ? "Verified Signer" : "Unverified Signer",
            verified: verified,
            isRevoked: isRevoked,
            isExpired: isExpired
        )
    }

    private func makeRecord(
        keyId: String,
        fingerprint: String,
        displayName: String,
        verified: Bool,
        isRevoked: Bool = false,
        isExpired: Bool = false
    ) -> ContactKeyRecord {
        ContactKeyRecord(
            keyId: keyId,
            contactId: "contact-\(keyId)",
            fingerprint: fingerprint,
            primaryUserId: nil,
            displayName: displayName,
            email: nil,
            keyVersion: 4,
            suite: .ed25519LegacyCurve25519Legacy,
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519",
            hasEncryptionSubkey: true,
            isRevoked: isRevoked,
            isExpired: isExpired,
            manualVerificationState: verified ? .verified : .unverified,
            usageState: .preferred,
            certificationProjection: .empty,
            certificationArtifactIds: [],
            publicKeyData: Data([0x01]),
            createdAt: Date(timeIntervalSince1970: 0),
            updatedAt: Date(timeIntervalSince1970: 0)
        )
    }

    private func artifact(
        id: String = "artifact",
        keyId: String? = nil,
        signerFingerprint: String
    ) -> ContactCertificationArtifactReference {
        ContactCertificationArtifactReference(
            artifactId: id,
            keyId: keyId ?? target,
            createdAt: Date(timeIntervalSince1970: 0),
            canonicalSignatureData: Data("signature-\(id)".utf8),
            signatureDigest: nil,
            source: .imported,
            targetKeyFingerprint: nil,
            targetSelector: .directKey,
            signerPrimaryFingerprint: signerFingerprint,
            signingKeyFingerprint: nil,
            certificationKind: .generic,
            validationStatus: .valid,
            targetCertificateDigest: nil,
            lastValidatedAt: nil,
            updatedAt: nil,
            exportFilename: nil
        )
    }
}
