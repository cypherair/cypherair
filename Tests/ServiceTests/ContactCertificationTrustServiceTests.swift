import XCTest
@testable import CypherAir

/// The trust derivation as the app actually runs it: a real certification, made
/// by a real key, read back through the same projection the UI reads.
final class ContactCertificationTrustServiceTests: ContactServiceTestCase {

    /// The property the design exists for. Nothing about the certification
    /// changes across these three reads — only whether the user currently
    /// stands behind the signer — and the vouch appears and disappears with it.
    func test_vouchingFollowsTheSignerVerificationOnEveryRead() async throws {
        let opened = try await makeOpenedProtectedContactService(prefix: "ContactsVouching")
        defer {
            try? FileManager.default.removeItem(
                at: opened.harness.storageRoot.rootURL.deletingLastPathComponent()
            )
        }
        let service = opened.service
        let scenario = try await makeCertifiedContact(service: service)

        XCTAssertTrue(
            try trust(for: scenario.targetFingerprint, in: service).vouchers.isEmpty,
            "An unverified signer must carry no weight."
        )

        try service.setVerificationState(.verified, for: scenario.signerFingerprint)
        let vouched = try trust(for: scenario.targetFingerprint, in: service)
        XCTAssertEqual(vouched.vouchers.map(\.fingerprint), [scenario.signerFingerprint])
        XCTAssertFalse(vouched.isVerifiedByUser)
        XCTAssertEqual(vouched.anchor, .vouched(by: vouched.vouchers[0], otherVoucherCount: 0))

        try service.setVerificationState(.unverified, for: scenario.signerFingerprint)
        let withdrawn = try trust(for: scenario.targetFingerprint, in: service)
        XCTAssertTrue(withdrawn.vouchers.isEmpty)
        XCTAssertEqual(withdrawn.anchor, .unanchored)

        // The certification itself is untouched by any of this: the signature is
        // still valid, and only the weight the app gives it moved.
        XCTAssertEqual(
            service.availableKey(fingerprint: scenario.targetFingerprint)?
                .certificationProjection.signatureState,
            .valid
        )
    }

    /// A key signing its own User ID is not a certification of anything, and must
    /// not become a saveable artifact — the path by which a key with nothing but
    /// self-signatures used to read as certified.
    func test_selfSignatureIsValidButIsNotACertification() async throws {
        let keyManagement = TestHelpers.makeKeyManagement(engine: engine).service
        let owner = try await TestHelpers.generateLegacyKey(
            service: keyManagement,
            name: "Self Signer",
            email: "self-signer@example.invalid"
        )
        _ = try contactService.importContact(
            publicKeyData: owner.publicKeyData,
            verificationState: .unverified
        )
        let targetKey = try XCTUnwrap(contactService.availableKey(fingerprint: owner.fingerprint))
        let targetCert = try contactService.requireContactPublicKeyData(keyId: targetKey.keyId)
        let certificateSignatureService = makeCertificateSignatureService(
            keyManagement: keyManagement,
            contactService: contactService
        )
        let selectedUserId = try XCTUnwrap(
            certificateSignatureService.selectionCatalog(targetCert: targetCert).userIds.first
        )

        let selfSignature = try await certificateSignatureService
            .generateArmoredUserIdCertification(
                signerFingerprint: owner.fingerprint,
                targetCert: targetCert,
                selectedUserId: selectedUserId,
                certificationKind: .generic
            )
        let validation = try await certificateSignatureService.validateUserIdCertificationArtifact(
            signature: selfSignature,
            targetKey: targetKey,
            targetCert: targetCert,
            selectedUserId: selectedUserId,
            source: .imported,
            exportFilename: nil
        )

        // Valid describes the signature, and it genuinely is valid.
        XCTAssertEqual(validation.verification.status, .valid)
        XCTAssertEqual(validation.verification.signerPrimaryFingerprint, owner.fingerprint)
        // But there is nothing to record and nobody vouching.
        XCTAssertNil(validation.artifact)
    }

    // MARK: - Fixtures

    private struct CertifiedContact {
        let targetFingerprint: String
        let signerFingerprint: String
    }

    /// Imports two contacts and has one of them certify the other's User ID,
    /// which needs the signer's private half — so the signer is generated
    /// locally and its public certificate imported as an ordinary contact.
    private func makeCertifiedContact(
        service: ContactService
    ) async throws -> CertifiedContact {
        let keyManagement = TestHelpers.makeKeyManagement(engine: engine).service
        let signer = try await TestHelpers.generateLegacyKey(
            service: keyManagement,
            name: "Vouching Contact",
            email: "voucher@example.invalid"
        )
        let target = try engine.generateKey(
            name: "Certified Contact",
            email: "certified@example.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        // Both arrive unverified: the point of the test is that the vouch turns
        // on the user's verification of the signer and nothing else.
        _ = try service.importContact(
            publicKeyData: signer.publicKeyData,
            verificationState: .unverified
        )
        _ = try service.importContact(
            publicKeyData: target.publicKeyData,
            verificationState: .unverified
        )

        let targetKey = try XCTUnwrap(service.availableKey(fingerprint: target.fingerprint))
        let targetCert = try service.requireContactPublicKeyData(keyId: targetKey.keyId)
        let certificateSignatureService = makeCertificateSignatureService(
            keyManagement: keyManagement,
            contactService: service
        )
        let selectedUserId = try XCTUnwrap(
            certificateSignatureService.selectionCatalog(targetCert: targetCert).userIds.first
        )
        let signature = try await certificateSignatureService.generateArmoredUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: targetCert,
            selectedUserId: selectedUserId,
            certificationKind: .generic
        )
        let validation = try await certificateSignatureService.validateUserIdCertificationArtifact(
            signature: signature,
            targetKey: targetKey,
            targetCert: targetCert,
            selectedUserId: selectedUserId,
            source: .imported,
            exportFilename: "vouching-certification.asc"
        )
        _ = try service.saveCertificationArtifact(try XCTUnwrap(validation.artifact))

        return CertifiedContact(
            targetFingerprint: target.fingerprint,
            signerFingerprint: signer.fingerprint
        )
    }

    private func makeCertificateSignatureService(
        keyManagement: KeyManagementService,
        contactService: ContactService
    ) -> CertificateSignatureService {
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        return CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            certificationSigner: TestHelpers.makeContactCertificationSigner(
                engine: engine,
                keyManagement: keyManagement,
                certificateAdapter: certificateAdapter
            )
        )
    }

    private func trust(
        for fingerprint: String,
        in service: ContactService
    ) throws -> ContactKeyTrust {
        try XCTUnwrap(service.availableKey(fingerprint: fingerprint)).trust
    }
}
