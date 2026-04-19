import XCTest
@testable import CypherAir

final class CertificateSignatureServiceTests: XCTestCase {

    private var stack: TestHelpers.ServiceStack!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
    }

    override func tearDown() {
        stack.cleanup()
        stack = nil
        super.tearDown()
    }

    private func loadFixture(_ name: String, ext: String = "gpg") throws -> Data {
        try FixtureLoader.loadData(name, ext: ext)
    }

    private func loadStringFixture(_ name: String, ext: String = "txt") throws -> String {
        try FixtureLoader.loadString(name, ext: ext)
    }

    private func generatedTarget(
        profile: KeyProfile,
        name: String,
        email: String
    ) throws -> GeneratedKey {
        try stack.engine.generateKey(
            name: name,
            email: email,
            expirySeconds: nil,
            profile: profile
        )
    }

    private func selectedUserId(
        for certData: Data,
        occurrenceIndex: Int = 0
    ) throws -> UserIdSelectionOption {
        let catalog = try stack.certificateSignatureService.selectionCatalog(targetCert: certData)
        return catalog.userIds[occurrenceIndex]
    }

    private func generateSigner(
        profile: KeyProfile,
        name: String,
        email: String
    ) async throws -> PGPKeyIdentity {
        try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: profile,
            name: name,
            email: email
        )
    }

    func test_selectionCatalog_targetCert_isReadOnly() throws {
        let target = try generatedTarget(
            profile: .universal,
            name: "Selector ReadOnly",
            email: "selector-readonly@example.com"
        )
        let unwrapCountBefore = stack.mockSE.unwrapCallCount
        let saveCountBefore = stack.mockKC.saveCallCount

        let catalog = try stack.certificateSignatureService.selectionCatalog(
            targetCert: target.publicKeyData
        )

        XCTAssertEqual(catalog.certificateFingerprint, target.fingerprint)
        XCTAssertEqual(stack.mockSE.unwrapCallCount, unwrapCountBefore)
        XCTAssertEqual(stack.mockKC.saveCallCount, saveCountBefore)
    }

    func test_verifyDirectKeySignature_fixtureContact_returnsValidContactIdentity() async throws {
        let target = try loadFixture("ffi_direct_key_target")
        let signature = try loadFixture("ffi_direct_key_signature", ext: "sig")
        let contactResult = try stack.contactService.addContact(publicKeyData: target)
        guard case .added(let contact) = contactResult else {
            return XCTFail("Expected contact to be added")
        }

        let verification = try await stack.certificateSignatureService.verifyDirectKeySignature(
            signature: signature,
            targetCert: target
        )

        XCTAssertEqual(verification.status, .valid)
        XCTAssertEqual(verification.signerPrimaryFingerprint, contact.fingerprint)
        XCTAssertEqual(verification.signerIdentity?.source, .contact)
    }

    func test_verifyDirectKeySignature_wrongTarget_returnsInvalid() async throws {
        let target = try loadFixture("ffi_direct_key_target")
        let signature = try loadFixture("ffi_direct_key_signature", ext: "sig")
        _ = try stack.contactService.addContact(publicKeyData: target)
        let wrongTarget = try generatedTarget(
            profile: .universal,
            name: "Wrong Direct Target",
            email: "wrong-direct-target@example.com"
        )

        let verification = try await stack.certificateSignatureService.verifyDirectKeySignature(
            signature: signature,
            targetCert: wrongTarget.publicKeyData
        )

        XCTAssertEqual(verification.status, .invalid)
        XCTAssertNil(verification.signerIdentity)
    }

    func test_verifyDirectKeySignature_missingSigner_returnsSignerMissing() async throws {
        let target = try loadFixture("ffi_direct_key_target")
        let signature = try loadFixture("ffi_direct_key_signature", ext: "sig")

        let verification = try await stack.certificateSignatureService.verifyDirectKeySignature(
            signature: signature,
            targetCert: target
        )

        XCTAssertEqual(verification.status, .signerMissing)
        XCTAssertNil(verification.signerPrimaryFingerprint)
        XCTAssertNil(verification.signerIdentity)
    }

    func test_verifyUserIdBindingSignature_fixtureFallbackSubkey_returnsContactAndSubkeyFingerprint()
        async throws
    {
        let signerPublic = try loadFixture("ffi_cert_binding_subkey_signer_public")
        let target = try loadFixture("ffi_cert_binding_target")
        let signature = try loadFixture("ffi_cert_binding_missing_issuer_positive", ext: "sig")
        let expectedSubkeyFingerprint = try loadStringFixture(
            "ffi_cert_binding_subkey_fingerprint"
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        let contactResult = try stack.contactService.addContact(publicKeyData: signerPublic)
        guard case .added(let contact) = contactResult else {
            return XCTFail("Expected contact to be added")
        }
        let selectedUserId = try selectedUserId(for: target)

        let verification = try await stack.certificateSignatureService.verifyUserIdBindingSignature(
            signature: signature,
            targetCert: target,
            selectedUserId: selectedUserId
        )

        XCTAssertEqual(verification.status, .valid)
        XCTAssertEqual(verification.signerPrimaryFingerprint, contact.fingerprint)
        XCTAssertEqual(verification.signingKeyFingerprint, expectedSubkeyFingerprint)
        XCTAssertEqual(verification.signerIdentity?.source, .contact)
    }

    func test_verifyUserIdBindingSignature_duplicateOccurrence_acceptsSelectedOccurrence() async throws {
        let signer = try await generateSigner(
            profile: .universal,
            name: "Duplicate Service Signer",
            email: "duplicate-service-signer@example.com"
        )
        let target = try loadFixture("selector_duplicate_userid_second_revoked_secret")
        let selectedUserId = try selectedUserId(for: target, occurrenceIndex: 1)
        let signature = try await stack.certificateSignatureService.generateUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: target,
            selectedUserId: selectedUserId,
            certificationKind: .positive
        )

        let verification = try await stack.certificateSignatureService.verifyUserIdBindingSignature(
            signature: signature,
            targetCert: target,
            selectedUserId: selectedUserId
        )

        XCTAssertEqual(verification.status, .valid)
        XCTAssertEqual(verification.signerIdentity?.source, .ownKey)
    }

    func test_generateUserIdCertification_roundTrip_profileA_returnsOwnKeyIdentity() async throws {
        let signer = try await generateSigner(
            profile: .universal,
            name: "Service Signer A",
            email: "service-signer-a@example.com"
        )
        let target = try generatedTarget(
            profile: .universal,
            name: "Service Target A",
            email: "service-target-a@example.com"
        )
        let selectedUserId = try selectedUserId(for: target.publicKeyData)

        let signature = try await stack.certificateSignatureService.generateUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId,
            certificationKind: .positive
        )
        let verification = try await stack.certificateSignatureService.verifyUserIdBindingSignature(
            signature: signature,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId
        )

        XCTAssertEqual(verification.status, .valid)
        XCTAssertEqual(verification.signerPrimaryFingerprint, signer.fingerprint)
        XCTAssertEqual(verification.signerIdentity?.source, .ownKey)
    }

    func test_generateUserIdCertification_roundTrip_profileB_returnsOwnKeyIdentity() async throws {
        let signer = try await generateSigner(
            profile: .advanced,
            name: "Service Signer B",
            email: "service-signer-b@example.com"
        )
        let target = try generatedTarget(
            profile: .advanced,
            name: "Service Target B",
            email: "service-target-b@example.com"
        )
        let selectedUserId = try selectedUserId(for: target.publicKeyData)

        let signature = try await stack.certificateSignatureService.generateUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId,
            certificationKind: .persona
        )
        let verification = try await stack.certificateSignatureService.verifyUserIdBindingSignature(
            signature: signature,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId
        )

        XCTAssertEqual(verification.status, .valid)
        XCTAssertEqual(verification.signerPrimaryFingerprint, signer.fingerprint)
        XCTAssertEqual(verification.certificationKind, .persona)
        XCTAssertEqual(verification.signerIdentity?.source, .ownKey)
    }

    func test_generateUserIdCertification_preservesAllCertificationKinds() async throws {
        let signer = try await generateSigner(
            profile: .advanced,
            name: "Kinds Signer",
            email: "kinds-signer@example.com"
        )
        let target = try generatedTarget(
            profile: .advanced,
            name: "Kinds Target",
            email: "kinds-target@example.com"
        )
        let selectedUserId = try selectedUserId(for: target.publicKeyData)
        let kinds: [CertificationKind] = [.generic, .persona, .casual, .positive]

        for kind in kinds {
            let signature = try await stack.certificateSignatureService.generateUserIdCertification(
                signerFingerprint: signer.fingerprint,
                targetCert: target.publicKeyData,
                selectedUserId: selectedUserId,
                certificationKind: kind
            )
            let verification = try await stack.certificateSignatureService.verifyUserIdBindingSignature(
                signature: signature,
                targetCert: target.publicKeyData,
                selectedUserId: selectedUserId
            )

            XCTAssertEqual(verification.status, .valid)
            XCTAssertEqual(verification.certificationKind, kind)
        }
    }

    func test_generateArmoredUserIdCertification_returnsArmoredSignature() async throws {
        let signer = try await generateSigner(
            profile: .advanced,
            name: "Armored Signer",
            email: "armored-signer@example.com"
        )
        let target = try generatedTarget(
            profile: .advanced,
            name: "Armored Target",
            email: "armored-target@example.com"
        )
        let selectedUserId = try selectedUserId(for: target.publicKeyData)

        let armored = try await stack.certificateSignatureService.generateArmoredUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId,
            certificationKind: .positive
        )

        XCTAssertTrue(
            String(data: armored, encoding: .utf8)?.contains("BEGIN PGP SIGNATURE") == true
        )
    }

    func test_generateArmoredUserIdCertification_dearmoredRoundTrip_verifiesSuccessfully() async throws {
        let signer = try await generateSigner(
            profile: .universal,
            name: "Armored Roundtrip Signer",
            email: "armored-roundtrip-signer@example.com"
        )
        let target = try generatedTarget(
            profile: .universal,
            name: "Armored Roundtrip Target",
            email: "armored-roundtrip-target@example.com"
        )
        let selectedUserId = try selectedUserId(for: target.publicKeyData)

        let armored = try await stack.certificateSignatureService.generateArmoredUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId,
            certificationKind: .casual
        )
        let binary = try stack.engine.dearmor(armored: armored)

        let verification = try await stack.certificateSignatureService.verifyUserIdBindingSignature(
            signature: binary,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId
        )

        XCTAssertEqual(verification.status, .valid)
        XCTAssertEqual(verification.certificationKind, .casual)
    }

    func test_verifyDirectKeySignature_acceptsBinaryAndArmoredSignatureBytes() async throws {
        let target = try loadFixture("ffi_direct_key_target")
        let binary = try loadFixture("ffi_direct_key_signature", ext: "sig")
        let armored = try stack.engine.armor(data: binary, kind: .signature)
        _ = try stack.contactService.addContact(publicKeyData: target)

        let armoredVerification = try await stack.certificateSignatureService.verifyDirectKeySignature(
            signature: armored,
            targetCert: target
        )
        let binaryVerification = try await stack.certificateSignatureService.verifyDirectKeySignature(
            signature: binary,
            targetCert: target
        )

        XCTAssertEqual(armoredVerification.status, .valid)
        XCTAssertEqual(binaryVerification.status, .valid)
    }

    func test_generateUserIdCertification_mismatchedSelector_throwsInvalidKeyDataWithoutUnwrap()
        async throws
    {
        let signer = try await generateSigner(
            profile: .universal,
            name: "Mismatch Signer",
            email: "mismatch-signer@example.com"
        )
        let target = try generatedTarget(
            profile: .universal,
            name: "Mismatch Target",
            email: "mismatch-target@example.com"
        )
        let selectedUserId = try selectedUserId(for: target.publicKeyData)
        let mismatchedSelector = UserIdSelectionOption(
            occurrenceIndex: selectedUserId.occurrenceIndex,
            userIdData: selectedUserId.userIdData + Data("-mismatch".utf8),
            displayText: selectedUserId.displayText,
            isCurrentlyPrimary: selectedUserId.isCurrentlyPrimary,
            isCurrentlyRevoked: selectedUserId.isCurrentlyRevoked
        )
        let unwrapCountBefore = stack.mockSE.unwrapCallCount

        await XCTAssertThrowsErrorAsync(
            try await self.stack.certificateSignatureService.generateUserIdCertification(
                signerFingerprint: signer.fingerprint,
                targetCert: target.publicKeyData,
                selectedUserId: mismatchedSelector,
                certificationKind: .positive
            )
        ) { error in
            guard case .invalidKeyData = error as? CypherAirError else {
                return XCTFail("Expected invalidKeyData, got \(error)")
            }
        }

        XCTAssertEqual(stack.mockSE.unwrapCallCount, unwrapCountBefore)
    }

    func test_verifyUserIdBindingSignature_mismatchedSelector_throwsInvalidKeyData() async throws {
        let signer = try await generateSigner(
            profile: .universal,
            name: "Verify Mismatch Signer",
            email: "verify-mismatch-signer@example.com"
        )
        let target = try generatedTarget(
            profile: .universal,
            name: "Verify Mismatch Target",
            email: "verify-mismatch-target@example.com"
        )
        let selectedUserId = try selectedUserId(for: target.publicKeyData)
        let signature = try await stack.certificateSignatureService.generateUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: target.publicKeyData,
            selectedUserId: selectedUserId,
            certificationKind: .positive
        )
        let mismatchedSelector = UserIdSelectionOption(
            occurrenceIndex: selectedUserId.occurrenceIndex,
            userIdData: selectedUserId.userIdData + Data("-mismatch".utf8),
            displayText: selectedUserId.displayText,
            isCurrentlyPrimary: selectedUserId.isCurrentlyPrimary,
            isCurrentlyRevoked: selectedUserId.isCurrentlyRevoked
        )

        await XCTAssertThrowsErrorAsync(
            try await self.stack.certificateSignatureService.verifyUserIdBindingSignature(
                signature: signature,
                targetCert: target.publicKeyData,
                selectedUserId: mismatchedSelector
            )
        ) { error in
            guard case .invalidKeyData = error as? CypherAirError else {
                return XCTFail("Expected invalidKeyData, got \(error)")
            }
        }
    }

    func test_candidateSignerCertificates_preservesContactThenOwnMultiplicity() async throws {
        let signer = try await generateSigner(
            profile: .universal,
            name: "Multiplicity Signer",
            email: "multiplicity-signer@example.com"
        )
        _ = try stack.contactService.addContact(publicKeyData: signer.publicKeyData)

        let candidates = stack.certificateSignatureService.candidateSignerCertificates()

        XCTAssertEqual(candidates.count, 2)
        XCTAssertEqual(candidates[0], signer.publicKeyData)
        XCTAssertEqual(candidates[1], signer.publicKeyData)
    }

    func test_resolveSignerIdentity_unknownFingerprint_returnsUnknownSource() {
        let identity = stack.certificateSignatureService.resolveSignerIdentity(
            primaryFingerprint: "0123456789abcdef0123456789abcdef01234567"
        )

        XCTAssertEqual(identity?.source, .unknown)
        XCTAssertEqual(identity?.shortKeyId, "89abcdef01234567")
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure @escaping () async throws -> T,
    _ errorHandler: @escaping (Error) -> Void
) async {
    do {
        _ = try await expression()
        XCTFail("Expected error to be thrown")
    } catch {
        errorHandler(error)
    }
}
