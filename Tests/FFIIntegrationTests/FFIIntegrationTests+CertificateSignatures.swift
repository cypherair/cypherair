import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    // MARK: - Certificate Signature FFI

    func test_certificateSignature_directKeyFixture_smokeAcrossFFI() throws {
        let target = try loadFixture("ffi_direct_key_target")
        let signature = try loadArmoredFixture("ffi_direct_key_signature", ext: "sig")
        let targetInfo = try engine.parseKeyInfo(keyData: target)

        let result = try engine.verifyDirectKeySignature(
            signature: signature,
            targetCert: target,
            candidateSigners: [target]
        )

        XCTAssertEqual(result.status, .valid)
        XCTAssertNil(result.certificationKind)
        XCTAssertEqual(result.signerPrimaryFingerprint, targetInfo.fingerprint)
        XCTAssertNil(result.signingKeyFingerprint)
    }

    func test_certificateSignature_directKeyWrongTarget_returnsInvalidNotError() throws {
        let target = try loadFixture("ffi_direct_key_target")
        let signature = try loadArmoredFixture("ffi_direct_key_signature", ext: "sig")
        let wrongTarget = try engine.generateKey(
            name: "Wrong Direct Target",
            email: "wrong-direct@example.com",
            expirySeconds: nil,
            profile: .universal
        )

        let result = try engine.verifyDirectKeySignature(
            signature: signature,
            targetCert: wrongTarget.publicKeyData,
            candidateSigners: [target]
        )

        XCTAssertEqual(result.status, .invalid)
        XCTAssertNil(result.certificationKind)
        XCTAssertNil(result.signerPrimaryFingerprint)
        XCTAssertNil(result.signingKeyFingerprint)
    }

    func test_certificateSignature_directKeyMissingSigner_returnsSignerMissingAcrossFFI() throws {
        let target = try loadFixture("ffi_direct_key_target")
        let signature = try loadArmoredFixture("ffi_direct_key_signature", ext: "sig")

        let result = try engine.verifyDirectKeySignature(
            signature: signature,
            targetCert: target,
            candidateSigners: []
        )

        XCTAssertEqual(result.status, .signerMissing)
        XCTAssertNil(result.certificationKind)
        XCTAssertNil(result.signerPrimaryFingerprint)
        XCTAssertNil(result.signingKeyFingerprint)
    }

    func test_certificateSignature_wrongTypeBoundary_throwsCorruptData() throws {
        let target = try loadFixture("ffi_cert_binding_target")
        let signature = try loadArmoredFixture("ffi_cert_binding_missing_issuer_positive", ext: "sig")

        XCTAssertThrowsError(
            try engine.verifyDirectKeySignature(
                signature: signature,
                targetCert: target,
                candidateSigners: [target]
            )
        ) { error in
            guard case .CorruptData = error as? PgpError else {
                return XCTFail("Expected CorruptData, got \(error)")
            }
        }
    }

    func test_certificateSignature_userIdCertificationPersona_roundTripPreservesKindAcrossFFI() throws {
        let signer = try engine.generateKey(
            name: "FFI Persona Signer",
            email: "ffi-persona-signer@example.com",
            expirySeconds: nil,
            profile: .advanced
        )
        let target = try engine.generateKey(
            name: "FFI Persona Target",
            email: "ffi-persona-target@example.com",
            expirySeconds: nil,
            profile: .advanced
        )
        let selector = try userIdSelector(for: target.publicKeyData)

        let signature = try engine.generateUserIdCertificationBySelector(
            signerSecretCert: signer.certData,
            targetCert: target.publicKeyData,
            userIdSelector: selector,
            certificationKind: .persona
        )
        let result = try engine.verifyUserIdBindingSignatureBySelector(
            signature: signature,
            targetCert: target.publicKeyData,
            userIdSelector: selector,
            candidateSigners: [signer.publicKeyData]
        )

        XCTAssertEqual(result.status, .valid)
        XCTAssertEqual(result.certificationKind, .persona)
        XCTAssertEqual(result.signerPrimaryFingerprint, signer.fingerprint)
        XCTAssertNil(result.signingKeyFingerprint)
    }

    func test_certificateSignature_userIdBindingWrongTargetWithMatchingUserId_returnsInvalidAcrossFFI()
        throws
    {
        let signer = try engine.generateKey(
            name: "FFI Invalid Signer",
            email: "ffi-invalid-signer@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let target = try engine.generateKey(
            name: "Shared Identity",
            email: "shared-identity@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let wrongTarget = try engine.generateKey(
            name: "Shared Identity",
            email: "shared-identity@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let targetSelector = try userIdSelector(for: target.publicKeyData)
        let wrongTargetSelector = try userIdSelector(for: wrongTarget.publicKeyData)
        XCTAssertEqual(targetSelector.userIdData, wrongTargetSelector.userIdData)

        let signature = try engine.generateUserIdCertificationBySelector(
            signerSecretCert: signer.certData,
            targetCert: target.publicKeyData,
            userIdSelector: targetSelector,
            certificationKind: .positive
        )
        let result = try engine.verifyUserIdBindingSignatureBySelector(
            signature: signature,
            targetCert: wrongTarget.publicKeyData,
            userIdSelector: wrongTargetSelector,
            candidateSigners: [signer.publicKeyData]
        )

        XCTAssertEqual(result.status, .invalid)
        XCTAssertEqual(result.certificationKind, .positive)
        XCTAssertNil(result.signerPrimaryFingerprint)
        XCTAssertNil(result.signingKeyFingerprint)
    }

    func test_certificateSignature_userIdBindingFixtureFallbackSubkey_returnsExpectedFingerprints() throws {
        let signer = try loadFixture("ffi_cert_binding_subkey_signer")
        let target = try loadFixture("ffi_cert_binding_target")
        let signature = try loadArmoredFixture("ffi_cert_binding_missing_issuer_positive", ext: "sig")
        let expectedSubkeyFingerprint = try FixtureLoader.loadString(
            "ffi_cert_binding_subkey_fingerprint",
            ext: "txt"
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        let signerInfo = try engine.parseKeyInfo(keyData: signer)
        let selector = try userIdSelector(for: target)

        let result = try engine.verifyUserIdBindingSignatureBySelector(
            signature: signature,
            targetCert: target,
            userIdSelector: selector,
            candidateSigners: [signer]
        )

        XCTAssertEqual(result.status, .valid)
        XCTAssertEqual(result.certificationKind, .positive)
        XCTAssertEqual(result.signerPrimaryFingerprint, signerInfo.fingerprint)
        XCTAssertEqual(result.signingKeyFingerprint, expectedSubkeyFingerprint)
    }

    func test_certificateSignature_userIdBindingSignerMissing_clearsFingerprintsAcrossFFI() throws {
        let signer = try engine.generateKey(
            name: "FFI Missing Signer",
            email: "ffi-missing-signer@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let target = try engine.generateKey(
            name: "FFI Missing Target",
            email: "ffi-missing-target@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let selector = try userIdSelector(for: target.publicKeyData)

        let signature = try engine.generateUserIdCertificationBySelector(
            signerSecretCert: signer.certData,
            targetCert: target.publicKeyData,
            userIdSelector: selector,
            certificationKind: .positive
        )
        let result = try engine.verifyUserIdBindingSignatureBySelector(
            signature: signature,
            targetCert: target.publicKeyData,
            userIdSelector: selector,
            candidateSigners: []
        )

        XCTAssertEqual(result.status, .signerMissing)
        XCTAssertEqual(result.certificationKind, .positive)
        XCTAssertNil(result.signerPrimaryFingerprint)
        XCTAssertNil(result.signingKeyFingerprint)
    }

    func test_certificateSignature_userIdCertificationBySelector_roundTripAcrossFFI() throws {
        let signer = try engine.generateKey(
            name: "FFI Selector Signer",
            email: "ffi-selector-signer@example.com",
            expirySeconds: nil,
            profile: .advanced
        )
        let target = try engine.generateKey(
            name: "FFI Selector Target",
            email: "ffi-selector-target@example.com",
            expirySeconds: nil,
            profile: .advanced
        )
        let discovered = try engine.discoverCertificateSelectors(certData: target.publicKeyData)
        let selector = selectorInput(
            userIdData: discovered.userIds[0].userIdData,
            occurrenceIndex: discovered.userIds[0].occurrenceIndex
        )

        let signature = try engine.generateUserIdCertificationBySelector(
            signerSecretCert: signer.certData,
            targetCert: target.publicKeyData,
            userIdSelector: selector,
            certificationKind: .persona
        )
        let result = try engine.verifyUserIdBindingSignatureBySelector(
            signature: signature,
            targetCert: target.publicKeyData,
            userIdSelector: selector,
            candidateSigners: [signer.publicKeyData]
        )

        XCTAssertEqual(result.status, .valid)
        XCTAssertEqual(result.certificationKind, .persona)
        XCTAssertEqual(result.signerPrimaryFingerprint, signer.fingerprint)
    }

    func test_certificateSignature_userIdBindingBySelector_duplicateFixtureAcceptsSecondOccurrence()
        throws
    {
        let signer = try engine.generateKey(
            name: "FFI Duplicate Selector Signer",
            email: "ffi-duplicate-selector-signer@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let target = try loadFixture("selector_duplicate_userid_second_revoked_secret")
        let discovered = try engine.discoverCertificateSelectors(certData: target)
        let selector = selectorInput(
            userIdData: discovered.userIds[1].userIdData,
            occurrenceIndex: discovered.userIds[1].occurrenceIndex
        )

        let signature = try engine.generateUserIdCertificationBySelector(
            signerSecretCert: signer.certData,
            targetCert: target,
            userIdSelector: selector,
            certificationKind: .positive
        )
        let result = try engine.verifyUserIdBindingSignatureBySelector(
            signature: signature,
            targetCert: target,
            userIdSelector: selector,
            candidateSigners: [signer.publicKeyData]
        )

        XCTAssertEqual(result.status, .valid)
        XCTAssertEqual(result.certificationKind, .positive)
    }

    func test_certificateSignature_userIdBindingBySelector_outOfRange_throwsInvalidKeyData() throws {
        let signer = try engine.generateKey(
            name: "FFI Selector Range Signer",
            email: "ffi-selector-range-signer@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let target = try engine.generateKey(
            name: "FFI Selector Range Target",
            email: "ffi-selector-range-target@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let discovered = try engine.discoverCertificateSelectors(certData: target.publicKeyData)
        let selector = selectorInput(
            userIdData: discovered.userIds[0].userIdData,
            occurrenceIndex: discovered.userIds[0].occurrenceIndex
        )
        let signature = try engine.generateUserIdCertificationBySelector(
            signerSecretCert: signer.certData,
            targetCert: target.publicKeyData,
            userIdSelector: selector,
            certificationKind: .positive
        )

        XCTAssertThrowsError(
            try engine.verifyUserIdBindingSignatureBySelector(
                signature: signature,
                targetCert: target.publicKeyData,
                userIdSelector: selectorInput(
                    userIdData: discovered.userIds[0].userIdData,
                    occurrenceIndex: 99
                ),
                candidateSigners: [signer.publicKeyData]
            )
        ) { error in
            guard case .InvalidKeyData = error as? PgpError else {
                return XCTFail("Expected InvalidKeyData, got \(error)")
            }
        }
    }

    func test_certificateSignature_userIdBindingBySelector_bytesMismatch_throwsInvalidKeyData()
        throws
    {
        let signer = try engine.generateKey(
            name: "FFI Selector Mismatch Signer",
            email: "ffi-selector-mismatch-signer@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let target = try engine.generateKey(
            name: "FFI Selector Mismatch Target",
            email: "ffi-selector-mismatch-target@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let discovered = try engine.discoverCertificateSelectors(certData: target.publicKeyData)
        let selector = selectorInput(
            userIdData: discovered.userIds[0].userIdData,
            occurrenceIndex: discovered.userIds[0].occurrenceIndex
        )
        let signature = try engine.generateUserIdCertificationBySelector(
            signerSecretCert: signer.certData,
            targetCert: target.publicKeyData,
            userIdSelector: selector,
            certificationKind: .positive
        )
        let mismatchedData = discovered.userIds[0].userIdData + Data("-mismatch".utf8)

        XCTAssertThrowsError(
            try engine.verifyUserIdBindingSignatureBySelector(
                signature: signature,
                targetCert: target.publicKeyData,
                userIdSelector: selectorInput(
                    userIdData: mismatchedData,
                    occurrenceIndex: discovered.userIds[0].occurrenceIndex
                ),
                candidateSigners: [signer.publicKeyData]
            )
        ) { error in
            guard case .InvalidKeyData = error as? PgpError else {
                return XCTFail("Expected InvalidKeyData, got \(error)")
            }
        }
    }
}
