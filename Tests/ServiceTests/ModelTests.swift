import XCTest
import SwiftUI
@testable import CypherAir

/// Tests for model types: CypherAirError, Contact, PGPKeyIdentity,
/// PGPKeyProfile, and SignatureVerification.
final class ModelTests: XCTestCase {

    // MARK: - PGPErrorMapper

    func test_pgpErrorMapper_aeadMapped() {
        let error = PGPErrorMapper.map(.AeadAuthenticationFailed)
        if case .aeadAuthenticationFailed = error {
            // Expected
        } else {
            XCTFail("Expected .aeadAuthenticationFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_noMatchingKeyMapped() {
        let error = PGPErrorMapper.map(.NoMatchingKey)
        if case .noMatchingKey = error {
            // Expected
        } else {
            XCTFail("Expected .noMatchingKey, got \(error)")
        }
    }

    func test_pgpErrorMapper_recipientMatchingOnlyNoMatchingKeyMapsToNoMatchingKey() {
        let error = PGPErrorMapper.mapRecipientMatching(PgpError.NoMatchingKey)
        if case .noMatchingKey = error {
            // Expected
        } else {
            XCTFail("Expected .noMatchingKey, got \(error)")
        }
    }

    func test_pgpErrorMapper_recipientMatchingPreservesFileIoError() {
        let error = PGPErrorMapper.mapRecipientMatching(
            PgpError.FileIoError(reason: "Cannot open file")
        )
        if case .fileIoError(let reason) = error {
            XCTAssertEqual(reason, "Cannot open file")
        } else {
            XCTFail("Expected .fileIoError, got \(error)")
        }
    }

    func test_pgpErrorMapper_recipientMatchingPreservesCancellation() {
        let error = PGPErrorMapper.mapRecipientMatching(PgpError.OperationCancelled)
        if case .operationCancelled = error {
            // Expected
        } else {
            XCTFail("Expected .operationCancelled, got \(error)")
        }
    }

    func test_pgpErrorMapper_recipientMatchingNonPGPErrorDoesNotBecomeNoMatchingKey() {
        let error = PGPErrorMapper.mapRecipientMatching(
            NSError(domain: "test", code: 7)
        )
        if case .internalError = error {
            // Expected
        } else {
            XCTFail("Expected .internalError, got \(error)")
        }
    }

    func test_pgpErrorMapper_wrongPassphraseMapped() {
        let error = PGPErrorMapper.map(.WrongPassphrase)
        if case .wrongPassphrase = error {
            // Expected
        } else {
            XCTFail("Expected .wrongPassphrase, got \(error)")
        }
    }

    func test_pgpErrorMapper_unsupportedAlgorithmMapped() {
        let error = PGPErrorMapper.map(.UnsupportedAlgorithm(algo: "RSA"))
        if case .unsupportedAlgorithm(let algo) = error {
            XCTAssertEqual(algo, "RSA")
        } else {
            XCTFail("Expected .unsupportedAlgorithm, got \(error)")
        }
    }

    func test_pgpErrorMapper_keyExpiredMapped() {
        let error = PGPErrorMapper.map(.KeyExpired)
        if case .keyExpired = error {
            // Expected
        } else {
            XCTFail("Expected .keyExpired, got \(error)")
        }
    }

    func test_pgpErrorMapper_badSignatureMapped() {
        let error = PGPErrorMapper.map(.BadSignature)
        if case .badSignature = error {
            // Expected
        } else {
            XCTFail("Expected .badSignature, got \(error)")
        }
    }

    func test_pgpErrorMapper_unknownSignerMapped() {
        let error = PGPErrorMapper.map(.UnknownSigner)
        if case .unknownSigner = error {
            // Expected
        } else {
            XCTFail("Expected .unknownSigner, got \(error)")
        }
    }

    func test_pgpErrorMapper_corruptDataMapped() {
        let error = PGPErrorMapper.map(.CorruptData(reason: "test damage"))
        if case .corruptData(let reason) = error {
            XCTAssertEqual(reason, "test damage")
        } else {
            XCTFail("Expected .corruptData, got \(error)")
        }
    }

    func test_pgpErrorMapper_invalidKeyDataMapped() {
        let error = PGPErrorMapper.map(.InvalidKeyData(reason: "not a key"))
        if case .invalidKeyData(let reason) = error {
            XCTAssertEqual(reason, "not a key")
        } else {
            XCTFail("Expected .invalidKeyData, got \(error)")
        }
    }

    func test_pgpErrorMapper_encryptionFailedMapped() {
        let error = PGPErrorMapper.map(.EncryptionFailed(reason: "no recipients"))
        if case .encryptionFailed(let reason) = error {
            XCTAssertEqual(reason, "no recipients")
        } else {
            XCTFail("Expected .encryptionFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_signingFailedMapped() {
        let error = PGPErrorMapper.map(.SigningFailed(reason: "invalid key"))
        if case .signingFailed(let reason) = error {
            XCTAssertEqual(reason, "invalid key")
        } else {
            XCTFail("Expected .signingFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_externalP256SigningFailureMapped() {
        let error = PGPErrorMapper.map(
            .ExternalP256SigningFailed(category: .localAuthenticationFailed)
        )
        if case .keyOperationUnavailable(let category) = error {
            XCTAssertEqual(category, .localAuthenticationFailed)
        } else {
            XCTFail("Expected .keyOperationUnavailable, got \(error)")
        }
    }

    func test_pgpErrorMapper_externalCompositeSigningFailureMapped() {
        let error = PGPErrorMapper.map(
            .ExternalCompositeSigningFailed(category: .classicalComponentFailed)
        )
        if case .keyOperationUnavailable(let category) = error {
            XCTAssertEqual(category, .classicalComponentFailed)
        } else {
            XCTFail("Expected .keyOperationUnavailable, got \(error)")
        }
    }

    func test_pgpErrorMapper_externalCompositeKeyAgreementFailureMapped() {
        let error = PGPErrorMapper.map(
            .ExternalCompositeKeyAgreementFailed(category: .localAuthenticationCancelled)
        )
        if case .keyOperationUnavailable(let category) = error {
            XCTAssertEqual(category, .localAuthenticationCancelled)
        } else {
            XCTFail("Expected .keyOperationUnavailable, got \(error)")
        }
    }

    func test_pgpErrorMapper_armorErrorMapped() {
        let error = PGPErrorMapper.map(.ArmorError(reason: "bad format"))
        if case .armorError(let reason) = error {
            XCTAssertEqual(reason, "bad format")
        } else {
            XCTFail("Expected .armorError, got \(error)")
        }
    }

    func test_pgpErrorMapper_integrityCheckFailedMapped() {
        let error = PGPErrorMapper.map(.IntegrityCheckFailed)
        if case .integrityCheckFailed = error {
            // Expected
        } else {
            XCTFail("Expected .integrityCheckFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_argon2idMemoryExceededMapped() {
        let error = PGPErrorMapper.map(.Argon2idMemoryExceeded(requiredMb: 512))
        if case .argon2idMemoryExceeded(let requiredMb) = error {
            XCTAssertEqual(requiredMb, 512)
        } else {
            XCTFail("Expected .argon2idMemoryExceeded, got \(error)")
        }
    }

    func test_pgpErrorMapper_revocationErrorMapped() {
        let error = PGPErrorMapper.map(.RevocationError(reason: "bad cert"))
        if case .revocationError(let reason) = error {
            XCTAssertEqual(reason, "bad cert")
        } else {
            XCTFail("Expected .revocationError, got \(error)")
        }
    }

    func test_pgpErrorMapper_keyGenerationFailedMapped() {
        let error = PGPErrorMapper.map(.KeyGenerationFailed(reason: "rng failure"))
        if case .keyGenerationFailed(let reason) = error {
            XCTAssertEqual(reason, "rng failure")
        } else {
            XCTFail("Expected .keyGenerationFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_s2kErrorMapped() {
        let error = PGPErrorMapper.map(.S2kError(reason: "unsupported mode"))
        if case .s2kError(let reason) = error {
            XCTAssertEqual(reason, "unsupported mode")
        } else {
            XCTFail("Expected .s2kError, got \(error)")
        }
    }

    func test_pgpErrorMapper_internalErrorMapped() {
        let error = PGPErrorMapper.map(.InternalError(reason: "unexpected state"))
        if case .internalError(let reason) = error {
            XCTAssertEqual(reason, "unexpected state")
        } else {
            XCTFail("Expected .internalError, got \(error)")
        }
    }

    func test_cypherAirError_errorDescription_notNil() {
        // Every error case should produce a non-nil errorDescription
        let errors: [CypherAirError] = [
            .aeadAuthenticationFailed,
            .noMatchingKey,
            .unsupportedAlgorithm(algo: "RSA"),
            .keyExpired,
            .badSignature,
            .unknownSigner,
            .corruptData(reason: "test"),
            .wrongPassphrase,
            .invalidKeyData(reason: "test"),
            .encryptionFailed(reason: "test"),
            .signingFailed(reason: "test"),
            .armorError(reason: "test"),
            .integrityCheckFailed,
            .argon2idMemoryExceeded(requiredMb: 512),
            .revocationError(reason: "test"),
            .keyGenerationFailed(reason: "test"),
            .s2kError(reason: "test"),
            .internalError(reason: "test"),
            .secureEnclaveUnavailable,
            .authenticationFailed,
            .authenticationCancelled,
            .keychainError("test"),
            .invalidQRCode,
            .unsupportedQRVersion,
            .contactImportRequiresPublicCertificate,
            .noKeySelected,
            .noRecipientsSelected,
            .biometricsUnavailable,
            .fileIoError(reason: "test io error"),
            .operationCancelled,
            .keyOperationUnavailable(category: .operationUnsupportedForCustody),
            .insufficientDiskSpace(fileSizeMB: 50, requiredMB: 100, availableMB: 30),
            .duplicateKey,
            .keyTooLargeForQr,
            .contactsUnavailable(.locked),
            .contactImportConfirmationStale,
            .contactImportConfirmationAlreadyPending,
        ]

        for error in errors {
            XCTAssertNotNil(error.errorDescription,
                            "\(error) should have a non-nil errorDescription")
            XCTAssertFalse(error.errorDescription!.isEmpty,
                           "\(error) should have a non-empty errorDescription")
        }
    }

    // MARK: - ContactKeyRecord: Display Name

    func test_contactKeyRecord_displayName_withNameAndEmail_extractsName() {
        let keyRecord = makeContactKeyRecord(userId: "Alice <alice@example.com>")
        XCTAssertEqual(keyRecord.displayName, "Alice")
    }

    func test_contactKeyRecord_displayName_noAngleBrackets_returnsUserId() {
        let keyRecord = makeContactKeyRecord(userId: "just-a-name")
        XCTAssertEqual(keyRecord.displayName, "just-a-name")
    }

    // MARK: - ContactKeyRecord: Email Extraction

    func test_contactKeyRecord_email_extractsFromUserId() {
        let keyRecord = makeContactKeyRecord(userId: "Alice <alice@example.com>")
        XCTAssertEqual(keyRecord.email, "alice@example.com")
    }

    func test_contactKeyRecord_email_noAngleBrackets_returnsNil() {
        let keyRecord = makeContactKeyRecord(userId: "Alice")
        XCTAssertNil(keyRecord.email)
    }

    func test_contactKeyRecord_email_nilUserId_returnsNil() {
        let keyRecord = makeContactKeyRecord(userId: nil)
        XCTAssertNil(keyRecord.email)
    }

    // MARK: - ContactKeyRecord: canEncryptTo

    func test_contactKeyRecord_canEncryptTo_validKey_returnsTrue() {
        let keyRecord = makeContactKeyRecord(hasEncryptionSubkey: true, isRevoked: false, isExpired: false)
        XCTAssertTrue(keyRecord.canEncryptTo)
    }

    func test_contactKeyRecord_canEncryptTo_expired_returnsFalse() {
        let keyRecord = makeContactKeyRecord(hasEncryptionSubkey: true, isRevoked: false, isExpired: true)
        XCTAssertFalse(keyRecord.canEncryptTo)
    }

    func test_contactKeyRecord_canEncryptTo_revoked_returnsFalse() {
        let keyRecord = makeContactKeyRecord(hasEncryptionSubkey: true, isRevoked: true, isExpired: false)
        XCTAssertFalse(keyRecord.canEncryptTo)
    }

    func test_contactKeyRecord_canEncryptTo_noSubkey_returnsFalse() {
        let keyRecord = makeContactKeyRecord(hasEncryptionSubkey: false, isRevoked: false, isExpired: false)
        XCTAssertFalse(keyRecord.canEncryptTo)
    }

    // MARK: - PGPKeyIdentity: Computed Properties

    func test_pgpKeyIdentity_shortKeyId_returnsLast16Chars() {
        let identity = makeIdentity(fingerprint: "abcdef1234567890abcdef1234567890abcdef12")
        XCTAssertEqual(identity.shortKeyId, "34567890abcdef12")
    }

    func test_identityPresentation_fingerprintGroups_groupsInChunksOfFour() {
        XCTAssertEqual(
            IdentityPresentation.fingerprintGroups("abcdef1234567890"),
            ["abcd", "ef12", "3456", "7890"]
        )
    }

    func test_identityPresentation_fingerprintGroups_preservesShortFinalGroup() {
        XCTAssertEqual(
            IdentityPresentation.fingerprintGroups("abcdef12345"),
            ["abcd", "ef12", "345"]
        )
    }

    func test_identityPresentation_fingerprintAccessibilityGroupLabel_spellsCharacters() {
        XCTAssertEqual(
            IdentityPresentation.fingerprintAccessibilityGroupLabel("ab12"),
            "a b 1 2"
        )
    }

    func test_identityPresentation_parsedDisplayName_nilUserId_returnsNil() {
        XCTAssertNil(IdentityPresentation.parsedDisplayName(from: nil))
    }

    func test_identityDisplayPresentation_nilUserId_returnsLocalizedFallback() {
        XCTAssertEqual(
            IdentityDisplayPresentation.displayName(from: nil),
            String(localized: "contact.unknown", defaultValue: "Unknown")
        )
    }

    func test_identityDisplayPresentation_emptyDisplayName_returnsLocalizedFallback() {
        XCTAssertEqual(
            IdentityDisplayPresentation.displayName(""),
            String(localized: "contact.unknown", defaultValue: "Unknown")
        )
    }

    func test_identityDisplayPresentation_nonFallbackDisplayName_isUnchanged() {
        XCTAssertEqual(IdentityDisplayPresentation.displayName("Alice"), "Alice")
    }

    // MARK: - PGPKeyProfile

    func test_pgpKeyProfile_decode_historicalRawValues() throws {
        let decoder = JSONDecoder()

        XCTAssertEqual(
            try decoder.decode(PGPKeyProfile.self, from: Data(#""universal""#.utf8)),
            .universal
        )
        XCTAssertEqual(
            try decoder.decode(PGPKeyProfile.self, from: Data(#""advanced""#.utf8)),
            .advanced
        )
    }

    func test_pgpKeyProfile_encodeDecode_universal_roundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let profile = PGPKeyProfile.universal
        let data = try encoder.encode(profile)
        let decoded = try decoder.decode(PGPKeyProfile.self, from: data)

        XCTAssertEqual(decoded, .universal)
    }

    func test_pgpKeyProfile_encodeDecode_advanced_roundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let profile = PGPKeyProfile.advanced
        let data = try encoder.encode(profile)
        let decoded = try decoder.decode(PGPKeyProfile.self, from: data)

        XCTAssertEqual(decoded, .advanced)
    }

    func test_pgpKeyProfile_decode_unknownValue_throwsError() {
        let decoder = JSONDecoder()
        let invalidJSON = Data("\"quantum\"".utf8)

        XCTAssertThrowsError(try decoder.decode(PGPKeyProfile.self, from: invalidJSON)) { error in
            guard case DecodingError.dataCorrupted = error else {
                XCTFail("Expected DecodingError.dataCorrupted, got \(error)")
                return
            }
        }
    }

    func test_pgpKeyProfile_successorConfigurationMappings_preserveSoftwareCustody() {
        let universal = PGPKeyProfile.universal.openPGPConfiguration
        XCTAssertEqual(universal.identity, .compatibleSoftwareV4)
        XCTAssertEqual(universal.keyVersion, 4)
        XCTAssertEqual(universal.algorithmSuite, .ed25519X25519)
        XCTAssertEqual(universal.compatibilityTarget, .gnupgOriented)
        XCTAssertEqual(universal.messageFormatPreference, .seipdV1)
        XCTAssertEqual(universal.softwareExportProtection, .iteratedSaltedS2K)

        let modern = PGPKeyProfile.modern.openPGPConfiguration
        XCTAssertEqual(modern.identity, .modernSoftwareV6)
        XCTAssertEqual(modern.keyVersion, 6)
        XCTAssertEqual(modern.algorithmSuite, .ed25519X25519)
        XCTAssertEqual(modern.compatibilityTarget, .rfc9580Oriented)
        XCTAssertEqual(modern.messageFormatPreference, .seipdV2Aead)
        XCTAssertEqual(modern.softwareExportProtection, .argon2idS2K)

        let advanced = PGPKeyProfile.advanced.openPGPConfiguration
        XCTAssertEqual(advanced.identity, .modernHighSoftwareV6)
        XCTAssertEqual(advanced.keyVersion, 6)
        XCTAssertEqual(advanced.algorithmSuite, .ed448X448)
        XCTAssertEqual(advanced.compatibilityTarget, .rfc9580Oriented)
        XCTAssertEqual(advanced.messageFormatPreference, .seipdV2Aead)
        XCTAssertEqual(advanced.softwareExportProtection, .argon2idS2K)

        let postQuantumHigh = PGPKeyProfile.postQuantumHigh.openPGPConfiguration
        XCTAssertEqual(postQuantumHigh.identity, .postQuantumHighSoftwareV6)
        XCTAssertEqual(postQuantumHigh.keyVersion, 6)
        XCTAssertEqual(postQuantumHigh.algorithmSuite, .mldsa87Ed448Mlkem1024X448)
        XCTAssertEqual(postQuantumHigh.compatibilityTarget, .rfc9580Oriented)
        XCTAssertEqual(postQuantumHigh.messageFormatPreference, .seipdV2Aead)
        XCTAssertEqual(postQuantumHigh.softwareExportProtection, .argon2idS2K)
    }

    func test_secureEnclaveVocabulary_isRepresentableButNotSelectedByCurrentProfiles() {
        let compatibleP256 = PGPKeyConfiguration.compatibleP256V4
        XCTAssertEqual(compatibleP256.identity, .compatibleP256V4)
        XCTAssertEqual(compatibleP256.keyVersion, 4)
        XCTAssertEqual(compatibleP256.algorithmSuite, .p256)
        XCTAssertEqual(compatibleP256.compatibilityTarget, .gnupgOriented)
        XCTAssertEqual(compatibleP256.softwareExportProtection, .notAvailable)

        let modernP256 = PGPKeyConfiguration.modernP256V6
        XCTAssertEqual(modernP256.identity, .modernP256V6)
        XCTAssertEqual(modernP256.keyVersion, 6)
        XCTAssertEqual(modernP256.algorithmSuite, .p256)
        XCTAssertEqual(modernP256.messageFormatPreference, .seipdV2Aead)
        XCTAssertEqual(modernP256.softwareExportProtection, .notAvailable)

        for profile in PGPKeyProfile.allCases {
            XCTAssertNotEqual(profile.openPGPConfiguration, .compatibleP256V4)
            XCTAssertNotEqual(profile.openPGPConfiguration, .modernP256V6)
        }

        XCTAssertEqual(
            Set(PGPPrivateOperationRole.allCases),
            [.signing, .keyAgreement]
        )
        XCTAssertEqual(
            Set(PGPPrivateOperationKind.allCases),
            [.sign, .decrypt, .certify, .revoke, .modifyExpiry]
        )
        XCTAssertEqual(PGPPrivateOperationKind.sign.keyOperationKind, .sign)
        XCTAssertEqual(PGPPrivateOperationKind.decrypt.keyOperationKind, .decrypt)
        XCTAssertEqual(PGPPrivateOperationKind.certify.keyOperationKind, .certify)
        XCTAssertEqual(PGPPrivateOperationKind.revoke.keyOperationKind, .revoke)
        XCTAssertEqual(PGPPrivateOperationKind.modifyExpiry.keyOperationKind, .modifyExpiry)
        XCTAssertEqual(PGPPrivateOperationKind.sign.requiredRole, .signing)
        XCTAssertEqual(PGPPrivateOperationKind.certify.requiredRole, .signing)
        XCTAssertEqual(PGPPrivateOperationKind.revoke.requiredRole, .signing)
        XCTAssertEqual(PGPPrivateOperationKind.modifyExpiry.requiredRole, .signing)
        XCTAssertEqual(PGPPrivateOperationKind.decrypt.requiredRole, .keyAgreement)
        XCTAssertTrue(PGPKeyOperationKind.allCases.contains(.exportPrivateMaterial))
        XCTAssertEqual(PGPKeyOperationSupport.notImplemented.rawValue, "notImplemented")
    }

    func test_pgpKeyOperationFailureCategory_rawValuesCoverSecureEnclaveTaxonomy() throws {
        let expected: [PGPKeyOperationFailureCategory] = [
            .invalidConfigurationCustody,
            .operationUnsupportedForCustody,
            .operationNotImplementedForCustody,
            .operationUnavailableByPolicy,
            .hardwareUnavailable,
            .localAuthenticationRequired,
            .localAuthenticationCancelled,
            .localAuthenticationFailed,
            .localAuthenticationUnavailable,
            .localAuthenticationLockedOut,
            .privateHandleMissing,
            .privateHandleInaccessible,
            .privateHandleUnauthorized,
            .privateOperationRoleMismatch,
            .handlePublicKeyBindingMismatch,
            .classicalComponentFailed,
            .metadataAssociationMismatch,
            .publicCertificateAssociationMismatch,
            .publicMaterialUnavailable,
            .revocationArtifactUnavailable,
            .externalOperationInvalidRequest,
            .externalOperationInvalidResponse,
            .externalOperationFailed,
            .openPGPSemanticFailure,
            .payloadAuthenticationFailure,
            .migrationOrRecoveryRequired,
            .prohibitedFallbackAttempted,
            .cleanupOrRollbackFailure,
        ]

        XCTAssertEqual(PGPKeyOperationFailureCategory.allCases, expected)
        XCTAssertEqual(
            expected.map(\.rawValue),
            [
                "invalidConfigurationCustody",
                "operationUnsupportedForCustody",
                "operationNotImplementedForCustody",
                "operationUnavailableByPolicy",
                "hardwareUnavailable",
                "localAuthenticationRequired",
                "localAuthenticationCancelled",
                "localAuthenticationFailed",
                "localAuthenticationUnavailable",
                "localAuthenticationLockedOut",
                "privateHandleMissing",
                "privateHandleInaccessible",
                "privateHandleUnauthorized",
                "privateOperationRoleMismatch",
                "handlePublicKeyBindingMismatch",
                "classicalComponentFailed",
                "metadataAssociationMismatch",
                "publicCertificateAssociationMismatch",
                "publicMaterialUnavailable",
                "revocationArtifactUnavailable",
                "externalOperationInvalidRequest",
                "externalOperationInvalidResponse",
                "externalOperationFailed",
                "openPGPSemanticFailure",
                "payloadAuthenticationFailure",
                "migrationOrRecoveryRequired",
                "prohibitedFallbackAttempted",
                "cleanupOrRollbackFailure",
            ]
        )

        let encoded = try JSONEncoder().encode(PGPKeyOperationFailureCategory.payloadAuthenticationFailure)
        let decoded = try JSONDecoder().decode(PGPKeyOperationFailureCategory.self, from: encoded)
        XCTAssertEqual(decoded, .payloadAuthenticationFailure)
    }

    func test_pgpKeyOperationResolution_factoriesSetSupportAndFailureCategory() throws {
        let supported = PGPKeyOperationResolution.supported
        XCTAssertEqual(supported.support, .supported)
        XCTAssertNil(supported.failureCategory)

        let unsupported = PGPKeyOperationResolution.unsupported(.invalidConfigurationCustody)
        XCTAssertEqual(unsupported.support, .unsupported)
        XCTAssertEqual(unsupported.failureCategory, .invalidConfigurationCustody)

        let notImplemented = PGPKeyOperationResolution.notImplemented(.operationNotImplementedForCustody)
        XCTAssertEqual(notImplemented.support, .notImplemented)
        XCTAssertEqual(notImplemented.failureCategory, .operationNotImplementedForCustody)

        let unavailable = PGPKeyOperationResolution.unavailable(.operationUnavailableByPolicy)
        XCTAssertEqual(unavailable.support, .unavailable)
        XCTAssertEqual(unavailable.failureCategory, .operationUnavailableByPolicy)

        let supportedObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(supported)) as? [String: Any]
        )
        XCTAssertEqual(Set(supportedObject.keys), ["support"])
        XCTAssertEqual(supportedObject["support"] as? String, "supported")
        XCTAssertNil(supportedObject["failureCategory"])

        let roundTrip = try JSONDecoder().decode(
            PGPKeyOperationResolution.self,
            from: JSONEncoder().encode(unavailable)
        )
        XCTAssertEqual(roundTrip, unavailable)
    }

    func test_pgpKeyOperationResolution_decodeRejectsInvalidSupportCategoryPairs() throws {
        let decoder = JSONDecoder()

        let supportedWithCategory = Data(
            """
            {
              "support": "supported",
              "failureCategory": "invalidConfigurationCustody"
            }
            """.utf8
        )
        XCTAssertThrowsError(
            try decoder.decode(PGPKeyOperationResolution.self, from: supportedWithCategory)
        )

        for support in ["unsupported", "notImplemented", "unavailable"] {
            let missingCategory = Data(
                """
                {
                  "support": "\(support)"
                }
                """.utf8
            )
            XCTAssertThrowsError(
                try decoder.decode(PGPKeyOperationResolution.self, from: missingCategory)
            )
        }
    }

    // MARK: - OpenPGPCertificationKind

    func test_openPGPCertificationKind_decode_historicalRawValues() throws {
        let decoder = JSONDecoder()

        let historicalValues: [(String, OpenPGPCertificationKind)] = [
            ("generic", .generic),
            ("persona", .persona),
            ("casual", .casual),
            ("positive", .positive),
        ]

        for (rawValue, expectedKind) in historicalValues {
            let decoded = try decoder.decode(
                OpenPGPCertificationKind.self,
                from: Data(#""\#(rawValue)""#.utf8)
            )
            XCTAssertEqual(decoded, expectedKind)
        }
    }

    func test_openPGPCertificationKind_encode_preservesHistoricalRawValues() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        for kind in OpenPGPCertificationKind.allCases {
            let data = try encoder.encode(kind)
            let rawValue = try decoder.decode(String.self, from: data)

            XCTAssertEqual(rawValue, kind.rawValue)
        }
    }

    // MARK: - SignatureVerification

    func test_signatureVerification_isWarning_forBad() {
        let verification = SignatureVerification(
            signerFingerprint: nil, verificationState: .invalid
        )
        XCTAssertTrue(verification.isWarning)
    }

    func test_signatureVerification_isWarning_forUnknown() {
        let verification = SignatureVerification(
            signerFingerprint: "abc", verificationState: .signerCertificateUnavailable
        )
        XCTAssertTrue(verification.isWarning)
    }

    func test_signatureVerification_isWarning_validIsFalse() {
        let verification = SignatureVerification(
            signerFingerprint: "abc", verificationState: .verified
        )
        XCTAssertFalse(verification.isWarning)
    }

    func test_signatureVerification_isWarning_notSignedIsFalse() {
        let verification = SignatureVerification(
            signerFingerprint: nil, verificationState: .notSigned
        )
        XCTAssertFalse(verification.isWarning)
    }

    func test_detailedSignatureVerification_missingCertificateMapsToUnavailableCertificate() {
        let entry = DetailedSignatureEntry(
            status: .unknownSigner,
            signerPrimaryFingerprint: nil
        )

        let detailed = PGPMessageResultMapper.fileVerifyDetailedResult(
            FileVerifyDetailedResult(
                summaryState: .signerCertificateUnavailable,
                summaryEntryIndex: 0,
                signatures: [entry]
            ),
            context: PGPMessageVerificationContext(
                verificationKeys: [],
                contactKeys: [],
                ownKeys: [],
                contactsAvailability: .availableProtectedDomain
            )
        )

        XCTAssertEqual(detailed.summaryState, .signerCertificateUnavailable)
        XCTAssertEqual(detailed.signatures[0].verificationState, .signerCertificateUnavailable)
        XCTAssertFalse(detailed.summaryVerification.requiresContactsContext)
        XCTAssertNil(detailed.summaryVerification.contactsUnavailableReason)
    }

    // MARK: - DetailedSignatureVerification.summaryVerification (no-entries row)

    func test_summaryVerification_notSigned_rendersNotSignedRow() {
        let detailed = DetailedSignatureVerification(summaryState: .notSigned, signatures: [])
        let summary = detailed.summaryVerification

        XCTAssertEqual(summary.verificationState, .notSigned)
        XCTAssertNil(summary.signerFingerprint)
        XCTAssertNil(summary.signerIdentity)
        XCTAssertEqual(summary.symbolName, "minus.circle")
        XCTAssertFalse(summary.isWarning)
    }

    func test_summaryVerification_emptySignaturesInvalid_rendersInvalidRowNotNotSigned() {
        // A malformed signed message whose verifier setup fails yields empty `signatures`
        // with an `.invalid` summary state. The no-entries row must surface "invalid", never
        // collapse to "not signed".
        let detailed = DetailedSignatureVerification(summaryState: .invalid, signatures: [])
        let summary = detailed.summaryVerification

        XCTAssertEqual(summary.verificationState, .invalid)
        XCTAssertEqual(summary.symbolName, "xmark.seal.fill")
        XCTAssertTrue(summary.isWarning)
    }

    func test_summaryVerification_emptySignaturesExpired_rendersExpiredRow() {
        let detailed = DetailedSignatureVerification(summaryState: .expired, signatures: [])
        let summary = detailed.summaryVerification

        XCTAssertEqual(summary.verificationState, .expired)
        XCTAssertEqual(summary.symbolName, "clock.badge.exclamationmark")
        XCTAssertTrue(summary.isWarning)
    }

    // MARK: - SignatureVerification: statusColor

    func test_signatureVerification_statusColor_validIsGreen() {
        let verification = SignatureVerification(
            signerFingerprint: nil, verificationState: .verified
        )
        XCTAssertEqual(verification.statusColor, .green)
    }

    func test_signatureVerification_statusColor_badIsRed() {
        let verification = SignatureVerification(
            signerFingerprint: nil, verificationState: .invalid
        )
        XCTAssertEqual(verification.statusColor, .red)
    }

    func test_signatureVerification_statusColor_notSignedIsSecondary() {
        let verification = SignatureVerification(
            signerFingerprint: nil, verificationState: .notSigned
        )
        XCTAssertEqual(verification.statusColor, .secondary)
    }

    func test_signatureVerification_signerIdentity_prefersVerifiedContact() {
        let contact = makeContactKeyRecord(
            fingerprint: "abcdef1234567890abcdef1234567890",
            userId: "Alice <alice@example.com>"
        )

        let identity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: contact.fingerprint,
            contactKeys: [contact],
            ownKeys: []
        )

        XCTAssertEqual(identity?.source, .contact)
        XCTAssertEqual(identity?.displayName, "Alice")
        XCTAssertEqual(identity?.secondaryText, "alice@example.com")
        XCTAssertTrue(identity?.isVerifiedContact == true)
    }

    func test_signatureVerification_signerIdentity_resolvesOwnKey() {
        let ownKey = makeIdentity(fingerprint: "1234567890abcdef1234567890abcdef")

        let identity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: ownKey.fingerprint,
            contactKeys: [],
            ownKeys: [ownKey]
        )

        XCTAssertEqual(identity?.source, .ownKey)
        XCTAssertEqual(identity?.displayName, "")
        XCTAssertEqual(identity?.presentationDisplayName, "Your Key")
        XCTAssertEqual(identity?.secondaryText, ownKey.userId)
    }

    func test_signatureVerification_signerIdentity_unknownFallback_keepsFingerprint() {
        let fingerprint = "fedcba0987654321fedcba0987654321"

        let identity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: fingerprint,
            contactKeys: [],
            ownKeys: []
        )

        XCTAssertEqual(identity?.source, .unknown)
        XCTAssertEqual(identity?.shortKeyId, "fedcba0987654321")
        XCTAssertEqual(identity?.fingerprint, fingerprint)
    }

    // MARK: - Protected Ordinary Settings

    func test_protectedOrdinarySettings_gracePeriod_validValuePersists() {
        let store = InMemoryOrdinarySettingsStore()
        let coordinator = makeLoadedProtectedOrdinarySettings(store: store)

        coordinator.setGracePeriod(60)

        let reloaded = makeLoadedProtectedOrdinarySettings(store: store)
        XCTAssertEqual(reloaded.snapshot?.gracePeriod, 60)
    }

    func test_protectedOrdinarySettings_gracePeriod_invalidValueClampsToDefault() {
        let coordinator = makeLoadedProtectedOrdinarySettings()

        coordinator.setGracePeriod(42)

        XCTAssertEqual(coordinator.snapshot?.gracePeriod, AuthPreferences.defaultGracePeriod)
    }

    func test_protectedOrdinarySettings_validGracePeriodValues_matchSettingsOptions() {
        let modelValues = Array(ProtectedOrdinarySettingsSnapshot.validGracePeriodValues).sorted()
        let settingsValues = SettingsGracePeriodPresentation.options.map(\.value).sorted()

        XCTAssertEqual(modelValues, [0, 60, 180, 300])
        XCTAssertEqual(settingsValues, modelValues)
        XCTAssertTrue(SettingsGracePeriodPresentation.options.allSatisfy { !$0.label.isEmpty })
    }

    func test_protectedOrdinarySettings_startsLockedWithoutReadingPersistence() {
        let persistence = SpyProtectedOrdinarySettingsPersistence(
            snapshot: .firstRunDefaults
        )

        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: persistence
        )

        XCTAssertNil(coordinator.gracePeriodForSession)
        XCTAssertNil(coordinator.hasCompletedOnboarding)
        XCTAssertNil(coordinator.encryptToSelf)
        XCTAssertEqual(persistence.loadCount, 0)
        XCTAssertEqual(persistence.saveCount, 0)
    }

    func test_protectedOrdinarySettings_loadsOnlyAfterUnlockedPostAuthenticationDomain() {
        let persistence = SpyProtectedOrdinarySettingsPersistence(
            snapshot: ProtectedOrdinarySettingsSnapshot(
                gracePeriod: 300,
                hasCompletedOnboarding: true,
                encryptToSelf: false,
                guidedTutorialCompletedVersion: GuidedTutorialVersion.current
            )
        )
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: persistence
        )

        coordinator.loadAfterAppAuthentication(
            availability: .available
        )

        XCTAssertEqual(coordinator.snapshot?.gracePeriod, 300)
        XCTAssertEqual(coordinator.snapshot?.hasCompletedOnboarding, true)
        XCTAssertEqual(coordinator.snapshot?.encryptToSelf, false)
        XCTAssertEqual(persistence.loadCount, 1)
    }

    func test_protectedOrdinarySettings_lockedPostAuthenticationDomainFailsClosed() {
        let persistence = SpyProtectedOrdinarySettingsPersistence(
            snapshot: .firstRunDefaults
        )
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: persistence
        )

        coordinator.loadAfterAppAuthentication(
            availability: .unavailable
        )

        XCTAssertNil(coordinator.snapshot)
        XCTAssertEqual(coordinator.state, .recoveryRequired)
        XCTAssertEqual(persistence.loadCount, 0)
        XCTAssertEqual(persistence.saveCount, 0)
    }

    func test_protectedOrdinarySettings_recoveryDoesNotReadPersistence() {
        let persistence = SpyProtectedOrdinarySettingsPersistence(
            snapshot: ProtectedOrdinarySettingsSnapshot(
                gracePeriod: 300,
                hasCompletedOnboarding: true,
                encryptToSelf: false,
                guidedTutorialCompletedVersion: GuidedTutorialVersion.current
            )
        )
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: persistence
        )

        coordinator.loadAfterAppAuthentication(
            availability: .unavailable
        )

        XCTAssertNil(coordinator.snapshot)
        XCTAssertEqual(coordinator.state, .recoveryRequired)
        XCTAssertEqual(persistence.loadCount, 0)
        XCTAssertEqual(persistence.saveCount, 0)
    }

    func test_appConfiguration_appSessionPolicy_defaultsToUserPresence() {
        let defaults = makeIsolatedDefaults()
        let config = AppConfiguration(defaults: defaults)

        XCTAssertEqual(config.appSessionAuthenticationPolicy, .userPresence)
    }

    func test_appConfiguration_appSessionPolicy_persistsBiometricsOnly() {
        let defaults = makeIsolatedDefaults()
        let config = AppConfiguration(defaults: defaults)
        config.appSessionAuthenticationPolicy = .biometricsOnly

        let reloaded = AppConfiguration(defaults: defaults)
        XCTAssertEqual(reloaded.appSessionAuthenticationPolicy, .biometricsOnly)
    }

    func test_protectedOrdinarySettings_guidedTutorial_defaultsToNeverCompleted() {
        let coordinator = makeLoadedProtectedOrdinarySettings()

        XCTAssertEqual(coordinator.snapshot?.guidedTutorialCompletedVersion, 0)
        XCTAssertEqual(coordinator.guidedTutorialCompletionState, .neverCompleted)
    }

    func test_protectedOrdinarySettings_guidedTutorial_currentVersionPersists() {
        let store = InMemoryOrdinarySettingsStore()
        let coordinator = makeLoadedProtectedOrdinarySettings(store: store)
        coordinator.markGuidedTutorialCompletedCurrentVersion()

        let reloaded = makeLoadedProtectedOrdinarySettings(store: store)
        XCTAssertEqual(reloaded.snapshot?.guidedTutorialCompletedVersion, GuidedTutorialVersion.current)
        XCTAssertEqual(reloaded.guidedTutorialCompletionState, .completedCurrentVersion)
    }

    func test_protectedOrdinarySettings_guidedTutorial_previousVersionIsRecognized() {
        var snapshot = ProtectedOrdinarySettingsSnapshot.firstRunDefaults
        snapshot.guidedTutorialCompletedVersion = GuidedTutorialVersion.current - 1

        let coordinator = makeLoadedProtectedOrdinarySettings(
            store: InMemoryOrdinarySettingsStore(snapshot: snapshot)
        )
        XCTAssertEqual(coordinator.guidedTutorialCompletionState, .completedPreviousVersion)
    }

    // MARK: - Factory Helpers

    private func makeContactKeyRecord(
        fingerprint: String = "abc123",
        userId: String? = "Test <test@example.com>",
        hasEncryptionSubkey: Bool = true,
        isRevoked: Bool = false,
        isExpired: Bool = false
    ) -> ContactKeyRecord {
        ContactKeyRecord(
            keyId: fingerprint,
            contactId: fingerprint,
            fingerprint: fingerprint,
            primaryUserId: userId,
            displayName: IdentityPresentation.parsedDisplayName(from: userId) ?? "",
            email: IdentityPresentation.email(from: userId),
            keyVersion: 4,
            profile: .universal,
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519",
            hasEncryptionSubkey: hasEncryptionSubkey,
            isRevoked: isRevoked,
            isExpired: isExpired,
            manualVerificationState: .verified,
            usageState: .preferred,
            certificationProjection: .empty,
            certificationArtifactIds: [],
            publicKeyData: Data(),
            createdAt: Date(),
            updatedAt: Date()
        )
    }

    private func makeIdentity(
        fingerprint: String = "abc123"
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: 4,
            userId: "Test",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data(),
            revocationCert: Data(),
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519",
            expiryDate: nil,
            openPGPConfigurationIdentity: .compatibleSoftwareV4,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
    }

    private func makeIsolatedDefaults() -> UserDefaults {
        let suiteName = "com.cypherair.tests.model.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }

    private func makeLoadedProtectedOrdinarySettings(
        store: InMemoryOrdinarySettingsStore = InMemoryOrdinarySettingsStore()
    ) -> ProtectedOrdinarySettingsCoordinator {
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: store
        )
        coordinator.loadForAuthenticatedTestBypass()
        return coordinator
    }

    private final class SpyProtectedOrdinarySettingsPersistence: ProtectedOrdinarySettingsPersistence {
        private let storedSnapshot: ProtectedOrdinarySettingsSnapshot
        private(set) var loadCount = 0
        private(set) var saveCount = 0

        init(snapshot: ProtectedOrdinarySettingsSnapshot) {
            self.storedSnapshot = snapshot
        }

        func loadSnapshot() -> ProtectedOrdinarySettingsSnapshot {
            loadCount += 1
            return storedSnapshot
        }

        func saveSnapshot(_ snapshot: ProtectedOrdinarySettingsSnapshot) {
            saveCount += 1
        }

        func removePersistentValues() {}
    }

    func test_certificateSelectionAdapter_selectorInput_preservesBytesAndOccurrence() {
        let option = UserIdSelectionOption(
            occurrenceIndex: 1,
            userIdData: Data("duplicate@example.com".utf8),
            displayText: "duplicate@example.com",
            isCurrentlyPrimary: false,
            isCurrentlyRevoked: true,
            isSelfCertified: true
        )
        let selectorInput = PGPCertificateSelectionAdapter.userIdSelectorInput(for: option)

        XCTAssertEqual(selectorInput.userIdData, option.userIdData)
        XCTAssertEqual(selectorInput.occurrenceIndex, 1)
    }

    // MARK: - Key-family vocabulary

    func test_keyFamily_equivalentSoftwareProfile_isTotalAndCorrect() {
        XCTAssertEqual(PGPKeyConfiguration.Identity.compatibleSoftwareV4.equivalentSoftwareProfile, .universal)
        XCTAssertEqual(PGPKeyConfiguration.Identity.modernSoftwareV6.equivalentSoftwareProfile, .modern)
        XCTAssertEqual(PGPKeyConfiguration.Identity.modernHighSoftwareV6.equivalentSoftwareProfile, .advanced)
        XCTAssertEqual(PGPKeyConfiguration.Identity.postQuantumHighSoftwareV6.equivalentSoftwareProfile, .postQuantumHigh)
        XCTAssertNil(PGPKeyConfiguration.Identity.compatibleP256V4.equivalentSoftwareProfile)
        XCTAssertNil(PGPKeyConfiguration.Identity.modernP256V6.equivalentSoftwareProfile)

        // The inverse mapping round-trips through the existing profile bridge.
        for profile in PGPKeyProfile.allCases {
            XCTAssertEqual(
                profile.openPGPConfiguration.identity.equivalentSoftwareProfile,
                profile
            )
        }
    }

    func test_keyFamily_orderedFamiliesCoverEveryIdentityOnce() {
        XCTAssertEqual(
            PGPKeyConfiguration.Identity.orderedFamilies.sorted { $0.rawValue < $1.rawValue },
            PGPKeyConfiguration.Identity.allCases.sorted { $0.rawValue < $1.rawValue }
        )
    }

    func test_keyFamily_deviceBoundFlagsMatchCustodyValidity() {
        XCTAssertFalse(PGPKeyConfiguration.Identity.compatibleSoftwareV4.isDeviceBoundFamily)
        XCTAssertFalse(PGPKeyConfiguration.Identity.modernSoftwareV6.isDeviceBoundFamily)
        XCTAssertFalse(PGPKeyConfiguration.Identity.modernHighSoftwareV6.isDeviceBoundFamily)
        XCTAssertFalse(PGPKeyConfiguration.Identity.postQuantumSoftwareV6.isDeviceBoundFamily)
        XCTAssertFalse(PGPKeyConfiguration.Identity.postQuantumHighSoftwareV6.isDeviceBoundFamily)
        XCTAssertTrue(PGPKeyConfiguration.Identity.compatibleP256V4.isDeviceBoundFamily)
        XCTAssertTrue(PGPKeyConfiguration.Identity.modernP256V6.isDeviceBoundFamily)
        XCTAssertTrue(PGPKeyConfiguration.Identity.deviceBoundPostQuantumV6.isDeviceBoundFamily)

        // Device-bound flag agrees with the resolver's valid configuration/custody pairs.
        let resolver = PGPKeyCapabilityResolver()
        for identity in PGPKeyConfiguration.Identity.allCases {
            XCTAssertEqual(
                resolver.isValidConfigurationCustodyPair(
                    configuration: identity.configuration,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                identity.isDeviceBoundFamily
            )
        }
    }

    func test_keyFamily_presentationStringsAreDistinctAndNonEmpty() {
        let names = PGPKeyConfiguration.Identity.allCases.map(\.familyDisplayName)
        let descriptions = PGPKeyConfiguration.Identity.allCases.map(\.familyDescription)

        XCTAssertEqual(Set(names).count, names.count)
        XCTAssertEqual(Set(descriptions).count, descriptions.count)
        for value in names + descriptions {
            XCTAssertFalse(value.isEmpty)
        }
        for identity in PGPKeyConfiguration.Identity.allCases {
            XCTAssertFalse(identity.familySecurityLevel.isEmpty)
            XCTAssertFalse(identity.familyAlgorithmSummary.isEmpty)
            XCTAssertFalse(identity.familyKeyVersionDisplay.isEmpty)
            XCTAssertFalse(identity.familyMessageFormatDisplay.isEmpty)
            XCTAssertFalse(identity.familyExportabilityDisplay.isEmpty)
            XCTAssertFalse(identity.familyGnuPGCompatibilityDisplay.isEmpty)
            XCTAssertFalse(identity.familyCustodyDisplay.isEmpty)
        }
        XCTAssertFalse(PGPKeyConfiguration.Identity.deviceBoundBiometricRequirement.isEmpty)
    }

    func test_keyFamily_deviceBoundCopyAvoidsBannedClaims() {
        // Device-bound families are P-256 (~128 bit): they must not inherit the
        // "~224 bit"/"stronger algorithms" claims, and the commitment copy must
        // not mention a passcode (access control is biometry-only).
        for identity in PGPKeyConfiguration.Identity.allCases where identity.isDeviceBoundFamily {
            let copy = [
                identity.familyDisplayName,
                identity.familyDescription,
                identity.familySecurityLevel,
                identity.familyAlgorithmSummary,
                identity.familyKeyVersionDisplay,
                identity.familyMessageFormatDisplay,
                identity.familyExportabilityDisplay,
                identity.familyGnuPGCompatibilityDisplay,
                identity.familyCustodyDisplay,
                PGPKeyConfiguration.Identity.deviceBoundBiometricRequirement,
            ].joined(separator: " ")
            XCTAssertFalse(copy.contains("224"))
            XCTAssertFalse(copy.lowercased().contains("stronger"))
            XCTAssertFalse(copy.lowercased().contains("passcode"))
        }
    }

    func test_contactKeyKindPresentation_avoidsCustodyVocabulary() {
        // Contact certificates expose compatibility, not custody: contact rows
        // must not claim portable or device-bound custody for someone else's key.
        for profile in PGPKeyProfile.allCases {
            let value = profile.contactKeyKindDisplayName
            XCTAssertFalse(value.isEmpty)
            XCTAssertFalse(value.lowercased().contains("portable"))
            XCTAssertFalse(value.lowercased().contains("device-bound"))
        }
    }
}
