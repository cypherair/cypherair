import XCTest
import SwiftUI
@testable import CypherAir

/// Tests for model types: CypherAirError, Contact, PGPKeyIdentity,
/// KeyProfile+Codable, and SignatureVerification.
final class ModelTests: XCTestCase {

    // MARK: - CypherAirError: PgpError Mapping

    func test_cypherAirError_initFromPgpError_aeadMapped() {
        let error = CypherAirError(pgpError: .AeadAuthenticationFailed)
        if case .aeadAuthenticationFailed = error {
            // Expected
        } else {
            XCTFail("Expected .aeadAuthenticationFailed, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_noMatchingKeyMapped() {
        let error = CypherAirError(pgpError: .NoMatchingKey)
        if case .noMatchingKey = error {
            // Expected
        } else {
            XCTFail("Expected .noMatchingKey, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_wrongPassphraseMapped() {
        let error = CypherAirError(pgpError: .WrongPassphrase)
        if case .wrongPassphrase = error {
            // Expected
        } else {
            XCTFail("Expected .wrongPassphrase, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_unsupportedAlgorithmMapped() {
        let error = CypherAirError(pgpError: .UnsupportedAlgorithm(algo: "RSA"))
        if case .unsupportedAlgorithm(let algo) = error {
            XCTAssertEqual(algo, "RSA")
        } else {
            XCTFail("Expected .unsupportedAlgorithm, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_keyExpiredMapped() {
        let error = CypherAirError(pgpError: .KeyExpired)
        if case .keyExpired = error {
            // Expected
        } else {
            XCTFail("Expected .keyExpired, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_badSignatureMapped() {
        let error = CypherAirError(pgpError: .BadSignature)
        if case .badSignature = error {
            // Expected
        } else {
            XCTFail("Expected .badSignature, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_unknownSignerMapped() {
        let error = CypherAirError(pgpError: .UnknownSigner)
        if case .unknownSigner = error {
            // Expected
        } else {
            XCTFail("Expected .unknownSigner, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_corruptDataMapped() {
        let error = CypherAirError(pgpError: .CorruptData(reason: "test damage"))
        if case .corruptData(let reason) = error {
            XCTAssertEqual(reason, "test damage")
        } else {
            XCTFail("Expected .corruptData, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_invalidKeyDataMapped() {
        let error = CypherAirError(pgpError: .InvalidKeyData(reason: "not a key"))
        if case .invalidKeyData(let reason) = error {
            XCTAssertEqual(reason, "not a key")
        } else {
            XCTFail("Expected .invalidKeyData, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_encryptionFailedMapped() {
        let error = CypherAirError(pgpError: .EncryptionFailed(reason: "no recipients"))
        if case .encryptionFailed(let reason) = error {
            XCTAssertEqual(reason, "no recipients")
        } else {
            XCTFail("Expected .encryptionFailed, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_signingFailedMapped() {
        let error = CypherAirError(pgpError: .SigningFailed(reason: "invalid key"))
        if case .signingFailed(let reason) = error {
            XCTAssertEqual(reason, "invalid key")
        } else {
            XCTFail("Expected .signingFailed, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_armorErrorMapped() {
        let error = CypherAirError(pgpError: .ArmorError(reason: "bad format"))
        if case .armorError(let reason) = error {
            XCTAssertEqual(reason, "bad format")
        } else {
            XCTFail("Expected .armorError, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_integrityCheckFailedMapped() {
        let error = CypherAirError(pgpError: .IntegrityCheckFailed)
        if case .integrityCheckFailed = error {
            // Expected
        } else {
            XCTFail("Expected .integrityCheckFailed, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_argon2idMemoryExceededMapped() {
        let error = CypherAirError(pgpError: .Argon2idMemoryExceeded(requiredMb: 512))
        if case .argon2idMemoryExceeded(let requiredMb) = error {
            XCTAssertEqual(requiredMb, 512)
        } else {
            XCTFail("Expected .argon2idMemoryExceeded, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_revocationErrorMapped() {
        let error = CypherAirError(pgpError: .RevocationError(reason: "bad cert"))
        if case .revocationError(let reason) = error {
            XCTAssertEqual(reason, "bad cert")
        } else {
            XCTFail("Expected .revocationError, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_keyGenerationFailedMapped() {
        let error = CypherAirError(pgpError: .KeyGenerationFailed(reason: "rng failure"))
        if case .keyGenerationFailed(let reason) = error {
            XCTAssertEqual(reason, "rng failure")
        } else {
            XCTFail("Expected .keyGenerationFailed, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_s2kErrorMapped() {
        let error = CypherAirError(pgpError: .S2kError(reason: "unsupported mode"))
        if case .s2kError(let reason) = error {
            XCTAssertEqual(reason, "unsupported mode")
        } else {
            XCTFail("Expected .s2kError, got \(error)")
        }
    }

    func test_cypherAirError_initFromPgpError_internalErrorMapped() {
        let error = CypherAirError(pgpError: .InternalError(reason: "unexpected state"))
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
            .fileTooLarge(sizeMB: 200),
            .noKeySelected,
            .noRecipientsSelected,
            .biometricsUnavailable,
        ]

        for error in errors {
            XCTAssertNotNil(error.errorDescription,
                            "\(error) should have a non-nil errorDescription")
            XCTAssertFalse(error.errorDescription!.isEmpty,
                           "\(error) should have a non-empty errorDescription")
        }
    }

    // MARK: - Contact: Display Name

    func test_contact_displayName_withNameAndEmail_extractsName() {
        let contact = makeContact(userId: "Alice <alice@example.com>")
        XCTAssertEqual(contact.displayName, "Alice")
    }

    func test_contact_displayName_nilUserId_returnsUnknown() {
        let contact = makeContact(userId: nil)
        // The display name should use the localized "Unknown" fallback
        XCTAssertFalse(contact.displayName.isEmpty)
    }

    func test_contact_displayName_noAngleBrackets_returnsUserId() {
        let contact = makeContact(userId: "just-a-name")
        XCTAssertEqual(contact.displayName, "just-a-name")
    }

    // MARK: - Contact: Email Extraction

    func test_contact_email_extractsFromUserId() {
        let contact = makeContact(userId: "Alice <alice@example.com>")
        XCTAssertEqual(contact.email, "alice@example.com")
    }

    func test_contact_email_noAngleBrackets_returnsNil() {
        let contact = makeContact(userId: "Alice")
        XCTAssertNil(contact.email)
    }

    func test_contact_email_nilUserId_returnsNil() {
        let contact = makeContact(userId: nil)
        XCTAssertNil(contact.email)
    }

    // MARK: - Contact: canEncryptTo

    func test_contact_canEncryptTo_validKey_returnsTrue() {
        let contact = makeContact(hasEncryptionSubkey: true, isRevoked: false, isExpired: false)
        XCTAssertTrue(contact.canEncryptTo)
    }

    func test_contact_canEncryptTo_expired_returnsFalse() {
        let contact = makeContact(hasEncryptionSubkey: true, isRevoked: false, isExpired: true)
        XCTAssertFalse(contact.canEncryptTo)
    }

    func test_contact_canEncryptTo_revoked_returnsFalse() {
        let contact = makeContact(hasEncryptionSubkey: true, isRevoked: true, isExpired: false)
        XCTAssertFalse(contact.canEncryptTo)
    }

    func test_contact_canEncryptTo_noSubkey_returnsFalse() {
        let contact = makeContact(hasEncryptionSubkey: false, isRevoked: false, isExpired: false)
        XCTAssertFalse(contact.canEncryptTo)
    }

    // MARK: - PGPKeyIdentity: Computed Properties

    func test_pgpKeyIdentity_shortKeyId_returnsLast16Chars() {
        let identity = makeIdentity(fingerprint: "abcdef1234567890abcdef1234567890abcdef12")
        XCTAssertEqual(identity.shortKeyId, "34567890abcdef12")
    }

    func test_pgpKeyIdentity_formattedFingerprint_groupsOf4() {
        let identity = makeIdentity(fingerprint: "abcdef1234567890")
        XCTAssertEqual(identity.formattedFingerprint, "abcd ef12 3456 7890")
    }

    // MARK: - KeyProfile+Codable

    func test_keyProfile_encodeDecode_universal_roundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let profile = KeyProfile.universal
        let data = try encoder.encode(profile)
        let decoded = try decoder.decode(KeyProfile.self, from: data)

        XCTAssertEqual(decoded, .universal)
    }

    func test_keyProfile_encodeDecode_advanced_roundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let profile = KeyProfile.advanced
        let data = try encoder.encode(profile)
        let decoded = try decoder.decode(KeyProfile.self, from: data)

        XCTAssertEqual(decoded, .advanced)
    }

    func test_keyProfile_decode_unknownValue_throwsError() {
        let decoder = JSONDecoder()
        let invalidJSON = Data("\"quantum\"".utf8)

        XCTAssertThrowsError(try decoder.decode(KeyProfile.self, from: invalidJSON)) { error in
            guard case DecodingError.dataCorrupted = error else {
                XCTFail("Expected DecodingError.dataCorrupted, got \(error)")
                return
            }
        }
    }

    // MARK: - SignatureVerification

    func test_signatureVerification_isWarning_forBad() {
        let verification = SignatureVerification(
            status: .bad, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertTrue(verification.isWarning)
    }

    func test_signatureVerification_isWarning_forUnknown() {
        let verification = SignatureVerification(
            status: .unknownSigner, signerFingerprint: "abc", signerContact: nil
        )
        XCTAssertTrue(verification.isWarning)
    }

    func test_signatureVerification_isWarning_validIsFalse() {
        let verification = SignatureVerification(
            status: .valid, signerFingerprint: "abc", signerContact: nil
        )
        XCTAssertFalse(verification.isWarning)
    }

    func test_signatureVerification_isWarning_notSignedIsFalse() {
        let verification = SignatureVerification(
            status: .notSigned, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertFalse(verification.isWarning)
    }

    // MARK: - SignatureVerification: statusColor

    func test_signatureVerification_statusColor_validIsGreen() {
        let verification = SignatureVerification(
            status: .valid, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertEqual(verification.statusColor, .green)
    }

    func test_signatureVerification_statusColor_badIsRed() {
        let verification = SignatureVerification(
            status: .bad, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertEqual(verification.statusColor, .red)
    }

    func test_signatureVerification_statusColor_notSignedIsSecondary() {
        let verification = SignatureVerification(
            status: .notSigned, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertEqual(verification.statusColor, .secondary)
    }

    // MARK: - AppConfiguration: Grace Period Validation

    func test_appConfiguration_gracePeriod_validValuePersists() {
        let config = AppConfiguration()
        config.gracePeriod = 60
        XCTAssertEqual(config.gracePeriod, 60)
    }

    func test_appConfiguration_gracePeriod_invalidValueClampsToDefault() {
        let config = AppConfiguration()
        config.gracePeriod = 42  // Not a valid option
        XCTAssertEqual(config.gracePeriod, 180,
                       "Invalid gracePeriod should be clamped to the default (180)")
    }

    // MARK: - Contact: Formatted Fingerprint

    func test_contact_formattedFingerprint_groupsOf4() {
        let contact = makeContact(fingerprint: "abcdef1234567890")
        XCTAssertEqual(contact.formattedFingerprint, "abcd ef12 3456 7890")
    }

    // MARK: - Factory Helpers

    private func makeContact(
        fingerprint: String = "abc123",
        userId: String? = "Test <test@example.com>",
        hasEncryptionSubkey: Bool = true,
        isRevoked: Bool = false,
        isExpired: Bool = false
    ) -> Contact {
        Contact(
            fingerprint: fingerprint,
            keyVersion: 4,
            profile: .universal,
            userId: userId,
            isRevoked: isRevoked,
            isExpired: isExpired,
            hasEncryptionSubkey: hasEncryptionSubkey,
            publicKeyData: Data(),
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519"
        )
    }

    private func makeIdentity(
        fingerprint: String = "abc123"
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: 4,
            profile: .universal,
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
            expiryDate: nil
        )
    }
}
