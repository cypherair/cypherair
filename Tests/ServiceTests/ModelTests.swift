import XCTest
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
            subkeyAlgo: "X25519"
        )
    }
}
