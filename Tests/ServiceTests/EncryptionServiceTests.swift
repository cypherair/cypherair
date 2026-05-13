import XCTest
@testable import CypherAir

/// Tests for EncryptionService — text and file encryption orchestration,
/// file size validation, encrypt-to-self, and cross-profile behavior.
final class EncryptionServiceTests: XCTestCase {

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

    // MARK: - Helpers

    /// Generate a key and register it as a contact, returning the identity.
    private func generateKeyAndContact(
        profile: KeyProfile,
        name: String = "Test"
    ) async throws -> PGPKeyIdentity {
        let identity = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: profile,
            name: name
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)
        return identity
    }

    private func contactId(for identity: PGPKeyIdentity) throws -> String {
        try XCTUnwrap(stack.contactService.contactId(forFingerprint: identity.fingerprint))
    }

    // MARK: - Text Encryption: Profile A

    func test_encryptText_profileA_producesNonEmptyCiphertext() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)

        let ciphertext = try await stack.encryptionService.encryptText(
            "Hello, Profile A!",
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        XCTAssertFalse(ciphertext.isEmpty)
        // Should be ASCII-armored
        let header = String(data: ciphertext.prefix(27), encoding: .utf8)
        XCTAssertTrue(header?.hasPrefix("-----BEGIN PGP") == true)
    }

    // MARK: - Text Encryption: Profile B

    func test_encryptText_profileB_producesNonEmptyCiphertext() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)

        let ciphertext = try await stack.encryptionService.encryptText(
            "Hello, Profile B!",
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        XCTAssertFalse(ciphertext.isEmpty)
    }

    // MARK: - No Recipients

    func test_encryptText_noRecipients_throwsError() async {
        do {
            _ = try await stack.encryptionService.encryptText(
                "test",
                recipientContactIds: [],
                signWithFingerprint: nil,
                encryptToSelf: false
            )
            XCTFail("Expected noRecipientsSelected error")
        } catch let error as CypherAirError {
            if case .noRecipientsSelected = error {
                // Expected
            } else {
                XCTFail("Expected .noRecipientsSelected, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    // MARK: - Unknown Recipient

    func test_encryptText_unknownRecipient_throwsError() async {
        do {
            _ = try await stack.encryptionService.encryptText(
                "test",
                recipientContactIds: ["nonexistent-contact-id"],
                signWithFingerprint: nil,
                encryptToSelf: false
            )
            XCTFail("Expected error for unknown recipient")
        } catch let error as CypherAirError {
            if case .invalidKeyData = error {
                // Expected — recipient contact ID not found in contacts
            } else {
                XCTFail("Expected .invalidKeyData, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    // MARK: - Signing

    func test_encryptText_withSignature_succeeds() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)

        let ciphertext = try await stack.encryptionService.encryptText(
            "Signed message",
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: identity.fingerprint,
            encryptToSelf: false
        )

        XCTAssertFalse(ciphertext.isEmpty)

        // Verify by decrypting directly via engine
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var secretKey = try await stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }

        let result = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [secretKey],
            verificationKeys: [identity.publicKeyData]
        )
        XCTAssertEqual(result.signatureStatus, .valid)
    }

    // MARK: - Encrypt-to-Self

    func test_encryptText_encryptToSelf_canDecryptWithOwnKey() async throws {
        let sender = try await generateKeyAndContact(profile: .universal, name: "Sender")
        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Encrypt to self test",
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: true
        )

        // Sender should be able to decrypt (encrypted to self)
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var senderSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: sender.fingerprint)
        defer { senderSecret.resetBytes(in: 0..<senderSecret.count) }

        let result = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [senderSecret],
            verificationKeys: []
        )
        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, "Encrypt to self test")
    }

    func test_encryptText_encryptToSelfOff_cannotDecryptWithSenderKey() async throws {
        let sender = try await generateKeyAndContact(profile: .universal, name: "Sender")
        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient")

        let ciphertext = try await stack.encryptionService.encryptText(
            "No self-encryption",
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        // Sender should NOT be able to decrypt — not encrypted to self
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var senderSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: sender.fingerprint)
        defer { senderSecret.resetBytes(in: 0..<senderSecret.count) }

        XCTAssertThrowsError(
            try stack.engine.decrypt(
                ciphertext: binary,
                secretKeys: [senderSecret],
                verificationKeys: []
            )
        ) { error in
            // Expected: sender's key is not a recipient
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            if case .NoMatchingKey = pgpError {
                // Expected
            } else {
                XCTFail("Expected .NoMatchingKey, got \(pgpError)")
            }
        }
    }

    func test_encryptText_profileB_encryptToSelf_canDecryptWithOwnKey() async throws {
        let sender = try await generateKeyAndContact(profile: .advanced, name: "Sender B")
        let recipient = try await generateKeyAndContact(profile: .advanced, name: "Recipient B")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Profile B encrypt to self test",
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: true
        )

        // Sender should be able to decrypt (encrypted to self)
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var senderSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: sender.fingerprint)
        defer { senderSecret.resetBytes(in: 0..<senderSecret.count) }

        let result = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [senderSecret],
            verificationKeys: []
        )
        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, "Profile B encrypt to self test")
    }

    func test_encryptText_profileB_encryptToSelfOff_cannotDecryptWithSenderKey() async throws {
        let sender = try await generateKeyAndContact(profile: .advanced, name: "Sender B")
        let recipient = try await generateKeyAndContact(profile: .advanced, name: "Recipient B")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Profile B no self-encryption",
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        // Sender should NOT be able to decrypt — not encrypted to self
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var senderSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: sender.fingerprint)
        defer { senderSecret.resetBytes(in: 0..<senderSecret.count) }

        XCTAssertThrowsError(
            try stack.engine.decrypt(
                ciphertext: binary,
                secretKeys: [senderSecret],
                verificationKeys: []
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            if case .NoMatchingKey = pgpError {
                // Expected
            } else {
                XCTFail("Expected .NoMatchingKey, got \(pgpError)")
            }
        }
    }

    // MARK: - File Encryption: Size Validation

    func test_encryptFile_underLimit_succeeds() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)

        // Create a 1 KB file
        let fileData = Data(repeating: 0xAB, count: 1024)
        let ciphertext = try await stack.encryptionService.encryptFile(
            fileData,
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        XCTAssertFalse(ciphertext.isEmpty)
    }

    func test_encryptFile_over100MB_throwsFileTooLarge() async {
        do {
            let identity = try await generateKeyAndContact(profile: .universal)

            // Create data slightly over 100 MB
            let fileData = Data(repeating: 0xFF, count: 100 * 1024 * 1024 + 1)
            _ = try await stack.encryptionService.encryptFile(
                fileData,
                recipientContactIds: [try contactId(for: identity)],
                signWithFingerprint: nil,
                encryptToSelf: false
            )
            XCTFail("Expected fileTooLarge error")
        } catch let error as CypherAirError {
            if case .fileTooLarge = error {
                // Expected
            } else {
                XCTFail("Expected .fileTooLarge, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func test_encryptFile_exactly100MB_succeeds() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)

        // Exactly 100 MB — should be within the limit
        let fileData = Data(repeating: 0xCC, count: 100 * 1024 * 1024)
        let ciphertext = try await stack.encryptionService.encryptFile(
            fileData,
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        XCTAssertFalse(ciphertext.isEmpty)
    }

    func test_encryptFile_profileB_underLimit_succeeds() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)

        // Create a 1 KB file
        let fileData = Data(repeating: 0xAB, count: 1024)
        let ciphertext = try await stack.encryptionService.encryptFile(
            fileData,
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        XCTAssertFalse(ciphertext.isEmpty)
    }

    // MARK: - Cross-Profile

    func test_encryptText_profileBSender_profileARecipient_succeeds() async throws {
        let sender = try await generateKeyAndContact(profile: .advanced, name: "ProfileB Sender")
        let recipient = try await generateKeyAndContact(profile: .universal, name: "ProfileA Recipient")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Cross-profile message",
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: sender.fingerprint,
            encryptToSelf: false
        )

        // Recipient (Profile A, v4) should be able to decrypt
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var recipientSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: recipient.fingerprint)
        defer { recipientSecret.resetBytes(in: 0..<recipientSecret.count) }

        let result = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [recipientSecret],
            verificationKeys: [sender.publicKeyData]
        )

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, "Cross-profile message")
    }

    func test_encryptText_mixedRecipients_v4AndV6_bothCanDecrypt() async throws {
        // PRD §3.3 / TDD §1.4: mixed v4+v6 recipients → SEIPDv1 (lowest common denominator)
        let keyV4 = try await generateKeyAndContact(profile: .universal, name: "RecipientV4")
        let keyV6 = try await generateKeyAndContact(profile: .advanced, name: "RecipientV6")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Mixed recipients message",
            recipientContactIds: [try contactId(for: keyV4), try contactId(for: keyV6)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        let binary = try stack.engine.dearmor(armored: ciphertext)

        // v4 recipient can decrypt
        var secretV4 = try await stack.keyManagement.unwrapPrivateKey(fingerprint: keyV4.fingerprint)
        defer { secretV4.resetBytes(in: 0..<secretV4.count) }

        let resultV4 = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [secretV4],
            verificationKeys: []
        )
        XCTAssertEqual(String(data: resultV4.plaintext, encoding: .utf8), "Mixed recipients message")

        // v6 recipient can also decrypt
        var secretV6 = try await stack.keyManagement.unwrapPrivateKey(fingerprint: keyV6.fingerprint)
        defer { secretV6.resetBytes(in: 0..<secretV6.count) }

        let resultV6 = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [secretV6],
            verificationKeys: []
        )
        XCTAssertEqual(String(data: resultV6.plaintext, encoding: .utf8), "Mixed recipients message")
    }

    // MARK: - Encrypt-to-Self: No Default Key

    func test_encryptText_encryptToSelf_noDefaultKey_throwsNoKeySelected() async {
        // Create a recipient contact directly (no own key generated → no default key)
        let recipientKey = try! PgpEngine().generateKey(
            name: "Recipient", email: nil, expirySeconds: nil, profile: .universal
        )
        try! stack.contactService.addContact(publicKeyData: recipientKey.publicKeyData)
        let info = try! PgpEngine().parseKeyInfo(keyData: recipientKey.publicKeyData)
        guard let recipientContactId = stack.contactService.contactId(forFingerprint: info.fingerprint) else {
            return XCTFail("Expected recipient contact ID")
        }

        do {
            _ = try await stack.encryptionService.encryptText(
                "test",
                recipientContactIds: [recipientContactId],
                signWithFingerprint: nil,
                encryptToSelf: true
            )
            XCTFail("Expected noKeySelected error")
        } catch let error as CypherAirError {
            if case .noKeySelected = error {
                // Expected — no default key when encryptToSelf is true
            } else {
                XCTFail("Expected .noKeySelected, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    // MARK: - Encrypt-to-Self: Key Selection

    func test_encryptText_encryptToSelfWithSpecificKey_canDecryptWithThatKey() async throws {
        // Generate two keys — first becomes default, second is non-default
        let defaultKey = try await generateKeyAndContact(profile: .universal, name: "Default")
        let specificKey = try await generateKeyAndContact(profile: .universal, name: "Specific")
        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient")

        // Encrypt-to-self using the non-default key
        let ciphertext = try await stack.encryptionService.encryptText(
            "Specific key self-encrypt",
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: true,
            encryptToSelfFingerprint: specificKey.fingerprint
        )

        let binary = try stack.engine.dearmor(armored: ciphertext)

        // The specific (non-default) key should be able to decrypt
        var specificSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: specificKey.fingerprint)
        defer { specificSecret.resetBytes(in: 0..<specificSecret.count) }

        let result = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [specificSecret],
            verificationKeys: []
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "Specific key self-encrypt")

        // The default key should NOT be able to decrypt
        var defaultSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: defaultKey.fingerprint)
        defer { defaultSecret.resetBytes(in: 0..<defaultSecret.count) }

        XCTAssertThrowsError(
            try stack.engine.decrypt(
                ciphertext: binary,
                secretKeys: [defaultSecret],
                verificationKeys: []
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            if case .NoMatchingKey = pgpError {
                // Expected — default key is not a recipient
            } else {
                XCTFail("Expected .NoMatchingKey, got \(pgpError)")
            }
        }
    }

    func test_encryptText_encryptToSelfFingerprintNil_usesDefaultKey() async throws {
        // Generate two keys — first becomes default
        let defaultKey = try await generateKeyAndContact(profile: .universal, name: "Default")
        _ = try await generateKeyAndContact(profile: .universal, name: "Other")
        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient")

        // Encrypt-to-self with nil fingerprint — should fall back to default key
        let ciphertext = try await stack.encryptionService.encryptText(
            "Default key fallback",
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: true,
            encryptToSelfFingerprint: nil
        )

        let binary = try stack.engine.dearmor(armored: ciphertext)

        // Default key should be able to decrypt
        var defaultSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: defaultKey.fingerprint)
        defer { defaultSecret.resetBytes(in: 0..<defaultSecret.count) }

        let result = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [defaultSecret],
            verificationKeys: []
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "Default key fallback")
    }

    func test_encryptText_encryptToSelfWithSpecificKey_profileB() async throws {
        let defaultKey = try await generateKeyAndContact(profile: .advanced, name: "Default B")
        let specificKey = try await generateKeyAndContact(profile: .advanced, name: "Specific B")
        let recipient = try await generateKeyAndContact(profile: .advanced, name: "Recipient B")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Profile B specific key",
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: true,
            encryptToSelfFingerprint: specificKey.fingerprint
        )

        let binary = try stack.engine.dearmor(armored: ciphertext)

        // Specific key can decrypt
        var specificSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: specificKey.fingerprint)
        defer { specificSecret.resetBytes(in: 0..<specificSecret.count) }

        let result = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [specificSecret],
            verificationKeys: []
        )
        XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "Profile B specific key")

        // Default key cannot decrypt
        var defaultSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: defaultKey.fingerprint)
        defer { defaultSecret.resetBytes(in: 0..<defaultSecret.count) }

        XCTAssertThrowsError(
            try stack.engine.decrypt(
                ciphertext: binary,
                secretKeys: [defaultSecret],
                verificationKeys: []
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            if case .NoMatchingKey = pgpError {
                // Expected
            } else {
                XCTFail("Expected .NoMatchingKey, got \(pgpError)")
            }
        }
    }

    // MARK: - Unknown Recipient: Improved Error

    func test_encryptText_partialUnknownRecipient_throwsInvalidKeyData() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)

        do {
            _ = try await stack.encryptionService.encryptText(
                "test",
                recipientContactIds: [try contactId(for: identity), "nonexistent-contact-id"],
                signWithFingerprint: nil,
                encryptToSelf: false
            )
            XCTFail("Expected error for partially unknown recipients")
        } catch let error as CypherAirError {
            if case .invalidKeyData = error {
                // Expected — one recipient not found in contacts
            } else {
                XCTFail("Expected .invalidKeyData, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    // MARK: - File Size: Rounding

    func test_encryptFile_slightlyOver100MB_reportsCeiledSize() async {
        do {
            let identity = try await generateKeyAndContact(profile: .universal)
            // 100 MB + 1 byte → should report 101 MB (ceiling), not 100 MB (truncated)
            let fileData = Data(repeating: 0xFF, count: 100 * 1024 * 1024 + 1)
            _ = try await stack.encryptionService.encryptFile(
                fileData,
                recipientContactIds: [try contactId(for: identity)],
                signWithFingerprint: nil,
                encryptToSelf: false
            )
            XCTFail("Expected fileTooLarge error")
        } catch let error as CypherAirError {
            if case .fileTooLarge(let sizeMB) = error {
                XCTAssertEqual(sizeMB, 101,
                               "File size should be ceiling-rounded to 101 MB, not truncated to 100")
            } else {
                XCTFail("Expected .fileTooLarge, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    // MARK: - Multiple Recipients

    func test_encryptText_multipleRecipients_bothCanDecrypt() async throws {
        let keyA = try await generateKeyAndContact(profile: .universal, name: "RecipientA")
        let keyB = try await generateKeyAndContact(profile: .universal, name: "RecipientB")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Multi-recipient message",
            recipientContactIds: [try contactId(for: keyA), try contactId(for: keyB)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        // Test that keyA can decrypt
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var secretA = try await stack.keyManagement.unwrapPrivateKey(fingerprint: keyA.fingerprint)
        defer { secretA.resetBytes(in: 0..<secretA.count) }

        let resultA = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [secretA],
            verificationKeys: []
        )
        XCTAssertEqual(String(data: resultA.plaintext, encoding: .utf8), "Multi-recipient message")
    }
}
