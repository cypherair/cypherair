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
    ) throws -> PGPKeyIdentity {
        let identity = try TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: profile,
            name: name
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)
        return identity
    }

    // MARK: - Text Encryption: Profile A

    func test_encryptText_profileA_producesNonEmptyCiphertext() async throws {
        let identity = try generateKeyAndContact(profile: .universal)

        let ciphertext = try await stack.encryptionService.encryptText(
            "Hello, Profile A!",
            recipientFingerprints: [identity.fingerprint],
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
        let identity = try generateKeyAndContact(profile: .advanced)

        let ciphertext = try await stack.encryptionService.encryptText(
            "Hello, Profile B!",
            recipientFingerprints: [identity.fingerprint],
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
                recipientFingerprints: [],
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
                recipientFingerprints: ["nonexistent-fingerprint"],
                signWithFingerprint: nil,
                encryptToSelf: false
            )
            XCTFail("Expected error for unknown recipient")
        } catch let error as CypherAirError {
            if case .invalidKeyData = error {
                // Expected — recipient fingerprint not found in contacts
            } else {
                XCTFail("Expected .invalidKeyData, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    // MARK: - Signing

    func test_encryptText_withSignature_succeeds() async throws {
        let identity = try generateKeyAndContact(profile: .universal)

        let ciphertext = try await stack.encryptionService.encryptText(
            "Signed message",
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: identity.fingerprint,
            encryptToSelf: false
        )

        XCTAssertFalse(ciphertext.isEmpty)

        // Verify by decrypting directly via engine
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var secretKey = try stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
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
        let sender = try generateKeyAndContact(profile: .universal, name: "Sender")
        let recipient = try generateKeyAndContact(profile: .universal, name: "Recipient")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Encrypt to self test",
            recipientFingerprints: [recipient.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: true
        )

        // Sender should be able to decrypt (encrypted to self)
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var senderSecret = try stack.keyManagement.unwrapPrivateKey(fingerprint: sender.fingerprint)
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
        let sender = try generateKeyAndContact(profile: .universal, name: "Sender")
        let recipient = try generateKeyAndContact(profile: .universal, name: "Recipient")

        let ciphertext = try await stack.encryptionService.encryptText(
            "No self-encryption",
            recipientFingerprints: [recipient.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        // Sender should NOT be able to decrypt — not encrypted to self
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var senderSecret = try stack.keyManagement.unwrapPrivateKey(fingerprint: sender.fingerprint)
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

    // MARK: - File Encryption: Size Validation

    func test_encryptFile_underLimit_succeeds() async throws {
        let identity = try generateKeyAndContact(profile: .universal)

        // Create a 1 KB file
        let fileData = Data(repeating: 0xAB, count: 1024)
        let ciphertext = try await stack.encryptionService.encryptFile(
            fileData,
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        XCTAssertFalse(ciphertext.isEmpty)
    }

    func test_encryptFile_over100MB_throwsFileTooLarge() async {
        do {
            let identity = try generateKeyAndContact(profile: .universal)

            // Create data slightly over 100 MB
            let fileData = Data(repeating: 0xFF, count: 100 * 1024 * 1024 + 1)
            _ = try await stack.encryptionService.encryptFile(
                fileData,
                recipientFingerprints: [identity.fingerprint],
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
        let identity = try generateKeyAndContact(profile: .universal)

        // Exactly 100 MB — should be within the limit
        let fileData = Data(repeating: 0xCC, count: 100 * 1024 * 1024)
        let ciphertext = try await stack.encryptionService.encryptFile(
            fileData,
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        XCTAssertFalse(ciphertext.isEmpty)
    }

    // MARK: - Cross-Profile

    func test_encryptText_profileBSender_profileARecipient_succeeds() async throws {
        let sender = try generateKeyAndContact(profile: .advanced, name: "ProfileB Sender")
        let recipient = try generateKeyAndContact(profile: .universal, name: "ProfileA Recipient")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Cross-profile message",
            recipientFingerprints: [recipient.fingerprint],
            signWithFingerprint: sender.fingerprint,
            encryptToSelf: false
        )

        // Recipient (Profile A, v4) should be able to decrypt
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var recipientSecret = try stack.keyManagement.unwrapPrivateKey(fingerprint: recipient.fingerprint)
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
        let keyV4 = try generateKeyAndContact(profile: .universal, name: "RecipientV4")
        let keyV6 = try generateKeyAndContact(profile: .advanced, name: "RecipientV6")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Mixed recipients message",
            recipientFingerprints: [keyV4.fingerprint, keyV6.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        let binary = try stack.engine.dearmor(armored: ciphertext)

        // v4 recipient can decrypt
        var secretV4 = try stack.keyManagement.unwrapPrivateKey(fingerprint: keyV4.fingerprint)
        defer { secretV4.resetBytes(in: 0..<secretV4.count) }

        let resultV4 = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [secretV4],
            verificationKeys: []
        )
        XCTAssertEqual(String(data: resultV4.plaintext, encoding: .utf8), "Mixed recipients message")

        // v6 recipient can also decrypt
        var secretV6 = try stack.keyManagement.unwrapPrivateKey(fingerprint: keyV6.fingerprint)
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

        do {
            _ = try await stack.encryptionService.encryptText(
                "test",
                recipientFingerprints: [info.fingerprint],
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

    // MARK: - Unknown Recipient: Improved Error

    func test_encryptText_partialUnknownRecipient_throwsInvalidKeyData() async throws {
        let identity = try generateKeyAndContact(profile: .universal)

        do {
            _ = try await stack.encryptionService.encryptText(
                "test",
                recipientFingerprints: [identity.fingerprint, "nonexistent-fingerprint"],
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
            let identity = try generateKeyAndContact(profile: .universal)
            // 100 MB + 1 byte → should report 101 MB (ceiling), not 100 MB (truncated)
            let fileData = Data(repeating: 0xFF, count: 100 * 1024 * 1024 + 1)
            _ = try await stack.encryptionService.encryptFile(
                fileData,
                recipientFingerprints: [identity.fingerprint],
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
        let keyA = try generateKeyAndContact(profile: .universal, name: "RecipientA")
        let keyB = try generateKeyAndContact(profile: .universal, name: "RecipientB")

        let ciphertext = try await stack.encryptionService.encryptText(
            "Multi-recipient message",
            recipientFingerprints: [keyA.fingerprint, keyB.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        // Test that keyA can decrypt
        let binary = try stack.engine.dearmor(armored: ciphertext)
        var secretA = try stack.keyManagement.unwrapPrivateKey(fingerprint: keyA.fingerprint)
        defer { secretA.resetBytes(in: 0..<secretA.count) }

        let resultA = try stack.engine.decrypt(
            ciphertext: binary,
            secretKeys: [secretA],
            verificationKeys: []
        )
        XCTAssertEqual(String(data: resultA.plaintext, encoding: .utf8), "Multi-recipient message")
    }
}
