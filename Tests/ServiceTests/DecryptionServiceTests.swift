import XCTest
@testable import CypherAir

/// Tests for DecryptionService — SECURITY-CRITICAL: validates Phase 1/Phase 2 boundary.
/// Phase 1 (parseRecipients) must NOT trigger SE unwrap or authentication.
/// Phase 2 (decrypt) MUST trigger SE unwrap (which requires biometric auth).
///
/// `parseRecipients` now uses `PgpEngine.matchRecipients()` for correct
/// subkey-to-certificate matching via Sequoia's key_handles(). It returns
/// primary fingerprints that match PGPKeyIdentity.fingerprint directly.
/// Some Phase 2 tests still construct Phase1Result directly to isolate
/// the decryption logic from the key-matching logic.
final class DecryptionServiceTests: XCTestCase {

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

    /// Generate a key, add it as a contact, and encrypt a message to it.
    /// Returns the identity, binary ciphertext, and a Phase1Result with the correct matchedKey.
    private func encryptAndPreparePhase1(
        profile: KeyProfile,
        plaintext: String = "Hello, encrypted world!",
        sign: Bool = true
    ) async throws -> (identity: PGPKeyIdentity, ciphertext: Data, phase1: DecryptionService.Phase1Result) {
        let identity = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: profile,
            name: profile == .universal ? "Alice" : "Bob"
        )

        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let armoredCiphertext = try await stack.encryptionService.encryptText(
            plaintext,
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: sign ? identity.fingerprint : nil,
            encryptToSelf: false
        )

        // Dearmor for Phase 2 (parseRecipients would do this)
        let binaryCiphertext: Data
        if let first = armoredCiphertext.first, first == 0x2D {
            binaryCiphertext = try stack.engine.dearmor(armored: armoredCiphertext)
        } else {
            binaryCiphertext = armoredCiphertext
        }

        // Get recipient key IDs from the engine
        let recipientKeyIds = try stack.engine.parseRecipients(ciphertext: binaryCiphertext)

        // Construct Phase1Result with the correct matched key
        let phase1 = DecryptionService.Phase1Result(
            recipientKeyIds: recipientKeyIds,
            matchedKey: identity,
            ciphertext: binaryCiphertext
        )

        return (identity, binaryCiphertext, phase1)
    }

    // MARK: - Phase 1: Parse Recipients Behavior

    func test_parseRecipients_returnsNonEmptyKeyIds() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            "test",
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        // Dearmor and parse recipients directly via engine
        let binary = try stack.engine.dearmor(armored: ciphertext)
        let recipientKeyIds = try stack.engine.parseRecipients(ciphertext: binary)

        XCTAssertFalse(recipientKeyIds.isEmpty, "Should find at least one recipient key ID")
        for keyId in recipientKeyIds {
            XCTAssertTrue(keyId.allSatisfy { $0.isHexDigit },
                          "Recipient key ID should be hex: \(keyId)")
        }
    }

    func test_parseRecipients_profileB_returnsNonEmptyKeyIds() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            "test",
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        let binary = try stack.engine.dearmor(armored: ciphertext)
        let recipientKeyIds = try stack.engine.parseRecipients(ciphertext: binary)

        XCTAssertFalse(recipientKeyIds.isEmpty)
    }

    func test_parseRecipients_noMatchingKey_throwsError() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            "secret",
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        // Delete the key so parseRecipients won't find a match
        try stack.keyManagement.deleteKey(fingerprint: identity.fingerprint)

        do {
            _ = try await stack.decryptionService.parseRecipients(ciphertext: ciphertext)
            XCTFail("Expected noMatchingKey error")
        } catch let error as CypherAirError {
            if case .noMatchingKey = error {
                // Expected
            } else {
                XCTFail("Expected .noMatchingKey, got \(error)")
            }
        }
    }

    func test_parseRecipients_corruptData_throwsCorruptDataError() async throws {
        // Feed completely invalid (non-OpenPGP) data.
        // matchRecipients should fail with CorruptData, which parseRecipients
        // now preserves instead of mapping to noMatchingKey.
        let garbageData = Data("this is not an OpenPGP message".utf8)

        do {
            _ = try await stack.decryptionService.parseRecipients(ciphertext: garbageData)
            XCTFail("Expected corruptData error")
        } catch let error as CypherAirError {
            if case .corruptData = error {
                // Expected — garbage data is not a valid OpenPGP message
            } else {
                XCTFail("Expected .corruptData, got \(error)")
            }
        }
    }

    func test_parseRecipientsFromFile_corruptData_throwsCorruptDataError() async throws {
        // Write garbage data to a temp file and attempt to parse it.
        let tempDir = FileManager.default.temporaryDirectory
        let tempFile = tempDir.appendingPathComponent("corrupt-\(UUID().uuidString).gpg")
        try Data("not an OpenPGP message".utf8).write(to: tempFile)
        defer { try? FileManager.default.removeItem(at: tempFile) }

        do {
            _ = try await stack.decryptionService.parseRecipientsFromFile(fileURL: tempFile)
            XCTFail("Expected corruptData error")
        } catch let error as CypherAirError {
            if case .corruptData = error {
                // Expected — garbage data is not a valid OpenPGP message
            } else {
                XCTFail("Expected .corruptData, got \(error)")
            }
        }
    }

    func test_parseRecipients_doesNotTriggerSeUnwrap() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            "test",
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        let unwrapCountBefore = stack.mockSE.unwrapCallCount

        // Phase 1 should succeed AND should NOT trigger SE unwrap
        let phase1 = try await stack.decryptionService.parseRecipients(ciphertext: ciphertext)

        XCTAssertEqual(stack.mockSE.unwrapCallCount, unwrapCountBefore,
                       "Phase 1 must NOT trigger SE unwrap — no authentication should occur")
        XCTAssertNotNil(phase1.matchedKey,
                        "Phase 1 should find a matched key")
        XCTAssertEqual(phase1.matchedKey?.fingerprint, identity.fingerprint,
                       "Phase 1 should match the correct key by primary fingerprint")
    }

    // MARK: - Phase 2: Decrypt (Authentication Required)

    func test_decrypt_phase2_profileA_returnsPlaintext() async throws {
        let plaintext = "Profile A secret message 🔐"
        let (_, _, phase1) = try await encryptAndPreparePhase1(
            profile: .universal, plaintext: plaintext
        )

        let result = try await stack.decryptionService.decrypt(phase1: phase1)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
    }

    func test_decrypt_phase2_profileB_returnsPlaintext() async throws {
        let plaintext = "Profile B secret message 🛡️"
        let (_, _, phase1) = try await encryptAndPreparePhase1(
            profile: .advanced, plaintext: plaintext
        )

        let result = try await stack.decryptionService.decrypt(phase1: phase1)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
    }

    func test_decrypt_phase2_withSignature_returnsValidVerification() async throws {
        let (_, _, phase1) = try await encryptAndPreparePhase1(
            profile: .universal, sign: true
        )

        let result = try await stack.decryptionService.decrypt(phase1: phase1)

        XCTAssertEqual(result.signature.status, .valid,
                       "Signed message should verify with .valid status")
    }

    func test_decrypt_phase2_triggersSeUnwrap() async throws {
        let (_, _, phase1) = try await encryptAndPreparePhase1(profile: .universal)

        let unwrapCountBefore = stack.mockSE.unwrapCallCount

        _ = try await stack.decryptionService.decrypt(phase1: phase1)

        XCTAssertGreaterThan(stack.mockSE.unwrapCallCount, unwrapCountBefore,
                             "Phase 2 must trigger SE unwrap for authentication")
    }

    func test_decrypt_phase2_noMatchedKey_throwsError() async throws {
        let phase1 = DecryptionService.Phase1Result(
            recipientKeyIds: ["unknown"],
            matchedKey: nil,
            ciphertext: Data()
        )

        do {
            _ = try await stack.decryptionService.decrypt(phase1: phase1)
            XCTFail("Expected noMatchingKey error")
        } catch let error as CypherAirError {
            if case .noMatchingKey = error {
                // Expected
            } else {
                XCTFail("Expected .noMatchingKey, got \(error)")
            }
        }
    }

    // MARK: - Tamper Detection (1-Bit Flip)

    func test_decrypt_profileA_tamperedCiphertext_throwsIntegrityError() async throws {
        let (identity, binaryCiphertext, _) = try await encryptAndPreparePhase1(
            profile: .universal
        )

        // Flip one bit near the middle of the ciphertext
        var tampered = binaryCiphertext
        let midpoint = tampered.count / 2
        tampered[midpoint] ^= 0x01

        // Construct Phase1Result with tampered data
        let recipientKeyIds = try stack.engine.parseRecipients(ciphertext: binaryCiphertext)
        let phase1 = DecryptionService.Phase1Result(
            recipientKeyIds: recipientKeyIds,
            matchedKey: identity,
            ciphertext: tampered
        )

        // Phase 2 should fail — MDC integrity check (Profile A / SEIPDv1)
        do {
            _ = try await stack.decryptionService.decrypt(phase1: phase1)
            XCTFail("Expected decryption to fail on tampered ciphertext")
        } catch let error as CypherAirError {
            // Profile A (SEIPDv1): bit-flip may corrupt the encrypted payload
            // (→ integrityCheckFailed), the framing (→ corruptData), or the
            // recipient key ID (→ noMatchingKey).
            switch error {
            case .integrityCheckFailed, .corruptData, .noMatchingKey:
                break // acceptable MDC/parsing failures
            default:
                XCTFail("Expected integrityCheckFailed, corruptData, or noMatchingKey, got \(error)")
            }
        } catch let error as PgpError {
            switch error {
            case .IntegrityCheckFailed, .CorruptData, .NoMatchingKey:
                break
            default:
                XCTFail("Expected IntegrityCheckFailed, CorruptData, or NoMatchingKey, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(type(of: error))")
        }
    }

    func test_decrypt_profileB_tamperedCiphertext_throwsAEADError() async throws {
        let (identity, binaryCiphertext, _) = try await encryptAndPreparePhase1(
            profile: .advanced
        )

        // Flip one bit near the middle of the ciphertext
        var tampered = binaryCiphertext
        let midpoint = tampered.count / 2
        tampered[midpoint] ^= 0x01

        // Construct Phase1Result with tampered data
        let recipientKeyIds = try stack.engine.parseRecipients(ciphertext: binaryCiphertext)
        let phase1 = DecryptionService.Phase1Result(
            recipientKeyIds: recipientKeyIds,
            matchedKey: identity,
            ciphertext: tampered
        )

        // Phase 2 should fail — AEAD hard-fail (Profile B / SEIPDv2)
        do {
            _ = try await stack.decryptionService.decrypt(phase1: phase1)
            XCTFail("Expected AEAD hard-fail on tampered ciphertext")
        } catch let error as CypherAirError {
            // Profile B (SEIPDv2 AEAD): bit-flip may corrupt the AEAD payload
            // (→ aeadAuthenticationFailed), the framing (→ corruptData/integrityCheckFailed),
            // or the recipient key ID (→ noMatchingKey).
            switch error {
            case .aeadAuthenticationFailed, .integrityCheckFailed, .corruptData, .noMatchingKey:
                break // acceptable AEAD/parsing failures
            default:
                XCTFail("Expected aeadAuthenticationFailed, integrityCheckFailed, corruptData, or noMatchingKey, got \(error)")
            }
        } catch let error as PgpError {
            switch error {
            case .AeadAuthenticationFailed, .IntegrityCheckFailed, .CorruptData, .NoMatchingKey:
                break
            default:
                XCTFail("Expected AeadAuthenticationFailed, IntegrityCheckFailed, CorruptData, or NoMatchingKey, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(type(of: error))")
        }
    }

    // MARK: - Full Round-Trip via Engine (Encrypt → Decrypt)

    func test_encryptDecrypt_profileA_fullRoundTrip() async throws {
        let plaintext = "Full round-trip Profile A 你好"
        let (identity, binaryCiphertext, _) = try await encryptAndPreparePhase1(
            profile: .universal, plaintext: plaintext
        )

        // Unwrap the private key and decrypt directly via engine
        var secretKey = try stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }

        let verificationKeys = [identity.publicKeyData]
        let result = try stack.engine.decrypt(
            ciphertext: binaryCiphertext,
            secretKeys: [secretKey],
            verificationKeys: verificationKeys
        )

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
    }

    func test_encryptDecrypt_profileB_fullRoundTrip() async throws {
        let plaintext = "Full round-trip Profile B 加密"
        let (identity, binaryCiphertext, _) = try await encryptAndPreparePhase1(
            profile: .advanced, plaintext: plaintext
        )

        var secretKey = try stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }

        let result = try stack.engine.decrypt(
            ciphertext: binaryCiphertext,
            secretKeys: [secretKey],
            verificationKeys: [identity.publicKeyData]
        )

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
    }

    func test_encryptDecrypt_unicodePreserved() async throws {
        let plaintext = "Unicode: 你好世界 🔐🛡️ Ñoño café ü∑ß"
        let (identity, binaryCiphertext, _) = try await encryptAndPreparePhase1(
            profile: .universal, plaintext: plaintext
        )

        var secretKey = try stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }

        let result = try stack.engine.decrypt(
            ciphertext: binaryCiphertext,
            secretKeys: [secretKey],
            verificationKeys: [identity.publicKeyData]
        )

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
    }

    // MARK: - Phase 2 via DecryptionService (with prepared Phase1Result)

    func test_decryptViaService_profileA_fullFlow() async throws {
        let plaintext = "Service layer decrypt Profile A"
        let (_, _, phase1) = try await encryptAndPreparePhase1(
            profile: .universal, plaintext: plaintext, sign: true
        )

        let result = try await stack.decryptionService.decrypt(phase1: phase1)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
        XCTAssertEqual(result.signature.status, .valid)
    }

    func test_decryptViaService_profileB_fullFlow() async throws {
        let plaintext = "Service layer decrypt Profile B"
        let (_, _, phase1) = try await encryptAndPreparePhase1(
            profile: .advanced, plaintext: plaintext, sign: true
        )

        let result = try await stack.decryptionService.decrypt(phase1: phase1)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
        XCTAssertEqual(result.signature.status, .valid)
    }

    // MARK: - End-to-End via decryptMessage() (Phase 1 + Phase 2)

    func test_decryptMessage_profileA_endToEnd() async throws {
        let plaintext = "End-to-end Profile A 你好"
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            plaintext,
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: identity.fingerprint,
            encryptToSelf: false
        )

        // decryptMessage exercises both Phase 1 (parseRecipients) and Phase 2 (decrypt)
        let result = try await stack.decryptionService.decryptMessage(ciphertext: ciphertext)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
        XCTAssertEqual(result.signature.status, .valid)
    }

    func test_decryptMessage_profileB_endToEnd() async throws {
        let plaintext = "End-to-end Profile B 加密"
        let identity = try await TestHelpers.generateProfileBKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            plaintext,
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: identity.fingerprint,
            encryptToSelf: false
        )

        let result = try await stack.decryptionService.decryptMessage(ciphertext: ciphertext)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
        XCTAssertEqual(result.signature.status, .valid)
    }

    func test_parseRecipients_profileA_matchesCorrectKey() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            "match test",
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        let phase1 = try await stack.decryptionService.parseRecipients(ciphertext: ciphertext)

        XCTAssertEqual(phase1.matchedKey?.fingerprint, identity.fingerprint,
                       "Should match the correct Profile A key")
        XCTAssertFalse(phase1.recipientKeyIds.isEmpty,
                       "Should return matched fingerprints")
    }

    func test_parseRecipients_profileB_matchesCorrectKey() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            "match test",
            recipientFingerprints: [identity.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        let phase1 = try await stack.decryptionService.parseRecipients(ciphertext: ciphertext)

        XCTAssertEqual(phase1.matchedKey?.fingerprint, identity.fingerprint,
                       "Should match the correct Profile B key")
    }

    // MARK: - H1: High Security Biometrics Blocking

    func test_decrypt_highSecurity_biometricsUnavailable_throwsAuthError() async throws {
        let (_, _, phase1) = try await encryptAndPreparePhase1(profile: .universal)

        // Simulate High Security mode with biometrics unavailable
        stack.mockSE.simulatedAuthMode = .highSecurity
        stack.mockSE.biometricsAvailable = false

        do {
            _ = try await stack.decryptionService.decrypt(phase1: phase1)
            XCTFail("Expected authentication error when biometrics unavailable in High Security mode")
        } catch {
            // The error propagates from MockSEError.authenticationFailed through
            // KeyManagementService.unwrapPrivateKey → CypherAirError
            // Accept any error here — the key invariant is that decryption does NOT succeed
        }
    }
}
