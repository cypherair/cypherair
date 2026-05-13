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

    private func contactId(for identity: PGPKeyIdentity) throws -> String {
        try XCTUnwrap(stack.contactService.contactId(forFingerprint: identity.fingerprint))
    }

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
            recipientContactIds: [try contactId(for: identity)],
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
            recipientContactIds: [try contactId(for: identity)],
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
            recipientContactIds: [try contactId(for: identity)],
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
            recipientContactIds: [try contactId(for: identity)],
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
            recipientContactIds: [try contactId(for: identity)],
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

        let result = try await stack.decryptionService.decryptDetailed(phase1: phase1)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
    }

    func test_decrypt_phase2_profileB_returnsPlaintext() async throws {
        let plaintext = "Profile B secret message 🛡️"
        let (_, _, phase1) = try await encryptAndPreparePhase1(
            profile: .advanced, plaintext: plaintext
        )

        let result = try await stack.decryptionService.decryptDetailed(phase1: phase1)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
    }

    func test_decrypt_phase2_withSignature_returnsValidVerification() async throws {
        let (_, _, phase1) = try await encryptAndPreparePhase1(
            profile: .universal, sign: true
        )

        let result = try await stack.decryptionService.decryptDetailed(phase1: phase1)

        XCTAssertEqual(result.verification.legacyStatus, .valid,
                       "Signed message should verify with .valid status")
    }

    func test_decrypt_phase2_triggersSeUnwrap() async throws {
        let (_, _, phase1) = try await encryptAndPreparePhase1(profile: .universal)

        let unwrapCountBefore = stack.mockSE.unwrapCallCount

        _ = try await stack.decryptionService.decryptDetailed(phase1: phase1)

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
            _ = try await stack.decryptionService.decryptDetailed(phase1: phase1)
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
            _ = try await stack.decryptionService.decryptDetailed(phase1: phase1)
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
            _ = try await stack.decryptionService.decryptDetailed(phase1: phase1)
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
        var secretKey = try await stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }

        let verificationKeys = [identity.publicKeyData]
        let result = try stack.engine.decryptDetailed(
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

        var secretKey = try await stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }

        let result = try stack.engine.decryptDetailed(
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

        var secretKey = try await stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }

        let result = try stack.engine.decryptDetailed(
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

        let result = try await stack.decryptionService.decryptDetailed(phase1: phase1)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
        XCTAssertEqual(result.verification.legacyStatus, .valid)
    }

    func test_decryptViaService_profileB_fullFlow() async throws {
        let plaintext = "Service layer decrypt Profile B"
        let (_, _, phase1) = try await encryptAndPreparePhase1(
            profile: .advanced, plaintext: plaintext, sign: true
        )

        let result = try await stack.decryptionService.decryptDetailed(phase1: phase1)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
        XCTAssertEqual(result.verification.legacyStatus, .valid)
    }

    // MARK: - End-to-End via decryptMessage() (Phase 1 + Phase 2)

    func test_decryptMessage_profileA_endToEnd() async throws {
        let plaintext = "End-to-end Profile A 你好"
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            plaintext,
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: identity.fingerprint,
            encryptToSelf: false
        )

        // decryptMessage exercises both Phase 1 (parseRecipients) and Phase 2 (decrypt)
        let result = try await stack.decryptionService.decryptMessageDetailed(ciphertext: ciphertext)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
        XCTAssertEqual(result.verification.legacyStatus, .valid)
    }

    func test_decryptMessage_profileB_endToEnd() async throws {
        let plaintext = "End-to-end Profile B 加密"
        let identity = try await TestHelpers.generateProfileBKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            plaintext,
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: identity.fingerprint,
            encryptToSelf: false
        )

        let result = try await stack.decryptionService.decryptMessageDetailed(ciphertext: ciphertext)

        let decryptedText = String(data: result.plaintext, encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
        XCTAssertEqual(result.verification.legacyStatus, .valid)
    }

    func test_parseRecipients_profileA_matchesCorrectKey() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement)
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            "match test",
            recipientContactIds: [try contactId(for: identity)],
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
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        let phase1 = try await stack.decryptionService.parseRecipients(ciphertext: ciphertext)

        XCTAssertEqual(phase1.matchedKey?.fingerprint, identity.fingerprint,
                       "Should match the correct Profile B key")
    }

    // MARK: - Detailed Results

    func test_decryptDetailed_validOwnKeySigner_resolvesOwnKey() async throws {
        let sender = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: .universal,
            name: "Detailed Sender",
            email: "detailed-sender@example.com"
        )
        let recipient = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: .universal,
            name: "Detailed Recipient",
            email: "detailed-recipient@example.com"
        )

        let plaintext = Data("Detailed decrypt own-key signer".utf8)
        var senderSecret = try await stack.keyManagement.unwrapPrivateKey(fingerprint: sender.fingerprint)
        defer { senderSecret.resetBytes(in: 0..<senderSecret.count) }

        let ciphertext = try stack.engine.encryptBinary(
            plaintext: plaintext,
            recipients: [recipient.publicKeyData],
            signingKey: senderSecret,
            encryptToSelf: nil
        )
        let phase1 = try makePhase1(matchedKey: recipient, ciphertext: ciphertext)

        let unwrapBefore = stack.mockSE.unwrapCallCount
        let detailed = try await stack.decryptionService.decryptDetailed(phase1: phase1)
        XCTAssertEqual(
            stack.mockSE.unwrapCallCount,
            unwrapBefore + 1,
            "Detailed decrypt should unwrap exactly once"
        )
        XCTAssertEqual(detailed.plaintext, plaintext)
        XCTAssertEqual(detailed.verification.signatures.count, 1)
        XCTAssertEqual(detailed.verification.signatures[0].status, .valid)
        XCTAssertEqual(
            detailed.verification.signatures[0].signerPrimaryFingerprint,
            sender.fingerprint
        )
        XCTAssertEqual(
            detailed.verification.signatures[0].signerIdentity?.source,
            .ownKey
        )
        XCTAssertEqual(
            detailed.verification.signatures[0].signerIdentity?.fingerprint,
            sender.fingerprint
        )
    }

    func test_decryptDetailed_unsigned_returnsEmptySignaturesAndNotSigned() async throws {
        let recipient = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Unsigned Detailed Recipient"
        )
        let plaintext = Data("Unsigned detailed decrypt".utf8)
        let ciphertext = try stack.engine.encryptBinary(
            plaintext: plaintext,
            recipients: [recipient.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let phase1 = try makePhase1(matchedKey: recipient, ciphertext: ciphertext)

        try await stack.contactService.relockProtectedData()
        let detailed = try await stack.decryptionService.decryptDetailed(phase1: phase1)

        XCTAssertEqual(detailed.plaintext, plaintext)
        XCTAssertEqual(detailed.verification.legacyStatus, .notSigned)
        XCTAssertTrue(detailed.verification.signatures.isEmpty)
    }

    func test_decryptDetailed_fixtureMultiSigner_preservesEntriesAndContactResolution()
        async throws
    {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerB = try loadFixture("ffi_detailed_signer_b")
        let recipientSecret = try loadFixture("ffi_detailed_recipient_secret")
        let ciphertext = try loadFixture("ffi_detailed_multisig_encrypted")

        let signerAInfo = try stack.engine.parseKeyInfo(keyData: signerA)
        let signerBInfo = try stack.engine.parseKeyInfo(keyData: signerB)
        try stack.contactService.addContact(publicKeyData: signerA)
        try stack.contactService.addContact(publicKeyData: signerB)

        let identity = try TestHelpers.provisionFixtureBackedIdentity(
            secretCertData: recipientSecret,
            engine: stack.engine,
            service: stack.keyManagement,
            mockSE: stack.mockSE,
            mockKC: stack.mockKC,
            isDefault: true
        )
        let phase1 = try makePhase1(matchedKey: identity, ciphertext: ciphertext)

        let detailed = try await stack.decryptionService.decryptDetailed(phase1: phase1)
        let expected = try stack.engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [recipientSecret],
            verificationKeys: [signerA, signerB]
        )

        XCTAssertEqual(detailed.plaintext, expected.plaintext)
        XCTAssertEqual(detailed.verification.legacyStatus, expected.legacyStatus)
        XCTAssertEqual(
            detailed.verification.legacySignerFingerprint,
            expected.legacySignerFingerprint
        )
        assertDetailedEntriesMatchFFI(
            detailed.verification.signatures,
            expected.signatures
        )
        XCTAssertEqual(
            detailed.verification.signatures.map(\.signerPrimaryFingerprint),
            [signerBInfo.fingerprint, signerAInfo.fingerprint]
        )
        XCTAssertTrue(detailed.verification.signatures.allSatisfy {
            $0.signerIdentity?.source == .contact
        })
    }

    func test_decryptDetailed_runtimeUnknownSigner_returnsUnknownEntryWithoutFingerprint()
        async throws
    {
        let recipient = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Unknown Detailed Recipient"
        )
        let externalSigner = try stack.engine.generateKey(
            name: "Unknown Detailed Signer",
            email: "unknown-detailed@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let plaintext = Data("Unknown signer detailed decrypt".utf8)

        let ciphertext = try stack.engine.encryptBinary(
            plaintext: plaintext,
            recipients: [recipient.publicKeyData],
            signingKey: externalSigner.certData,
            encryptToSelf: nil
        )
        let phase1 = try makePhase1(matchedKey: recipient, ciphertext: ciphertext)

        try await stack.contactService.relockProtectedData()
        let detailed = try await stack.decryptionService.decryptDetailed(phase1: phase1)

        XCTAssertEqual(detailed.plaintext, plaintext)
        XCTAssertEqual(detailed.verification.legacyStatus, .unknownSigner)
        XCTAssertNil(detailed.verification.legacySignerFingerprint)
        XCTAssertEqual(detailed.verification.summaryState, .contactsContextUnavailable)
        XCTAssertEqual(detailed.verification.contactsUnavailableReason, .locked)
        XCTAssertTrue(detailed.verification.legacyVerification.requiresContactsContext)
        XCTAssertEqual(detailed.verification.signatures.count, 1)
        XCTAssertEqual(detailed.verification.signatures[0].status, .unknownSigner)
        XCTAssertEqual(detailed.verification.signatures[0].verificationState, .contactsContextUnavailable)
        XCTAssertEqual(detailed.verification.signatures[0].contactsUnavailableReason, .locked)
        XCTAssertNil(detailed.verification.signatures[0].signerPrimaryFingerprint)
        XCTAssertNil(detailed.verification.signatures[0].signerIdentity)
    }

    func test_decryptDetailed_noMatchedKey_throwsNoMatchingKeyWithoutUnwrap() async throws {
        let phase1 = DecryptionService.Phase1Result(
            recipientKeyIds: ["unknown"],
            matchedKey: nil,
            ciphertext: Data()
        )
        let unwrapBefore = stack.mockSE.unwrapCallCount

        do {
            _ = try await stack.decryptionService.decryptDetailed(phase1: phase1)
            XCTFail("Expected noMatchingKey")
        } catch {
            assertCypherAirError(error) { if case .noMatchingKey = $0 { return true } else { return false } }
        }

        XCTAssertEqual(stack.mockSE.unwrapCallCount, unwrapBefore)
    }

    func test_decryptDetailed_profileA_midpointBitFlip_rejectsTamperedCiphertext()
        async throws
    {
        let (identity, binaryCiphertext, _) = try await encryptAndPreparePhase1(
            profile: .universal
        )
        var tampered = binaryCiphertext
        tampered[tampered.count / 2] ^= 0x01
        let phase1 = DecryptionService.Phase1Result(
            recipientKeyIds: try stack.engine.parseRecipients(ciphertext: binaryCiphertext),
            matchedKey: identity,
            ciphertext: tampered
        )

        do {
            _ = try await stack.decryptionService.decryptDetailed(phase1: phase1)
            XCTFail("Expected midpoint corruption to hard-fail")
        } catch {
            assertCypherAirError(error) {
                switch $0 {
                case .integrityCheckFailed, .corruptData, .noMatchingKey:
                    return true
                default:
                    return false
                }
            }
        }
    }

    func test_decryptDetailed_profileA_targetedTamper_throwsIntegrityCheckFailed()
        async throws
    {
        let (identity, binaryCiphertext, _) = try await encryptAndPreparePhase1(
            profile: .universal
        )
        var secretKey = try await stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }
        let tampered = try findTargetedDecryptTamper(
            ciphertext: binaryCiphertext,
            secretKeys: [secretKey],
            verificationKeys: [identity.publicKeyData],
            acceptedErrors: [.IntegrityCheckFailed]
        )
        let phase1 = DecryptionService.Phase1Result(
            recipientKeyIds: try stack.engine.parseRecipients(ciphertext: binaryCiphertext),
            matchedKey: identity,
            ciphertext: tampered
        )

        do {
            _ = try await stack.decryptionService.decryptDetailed(phase1: phase1)
            XCTFail("Expected targeted Profile A tamper to surface integrityCheckFailed")
        } catch {
            assertCypherAirError(error) {
                if case .integrityCheckFailed = $0 { return true }
                return false
            }
        }
    }

    func test_decryptDetailed_profileB_midpointBitFlip_hardFailsWithMappedSecurityError()
        async throws
    {
        let (identity, binaryCiphertext, _) = try await encryptAndPreparePhase1(
            profile: .advanced
        )
        var tampered = binaryCiphertext
        tampered[tampered.count / 2] ^= 0x01
        let phase1 = DecryptionService.Phase1Result(
            recipientKeyIds: try stack.engine.parseRecipients(ciphertext: binaryCiphertext),
            matchedKey: identity,
            ciphertext: tampered
        )

        do {
            _ = try await stack.decryptionService.decryptDetailed(phase1: phase1)
            XCTFail("Expected self-generated Profile B midpoint corruption to hard-fail")
        } catch {
            // Self-generated v6 PKESK + SEIPDv2 messages may fail session-key recovery
            // before payload AEAD validation, so NoMatchingKey remains acceptable here.
            assertCypherAirError(error) {
                switch $0 {
                case .aeadAuthenticationFailed, .integrityCheckFailed, .corruptData, .noMatchingKey:
                    return true
                default:
                    return false
                }
            }
        }
    }

    func test_decryptMessageDetailed_endToEnd_matchesChainedPhases() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Detailed Message Recipient"
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let ciphertext = try await stack.encryptionService.encryptText(
            "Detailed message end-to-end",
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: identity.fingerprint,
            encryptToSelf: false
        )

        let endToEnd = try await stack.decryptionService.decryptMessageDetailed(ciphertext: ciphertext)
        let phase1 = try await stack.decryptionService.parseRecipients(ciphertext: ciphertext)
        let chained = try await stack.decryptionService.decryptDetailed(phase1: phase1)

        XCTAssertEqual(endToEnd.plaintext, chained.plaintext)
        XCTAssertEqual(endToEnd.verification, chained.verification)
    }

    func test_decryptFileStreamingDetailed_fixtureMultiSigner_matchesInMemoryDetailed()
        async throws
    {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerB = try loadFixture("ffi_detailed_signer_b")
        let recipientSecret = try loadFixture("ffi_detailed_recipient_secret")
        let ciphertext = try loadFixture("ffi_detailed_multisig_encrypted")

        try stack.contactService.addContact(publicKeyData: signerA)
        try stack.contactService.addContact(publicKeyData: signerB)
        let identity = try TestHelpers.provisionFixtureBackedIdentity(
            secretCertData: recipientSecret,
            engine: stack.engine,
            service: stack.keyManagement,
            mockSE: stack.mockSE,
            mockKC: stack.mockKC,
            isDefault: true
        )

        let inputURL = try makeTemporaryFile(
            named: "ffi-detailed-multisig-encrypted.gpg",
            contents: ciphertext
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: inputURL)
        let detailed = try await stack.decryptionService.decryptFileStreamingDetailed(
            phase1: phase1,
            progress: nil
        )
        defer { detailed.artifact.cleanup() }

        let inMemory = try await stack.decryptionService.decryptDetailed(
            phase1: makePhase1(matchedKey: identity, ciphertext: ciphertext)
        )
        let expectedOutputURL = makeTemporaryOutputURL(
            named: "ffi-detailed-multisig-expected.bin"
        )
        let expected = try stack.engine.decryptFileDetailed(
            inputPath: inputURL.path,
            outputPath: expectedOutputURL.path,
            secretKeys: [recipientSecret],
            verificationKeys: [signerA, signerB],
            progress: nil
        )
        defer { try? FileManager.default.removeItem(at: expectedOutputURL) }

        XCTAssertEqual(try Data(contentsOf: detailed.artifact.fileURL), inMemory.plaintext)
        XCTAssertEqual(detailed.verification.legacyStatus, inMemory.verification.legacyStatus)
        assertDetailedEntriesMatchFFI(
            detailed.verification.signatures,
            expected.signatures
        )
        XCTAssertEqual(detailed.verification.signatures, inMemory.verification.signatures)
        XCTAssertTrue(detailed.verification.signatures.allSatisfy {
            $0.signerIdentity?.source == .contact
        })
    }

    func test_decryptFileStreamingDetailed_runtimeUnknownSigner_matchesInMemoryDetailed()
        async throws
    {
        let recipient = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Unknown File Detailed Recipient"
        )
        let externalSigner = try stack.engine.generateKey(
            name: "Unknown File Detailed Signer",
            email: "unknown-file-detailed@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let plaintext = Data("Unknown signer detailed file decrypt".utf8)
        let ciphertext = try stack.engine.encryptBinary(
            plaintext: plaintext,
            recipients: [recipient.publicKeyData],
            signingKey: externalSigner.certData,
            encryptToSelf: nil
        )

        let inputURL = try makeTemporaryFile(
            named: "unknown-signer-detailed.gpg",
            contents: ciphertext
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: inputURL)
        try await stack.contactService.relockProtectedData()
        let detailed = try await stack.decryptionService.decryptFileStreamingDetailed(
            phase1: phase1,
            progress: nil
        )
        defer { detailed.artifact.cleanup() }

        let inMemory = try await stack.decryptionService.decryptDetailed(
            phase1: makePhase1(matchedKey: recipient, ciphertext: ciphertext)
        )

        XCTAssertEqual(try Data(contentsOf: detailed.artifact.fileURL), plaintext)
        XCTAssertEqual(detailed.verification, inMemory.verification)
        XCTAssertEqual(detailed.verification.signatures.count, 1)
        XCTAssertEqual(detailed.verification.signatures[0].status, .unknownSigner)
        XCTAssertEqual(detailed.verification.signatures[0].verificationState, .contactsContextUnavailable)
        XCTAssertNil(detailed.verification.signatures[0].signerPrimaryFingerprint)
        XCTAssertNil(detailed.verification.signatures[0].signerIdentity)
    }

    func test_decryptFileStreamingDetailed_fixtureRepeatedSigner_preservesRepeatedEntries()
        async throws
    {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let recipientSecret = try loadFixture("ffi_detailed_recipient_secret")
        let ciphertext = try loadFixture("ffi_detailed_repeated_encrypted")
        let signerAInfo = try stack.engine.parseKeyInfo(keyData: signerA)

        try stack.contactService.addContact(publicKeyData: signerA)
        _ = try TestHelpers.provisionFixtureBackedIdentity(
            secretCertData: recipientSecret,
            engine: stack.engine,
            service: stack.keyManagement,
            mockSE: stack.mockSE,
            mockKC: stack.mockKC,
            isDefault: true
        )

        let inputURL = try makeTemporaryFile(
            named: "ffi-detailed-repeated-encrypted.gpg",
            contents: ciphertext
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: inputURL)
        let detailed = try await stack.decryptionService.decryptFileStreamingDetailed(
            phase1: phase1,
            progress: nil
        )
        defer { detailed.artifact.cleanup() }

        XCTAssertEqual(detailed.verification.signatures.count, 2)
        XCTAssertEqual(
            detailed.verification.signatures.map(\.signerPrimaryFingerprint),
            [signerAInfo.fingerprint, signerAInfo.fingerprint]
        )
        XCTAssertTrue(detailed.verification.signatures.allSatisfy {
            $0.status == .valid && $0.signerIdentity?.source == .contact
        })
    }

    func test_decryptFileStreamingDetailed_cancellation_throwsMappedOperationCancelledAndCleansUp()
        async throws
    {
        let recipient = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Detailed Cancel Recipient"
        )
        try stack.contactService.addContact(publicKeyData: recipient.publicKeyData)

        let plaintextURL = try makeTemporaryFile(
            named: "detailed-cancel.txt",
            contents: Data(repeating: 0x42, count: 256 * 1024)
        )
        defer { try? FileManager.default.removeItem(at: plaintextURL) }

        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: plaintextURL,
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        let encryptedURL = encryptedArtifact.fileURL
        defer { encryptedArtifact.cleanup() }

        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedURL)
        try cleanupDecryptedOperationArtifacts()

        let progress = FileProgressReporter()
        progress.cancel()

        do {
            _ = try await stack.decryptionService.decryptFileStreamingDetailed(
                phase1: phase1,
                progress: progress
            )
            XCTFail("Expected operationCancelled")
        } catch {
            assertCypherAirError(error) {
                if case .operationCancelled = $0 { return true }
                return false
            }
        }

        try assertNoDecryptedOperationArtifacts()
    }

    func test_decryptFileStreamingDetailed_profileA_midpointBitFlip_rejectsTamperedFileAndCleansUp()
        async throws
    {
        let identity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Detailed Tampered File A"
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let plaintextURL = try makeTemporaryFile(
            named: "detailed-tampered-a.txt",
            contents: Data("Detailed tampered file A".utf8)
        )
        defer { try? FileManager.default.removeItem(at: plaintextURL) }

        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: plaintextURL,
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        let encryptedURL = encryptedArtifact.fileURL
        defer { encryptedArtifact.cleanup() }

        var encryptedData = try Data(contentsOf: encryptedURL)
        encryptedData[encryptedData.count / 2] ^= 0x01
        try encryptedData.write(to: encryptedURL, options: .atomic)

        let phase1 = DecryptionService.FilePhase1Result(
            recipientKeyIds: [identity.fingerprint],
            matchedKey: identity,
            inputPath: encryptedURL.path
        )
        try cleanupDecryptedOperationArtifacts()

        do {
            _ = try await stack.decryptionService.decryptFileStreamingDetailed(
                phase1: phase1,
                progress: nil
            )
            XCTFail("Expected midpoint file corruption to hard-fail")
        } catch {
            assertCypherAirError(error) {
                switch $0 {
                case .integrityCheckFailed, .corruptData, .noMatchingKey:
                    return true
                default:
                    return false
                }
            }
        }

        try assertNoDecryptedOperationArtifacts()
    }

    func test_decryptFileStreamingDetailed_profileA_targetedTamper_throwsIntegrityCheckFailedAndCleansUp()
        async throws
    {
        let identity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Detailed Targeted File A"
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let plaintextURL = try makeTemporaryFile(
            named: "detailed-targeted-a.txt",
            contents: Data("Detailed targeted file A".utf8)
        )
        defer { try? FileManager.default.removeItem(at: plaintextURL) }

        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: plaintextURL,
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        let encryptedURL = encryptedArtifact.fileURL
        defer { encryptedArtifact.cleanup() }

        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedURL)
        let originalCiphertext = try Data(contentsOf: encryptedURL)
        var secretKey = try await stack.keyManagement.unwrapPrivateKey(fingerprint: identity.fingerprint)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }
        let targetedCiphertext = try findTargetedDecryptTamper(
            ciphertext: originalCiphertext,
            secretKeys: [secretKey],
            verificationKeys: [],
            acceptedErrors: [.IntegrityCheckFailed]
        )
        try targetedCiphertext.write(to: encryptedURL, options: .atomic)

        try cleanupDecryptedOperationArtifacts()

        do {
            _ = try await stack.decryptionService.decryptFileStreamingDetailed(
                phase1: phase1,
                progress: nil
            )
            XCTFail("Expected targeted Profile A file tamper to surface integrityCheckFailed")
        } catch {
            assertCypherAirError(error) {
                if case .integrityCheckFailed = $0 { return true }
                return false
            }
        }

        try assertNoDecryptedOperationArtifacts()
    }

    func test_decryptFileStreamingDetailed_profileB_midpointBitFlip_hardFailsAndCleansUp()
        async throws
    {
        let identity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Detailed Tampered File B"
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        let plaintextURL = try makeTemporaryFile(
            named: "detailed-tampered-b.txt",
            contents: Data("Detailed tampered file B".utf8)
        )
        defer { try? FileManager.default.removeItem(at: plaintextURL) }

        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: plaintextURL,
            recipientContactIds: [try contactId(for: identity)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        let encryptedURL = encryptedArtifact.fileURL
        defer { encryptedArtifact.cleanup() }

        var encryptedData = try Data(contentsOf: encryptedURL)
        encryptedData[encryptedData.count / 2] ^= 0x01
        try encryptedData.write(to: encryptedURL, options: .atomic)

        let phase1 = DecryptionService.FilePhase1Result(
            recipientKeyIds: [identity.fingerprint],
            matchedKey: identity,
            inputPath: encryptedURL.path
        )
        try cleanupDecryptedOperationArtifacts()

        do {
            _ = try await stack.decryptionService.decryptFileStreamingDetailed(
                phase1: phase1,
                progress: nil
            )
            XCTFail("Expected self-generated Profile B file corruption to hard-fail")
        } catch {
            // Self-generated v6 PKESK + SEIPDv2 messages may fail session-key recovery
            // before payload AEAD validation, so NoMatchingKey remains acceptable here.
            assertCypherAirError(error) {
                switch $0 {
                case .aeadAuthenticationFailed, .integrityCheckFailed, .corruptData, .noMatchingKey:
                    return true
                default:
                    return false
                }
            }
        }

        try assertNoDecryptedOperationArtifacts()
    }

    // MARK: - H1: High Security Biometrics Blocking

    func test_decrypt_highSecurity_biometricsUnavailable_throwsAuthError() async throws {
        let (_, _, phase1) = try await encryptAndPreparePhase1(profile: .universal)

        // Simulate High Security mode with biometrics unavailable
        stack.mockSE.simulatedAuthMode = .highSecurity
        stack.mockSE.biometricsAvailable = false

        do {
            _ = try await stack.decryptionService.decryptDetailed(phase1: phase1)
            XCTFail("Expected authentication error when biometrics unavailable in High Security mode")
        } catch {
            // The error propagates from MockSEError.authenticationFailed through
            // KeyManagementService.unwrapPrivateKey → CypherAirError
            // Accept any error here — the key invariant is that decryption does NOT succeed
        }
    }

    // MARK: - Detailed Test Helpers

    private func loadFixture(_ name: String, ext: String = "gpg") throws -> Data {
        try FixtureLoader.loadData(name, ext: ext)
    }

    private func makeTemporaryFile(named name: String, contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirDetailedDecryptTests-\(UUID().uuidString)-\(name)")
        try contents.write(to: url, options: .atomic)
        return url
    }

    private func makeTemporaryOutputURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirDetailedDecryptTests-\(UUID().uuidString)-\(name)")
    }

    private func findTargetedDecryptTamper(
        ciphertext: Data,
        secretKeys: [Data],
        verificationKeys: [Data],
        acceptedErrors: [PgpError]
    ) throws -> Data {
        let positions = [
            max(ciphertext.count - 8, 0),
            max(ciphertext.count - 16, 0),
            max(ciphertext.count - 24, 0),
            max(ciphertext.count - 32, 0),
            max(ciphertext.count - 48, 0),
            max(ciphertext.count - 64, 0),
            ciphertext.count * 3 / 4,
        ]

        for position in positions where position < ciphertext.count {
            var tampered = ciphertext
            tampered[position] ^= 0x01

            do {
                _ = try stack.engine.decryptDetailed(
                    ciphertext: tampered,
                    secretKeys: secretKeys,
                    verificationKeys: verificationKeys
                )
            } catch let error as PgpError where acceptedErrors.contains(error) {
                return tampered
            } catch {
                continue
            }
        }

        XCTFail("Could not locate a deterministic decrypt auth/integrity tamper position")
        return ciphertext
    }

    private func makePhase1(
        matchedKey: PGPKeyIdentity,
        ciphertext: Data
    ) throws -> DecryptionService.Phase1Result {
        DecryptionService.Phase1Result(
            recipientKeyIds: try stack.engine.parseRecipients(ciphertext: ciphertext),
            matchedKey: matchedKey,
            ciphertext: ciphertext
        )
    }

    private func cleanupDecryptedOperationArtifacts() throws {
        let decryptedDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("decrypted", isDirectory: true)
        guard FileManager.default.fileExists(atPath: decryptedDir.path) else { return }
        for url in try FileManager.default.contentsOfDirectory(at: decryptedDir, includingPropertiesForKeys: nil)
            where url.lastPathComponent.hasPrefix("op-") {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private func assertNoDecryptedOperationArtifacts(
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let decryptedDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("decrypted", isDirectory: true)
        guard FileManager.default.fileExists(atPath: decryptedDir.path) else { return }
        let remaining = try FileManager.default.contentsOfDirectory(at: decryptedDir, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("op-") }
        XCTAssertTrue(remaining.isEmpty, file: file, line: line)
    }

    private func assertDetailedEntriesMatchFFI(
        _ actual: [DetailedSignatureVerification.Entry],
        _ expected: [DetailedSignatureEntry],
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(actual.count, expected.count, file: file, line: line)
        for (actualEntry, expectedEntry) in zip(actual, expected) {
            XCTAssertEqual(
                actualEntry.status,
                detailedStatus(from: expectedEntry.status),
                file: file,
                line: line
            )
            XCTAssertEqual(
                actualEntry.signerPrimaryFingerprint,
                expectedEntry.signerPrimaryFingerprint,
                file: file,
                line: line
            )
        }
    }

    private func detailedStatus(
        from status: DetailedSignatureStatus
    ) -> DetailedSignatureVerification.Entry.Status {
        switch status {
        case .valid:
            return .valid
        case .unknownSigner:
            return .unknownSigner
        case .bad:
            return .bad
        case .expired:
            return .expired
        }
    }

    private func assertCypherAirError(
        _ error: Error,
        file: StaticString = #filePath,
        line: UInt = #line,
        matches matcher: (CypherAirError) -> Bool
    ) {
        guard let cypherAirError = error as? CypherAirError else {
            return XCTFail(
                "Expected CypherAirError, got \(type(of: error)): \(error)",
                file: file,
                line: line
            )
        }
        XCTAssertTrue(
            matcher(cypherAirError),
            "Unexpected CypherAirError: \(cypherAirError)",
            file: file,
            line: line
        )
    }
}
