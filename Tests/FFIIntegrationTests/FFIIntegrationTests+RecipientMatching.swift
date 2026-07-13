import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    // MARK: - Phase 1/Phase 2 Two-Phase Decryption Tests

    /// Verify Phase 1 (parseRecipients) returns key IDs for Legacy ciphertext.
    func test_parseRecipients_legacy_returnsMatchingKeyIDs() throws {
        let engine = try XCTUnwrap(self.engine)
        let key = try engine.generateKey(name: "Phase1 A", email: nil, expirySeconds: nil, profile: .universal)
        let ciphertext = try engine.encrypt(
            plaintext: Data("Phase 1 test".utf8),
            recipients: [key.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let recipientKeyIDs = try engine.parseRecipients(ciphertext: ciphertext)
        XCTAssertFalse(recipientKeyIDs.isEmpty, "Phase 1 must identify at least one recipient")
    }

    /// Verify Phase 1 (parseRecipients) returns key IDs for Modern High ciphertext.
    func test_parseRecipients_modernHigh_returnsMatchingKeyIDs() throws {
        let engine = try XCTUnwrap(self.engine)
        let key = try engine.generateKey(name: "Phase1 B", email: nil, expirySeconds: nil, profile: .advanced)
        let ciphertext = try engine.encrypt(
            plaintext: Data("Phase 1 advanced".utf8),
            recipients: [key.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let recipientKeyIDs = try engine.parseRecipients(ciphertext: ciphertext)
        XCTAssertFalse(recipientKeyIDs.isEmpty, "Phase 1 must identify at least one recipient for Modern High")
    }

    /// Phase 1 succeeds (no auth), Phase 2 fails with wrong key.
    func test_twoPhaseDecrypt_noMatchingKey_phase1SucceedsPhase2Fails() throws {
        let engine = try XCTUnwrap(self.engine)
        let encryptKey = try engine.generateKey(name: "Encrypt Key", email: nil, expirySeconds: nil, profile: .universal)
        let wrongKey = try engine.generateKey(name: "Wrong Key", email: nil, expirySeconds: nil, profile: .universal)

        let ciphertext = try engine.encrypt(
            plaintext: Data("secret message".utf8),
            recipients: [encryptKey.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        // Phase 1: parseRecipients succeeds (no private key needed)
        let recipientKeyIDs = try engine.parseRecipients(ciphertext: ciphertext)
        XCTAssertFalse(recipientKeyIDs.isEmpty)

        // Phase 2: decrypt with wrong key should fail
        XCTAssertThrowsError(try engine.decryptDetailed(ciphertext: ciphertext, secretKeys: [wrongKey.certData], verificationKeys: [])) { error in
            // Accept any PgpError — the key doesn't match
            XCTAssertTrue(error is PgpError, "Expected PgpError, got \(type(of: error))")
        }
    }

    /// parseRecipients on garbage data should throw an error.
    func test_parseRecipients_garbageData_throwsError() {
        guard let engine = self.engine else { return }
        let garbage = Data([0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertThrowsError(try engine.parseRecipients(ciphertext: garbage)) { error in
            XCTAssertTrue(error is PgpError, "Expected PgpError for garbage input, got \(type(of: error))")
        }
    }

    /// Multi-recipient: both recipients can decrypt (Phase 1 shows ≥2 IDs, Phase 2 works for each).
    func test_twoPhaseDecrypt_multiRecipient_bothCanDecrypt() throws {
        let engine = try XCTUnwrap(self.engine)
        let alice = try engine.generateKey(name: "Alice Multi", email: nil, expirySeconds: nil, profile: .universal)
        let bob = try engine.generateKey(name: "Bob Multi", email: nil, expirySeconds: nil, profile: .universal)

        let plaintext = "multi-recipient message"
        let ciphertext = try engine.encrypt(
            plaintext: Data(plaintext.utf8),
            recipients: [alice.publicKeyData, bob.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        // Phase 1: should identify at least 2 recipients
        let recipientKeyIDs = try engine.parseRecipients(ciphertext: ciphertext)
        XCTAssertGreaterThanOrEqual(recipientKeyIDs.count, 2, "Phase 1 should find both recipients")

        // Phase 2: Alice can decrypt
        let resultAlice = try engine.decryptDetailed(ciphertext: ciphertext, secretKeys: [alice.certData], verificationKeys: [])
        XCTAssertEqual(String(data: resultAlice.plaintext, encoding: .utf8), plaintext)

        // Phase 2: Bob can decrypt
        let resultBob = try engine.decryptDetailed(ciphertext: ciphertext, secretKeys: [bob.certData], verificationKeys: [])
        XCTAssertEqual(String(data: resultBob.plaintext, encoding: .utf8), plaintext)
    }

    // MARK: - matchRecipients FFI Tests

    /// matchRecipients returns primary fingerprint for Legacy (v4) key.
    func test_matchRecipients_legacy_returnsPrimaryFingerprint() throws {
        let engine = try XCTUnwrap(self.engine)
        let key = try engine.generateKey(name: "Match A", email: nil, expirySeconds: nil, profile: .universal)

        let ciphertext = try engine.encrypt(
            plaintext: Data("match test".utf8),
            recipients: [key.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let matched = try engine.matchRecipients(
            ciphertext: ciphertext,
            localCerts: [key.publicKeyData]
        )

        XCTAssertEqual(matched.count, 1, "Should match exactly one certificate")
        XCTAssertEqual(matched.first, key.fingerprint.lowercased(),
                       "Should return the primary fingerprint")
    }

    /// matchRecipients returns primary fingerprint for Modern High (v6) key.
    func test_matchRecipients_modernHigh_returnsPrimaryFingerprint() throws {
        let engine = try XCTUnwrap(self.engine)
        let key = try engine.generateKey(name: "Match B", email: nil, expirySeconds: nil, profile: .advanced)

        let ciphertext = try engine.encrypt(
            plaintext: Data("match test B".utf8),
            recipients: [key.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let matched = try engine.matchRecipients(
            ciphertext: ciphertext,
            localCerts: [key.publicKeyData]
        )

        XCTAssertEqual(matched.count, 1, "Should match exactly one certificate")
        XCTAssertEqual(matched.first, key.fingerprint.lowercased(),
                       "Should return the primary fingerprint for Modern High")
    }

    /// matchRecipients throws NoMatchingKey when no local cert matches.
    func test_matchRecipients_wrongCert_throwsNoMatchingKey() throws {
        let engine = try XCTUnwrap(self.engine)
        let encryptKey = try engine.generateKey(name: "Encrypt", email: nil, expirySeconds: nil, profile: .universal)
        let wrongKey = try engine.generateKey(name: "Wrong", email: nil, expirySeconds: nil, profile: .universal)

        let ciphertext = try engine.encrypt(
            plaintext: Data("no match".utf8),
            recipients: [encryptKey.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        XCTAssertThrowsError(
            try engine.matchRecipients(
                ciphertext: ciphertext,
                localCerts: [wrongKey.publicKeyData]
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .NoMatchingKey:
                break // expected
            default:
                XCTFail("Expected NoMatchingKey, got \(pgpError)")
            }
        }
    }

    /// matchRecipients with multi-recipient message returns all matching certs.
    func test_matchRecipients_multiRecipient_returnsAllMatches() throws {
        let engine = try XCTUnwrap(self.engine)
        let alice = try engine.generateKey(name: "Alice MR", email: nil, expirySeconds: nil, profile: .universal)
        let bob = try engine.generateKey(name: "Bob MR", email: nil, expirySeconds: nil, profile: .universal)

        let ciphertext = try engine.encrypt(
            plaintext: Data("multi-recipient".utf8),
            recipients: [alice.publicKeyData, bob.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let matched = try engine.matchRecipients(
            ciphertext: ciphertext,
            localCerts: [alice.publicKeyData, bob.publicKeyData]
        )

        XCTAssertEqual(matched.count, 2, "Should match both recipients")
        XCTAssertTrue(matched.contains(alice.fingerprint.lowercased()))
        XCTAssertTrue(matched.contains(bob.fingerprint.lowercased()))
    }
}
