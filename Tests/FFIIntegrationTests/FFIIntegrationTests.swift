import XCTest
@testable import CypherAir

/// C5: FFI Boundary Integration Tests
/// Validates that data crosses the Rust↔Swift UniFFI boundary correctly.
final class FFIIntegrationTests: XCTestCase {

    private var engine: PgpEngine!

    override func setUp() {
        super.setUp()
        engine = PgpEngine()
    }

    override func tearDown() {
        engine = nil
        super.tearDown()
    }

    // MARK: - C5.1 Binary Round-Trip

    /// C5.1: Generate key → encrypt → decrypt. Verify Data↔Vec<u8> integrity.
    func test_binaryRoundTrip_profileA_dataPreservedAcrossFFI() throws {
        let plaintext = Data("Hello from Swift to Rust and back!".utf8)

        let generated = try engine.generateKey(
            name: "Test User A",
            email: "test-a@example.com",
            expirySeconds: nil,
            profile: .universal
        )

        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [generated.publicKeyData],
            signingKey: generated.certData,
            encryptToSelf: nil
        )

        XCTAssertFalse(ciphertext.isEmpty, "Ciphertext should not be empty")
        XCTAssertNotEqual(ciphertext, plaintext, "Ciphertext should differ from plaintext")

        let result = try engine.decrypt(
            ciphertext: ciphertext,
            secretKeys: [generated.certData],
            verificationKeys: [generated.publicKeyData]
        )

        XCTAssertEqual(result.plaintext, plaintext, "Decrypted data must match original plaintext")
    }

    /// C5.1: Same round-trip for Profile B (v6, Ed448+X448, SEIPDv2).
    func test_binaryRoundTrip_profileB_dataPreservedAcrossFFI() throws {
        let plaintext = Data("Profile B round-trip test data with binary: \0\u{01}\u{FF}".utf8)

        let generated = try engine.generateKey(
            name: "Test User B",
            email: "test-b@example.com",
            expirySeconds: nil,
            profile: .advanced
        )

        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [generated.publicKeyData],
            signingKey: generated.certData,
            encryptToSelf: nil
        )

        let result = try engine.decrypt(
            ciphertext: ciphertext,
            secretKeys: [generated.certData],
            verificationKeys: [generated.publicKeyData]
        )

        XCTAssertEqual(result.plaintext, plaintext)
    }

    /// C5.1: Large data round-trip (1 MB) to stress the RustBuffer transfer.
    func test_binaryRoundTrip_largeData_1MB() throws {
        var plaintext = Data(count: 1_000_000)
        for i in 0..<plaintext.count {
            plaintext[i] = UInt8(i % 256)
        }

        let generated = try engine.generateKey(
            name: "Large Data",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [generated.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let result = try engine.decrypt(
            ciphertext: ciphertext,
            secretKeys: [generated.certData],
            verificationKeys: []
        )

        XCTAssertEqual(result.plaintext, plaintext, "1 MB data must survive FFI round-trip")
    }

    // MARK: - C5.2 Unicode Round-Trip

    /// C5.2: Chinese + emoji + special Unicode characters survive FFI.
    func test_unicodeRoundTrip_chineseEmojiPreserved() throws {
        let testStrings = [
            "你好世界",
            "Hello, 你好, 🔐🌍🎉",
            "Zero-width: \u{200B}\u{200C}\u{200D}\u{FEFF}",
            "Combining: e\u{0301} n\u{0303}",
            "CJK: 你好世界こんにちは안녕하세요",
            "Emoji sequence: 👨‍👩‍👧‍👦 🏳️‍🌈 👩🏽‍💻",
            "Math: ∫∂∇×∞ ℝℂℤℚ",
            "Arabic: مرحبا بالعالم",
            "Mixed: Hello你好🌍مرحبا",
        ]

        let generated = try engine.generateKey(
            name: "Unicode测试用户🔑",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        for testString in testStrings {
            let plaintext = Data(testString.utf8)

            let ciphertext = try engine.encrypt(
                plaintext: plaintext,
                recipients: [generated.publicKeyData],
                signingKey: nil,
                encryptToSelf: nil
            )

            let result = try engine.decrypt(
                ciphertext: ciphertext,
                secretKeys: [generated.certData],
                verificationKeys: []
            )

            let decryptedString = String(data: result.plaintext, encoding: .utf8)
            XCTAssertEqual(
                decryptedString, testString,
                "Unicode string '\(testString)' must survive FFI round-trip"
            )
        }
    }

    /// C5.2: Unicode user ID survives key generation and parseKeyInfo.
    func test_unicodeRoundTrip_userIdPreserved() throws {
        let chineseName = "张三"
        let generated = try engine.generateKey(
            name: chineseName,
            email: "zhangsan@例え.jp",
            expirySeconds: nil,
            profile: .universal
        )

        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        XCTAssertNotNil(keyInfo.userId, "userId must not be nil")
        XCTAssertTrue(
            keyInfo.userId?.contains(chineseName) == true,
            "Chinese name must survive FFI: got '\(keyInfo.userId ?? "nil")'"
        )
    }

    // MARK: - C5.3 Error Enum Mapping

    /// C5.3: NoMatchingKey error when decrypting with wrong key.
    func test_errorMapping_noMatchingKey() throws {
        let keyA = try engine.generateKey(
            name: "Alice", email: nil, expirySeconds: nil, profile: .universal
        )
        let keyB = try engine.generateKey(
            name: "Bob", email: nil, expirySeconds: nil, profile: .universal
        )

        let ciphertext = try engine.encrypt(
            plaintext: Data("secret".utf8),
            recipients: [keyA.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        XCTAssertThrowsError(
            try engine.decrypt(
                ciphertext: ciphertext,
                secretKeys: [keyB.certData],
                verificationKeys: []
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

    /// C5.3: IntegrityCheckFailed / AeadAuthenticationFailed on tampered ciphertext.
    func test_errorMapping_integrityCheckFailed_profileA() throws {
        let key = try engine.generateKey(
            name: "Tamper A", email: nil, expirySeconds: nil, profile: .universal
        )

        var ciphertext = try engine.encrypt(
            plaintext: Data("tamper test".utf8),
            recipients: [key.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        // Flip a bit in the middle of the ciphertext
        let midpoint = ciphertext.count / 2
        ciphertext[midpoint] ^= 0x01

        XCTAssertThrowsError(
            try engine.decrypt(
                ciphertext: ciphertext,
                secretKeys: [key.certData],
                verificationKeys: []
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            // Profile A (SEIPDv1): bit-flip in armored ciphertext may corrupt
            // the encrypted payload (→ IntegrityCheckFailed), the armor framing
            // (→ CorruptData), or the recipient key ID (→ NoMatchingKey).
            switch pgpError {
            case .IntegrityCheckFailed, .CorruptData, .NoMatchingKey:
                break // all acceptable for armored ciphertext bit-flip
            default:
                XCTFail("Expected IntegrityCheckFailed, CorruptData, or NoMatchingKey, got \(pgpError)")
            }
        }
    }

    /// C5.3: AeadAuthenticationFailed on tampered Profile B (SEIPDv2) ciphertext.
    func test_errorMapping_aeadAuthenticationFailed_profileB() throws {
        let key = try engine.generateKey(
            name: "Tamper B", email: nil, expirySeconds: nil, profile: .advanced
        )

        var ciphertext = try engine.encrypt(
            plaintext: Data("tamper test AEAD".utf8),
            recipients: [key.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        // Flip a bit in the middle of the ciphertext
        let midpoint = ciphertext.count / 2
        ciphertext[midpoint] ^= 0x01

        XCTAssertThrowsError(
            try engine.decrypt(
                ciphertext: ciphertext,
                secretKeys: [key.certData],
                verificationKeys: []
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            // Profile B (SEIPDv2 AEAD): bit-flip may corrupt the AEAD payload
            // (→ AeadAuthenticationFailed), the armor framing (→ CorruptData),
            // or the recipient key ID (→ NoMatchingKey).
            switch pgpError {
            case .AeadAuthenticationFailed, .IntegrityCheckFailed, .CorruptData, .NoMatchingKey:
                break // all acceptable for armored ciphertext bit-flip
            default:
                XCTFail("Expected AeadAuthenticationFailed, IntegrityCheckFailed, CorruptData, or NoMatchingKey, got \(pgpError)")
            }
        }
    }

    /// C5.3: CorruptData on garbage input.
    func test_errorMapping_corruptData() throws {
        let key = try engine.generateKey(
            name: "Corrupt", email: nil, expirySeconds: nil, profile: .universal
        )

        let garbage = Data("this is not valid PGP data at all".utf8)

        XCTAssertThrowsError(
            try engine.decrypt(
                ciphertext: garbage,
                secretKeys: [key.certData],
                verificationKeys: []
            )
        ) { error in
            guard error is PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            // Any PgpError is acceptable for garbage input
        }
    }

    /// C5.3: WrongPassphrase on incorrect passphrase.
    func test_errorMapping_wrongPassphrase() throws {
        let key = try engine.generateKey(
            name: "Export", email: nil, expirySeconds: nil, profile: .universal
        )

        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "correct-password-123",
            profile: .universal
        )

        XCTAssertThrowsError(
            try engine.importSecretKey(
                armoredData: exported,
                passphrase: "wrong-password-456"
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .WrongPassphrase:
                break // expected
            default:
                XCTFail("Expected WrongPassphrase, got \(pgpError)")
            }
        }
    }

    /// C5.3: InvalidKeyData on garbage key input.
    func test_errorMapping_invalidKeyData() throws {
        let garbage = Data("not a key".utf8)

        XCTAssertThrowsError(
            try engine.parseKeyInfo(keyData: garbage)
        ) { error in
            guard error is PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
        }
    }

    // MARK: - C5.5 KeyProfile Enum

    /// C5.5: KeyProfile.universal → v4 key, KeyProfile.advanced → v6 key.
    func test_keyProfileEnum_universal_producesV4() throws {
        let key = try engine.generateKey(
            name: "Profile A", email: nil, expirySeconds: nil, profile: .universal
        )

        let version = try engine.getKeyVersion(certData: key.publicKeyData)
        XCTAssertEqual(version, 4, "KeyProfile.universal must produce v4 key")

        let detectedProfile = try engine.detectProfile(certData: key.publicKeyData)
        XCTAssertEqual(detectedProfile, .universal, "detectProfile must return .universal for v4 key")
    }

    /// C5.5: KeyProfile.advanced → v6 key.
    func test_keyProfileEnum_advanced_producesV6() throws {
        let key = try engine.generateKey(
            name: "Profile B", email: nil, expirySeconds: nil, profile: .advanced
        )

        let version = try engine.getKeyVersion(certData: key.publicKeyData)
        XCTAssertEqual(version, 6, "KeyProfile.advanced must produce v6 key")

        let detectedProfile = try engine.detectProfile(certData: key.publicKeyData)
        XCTAssertEqual(detectedProfile, .advanced, "detectProfile must return .advanced for v6 key")
    }

    /// C5.5: Both profiles generate keys with all expected components.
    func test_keyProfileEnum_bothProfiles_generateCompleteKeys() throws {
        for profile in [KeyProfile.universal, KeyProfile.advanced] {
            let key = try engine.generateKey(
                name: "Complete \(profile)",
                email: "test@example.com",
                expirySeconds: 86400 * 365,
                profile: profile
            )

            XCTAssertFalse(key.publicKeyData.isEmpty, "\(profile) public key must not be empty")
            XCTAssertFalse(key.certData.isEmpty, "\(profile) secret key must not be empty")
            XCTAssertFalse(key.revocationCert.isEmpty, "\(profile) revocation cert must not be empty")
            XCTAssertFalse(key.fingerprint.isEmpty, "\(profile) fingerprint must not be empty")

            let info = try engine.parseKeyInfo(keyData: key.publicKeyData)
            XCTAssertTrue(info.userId?.contains("Complete") == true, "\(profile) user ID must contain name")
            XCTAssertTrue(info.hasEncryptionSubkey, "\(profile) must have encryption subkey")
        }
    }

    // MARK: - C5.6 Concurrent Encrypt (Thread Safety)

    /// C5.6: 10 concurrent encryption tasks must all succeed.
    func test_concurrentEncrypt_threadsafe() async throws {
        let key = try engine.generateKey(
            name: "Concurrent", email: nil, expirySeconds: nil, profile: .universal
        )

        try await withThrowingTaskGroup(of: Data.self) { group in
            for i in 0..<10 {
                group.addTask { [engine] in
                    guard let engine else { throw ConcurrentTestError.engineDeallocated }
                    let plaintext = Data("Message \(i) for concurrent test".utf8)
                    return try engine.encrypt(
                        plaintext: plaintext,
                        recipients: [key.publicKeyData],
                        signingKey: nil,
                        encryptToSelf: nil
                    )
                }
            }

            var results: [Data] = []
            for try await ciphertext in group {
                XCTAssertFalse(ciphertext.isEmpty)
                results.append(ciphertext)
            }

            XCTAssertEqual(results.count, 10, "All 10 concurrent encryptions must succeed")
        }
    }

    // MARK: - C5.7 Concurrent Encrypt + Decrypt (Thread Safety)

    /// C5.7: Mixed concurrent encrypt and decrypt operations.
    func test_concurrentEncryptDecrypt_threadsafe() async throws {
        let key = try engine.generateKey(
            name: "MixedConcurrent", email: nil, expirySeconds: nil, profile: .universal
        )

        // Pre-encrypt some messages for decryption tasks
        var preCiphertexts: [Data] = []
        for i in 0..<5 {
            let ct = try engine.encrypt(
                plaintext: Data("Pre-encrypted \(i)".utf8),
                recipients: [key.publicKeyData],
                signingKey: nil,
                encryptToSelf: nil
            )
            preCiphertexts.append(ct)
        }

        try await withThrowingTaskGroup(of: Bool.self) { group in
            // 5 encrypt tasks
            for i in 0..<5 {
                group.addTask { [engine] in
                    guard let engine else { throw ConcurrentTestError.engineDeallocated }
                    let plaintext = Data("Encrypt task \(i)".utf8)
                    let ct = try engine.encrypt(
                        plaintext: plaintext,
                        recipients: [key.publicKeyData],
                        signingKey: nil,
                        encryptToSelf: nil
                    )
                    return !ct.isEmpty
                }
            }

            // 5 decrypt tasks
            for i in 0..<5 {
                let ct = preCiphertexts[i]
                group.addTask { [engine] in
                    guard let engine else { throw ConcurrentTestError.engineDeallocated }
                    let result = try engine.decrypt(
                        ciphertext: ct,
                        secretKeys: [key.certData],
                        verificationKeys: []
                    )
                    return !result.plaintext.isEmpty
                }
            }

            var successCount = 0
            for try await success in group {
                XCTAssertTrue(success)
                successCount += 1
            }

            XCTAssertEqual(successCount, 10, "All 10 concurrent operations must succeed")
        }
    }

    /// C5.7: Concurrent operations with Profile B (AEAD).
    func test_concurrentEncryptDecrypt_profileB_threadsafe() async throws {
        let key = try engine.generateKey(
            name: "ConcurrentB", email: nil, expirySeconds: nil, profile: .advanced
        )

        let preCiphertext = try engine.encrypt(
            plaintext: Data("Profile B concurrent".utf8),
            recipients: [key.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        try await withThrowingTaskGroup(of: Bool.self) { group in
            // Mix encrypt and decrypt
            for i in 0..<10 {
                if i % 2 == 0 {
                    group.addTask { [engine] in
                        guard let engine else { throw ConcurrentTestError.engineDeallocated }
                        let ct = try engine.encrypt(
                            plaintext: Data("B-\(i)".utf8),
                            recipients: [key.publicKeyData],
                            signingKey: nil,
                            encryptToSelf: nil
                        )
                        return !ct.isEmpty
                    }
                } else {
                    group.addTask { [engine] in
                        guard let engine else { throw ConcurrentTestError.engineDeallocated }
                        let result = try engine.decrypt(
                            ciphertext: preCiphertext,
                            secretKeys: [key.certData],
                            verificationKeys: []
                        )
                        return !result.plaintext.isEmpty
                    }
                }
            }

            var count = 0
            for try await success in group {
                XCTAssertTrue(success)
                count += 1
            }
            XCTAssertEqual(count, 10)
        }
    }
}

/// Error thrown when PgpEngine is unexpectedly nil in concurrent test closures.
private enum ConcurrentTestError: Error {
    case engineDeallocated
}
