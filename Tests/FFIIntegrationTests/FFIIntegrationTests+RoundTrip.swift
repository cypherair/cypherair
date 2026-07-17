import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    // MARK: - Binary Round-Trip

    /// Generate key → encrypt → decrypt. Verify Data↔Vec<u8> integrity.
    func test_binaryRoundTrip_legacy_dataPreservedAcrossFFI() throws {
        let plaintext = Data("Hello from Swift to Rust and back!".utf8)

        let generated = try engine.generateKey(
            name: "Test User A",
            email: "test-a@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [generated.publicKeyData],
            signingKey: generated.certData,
            encryptToSelf: nil
        )

        XCTAssertFalse(ciphertext.isEmpty, "Ciphertext should not be empty")
        XCTAssertNotEqual(ciphertext, plaintext, "Ciphertext should differ from plaintext")

        let result = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [generated.certData],
            verificationKeys: [generated.publicKeyData]
        )

        XCTAssertEqual(result.plaintext, plaintext, "Decrypted data must match original plaintext")
    }

    /// Same round-trip for Modern High (v6, Ed448+X448, SEIPDv2).
    func test_binaryRoundTrip_modernHigh_dataPreservedAcrossFFI() throws {
        let plaintext = Data("Modern High round-trip test data with binary: \0\u{01}\u{FF}".utf8)

        let generated = try engine.generateKey(
            name: "Test User B",
            email: "test-b@example.com",
            expirySeconds: nil,
            suite: .ed448X448
        )

        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [generated.publicKeyData],
            signingKey: generated.certData,
            encryptToSelf: nil
        )

        let result = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [generated.certData],
            verificationKeys: [generated.publicKeyData]
        )

        XCTAssertEqual(result.plaintext, plaintext)
    }

    /// Large data round-trip (1 MB) Legacy to stress the RustBuffer transfer.
    func test_binaryRoundTrip_largeData_1MB_legacy() throws {
        var plaintext = Data(count: 1_000_000)
        for i in 0..<plaintext.count {
            plaintext[i] = UInt8(i % 256)
        }

        let generated = try engine.generateKey(
            name: "Large Data A",
            email: nil,
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [generated.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let result = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [generated.certData],
            verificationKeys: []
        )

        XCTAssertEqual(result.plaintext, plaintext, "1 MB data must survive FFI round-trip (Legacy)")
    }

    /// Large data round-trip (1 MB) Modern High (SEIPDv2 AEAD).
    func test_binaryRoundTrip_largeData_1MB_modernHigh() throws {
        var plaintext = Data(count: 1_000_000)
        for i in 0..<plaintext.count {
            plaintext[i] = UInt8(i % 256)
        }

        let generated = try engine.generateKey(
            name: "Large Data B",
            email: nil,
            expirySeconds: nil,
            suite: .ed448X448
        )

        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [generated.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let result = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [generated.certData],
            verificationKeys: []
        )

        XCTAssertEqual(result.plaintext, plaintext, "1 MB data must survive FFI round-trip (Modern High)")
    }

    // MARK: - Unicode Round-Trip

    /// Chinese + emoji + special Unicode characters survive FFI.
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
            suite: .ed25519LegacyCurve25519Legacy
        )

        for testString in testStrings {
            let plaintext = Data(testString.utf8)

            let ciphertext = try engine.encrypt(
                plaintext: plaintext,
                recipients: [generated.publicKeyData],
                signingKey: nil,
                encryptToSelf: nil
            )

            let result = try engine.decryptDetailed(
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

    /// Unicode user ID survives key generation and parseKeyInfo.
    func test_unicodeRoundTrip_userIdPreserved() throws {
        let chineseName = "张三"
        let generated = try engine.generateKey(
            name: chineseName,
            email: "zhangsan@例え.jp",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        XCTAssertNotNil(keyInfo.userId, "userId must not be nil")
        XCTAssertTrue(
            keyInfo.userId?.contains(chineseName) == true,
            "Chinese name must survive FFI: got '\(keyInfo.userId ?? "nil")'"
        )
    }

    // MARK: - KeySuite Enum

    /// The classical software suites generate keys with all expected components,
    /// and the engine's parse-side classification round-trips each suite.
    func test_keySuiteEnum_classicalSuites_generateCompleteKeys() throws {
        for suite in [KeySuite.ed25519LegacyCurve25519Legacy, KeySuite.ed448X448] {
            let key = try engine.generateKey(
                name: "Complete \(suite)",
                email: "test@example.com",
                expirySeconds: 86400 * 365,
                suite: suite
            )

            XCTAssertFalse(key.publicKeyData.isEmpty, "\(suite) public key must not be empty")
            XCTAssertFalse(key.certData.isEmpty, "\(suite) secret key must not be empty")
            XCTAssertFalse(key.revocationCert.isEmpty, "\(suite) revocation cert must not be empty")
            XCTAssertFalse(key.fingerprint.isEmpty, "\(suite) fingerprint must not be empty")

            let info = try engine.parseKeyInfo(keyData: key.publicKeyData)
            XCTAssertTrue(info.userId?.contains("Complete") == true, "\(suite) user ID must contain name")
            XCTAssertTrue(info.hasEncryptionSubkey, "\(suite) must have encryption subkey")
        }
    }
}
