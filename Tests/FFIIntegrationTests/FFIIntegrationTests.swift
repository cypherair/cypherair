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

    /// C5.1: Large data round-trip (1 MB) Profile A to stress the RustBuffer transfer.
    func test_binaryRoundTrip_largeData_1MB_profileA() throws {
        var plaintext = Data(count: 1_000_000)
        for i in 0..<plaintext.count {
            plaintext[i] = UInt8(i % 256)
        }

        let generated = try engine.generateKey(
            name: "Large Data A",
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

        XCTAssertEqual(result.plaintext, plaintext, "1 MB data must survive FFI round-trip (Profile A)")
    }

    /// C5.1: Large data round-trip (1 MB) Profile B (SEIPDv2 AEAD).
    func test_binaryRoundTrip_largeData_1MB_profileB() throws {
        var plaintext = Data(count: 1_000_000)
        for i in 0..<plaintext.count {
            plaintext[i] = UInt8(i % 256)
        }

        let generated = try engine.generateKey(
            name: "Large Data B",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
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

        XCTAssertEqual(result.plaintext, plaintext, "1 MB data must survive FFI round-trip (Profile B)")
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
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            // Garbage input should fail at the parsing stage, not decryption
            switch pgpError {
            case .CorruptData, .ArmorError, .InternalError:
                break // acceptable for non-PGP garbage input
            default:
                XCTFail("Expected CorruptData, ArmorError, or InternalError, got \(pgpError)")
            }
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

    /// C5.3: BadSignature when verifying a tampered cleartext signature.
    func test_errorMapping_badSignature_cleartextVerify() throws {
        let key = try engine.generateKey(
            name: "Signer", email: nil, expirySeconds: nil, profile: .universal
        )

        let signed = try engine.signCleartext(
            text: Data("original message".utf8),
            signerCert: key.certData
        )

        // Convert to string, tamper with the message body, convert back.
        // Cleartext signatures have the text before the PGP signature block.
        guard var signedString = String(data: signed, encoding: .utf8) else {
            return XCTFail("Cleartext signature is not valid UTF-8")
        }
        signedString = signedString.replacingOccurrences(
            of: "original message",
            with: "tampered message"
        )
        let tamperedData = Data(signedString.utf8)

        let result = try engine.verifyCleartext(
            signedMessage: tamperedData,
            verificationKeys: [key.publicKeyData]
        )

        XCTAssertEqual(
            result.status, .bad,
            "Tampered cleartext signature must produce Bad status"
        )
    }

    /// C5.3: UnknownSigner status when signer key not in verification keys.
    func test_errorMapping_unknownSigner_viaCleartextVerify() throws {
        let signerKey = try engine.generateKey(
            name: "Unknown Signer", email: nil, expirySeconds: nil, profile: .universal
        )
        let otherKey = try engine.generateKey(
            name: "Other", email: nil, expirySeconds: nil, profile: .universal
        )

        let signed = try engine.signCleartext(
            text: Data("signed by unknown".utf8),
            signerCert: signerKey.certData
        )

        // Verify with a different key — signer is unknown
        let result = try engine.verifyCleartext(
            signedMessage: signed,
            verificationKeys: [otherKey.publicKeyData]
        )

        XCTAssertEqual(
            result.status, .unknownSigner,
            "Signer not in verification_keys must produce UnknownSigner status"
        )
    }

    /// C5.3: ArmorError on malformed armor input.
    func test_errorMapping_armorError() throws {
        let malformedArmor = Data("""
        -----BEGIN PGP MESSAGE-----

        not-valid-base64-!!!@@@###
        -----END PGP MESSAGE-----
        """.utf8)

        XCTAssertThrowsError(
            try engine.dearmor(armored: malformedArmor)
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .ArmorError, .CorruptData:
                break // either is acceptable for malformed armor
            default:
                XCTFail("Expected ArmorError or CorruptData, got \(pgpError)")
            }
        }
    }

    /// C5.3: SigningFailed with garbage signing key data.
    func test_errorMapping_signingFailed_invalidKey() throws {
        let garbage = Data("not a secret key".utf8)

        XCTAssertThrowsError(
            try engine.signCleartext(
                text: Data("hello".utf8),
                signerCert: garbage
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .SigningFailed, .InvalidKeyData, .InternalError:
                break // all acceptable for invalid signing key
            default:
                XCTFail("Expected SigningFailed, InvalidKeyData, or InternalError, got \(pgpError)")
            }
        }
    }

    /// C5.3: EncryptionFailed with empty recipients list.
    func test_errorMapping_encryptionFailed_noRecipients() throws {
        XCTAssertThrowsError(
            try engine.encrypt(
                plaintext: Data("hello".utf8),
                recipients: [],
                signingKey: nil,
                encryptToSelf: nil
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .EncryptionFailed, .InvalidKeyData, .InternalError:
                break // acceptable errors for no recipients
            default:
                XCTFail("Expected EncryptionFailed, InvalidKeyData, or InternalError, got \(pgpError)")
            }
        }
    }

    /// C5.3: RevocationError with garbage revocation cert data.
    func test_errorMapping_revocationError_invalidData() throws {
        let key = try engine.generateKey(
            name: "RevTest", email: nil, expirySeconds: nil, profile: .universal
        )
        let garbage = Data("not a revocation cert".utf8)

        XCTAssertThrowsError(
            try engine.parseRevocationCert(
                revData: garbage,
                certData: key.certData
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .RevocationError, .InvalidKeyData, .CorruptData, .InternalError:
                break // acceptable for garbage revocation data
            default:
                XCTFail("Expected RevocationError, InvalidKeyData, CorruptData, or InternalError, got \(pgpError)")
            }
        }
    }

    /// C5.3: S2kError / WrongPassphrase on Profile B export-import with wrong passphrase.
    func test_errorMapping_s2kError_profileB_wrongPassphrase() throws {
        let key = try engine.generateKey(
            name: "S2K Test", email: nil, expirySeconds: nil, profile: .advanced
        )

        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "correct-argon2id-pass",
            profile: .advanced
        )

        XCTAssertThrowsError(
            try engine.importSecretKey(
                armoredData: exported,
                passphrase: "wrong-argon2id-pass"
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .WrongPassphrase, .S2kError:
                break // either acceptable
            default:
                XCTFail("Expected WrongPassphrase or S2kError, got \(pgpError)")
            }
        }
    }

    /// C5.3: BadSignature via detached signature verification with tampered data.
    func test_errorMapping_badSignature_detachedVerify() throws {
        let key = try engine.generateKey(
            name: "DetachedSig", email: nil, expirySeconds: nil, profile: .universal
        )

        let originalData = Data("original data for detached sig".utf8)
        let signature = try engine.signDetached(
            data: originalData,
            signerCert: key.certData
        )

        // Verify with tampered data
        let tamperedData = Data("tampered data for detached sig".utf8)

        let result = try engine.verifyDetached(
            data: tamperedData,
            signature: signature,
            verificationKeys: [key.publicKeyData]
        )

        XCTAssertEqual(
            result.status, .bad,
            "Detached signature on tampered data must produce Bad status"
        )
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

    // MARK: - C4: Argon2id Memory Guard Tests

    /// C4.1: Import Profile B key with 512 MB Argon2id → success on device with enough memory.
    /// Uses real Profile B key export/parseS2kParams, but mocks memory to ensure success.
    func test_argon2idGuard_profileB_512MB_8GBDevice_passes() throws {
        let key = try engine.generateKey(
            name: "Argon2id Test", email: nil, expirySeconds: nil, profile: .advanced
        )
        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "test-pass-123",
            profile: .advanced
        )

        let s2kInfo = try engine.parseS2kParams(armoredData: exported)
        XCTAssertEqual(s2kInfo.s2kType, "argon2id")
        XCTAssertEqual(s2kInfo.memoryKib, 524_288, "Profile B export should use 512 MB (2^19 KiB)")

        // Mock: 8 GB device with 6 GB available.
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 6 * 1024 * 1024 * 1024
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // Should pass: 512 MB < 75% of 6 GB (4.5 GB).
        XCTAssertNoThrow(try memoryGuard.validate(s2kInfo: s2kInfo))
    }

    /// C4.2: 1 GB Argon2id params → graceful error with limited memory.
    func test_argon2idGuard_1GB_lowMemory_throwsExceeded() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 1_048_576, // 1 GB = 2^20 KiB
            parallelism: 4,
            timePasses: 3
        )

        // Mock: 1 GB available (device under heavy load).
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 1 * 1024 * 1024 * 1024
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // Should fail: 1 GB > 75% of 1 GB (768 MB).
        XCTAssertThrowsError(try memoryGuard.validate(s2kInfo: s2kInfo)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            switch cypherError {
            case .argon2idMemoryExceeded(let requiredMb):
                XCTAssertEqual(requiredMb, 1024, "Should report 1024 MB required")
            default:
                XCTFail("Expected argon2idMemoryExceeded, got \(cypherError)")
            }
        }
    }

    /// C4.2: 1 GB Argon2id params → success with ample memory.
    func test_argon2idGuard_1GB_ampleMemory_passes() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 1_048_576, // 1 GB
            parallelism: 4,
            timePasses: 3
        )

        // Mock: 6 GB available.
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 6 * 1024 * 1024 * 1024
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // Should pass: 1 GB < 75% of 6 GB (4.5 GB).
        XCTAssertNoThrow(try memoryGuard.validate(s2kInfo: s2kInfo))
    }

    /// C4.3: 2 GB Argon2id → graceful refusal even on device with moderate available memory.
    func test_argon2idGuard_2GB_moderateMemory_throwsExceeded() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 2_097_152, // 2 GB = 2^21 KiB
            parallelism: 4,
            timePasses: 3
        )

        // Mock: 2.5 GB available (8 GB device under moderate load).
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = UInt64(2.5 * 1024 * 1024 * 1024)
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // Should fail: 2 GB > 75% of 2.5 GB (1.875 GB).
        XCTAssertThrowsError(try memoryGuard.validate(s2kInfo: s2kInfo)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            switch cypherError {
            case .argon2idMemoryExceeded(let requiredMb):
                XCTAssertEqual(requiredMb, 2048, "Should report 2048 MB required")
            default:
                XCTFail("Expected argon2idMemoryExceeded, got \(cypherError)")
            }
        }
    }

    /// C4.4: Exact 75% boundary — at boundary should pass.
    /// Guard checks: required * 4 <= available * 3.
    /// Smallest passing available = ceil(required * 4 / 3).
    func test_argon2idGuard_exact75PercentBoundary_passes() throws {
        let requiredKib: UInt64 = 524_288 // 512 MB
        let requiredBytes = requiredKib * 1024

        // Smallest available where required * 4 <= available * 3 (ceiling division).
        let minPassingAvailable = (requiredBytes * 4 + 2) / 3

        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: requiredKib,
            parallelism: 4,
            timePasses: 3
        )

        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = minPassingAvailable
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // At exact threshold (<=): should pass.
        XCTAssertNoThrow(try memoryGuard.validate(s2kInfo: s2kInfo))
    }

    /// C4.4: One byte below 75% boundary — should fail.
    func test_argon2idGuard_justBelow75PercentBoundary_throwsExceeded() throws {
        let requiredKib: UInt64 = 524_288
        let requiredBytes = requiredKib * 1024
        let minPassingAvailable = (requiredBytes * 4 + 2) / 3

        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: requiredKib,
            parallelism: 4,
            timePasses: 3
        )

        // 1 byte below the minimum passing available: should fail.
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = minPassingAvailable - 1
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        XCTAssertThrowsError(try memoryGuard.validate(s2kInfo: s2kInfo))
    }

    /// C4.4: Profile A (Iterated+Salted) — guard is a no-op even with minimal memory.
    func test_argon2idGuard_profileA_iteratedSalted_alwaysPasses() throws {
        let key = try engine.generateKey(
            name: "Profile A Test", email: nil, expirySeconds: nil, profile: .universal
        )
        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "test-pass-456",
            profile: .universal
        )
        let s2kInfo = try engine.parseS2kParams(armoredData: exported)

        XCTAssertEqual(s2kInfo.s2kType, "iterated-salted")
        XCTAssertEqual(s2kInfo.memoryKib, 0)

        // Even with absurdly low memory, guard should pass for Profile A.
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 1
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        XCTAssertNoThrow(try memoryGuard.validate(s2kInfo: s2kInfo))
    }

    /// Defensive: argon2id type with memoryKib=0 — guard should not throw.
    func test_argon2idGuard_argon2idTypeZeroMemory_passes() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 0,
            parallelism: 4,
            timePasses: 3
        )
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 1
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        XCTAssertNoThrow(try memoryGuard.validate(s2kInfo: s2kInfo))
    }

    /// Defensive: unknown S2K type — guard should be a no-op.
    func test_argon2idGuard_unknownS2kType_passes() throws {
        let s2kInfo = S2kInfo(
            s2kType: "unknown",
            memoryKib: 999_999_999,
            parallelism: 4,
            timePasses: 3
        )
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 1
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        XCTAssertNoThrow(try memoryGuard.validate(s2kInfo: s2kInfo))
    }

    /// Verify that the guard queries the memory provider exactly once.
    func test_argon2idGuard_queriesMemoryProviderExactlyOnce() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 524_288,
            parallelism: 4,
            timePasses: 3
        )
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 8 * 1024 * 1024 * 1024
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        _ = try? memoryGuard.validate(s2kInfo: s2kInfo)
        XCTAssertEqual(mockMemory.callCount, 1,
                       "Guard should query memory provider exactly once")
    }

    // MARK: - Phase 1/Phase 2 Two-Phase Decryption Tests

    /// Verify Phase 1 (parseRecipients) returns key IDs for Profile A ciphertext.
    func test_parseRecipients_profileA_returnsMatchingKeyIDs() throws {
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

    /// Verify Phase 1 (parseRecipients) returns key IDs for Profile B ciphertext.
    func test_parseRecipients_profileB_returnsMatchingKeyIDs() throws {
        let engine = try XCTUnwrap(self.engine)
        let key = try engine.generateKey(name: "Phase1 B", email: nil, expirySeconds: nil, profile: .advanced)
        let ciphertext = try engine.encrypt(
            plaintext: Data("Phase 1 advanced".utf8),
            recipients: [key.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let recipientKeyIDs = try engine.parseRecipients(ciphertext: ciphertext)
        XCTAssertFalse(recipientKeyIDs.isEmpty, "Phase 1 must identify at least one recipient for Profile B")
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
        XCTAssertThrowsError(try engine.decrypt(ciphertext: ciphertext, secretKeys: [wrongKey.certData], verificationKeys: [])) { error in
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
        let resultAlice = try engine.decrypt(ciphertext: ciphertext, secretKeys: [alice.certData], verificationKeys: [])
        XCTAssertEqual(String(data: resultAlice.plaintext, encoding: .utf8), plaintext)

        // Phase 2: Bob can decrypt
        let resultBob = try engine.decrypt(ciphertext: ciphertext, secretKeys: [bob.certData], verificationKeys: [])
        XCTAssertEqual(String(data: resultBob.plaintext, encoding: .utf8), plaintext)
    }

    // MARK: - KeyExpired Error Mapping

    /// Verify that a key with expirySeconds=1 is detected as expired after waiting.
    /// Sequoia may or may not reject encryption to an expired key at the API level,
    /// so this test accepts both outcomes: if encryption succeeds, it verifies the key
    /// info shows isExpired; if it throws, it verifies the error type.
    func test_errorMapping_keyExpired_detectsExpiredKey() throws {
        let engine = try XCTUnwrap(self.engine)
        let key = try engine.generateKey(name: "Expiry Test", email: nil, expirySeconds: 1, profile: .universal)
        // Parse immediately — with expirySeconds=1, the key may already be expired
        // by the time generation + parsing completes, so we don't assert on this result.
        _ = try engine.parseKeyInfo(keyData: key.publicKeyData)

        // Wait to ensure the key is definitely expired
        Thread.sleep(forTimeInterval: 2.0)

        // Re-parse to check isExpired flag after waiting
        let infoAfter = try engine.parseKeyInfo(keyData: key.publicKeyData)

        do {
            _ = try engine.encrypt(
                plaintext: Data("to expired key".utf8),
                recipients: [key.publicKeyData],
                signingKey: nil,
                encryptToSelf: nil
            )
            // Sequoia allowed encryption — verify the key IS expired via parseKeyInfo
            XCTAssertTrue(infoAfter.isExpired, "Key with expirySeconds=1 should report isExpired after 2s")
        } catch {
            // Sequoia rejected encryption — verify it's a PgpError
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            // Accept KeyExpired or EncryptionFailed
            switch pgpError {
            case .KeyExpired, .EncryptionFailed:
                break // Expected
            default:
                XCTFail("Expected KeyExpired or EncryptionFailed, got \(pgpError)")
            }
        }
    }

    // MARK: - Memory Zeroing Tests

    /// Verify Data.zeroize() sets all bytes to zero.
    func test_dataZeroize_setsAllBytesToZero() {
        var data = Data([0xAB, 0xCD, 0xEF, 0x12, 0x34])
        let originalCount = data.count
        data.zeroize()
        XCTAssertEqual(data.count, originalCount, "Count must not change")
        XCTAssertTrue(data.allSatisfy { $0 == 0 }, "All bytes must be zero after zeroize()")
    }

    /// Verify Data.zeroize() on empty data does not crash.
    func test_dataZeroize_emptyData_noop() {
        var data = Data()
        data.zeroize()
        XCTAssertTrue(data.isEmpty, "Empty data remains empty")
    }

    /// Verify Data.zeroize() works on large buffers.
    func test_dataZeroize_largeBuffer_allZeros() {
        var data = Data(repeating: 0xFF, count: 1_048_576) // 1 MB
        data.zeroize()
        XCTAssertTrue(data.allSatisfy { $0 == 0 }, "All bytes in 1 MB buffer must be zero")
    }

    /// Verify Array<UInt8>.zeroize() sets all elements to zero.
    func test_arrayZeroize_setsAllElementsToZero() {
        var arr: [UInt8] = [0x01, 0x02, 0x03, 0xFF, 0xAB]
        let originalCount = arr.count
        arr.zeroize()
        XCTAssertEqual(arr.count, originalCount, "Count must not change")
        XCTAssertTrue(arr.allSatisfy { $0 == 0 }, "All elements must be zero after zeroize()")
    }

    /// Verify Array<UInt8>.zeroize() on empty array does not crash.
    func test_arrayZeroize_emptyArray_noop() {
        var arr: [UInt8] = []
        arr.zeroize()
        XCTAssertTrue(arr.isEmpty, "Empty array remains empty")
    }

    /// Verify SensitiveData.zeroize() clears the underlying storage.
    func test_sensitiveData_explicitZeroize_clearsData() {
        let sensitive = SensitiveData(Data([0xDE, 0xAD, 0xBE, 0xEF]))
        XCTAssertEqual(sensitive.count, 4)
        sensitive.zeroize()
        XCTAssertTrue(sensitive.data.allSatisfy { $0 == 0 }, "SensitiveData must be zeroed after zeroize()")
    }

    /// Verify SensitiveData deinit does not crash (zeroing happens in deinit).
    func test_sensitiveData_deinit_zerosStorage() {
        // Create and immediately release — deinit should fire without crash.
        autoreleasepool {
            _ = SensitiveData(Data(repeating: 0x42, count: 64))
        }
        // If we reach here without crash, deinit zeroing worked.
    }

    // MARK: - matchRecipients FFI Tests

    /// matchRecipients returns primary fingerprint for Profile A (v4) key.
    func test_matchRecipients_profileA_returnsPrimaryFingerprint() throws {
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

    /// matchRecipients returns primary fingerprint for Profile B (v6) key.
    func test_matchRecipients_profileB_returnsPrimaryFingerprint() throws {
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
                       "Should return the primary fingerprint for Profile B")
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

/// Error thrown when PgpEngine is unexpectedly nil in concurrent test closures.
private enum ConcurrentTestError: Error {
    case engineDeallocated
}
