import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    // MARK: - Error Enum Mapping

    /// NoMatchingKey error when decrypting with wrong key.
    func test_errorMapping_noMatchingKey() throws {
        let keyA = try engine.generateKey(
            name: "Alice", email: nil, expirySeconds: nil, suite: .ed25519LegacyCurve25519Legacy
        )
        let keyB = try engine.generateKey(
            name: "Bob", email: nil, expirySeconds: nil, suite: .ed25519LegacyCurve25519Legacy
        )

        let ciphertext = try engine.encrypt(
            plaintext: Data("secret".utf8),
            recipients: [keyA.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        XCTAssertThrowsError(
            try engine.decryptDetailed(
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

    /// IntegrityCheckFailed / AeadAuthenticationFailed on tampered ciphertext.
    func test_errorMapping_integrityCheckFailed_legacy() throws {
        let key = try engine.generateKey(
            name: "Tamper A", email: nil, expirySeconds: nil, suite: .ed25519LegacyCurve25519Legacy
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
            try engine.decryptDetailed(
                ciphertext: ciphertext,
                secretKeys: [key.certData],
                verificationKeys: []
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            // Legacy (SEIPDv1): bit-flip in armored ciphertext may corrupt
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

    /// AeadAuthenticationFailed on tampered Modern High (SEIPDv2) ciphertext.
    func test_errorMapping_aeadAuthenticationFailed_modernHigh() throws {
        let key = try engine.generateKey(
            name: "Tamper B", email: nil, expirySeconds: nil, suite: .ed448X448
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
            try engine.decryptDetailed(
                ciphertext: ciphertext,
                secretKeys: [key.certData],
                verificationKeys: []
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            // Modern High (SEIPDv2 AEAD): bit-flip may corrupt the AEAD payload
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

    /// CorruptData on garbage input.
    func test_errorMapping_corruptData() throws {
        let key = try engine.generateKey(
            name: "Corrupt", email: nil, expirySeconds: nil, suite: .ed25519LegacyCurve25519Legacy
        )

        let garbage = Data("this is not valid PGP data at all".utf8)

        XCTAssertThrowsError(
            try engine.decryptDetailed(
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

    /// WrongPassphrase on incorrect passphrase.
    func test_errorMapping_wrongPassphrase() throws {
        let key = try engine.generateKey(
            name: "Export", email: nil, expirySeconds: nil, suite: .ed25519LegacyCurve25519Legacy
        )

        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "correct-password-123"
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

    /// InvalidKeyData on garbage key input.
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

    func test_errorMapping_invalidKeyData_secretBearingCertificateMergeInput() throws {
        let generated = try engine.generateKey(
            name: "Merge Secret Reject",
            email: nil,
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        XCTAssertThrowsError(
            try engine.mergePublicCertificateUpdate(
                existingCert: generated.publicKeyData,
                incomingCertOrUpdate: generated.certData
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .InvalidKeyData:
                break
            default:
                XCTFail("Expected InvalidKeyData, got \(pgpError)")
            }
        }
    }

    /// BadSignature when verifying a tampered cleartext signature.
    func test_errorMapping_badSignature_cleartextVerify() throws {
        let key = try engine.generateKey(
            name: "Signer", email: nil, expirySeconds: nil, suite: .ed25519LegacyCurve25519Legacy
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

        let result = try engine.verifyCleartextDetailed(
            signedMessage: tamperedData,
            verificationKeys: [key.publicKeyData]
        )

        XCTAssertEqual(
            result.summaryState, .invalid,
            "Tampered cleartext signature must produce Invalid summary state"
        )
    }

    /// UnknownSigner status when signer key not in verification keys.
    func test_errorMapping_unknownSigner_viaCleartextVerify() throws {
        let signerKey = try engine.generateKey(
            name: "Unknown Signer", email: nil, expirySeconds: nil, suite: .ed25519LegacyCurve25519Legacy
        )
        let otherKey = try engine.generateKey(
            name: "Other", email: nil, expirySeconds: nil, suite: .ed25519LegacyCurve25519Legacy
        )

        let signed = try engine.signCleartext(
            text: Data("signed by unknown".utf8),
            signerCert: signerKey.certData
        )

        // Verify with a different key — signer is unknown
        let result = try engine.verifyCleartextDetailed(
            signedMessage: signed,
            verificationKeys: [otherKey.publicKeyData]
        )

        XCTAssertEqual(
            result.summaryState, .signerCertificateUnavailable,
            "Signer not in verification_keys must produce SignerCertificateUnavailable summary state"
        )
    }

    /// ArmorError on malformed armor input.
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

    /// SigningFailed with garbage signing key data.
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

    /// EncryptionFailed with empty recipients list.
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

    /// S2kError / WrongPassphrase on Modern High export-import with wrong passphrase.
    func test_errorMapping_s2kError_modernHigh_wrongPassphrase() throws {
        let key = try engine.generateKey(
            name: "S2K Test", email: nil, expirySeconds: nil, suite: .ed448X448
        )

        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "correct-argon2id-pass"
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

    /// BadSignature via detached signature verification with tampered data.
    func test_errorMapping_badSignature_detachedVerify() throws {
        let key = try engine.generateKey(
            name: "DetachedSig", email: nil, expirySeconds: nil, suite: .ed25519LegacyCurve25519Legacy
        )

        let originalData = Data("original data for detached sig".utf8)
        let originalURL = try writeTempFile(
            originalData,
            filename: "ffi-detached-original-\(UUID().uuidString).txt"
        )
        defer { try? FileManager.default.removeItem(at: originalURL) }
        let signature = try engine.signDetachedFile(
            inputPath: originalURL.path,
            signerCert: key.certData,
            progress: nil
        )

        // Verify with tampered data
        let tamperedData = Data("tampered data for detached sig".utf8)
        let tamperedURL = try writeTempFile(
            tamperedData,
            filename: "ffi-detached-tampered-\(UUID().uuidString).txt"
        )
        defer { try? FileManager.default.removeItem(at: tamperedURL) }

        let result = try engine.verifyDetachedFileDetailed(
            dataPath: tamperedURL.path,
            signature: signature,
            verificationKeys: [key.publicKeyData],
            progress: nil
        )

        XCTAssertEqual(
            result.summaryState, .invalid,
            "Detached signature on tampered data must produce Invalid summary state"
        )
    }

    // MARK: - KeyExpired Error Mapping

    /// Verify that a key with expirySeconds=1 is detected as expired after waiting.
    /// Sequoia may or may not reject encryption to an expired key at the API level,
    /// so this test accepts both outcomes: if encryption succeeds, it verifies the key
    /// info shows isExpired; if it throws, it verifies the error type.
    func test_errorMapping_keyExpired_detectsExpiredKey() throws {
        let engine = try XCTUnwrap(self.engine)
        let key = try engine.generateKey(name: "Expiry Test", email: nil, expirySeconds: 1, suite: .ed25519LegacyCurve25519Legacy)
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
}
