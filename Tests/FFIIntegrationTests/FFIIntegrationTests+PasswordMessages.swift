import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    private func findTargetedPasswordTamper(
        ciphertext: Data,
        password: String,
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
                _ = try engine.decryptWithPassword(
                    ciphertext: tampered,
                    password: password,
                    verificationKeys: []
                )
            } catch let error as PgpError where acceptedErrors.contains(error) {
                return tampered
            } catch {
                continue
            }
        }

        XCTFail("Could not locate a deterministic password-message auth/integrity tamper position")
        return ciphertext
    }

    // MARK: - C5.2C Password / SKESK

    func test_passwordRoundTrip_armoredSeipdv1_dataPreservedAcrossFFI() throws {
        let plaintext = Data("Password SEIPDv1 via FFI".utf8)

        let ciphertext = try engine.encryptWithPassword(
            plaintext: plaintext,
            password: "ffi-password-v1",
            format: .seipdv1,
            signingKey: nil
        )

        let result = try engine.decryptWithPassword(
            ciphertext: ciphertext,
            password: "ffi-password-v1",
            verificationKeys: []
        )

        XCTAssertEqual(result.status, .decrypted)
        XCTAssertEqual(result.plaintext, plaintext)
        XCTAssertEqual(result.signatureStatus, .notSigned)
    }

    func test_passwordRoundTrip_seipdv2_signed_preservesSignatureAcrossFFI() throws {
        let signer = try engine.generateKey(
            name: "Password FFI Signer",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
        )
        let plaintext = Data("Password SEIPDv2 signed via FFI".utf8)

        let ciphertext = try engine.encryptBinaryWithPassword(
            plaintext: plaintext,
            password: "ffi-password-v2",
            format: .seipdv2,
            signingKey: signer.certData
        )

        let result = try engine.decryptWithPassword(
            ciphertext: ciphertext,
            password: "ffi-password-v2",
            verificationKeys: [signer.publicKeyData]
        )

        XCTAssertEqual(result.status, .decrypted)
        XCTAssertEqual(result.plaintext, plaintext)
        XCTAssertEqual(result.signatureStatus, .valid)
        XCTAssertEqual(result.signerFingerprint, signer.fingerprint)
    }

    func test_passwordDecrypt_noSkesk_returnsStatus() throws {
        let recipient = try engine.generateKey(
            name: "No SKESK Recipient",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let ciphertext = try engine.encryptBinary(
            plaintext: Data("recipient only".utf8),
            recipients: [recipient.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let result = try engine.decryptWithPassword(
            ciphertext: ciphertext,
            password: "irrelevant-password",
            verificationKeys: []
        )

        XCTAssertEqual(result.status, .noSkesk)
        XCTAssertNil(result.plaintext)
    }

    func test_passwordDecrypt_passwordRejected_isDeterministicForSkesk6() throws {
        let ciphertext = try engine.encryptBinaryWithPassword(
            plaintext: Data("reject via ffi".utf8),
            password: "correct-ffi-password",
            format: .seipdv2,
            signingKey: nil
        )

        let result = try engine.decryptWithPassword(
            ciphertext: ciphertext,
            password: "wrong-ffi-password",
            verificationKeys: []
        )

        XCTAssertEqual(result.status, .passwordRejected)
        XCTAssertNil(result.plaintext)
    }

    func test_passwordDecrypt_tamperedSeipdv1_targeted_returnsIntegrityFailure() throws {
        let ciphertext = try engine.encryptBinaryWithPassword(
            plaintext: Data("tamper ffi v1".utf8),
            password: "tamper-ffi-v1",
            format: .seipdv1,
            signingKey: nil
        )
        let tampered = try findTargetedPasswordTamper(
            ciphertext: ciphertext,
            password: "tamper-ffi-v1",
            acceptedErrors: [.IntegrityCheckFailed]
        )

        XCTAssertThrowsError(
            try engine.decryptWithPassword(
                ciphertext: tampered,
                password: "tamper-ffi-v1",
                verificationKeys: []
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            XCTAssertEqual(pgpError, .IntegrityCheckFailed)
        }
    }

    func test_passwordDecrypt_tamperedSeipdv2_targeted_returnsFatalAuthFailure() throws {
        let ciphertext = try engine.encryptBinaryWithPassword(
            plaintext: Data("tamper ffi v2".utf8),
            password: "tamper-ffi-v2",
            format: .seipdv2,
            signingKey: nil
        )
        let tampered = try findTargetedPasswordTamper(
            ciphertext: ciphertext,
            password: "tamper-ffi-v2",
            acceptedErrors: [.AeadAuthenticationFailed, .IntegrityCheckFailed]
        )

        XCTAssertThrowsError(
            try engine.decryptWithPassword(
                ciphertext: tampered,
                password: "tamper-ffi-v2",
                verificationKeys: []
            )
        ) { error in
            guard let pgpError = error as? PgpError else {
                return XCTFail("Expected PgpError, got \(type(of: error))")
            }
            switch pgpError {
            case .AeadAuthenticationFailed, .IntegrityCheckFailed:
                break
            default:
                XCTFail("Expected AeadAuthenticationFailed or IntegrityCheckFailed, got \(pgpError)")
            }
        }
    }
}
