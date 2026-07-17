import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    // MARK: - Detailed Signature Results

    func test_detailedVerifyCleartext_fixtureMultiSigner_preservesEntries() throws {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerB = try loadFixture("ffi_detailed_signer_b")
        let signerAInfo = try engine.parseKeyInfo(keyData: signerA)
        let signerBInfo = try engine.parseKeyInfo(keyData: signerB)
        let signedMessage = try loadArmoredFixture("ffi_detailed_multisig_cleartext")

        let detailed = try engine.verifyCleartextDetailed(
            signedMessage: signedMessage,
            verificationKeys: [signerA, signerB]
        )

        XCTAssertEqual(detailed.content, Data("FFI detailed multi-signer cleartext".utf8))
        XCTAssertEqual(detailed.signatures.count, 2)
        XCTAssertTrue(detailed.signatures.allSatisfy { $0.status == .valid })
        let observedFingerprints = Set(
            detailed.signatures.compactMap(\.signerPrimaryFingerprint)
        )
        XCTAssertEqual(
            observedFingerprints,
            Set([signerAInfo.fingerprint, signerBInfo.fingerprint])
        )
        XCTAssertEqual(detailed.summaryEntryIndex, 0)
    }

    func test_detailedVerifyDetached_fixtureKnownPlusUnknown_preservesNilUnknownFingerprint() throws {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerAInfo = try engine.parseKeyInfo(keyData: signerA)
        let data = try loadTextFixture("ffi_detailed_detached_data")
        let signature = try loadArmoredFixture("ffi_detailed_multisig_detached", ext: "sig")
        let inputURL = try writeTempFile(
            data,
            filename: "ffi-detailed-known-unknown-\(UUID().uuidString).txt"
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let detailed = try engine.verifyDetachedFileDetailed(
            dataPath: inputURL.path,
            signature: signature,
            verificationKeys: [signerA],
            progress: nil
        )

        XCTAssertEqual(detailed.signatures.count, 2)
        XCTAssertTrue(detailed.signatures.contains {
            $0.status == .valid && $0.signerPrimaryFingerprint == Optional(signerAInfo.fingerprint)
        })
        XCTAssertTrue(detailed.signatures.contains {
            $0.status == .unknownSigner && $0.signerPrimaryFingerprint == nil
        })
    }

    func test_detailedVerifyDetached_fixtureRepeatedSigner_preservesRepeatedEntries() throws {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerAInfo = try engine.parseKeyInfo(keyData: signerA)
        let data = try loadTextFixture("ffi_detailed_detached_data")
        let signature = try loadArmoredFixture("ffi_detailed_repeated_detached", ext: "sig")
        let inputURL = try writeTempFile(
            data,
            filename: "ffi-detailed-repeated-\(UUID().uuidString).txt"
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let detailed = try engine.verifyDetachedFileDetailed(
            dataPath: inputURL.path,
            signature: signature,
            verificationKeys: [signerA],
            progress: nil
        )

        XCTAssertEqual(detailed.summaryState, .verified)
        XCTAssertEqual(detailed.signatures.count, 2)
        XCTAssertEqual(detailed.signatures[0].status, .valid)
        XCTAssertEqual(detailed.signatures[1].status, .valid)
        XCTAssertEqual(
            detailed.signatures[0].signerPrimaryFingerprint,
            Optional(signerAInfo.fingerprint)
        )
        XCTAssertEqual(
            detailed.signatures[1].signerPrimaryFingerprint,
            Optional(signerAInfo.fingerprint)
        )
    }

    func test_detailedDecrypt_fixtureMultiSigner_preservesEntries() throws {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerB = try loadFixture("ffi_detailed_signer_b")
        let signerAInfo = try engine.parseKeyInfo(keyData: signerA)
        let signerBInfo = try engine.parseKeyInfo(keyData: signerB)
        let recipientSecret = try loadFixture("ffi_detailed_recipient_secret")
        let ciphertext = try loadFixture("ffi_detailed_multisig_encrypted")

        let detailed = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [recipientSecret],
            verificationKeys: [signerA, signerB]
        )

        XCTAssertEqual(detailed.plaintext, Data("FFI detailed encrypted payload".utf8))
        XCTAssertEqual(detailed.signatures.count, 2)
        XCTAssertTrue(detailed.signatures.allSatisfy { $0.status == .valid })
        let observedFingerprints = Set(
            detailed.signatures.compactMap(\.signerPrimaryFingerprint)
        )
        XCTAssertEqual(
            observedFingerprints,
            Set([signerAInfo.fingerprint, signerBInfo.fingerprint])
        )
        XCTAssertEqual(detailed.summaryEntryIndex, 0)
    }

    func test_detailedDecryptFile_fixtureMultiSigner_preservesEntries() throws {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerB = try loadFixture("ffi_detailed_signer_b")
        let recipientSecret = try loadFixture("ffi_detailed_recipient_secret")
        let ciphertext = try loadFixture("ffi_detailed_multisig_encrypted")
        let inputURL = try writeTempFile(ciphertext, filename: "ffi-detailed-input-\(UUID().uuidString).gpg")
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let detailedOutputURL = makeTempOutputURL(filename: "ffi-detailed-out-\(UUID().uuidString).bin")
        defer { try? FileManager.default.removeItem(at: detailedOutputURL) }

        let detailed = try engine.decryptFileDetailed(
            inputPath: inputURL.path,
            outputPath: detailedOutputURL.path,
            secretKeys: [recipientSecret],
            verificationKeys: [signerA, signerB],
            progress: nil
        )

        XCTAssertEqual(
            try Data(contentsOf: detailedOutputURL),
            Data("FFI detailed encrypted payload".utf8)
        )
        XCTAssertEqual(detailed.signatures.count, 2)
    }

    func test_detailedVerifyDetachedFile_fixtureKnownPlusUnknown_preservesDetails() throws {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerAInfo = try engine.parseKeyInfo(keyData: signerA)
        let data = try loadTextFixture("ffi_detailed_detached_data")
        let signature = try loadArmoredFixture("ffi_detailed_multisig_detached", ext: "sig")
        let inputURL = try writeTempFile(
            data,
            filename: "ffi-detailed-detached-input-\(UUID().uuidString).txt"
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let fileDetailed = try engine.verifyDetachedFileDetailed(
            dataPath: inputURL.path,
            signature: signature,
            verificationKeys: [signerA],
            progress: nil
        )

        XCTAssertEqual(fileDetailed.summaryState, .verified)
        XCTAssertEqual(
            fileDetailed.signatures[Int(fileDetailed.summaryEntryIndex!)].signerPrimaryFingerprint,
            signerAInfo.fingerprint
        )
        XCTAssertEqual(fileDetailed.signatures.count, 2)
        XCTAssertTrue(fileDetailed.signatures.contains {
            $0.status == .valid && $0.signerPrimaryFingerprint == Optional(signerAInfo.fingerprint)
        })
        XCTAssertTrue(fileDetailed.signatures.contains {
            $0.status == .unknownSigner && $0.signerPrimaryFingerprint == nil
        })
    }

    func test_detailedVerifyDetachedFile_cancel_returnsOperationCancelled() throws {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let data = try loadTextFixture("ffi_detailed_detached_data")
        let signature = try loadArmoredFixture("ffi_detailed_multisig_detached", ext: "sig")
        let inputURL = try writeTempFile(data, filename: "ffi-detailed-detached-\(UUID().uuidString).txt")
        defer { try? FileManager.default.removeItem(at: inputURL) }

        XCTAssertThrowsError(
            try engine.verifyDetachedFileDetailed(
                dataPath: inputURL.path,
                signature: signature,
                verificationKeys: [signerA],
                progress: CancellingProgressReporter()
            )
        ) { error in
            guard case .OperationCancelled = error as? PgpError else {
                return XCTFail("Expected OperationCancelled, got \(error)")
            }
        }
    }

    func test_detailedDecrypt_unsignedRuntime_returnsEmptySignaturesAndNotSigned() throws {
        let recipient = try engine.generateKey(
            name: "FFI Detailed Recipient",
            email: "ffi-detailed@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        let ciphertext = try engine.encryptBinary(
            plaintext: Data("Unsigned detailed decrypt".utf8),
            recipients: [recipient.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let detailed = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [recipient.certData],
            verificationKeys: []
        )

        XCTAssertEqual(detailed.summaryState, .notSigned)
        XCTAssertTrue(detailed.signatures.isEmpty)
    }

    func test_detailedApis_modernHigh_runtimeSmoke() throws {
        let signer = try engine.generateKey(
            name: "FFI Detailed Modern High Signer",
            email: "ffi-detailed-b@example.com",
            expirySeconds: nil,
            suite: .ed448X448
        )
        let recipient = try engine.generateKey(
            name: "FFI Detailed Modern High Recipient",
            email: "ffi-detailed-b-recipient@example.com",
            expirySeconds: nil,
            suite: .ed448X448
        )

        let signed = try engine.signCleartext(
            text: Data("Modern High detailed verify".utf8),
            signerCert: signer.certData
        )
        let verifyDetailed = try engine.verifyCleartextDetailed(
            signedMessage: signed,
            verificationKeys: [signer.publicKeyData]
        )
        XCTAssertEqual(verifyDetailed.summaryState, .verified)
        XCTAssertEqual(verifyDetailed.signatures.count, 1)

        let ciphertext = try engine.encryptBinary(
            plaintext: Data("Modern High detailed decrypt".utf8),
            recipients: [recipient.publicKeyData],
            signingKey: signer.certData,
            encryptToSelf: nil
        )
        let decryptDetailed = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [recipient.certData],
            verificationKeys: [signer.publicKeyData]
        )
        XCTAssertEqual(decryptDetailed.summaryState, .verified)
        XCTAssertEqual(decryptDetailed.signatures.count, 1)
    }
}

private final class CancellingProgressReporter: StreamingProgressReporter, @unchecked Sendable {
    func onProgress(bytesProcessed: UInt64, totalBytes: UInt64) -> Bool {
        false
    }
}
