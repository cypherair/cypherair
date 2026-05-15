import XCTest
@testable import CypherAir

/// Tests for streaming file encryption, decryption, signing, and verification.
/// Covers both Profile A and Profile B, cancellation, disk space validation,
/// tamper detection, and error handling.
final class StreamingServiceTests: XCTestCase {

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
        profile: PGPKeyProfile,
        name: String = "Test"
    ) async throws -> PGPKeyIdentity {
        let identity = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: profile,
            name: name
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)
        return identity
    }

    private func contactId(for identity: PGPKeyIdentity) throws -> String {
        try contactId(forFingerprint: identity.fingerprint)
    }

    private func contactId(forFingerprint fingerprint: String) throws -> String {
        try XCTUnwrap(stack.contactService.contactId(forFingerprint: fingerprint))
    }

    /// Write data to a temporary file and return its URL.
    /// Caller is responsible for cleanup.
    private func writeTempFile(_ data: Data, filename: String = "test-\(UUID().uuidString).bin") throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(filename)
        try data.write(to: url)
        return url
    }

    // MARK: - Encrypt/Decrypt Round-Trip: Profile A

    func test_encryptFileStreaming_profileA_roundTrip() async throws {
        let sender = try await generateKeyAndContact(profile: .universal, name: "Sender A")
        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient A")

        // Write test file
        let plaintext = Data("Hello streaming Profile A! 你好世界 🔐".utf8)
        let inputURL = try writeTempFile(plaintext)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        // Encrypt
        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: sender.fingerprint,
            encryptToSelf: false,
            progress: nil
        )
        let encryptedURL = encryptedArtifact.fileURL
        defer { encryptedArtifact.cleanup() }

        XCTAssertTrue(FileManager.default.fileExists(atPath: encryptedURL.path))
        try assertCompleteFileProtection(at: encryptedURL)
        let encryptedData = try Data(contentsOf: encryptedURL)
        XCTAssertFalse(encryptedData.isEmpty)

        // Phase 1: Parse recipients from file
        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedURL)
        XCTAssertEqual(phase1.matchedKey?.fingerprint, recipient.fingerprint)

        // Phase 2: Decrypt
        let decryptedResult = try await stack.decryptionService.decryptFileStreamingDetailed(
            phase1: phase1,
            progress: nil
        )
        let outputURL = decryptedResult.artifact.fileURL
        let sig = decryptedResult.verification
        defer { decryptedResult.artifact.cleanup() }

        let decrypted = try Data(contentsOf: outputURL)
        try assertCompleteFileProtection(at: outputURL)
        XCTAssertEqual(decrypted, plaintext)
        // Signature should be valid (known signer is a contact)
        XCTAssertTrue(
            sig.legacyStatus == .valid,
            "Expected valid signature, got: \(sig.legacyStatus)"
        )
    }

    // MARK: - Encrypt/Decrypt Round-Trip: Profile B

    func test_encryptFileStreaming_profileB_roundTrip() async throws {
        let sender = try await generateKeyAndContact(profile: .advanced, name: "Sender B")
        let recipient = try await generateKeyAndContact(profile: .advanced, name: "Recipient B")

        let plaintext = Data("Hello streaming Profile B! 你好世界 🔐".utf8)
        let inputURL = try writeTempFile(plaintext)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: sender.fingerprint,
            encryptToSelf: false,
            progress: nil
        )
        let encryptedURL = encryptedArtifact.fileURL
        defer { encryptedArtifact.cleanup() }

        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedURL)
        XCTAssertEqual(phase1.matchedKey?.fingerprint, recipient.fingerprint)

        let decryptedResult = try await stack.decryptionService.decryptFileStreamingDetailed(
            phase1: phase1,
            progress: nil
        )
        let outputURL = decryptedResult.artifact.fileURL
        let sig = decryptedResult.verification
        defer { decryptedResult.artifact.cleanup() }

        let decrypted = try Data(contentsOf: outputURL)
        try assertCompleteFileProtection(at: outputURL)
        XCTAssertEqual(decrypted, plaintext)
        XCTAssertTrue(
            sig.legacyStatus == .valid,
            "Expected valid signature, got: \(sig.legacyStatus)"
        )
    }

    func test_encryptFileStreaming_sameFilename_usesUniqueOperationDirectories() async throws {
        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient")
        let inputURL = try writeTempFile(Data("same name".utf8), filename: "same-name.txt")
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let first = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        let second = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        defer {
            first.cleanup()
            second.cleanup()
        }

        XCTAssertNotEqual(first.fileURL, second.fileURL)
        XCTAssertEqual(first.fileURL.lastPathComponent, "same-name.txt.gpg")
        XCTAssertTrue(first.fileURL.path.contains("/streaming/op-"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.fileURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: second.fileURL.path))
    }

    func test_decryptFileStreaming_sameFilename_usesUniqueOperationDirectories() async throws {
        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient")
        let inputURL = try writeTempFile(Data("same encrypted".utf8), filename: "same-encrypted.txt")
        defer { try? FileManager.default.removeItem(at: inputURL) }
        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        defer { encryptedArtifact.cleanup() }
        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedArtifact.fileURL)

        let first = try await stack.decryptionService.decryptFileStreamingDetailed(phase1: phase1, progress: nil)
        let second = try await stack.decryptionService.decryptFileStreamingDetailed(phase1: phase1, progress: nil)
        defer {
            first.artifact.cleanup()
            second.artifact.cleanup()
        }

        XCTAssertNotEqual(first.artifact.fileURL, second.artifact.fileURL)
        XCTAssertEqual(first.artifact.fileURL.lastPathComponent, "same-encrypted.txt")
        XCTAssertTrue(first.artifact.fileURL.path.contains("/decrypted/op-"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.artifact.fileURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: second.artifact.fileURL.path))
    }

    func test_decryptFileStreaming_failedRepeatDoesNotDeletePreviousSuccessfulOutput() async throws {
        let recipient = try await generateKeyAndContact(profile: .advanced, name: "Recipient")
        let inputURL = try writeTempFile(Data("survives failure".utf8), filename: "repeat-failure.txt")
        defer { try? FileManager.default.removeItem(at: inputURL) }
        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        defer { encryptedArtifact.cleanup() }
        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedArtifact.fileURL)
        let first = try await stack.decryptionService.decryptFileStreamingDetailed(phase1: phase1, progress: nil)
        defer { first.artifact.cleanup() }

        var tampered = try Data(contentsOf: encryptedArtifact.fileURL)
        tampered[tampered.count / 2] ^= 0x01
        try tampered.write(to: encryptedArtifact.fileURL, options: .atomic)

        do {
            _ = try await stack.decryptionService.decryptFileStreamingDetailed(phase1: phase1, progress: nil)
            XCTFail("Expected tampered repeat decrypt to fail")
        } catch {
            XCTAssertTrue(FileManager.default.fileExists(atPath: first.artifact.fileURL.path))
        }
    }

    // MARK: - Sign/Verify Round-Trip: Profile A

    func test_signDetachedStreaming_profileA_roundTrip() async throws {
        let signer = try await generateKeyAndContact(profile: .universal, name: "Signer A")

        let fileData = Data("Sign me (Profile A)".utf8)
        let inputURL = try writeTempFile(fileData)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        // Sign
        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: inputURL,
            signerFingerprint: signer.fingerprint,
            progress: nil
        )
        XCTAssertFalse(signature.isEmpty)

        // Verify
        let verification = try await stack.signingService.verifyDetachedStreamingDetailed(
            fileURL: inputURL,
            signature: signature,
            progress: nil
        )
        XCTAssertTrue(
            verification.legacyStatus == .valid,
            "Expected valid signature, got: \(verification.legacyStatus)"
        )
    }

    // MARK: - Sign/Verify Round-Trip: Profile B

    func test_signDetachedStreaming_profileB_roundTrip() async throws {
        let signer = try await generateKeyAndContact(profile: .advanced, name: "Signer B")

        let fileData = Data("Sign me (Profile B)".utf8)
        let inputURL = try writeTempFile(fileData)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: inputURL,
            signerFingerprint: signer.fingerprint,
            progress: nil
        )
        XCTAssertFalse(signature.isEmpty)

        let verification = try await stack.signingService.verifyDetachedStreamingDetailed(
            fileURL: inputURL,
            signature: signature,
            progress: nil
        )
        XCTAssertTrue(
            verification.legacyStatus == .valid,
            "Expected valid signature, got: \(verification.legacyStatus)"
        )
    }

    // MARK: - Cancellation

    func test_encryptFileStreaming_cancellation_throwsOperationCancelled() async throws {
        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient")

        // Create a file large enough for progress to be reported
        let fileData = Data(repeating: 0x42, count: 256 * 1024)  // 256 KB
        let inputURL = try writeTempFile(fileData)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        // Pre-cancel the progress reporter
        let progress = FileProgressReporter()
        progress.cancel()

        do {
            let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
                inputURL: inputURL,
                recipientContactIds: [try contactId(for: recipient)],
                signWithFingerprint: nil,
                encryptToSelf: false,
                progress: progress
            )
            // Clean up if it somehow succeeds
            encryptedArtifact.cleanup()
            XCTFail("Expected operationCancelled error")
        } catch let error as CypherAirError {
            if case .operationCancelled = error {
                // Expected
            } else {
                XCTFail("Expected operationCancelled, got: \(error)")
            }
        } catch {
            XCTFail("Expected operationCancelled, got: \(error)")
        }
    }

    func test_verifyDetachedStreaming_cancellation_throwsOperationCancelled() async throws {
        let signer = try await generateKeyAndContact(profile: .universal, name: "Verify Signer")

        let fileData = Data(repeating: 0x42, count: 256 * 1024)  // 256 KB
        let inputURL = try writeTempFile(fileData)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: inputURL,
            signerFingerprint: signer.fingerprint,
            progress: nil
        )

        let progress = FileProgressReporter()
        progress.cancel()

        do {
            _ = try await stack.signingService.verifyDetachedStreamingDetailed(
                fileURL: inputURL,
                signature: signature,
                progress: progress
            )
            XCTFail("Expected operationCancelled error")
        } catch let error as CypherAirError {
            if case .operationCancelled = error {
                // Expected
            } else {
                XCTFail("Expected operationCancelled, got: \(error)")
            }
        } catch {
            XCTFail("Expected operationCancelled, got: \(error)")
        }
    }

    // MARK: - Insufficient Disk Space

    func test_encryptFileStreaming_insufficientDiskSpace_throws() async throws {
        // Create an encryption service with a mock disk space checker
        let mockDisk = MockDiskSpace()
        mockDisk.availableBytes = 100  // Very low — 100 bytes available
        let diskChecker = DiskSpaceChecker(diskSpace: mockDisk)
        let encService = EncryptionService(
            messageAdapter: stack.messageAdapter,
            keyManagement: stack.keyManagement,
            contactService: stack.contactService,
            diskSpaceChecker: diskChecker
        )

        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient")

        let fileData = Data(repeating: 0x42, count: 10 * 1024 * 1024)  // 10 MB
        let inputURL = try writeTempFile(fileData)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        do {
            let encryptedArtifact = try await encService.encryptFileStreaming(
                inputURL: inputURL,
                recipientContactIds: [try contactId(for: recipient)],
                signWithFingerprint: nil,
                encryptToSelf: false,
                progress: nil
            )
            encryptedArtifact.cleanup()
            XCTFail("Expected insufficientDiskSpace error")
        } catch let error as CypherAirError {
            if case .insufficientDiskSpace = error {
                // Expected
            } else {
                XCTFail("Expected insufficientDiskSpace, got: \(error)")
            }
        }

        XCTAssertEqual(mockDisk.callCount, 1, "Disk space should have been checked once")
    }

    // MARK: - Tamper Detection

    func test_decryptFileStreaming_tamperedFile_throwsError() async throws {
        let key = try await generateKeyAndContact(profile: .advanced, name: "Tamper Test")

        let plaintext = Data("Tamper test content".utf8)
        let inputURL = try writeTempFile(plaintext)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        // Encrypt
        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientContactIds: [try contactId(for: key)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        let encryptedURL = encryptedArtifact.fileURL

        // Tamper with the encrypted file (1-bit flip near the middle)
        var encryptedData = try Data(contentsOf: encryptedURL)
        let midpoint = encryptedData.count / 2
        encryptedData[midpoint] ^= 0x01
        try encryptedData.write(to: encryptedURL)
        defer { encryptedArtifact.cleanup() }

        // Parse recipients should still work (PKESK headers are at the beginning)
        // But decryption should fail with an integrity error
        do {
            let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedURL)

            let decryptedResult = try await stack.decryptionService.decryptFileStreamingDetailed(
                phase1: phase1,
                progress: nil
            )
            decryptedResult.artifact.cleanup()
            XCTFail("Expected decryption to fail on tampered file")
        } catch {
            // Any error is acceptable — could be AEAD failure, MDC failure,
            // corrupt data, or no matching key (if PKESK was tampered).
            // The key invariant is that NO plaintext was written.
        }
    }

    // MARK: - No Matching Key

    func test_parseRecipientsFromFile_noMatchingKey_throws() async throws {
        // Generate a key that we DON'T store locally
        let engine = PgpEngine()
        let externalKey = try engine.generateKey(
            name: "External",
            email: "ext@example.com",
            expirySeconds: nil,
            profile: .universal
        )

        // Parse the external public key and add as contact
        try stack.contactService.addContact(publicKeyData: externalKey.publicKeyData)

        // Create a file and encrypt it TO the external key only
        let plaintext = Data("Secret for external".utf8)
        let inputURL = try writeTempFile(plaintext)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        // Get the fingerprint of the external key
        let keyInfo = try engine.parseKeyInfo(keyData: externalKey.publicKeyData)

        // Encrypt to the external contact
        let encryptedArtifact = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientContactIds: [try contactId(forFingerprint: keyInfo.fingerprint)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        let encryptedURL = encryptedArtifact.fileURL
        defer { encryptedArtifact.cleanup() }

        // Now remove all local keys so nothing matches
        // We need a fresh decryption service with no local keys
        let (emptyKeyMgmt, _, _, _) = TestHelpers.makeKeyManagement()
        let decSvc = DecryptionService(
            messageAdapter: PGPMessageOperationAdapter(engine: engine),
            keyManagement: emptyKeyMgmt,
            contactService: stack.contactService
        )

        do {
            _ = try await decSvc.parseRecipientsFromFile(fileURL: encryptedURL)
            XCTFail("Expected noMatchingKey error")
        } catch let error as CypherAirError {
            if case .noMatchingKey = error {
                // Expected
            } else {
                XCTFail("Expected noMatchingKey, got: \(error)")
            }
        }
    }

    // MARK: - FileIoError

    func test_encryptFileStreaming_invalidInputPath_throwsError() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)

        let nonexistentURL = URL(fileURLWithPath: "/nonexistent/path/file.txt")

        do {
            _ = try await stack.encryptionService.encryptFileStreaming(
                inputURL: nonexistentURL,
                recipientContactIds: [try contactId(for: identity)],
                signWithFingerprint: nil,
                encryptToSelf: false,
                progress: nil
            )
            XCTFail("Expected error for non-existent input file")
        } catch {
            // The error may surface as CypherAirError.fileIoError (from pgp-mobile streaming)
            // or as NSCocoaErrorDomain/NSPOSIXErrorDomain (from Swift file validation).
            // The key invariant is that encryption does NOT succeed for a nonexistent path.
        }
    }

    private func assertCompleteFileProtection(
        at url: URL,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual(
            attributes[.protectionKey] as? FileProtectionType,
            .complete,
            file: file,
            line: line
        )
    }
}
