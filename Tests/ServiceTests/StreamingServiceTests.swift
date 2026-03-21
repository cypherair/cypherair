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
        profile: KeyProfile,
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
        let encryptedURL = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientFingerprints: [recipient.fingerprint],
            signWithFingerprint: sender.fingerprint,
            encryptToSelf: false,
            progress: nil
        )
        defer { try? FileManager.default.removeItem(at: encryptedURL) }

        XCTAssertTrue(FileManager.default.fileExists(atPath: encryptedURL.path))
        let encryptedData = try Data(contentsOf: encryptedURL)
        XCTAssertFalse(encryptedData.isEmpty)

        // Phase 1: Parse recipients from file
        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedURL)
        XCTAssertEqual(phase1.matchedKey?.fingerprint, recipient.fingerprint)

        // Phase 2: Decrypt
        let (outputURL, sig) = try await stack.decryptionService.decryptFileStreaming(
            phase1: phase1,
            progress: nil
        )
        defer { try? FileManager.default.removeItem(at: outputURL) }

        let decrypted = try Data(contentsOf: outputURL)
        XCTAssertEqual(decrypted, plaintext)
        // Signature should be valid (known signer is a contact)
        XCTAssertTrue(
            sig.status == .valid,
            "Expected valid signature, got: \(sig.status)"
        )
    }

    // MARK: - Encrypt/Decrypt Round-Trip: Profile B

    func test_encryptFileStreaming_profileB_roundTrip() async throws {
        let sender = try await generateKeyAndContact(profile: .advanced, name: "Sender B")
        let recipient = try await generateKeyAndContact(profile: .advanced, name: "Recipient B")

        let plaintext = Data("Hello streaming Profile B! 你好世界 🔐".utf8)
        let inputURL = try writeTempFile(plaintext)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let encryptedURL = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientFingerprints: [recipient.fingerprint],
            signWithFingerprint: sender.fingerprint,
            encryptToSelf: false,
            progress: nil
        )
        defer { try? FileManager.default.removeItem(at: encryptedURL) }

        let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedURL)
        XCTAssertEqual(phase1.matchedKey?.fingerprint, recipient.fingerprint)

        let (outputURL, sig) = try await stack.decryptionService.decryptFileStreaming(
            phase1: phase1,
            progress: nil
        )
        defer { try? FileManager.default.removeItem(at: outputURL) }

        let decrypted = try Data(contentsOf: outputURL)
        XCTAssertEqual(decrypted, plaintext)
        XCTAssertTrue(
            sig.status == .valid,
            "Expected valid signature, got: \(sig.status)"
        )
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
        let verification = try await stack.signingService.verifyDetachedStreaming(
            fileURL: inputURL,
            signature: signature,
            progress: nil
        )
        XCTAssertTrue(
            verification.status == .valid,
            "Expected valid signature, got: \(verification.status)"
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

        let verification = try await stack.signingService.verifyDetachedStreaming(
            fileURL: inputURL,
            signature: signature,
            progress: nil
        )
        XCTAssertTrue(
            verification.status == .valid,
            "Expected valid signature, got: \(verification.status)"
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
            let encryptedURL = try await stack.encryptionService.encryptFileStreaming(
                inputURL: inputURL,
                recipientFingerprints: [recipient.fingerprint],
                signWithFingerprint: nil,
                encryptToSelf: false,
                progress: progress
            )
            // Clean up if it somehow succeeds
            try? FileManager.default.removeItem(at: encryptedURL)
            XCTFail("Expected operationCancelled error")
        } catch let error as CypherAirError {
            if case .operationCancelled = error {
                // Expected
            } else {
                XCTFail("Expected operationCancelled, got: \(error)")
            }
        } catch let error as PgpError {
            // Also acceptable if the PgpError comes through directly
            if case .OperationCancelled = error {
                // Expected
            } else {
                XCTFail("Expected OperationCancelled, got: \(error)")
            }
        }
    }

    // MARK: - Insufficient Disk Space

    func test_encryptFileStreaming_insufficientDiskSpace_throws() async throws {
        // Create an encryption service with a mock disk space checker
        let mockDisk = MockDiskSpace()
        mockDisk.availableBytes = 100  // Very low — 100 bytes available
        let diskChecker = DiskSpaceChecker(diskSpace: mockDisk)
        let encService = EncryptionService(
            engine: stack.engine,
            keyManagement: stack.keyManagement,
            contactService: stack.contactService,
            diskSpaceChecker: diskChecker
        )

        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient")

        let fileData = Data(repeating: 0x42, count: 10 * 1024 * 1024)  // 10 MB
        let inputURL = try writeTempFile(fileData)
        defer { try? FileManager.default.removeItem(at: inputURL) }

        do {
            let encryptedURL = try await encService.encryptFileStreaming(
                inputURL: inputURL,
                recipientFingerprints: [recipient.fingerprint],
                signWithFingerprint: nil,
                encryptToSelf: false,
                progress: nil
            )
            try? FileManager.default.removeItem(at: encryptedURL)
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
        let encryptedURL = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientFingerprints: [key.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )

        // Tamper with the encrypted file (1-bit flip near the middle)
        var encryptedData = try Data(contentsOf: encryptedURL)
        let midpoint = encryptedData.count / 2
        encryptedData[midpoint] ^= 0x01
        try encryptedData.write(to: encryptedURL)
        defer { try? FileManager.default.removeItem(at: encryptedURL) }

        // Parse recipients should still work (PKESK headers are at the beginning)
        // But decryption should fail with an integrity error
        do {
            let phase1 = try await stack.decryptionService.parseRecipientsFromFile(fileURL: encryptedURL)

            let (outputURL, _) = try await stack.decryptionService.decryptFileStreaming(
                phase1: phase1,
                progress: nil
            )
            try? FileManager.default.removeItem(at: outputURL)
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
        let encryptedURL = try await stack.encryptionService.encryptFileStreaming(
            inputURL: inputURL,
            recipientFingerprints: [keyInfo.fingerprint],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        defer { try? FileManager.default.removeItem(at: encryptedURL) }

        // Now remove all local keys so nothing matches
        // We need a fresh decryption service with no local keys
        let (emptyKeyMgmt, _, _, _) = TestHelpers.makeKeyManagement()
        let decSvc = DecryptionService(
            engine: engine,
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
}
