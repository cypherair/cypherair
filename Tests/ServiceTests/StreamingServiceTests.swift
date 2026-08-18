import XCTest
@testable import CypherAir

/// Tests for streaming file encryption, decryption, signing, and verification.
/// Covers both Legacy and Modern High, cancellation, disk space validation,
/// tamper detection, and error handling.
final class StreamingServiceTests: XCTestCase {

    private var stack: TestHelpers.ServiceStack!

    override func setUp() async throws {
        try await super.setUp()
        stack = await TestHelpers.makeServiceStack()
    }

    override func tearDown() {
        stack.cleanup()
        stack = nil
        super.tearDown()
    }

    // MARK: - Helpers

    /// Generate a key and register it as a contact, returning the identity.
    private func generateKeyAndContact(
        suite: PGPKeySuite,
        name: String = "Test"
    ) async throws -> PGPKeyIdentity {
        let identity = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            suite: suite,
            name: name
        )
        try stack.contactService.importContact(publicKeyData: identity.publicKeyData)
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

    // MARK: - Encrypt/Decrypt Round-Trip: Legacy

    func test_encryptFileStreaming_legacy_roundTrip() async throws {
        let sender = try await generateKeyAndContact(suite: .ed25519LegacyCurve25519Legacy, name: "Sender A")
        let recipient = try await generateKeyAndContact(suite: .ed25519LegacyCurve25519Legacy, name: "Recipient A")

        // Write test file
        let plaintext = Data("Hello streaming Legacy! 你好世界 🔐".utf8)
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
            sig.summaryState == .verified,
            "Expected verified signature, got: \(sig.summaryState)"
        )
    }

    // MARK: - Encrypt/Decrypt Round-Trip: Modern High

    func test_encryptFileStreaming_modernHigh_roundTrip() async throws {
        let sender = try await generateKeyAndContact(suite: .ed448X448, name: "Sender B")
        let recipient = try await generateKeyAndContact(suite: .ed448X448, name: "Recipient B")

        let plaintext = Data("Hello streaming Modern High! 你好世界 🔐".utf8)
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
            sig.summaryState == .verified,
            "Expected verified signature, got: \(sig.summaryState)"
        )
    }

    func test_encryptFileStreaming_sameFilename_usesUniqueOperationDirectories() async throws {
        let recipient = try await generateKeyAndContact(suite: .ed25519LegacyCurve25519Legacy, name: "Recipient")
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
        XCTAssertEqual(first.exportFilename.value, "same-name.txt.gpg")
        XCTAssertFalse(first.fileURL.path.contains("same-name"))
        XCTAssertTrue(first.fileURL.path.contains("/streaming/op-"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.fileURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: second.fileURL.path))
    }

    func test_decryptFileStreaming_sameFilename_usesUniqueOperationDirectories() async throws {
        let recipient = try await generateKeyAndContact(suite: .ed25519LegacyCurve25519Legacy, name: "Recipient")
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
        XCTAssertFalse(first.artifact.fileURL.path.contains("same-encrypted"))
        XCTAssertTrue(first.artifact.fileURL.path.contains("/decrypted/op-"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: first.artifact.fileURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: second.artifact.fileURL.path))
    }

    func test_decryptFileStreaming_failedRepeatDoesNotDeletePreviousSuccessfulOutput() async throws {
        let recipient = try await generateKeyAndContact(suite: .ed448X448, name: "Recipient")
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

    // MARK: - Sign/Verify Round-Trip: Legacy

    func test_signDetachedStreaming_legacy_roundTrip() async throws {
        let signer = try await generateKeyAndContact(suite: .ed25519LegacyCurve25519Legacy, name: "Signer A")

        let fileData = Data("Sign me (Legacy)".utf8)
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
            verification.summaryState == .verified,
            "Expected verified signature, got: \(verification.summaryState)"
        )
    }

    // MARK: - Sign/Verify Round-Trip: Modern High

    func test_signDetachedStreaming_modernHigh_roundTrip() async throws {
        let signer = try await generateKeyAndContact(suite: .ed448X448, name: "Signer B")

        let fileData = Data("Sign me (Modern High)".utf8)
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
            verification.summaryState == .verified,
            "Expected verified signature, got: \(verification.summaryState)"
        )
    }

    // MARK: - Cancellation

    func test_encryptFileStreaming_cancellation_throwsOperationCancelled() async throws {
        let recipient = try await generateKeyAndContact(suite: .ed25519LegacyCurve25519Legacy, name: "Recipient")

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
        let signer = try await generateKeyAndContact(suite: .ed25519LegacyCurve25519Legacy, name: "Verify Signer")

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
            keyManagement: stack.keyManagement,
            contactService: stack.contactService,
            textEncryptor: stack.textEncryptor,
            fileEncryptor: stack.fileEncryptor,
            diskSpaceChecker: diskChecker
        )

        let recipient = try await generateKeyAndContact(suite: .ed25519LegacyCurve25519Legacy, name: "Recipient")

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

    /// An input whose size cannot be read is not a reason to refuse: the pre-flight
    /// only ever fails for missing space, and the real problem with the file surfaces
    /// from the encrypt pipeline itself. Reported free space is zero here, so a
    /// pre-flight that ran anyway would refuse and fail this test.
    func test_encryptFileStreaming_unreadableInputSize_skipsPreflightAndProceeds() async throws {
        let mockDisk = MockDiskSpace()
        mockDisk.availableBytes = 0
        let spyEncryptor = SpyStreamingFileEncryptor()
        let artifactRoot = try makeIsolatedArtifactRoot()
        defer { try? FileManager.default.removeItem(at: artifactRoot) }

        let recipient = try await generateKeyAndContact(
            suite: .ed25519LegacyCurve25519Legacy,
            name: "Unreadable Encrypt Input Recipient"
        )

        let encryptedArtifact = try await makeEncryptionService(
            fileEncryptor: spyEncryptor,
            diskSpace: mockDisk,
            artifactRoot: artifactRoot
        ).encryptFileStreaming(
            inputURL: URL(fileURLWithPath: "/nonexistent/CypherAirDiskPreflightTests/missing.bin"),
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: false,
            progress: nil
        )
        defer { encryptedArtifact.cleanup() }

        XCTAssertEqual(spyEncryptor.callCount, 1, "Encryption should have proceeded to the pipeline")
        XCTAssertEqual(
            mockDisk.callCount,
            0,
            "The skip must happen before free space is ever consulted"
        )
    }

    /// The decrypt pre-flight has to land before the private-key route, because the
    /// point of it is to spare the user an authentication prompt and a long write
    /// that the volume cannot finish. A refusal raised after the decryptor had run
    /// would still throw `insufficientDiskSpace`, so the spy — not the error — is
    /// what pins the ordering.
    func test_decryptFileStreaming_insufficientDiskSpace_refusesBeforeDecryptorRuns() async throws {
        let mockDisk = MockDiskSpace()
        mockDisk.availableBytes = 1024
        let spyDecryptor = SpyStreamingFileDecryptor()
        let artifactRoot = try makeIsolatedArtifactRoot()
        defer { try? FileManager.default.removeItem(at: artifactRoot) }

        let recipient = try await generateKeyAndContact(
            suite: .ed25519LegacyCurve25519Legacy,
            name: "Disk Preflight Recipient"
        )
        let encryptedURL = try writeTempFile(Data(repeating: 0x42, count: 4 * 1024 * 1024))
        defer { try? FileManager.default.removeItem(at: encryptedURL) }

        let decService = makeDecryptionService(
            fileDecryptor: spyDecryptor,
            diskSpace: mockDisk,
            artifactRoot: artifactRoot
        )

        do {
            let result = try await decService.decryptFileStreamingDetailed(
                phase1: FileDecryptionPhase1Result(
                    matchedKey: recipient,
                    inputPath: encryptedURL.path
                ),
                progress: nil
            )
            result.artifact.cleanup()
            XCTFail("Expected insufficientDiskSpace error")
        } catch let error as CypherAirError {
            if case .insufficientDiskSpace = error {
                // Expected
            } else {
                XCTFail("Expected insufficientDiskSpace, got: \(error)")
            }
        }

        XCTAssertEqual(mockDisk.callCount, 1, "Disk space should have been checked once")
        XCTAssertEqual(
            spyDecryptor.callCount,
            0,
            "The pre-flight must refuse before the private-key route authenticates"
        )
        XCTAssertEqual(
            try decryptedOperationArtifacts(in: artifactRoot),
            [],
            "A refused decrypt must not leave an output artifact behind"
        )
    }

    /// The decrypt estimate is the ciphertext size exactly, and that "exactly" is a
    /// decision, not an accident: free space equal to the input must be enough. Any
    /// safety margin someone adds later — even 1.01x — refuses here.
    func test_decryptFileStreaming_freeSpaceEqualToInputSize_proceeds() async throws {
        let inputByteCount = 4096
        let mockDisk = MockDiskSpace()
        mockDisk.availableBytes = UInt64(inputByteCount)
        let spyDecryptor = SpyStreamingFileDecryptor()
        let artifactRoot = try makeIsolatedArtifactRoot()
        defer { try? FileManager.default.removeItem(at: artifactRoot) }

        let recipient = try await generateKeyAndContact(
            suite: .ed25519LegacyCurve25519Legacy,
            name: "Exact Fit Recipient"
        )
        let encryptedURL = try writeTempFile(Data(repeating: 0x42, count: inputByteCount))
        defer { try? FileManager.default.removeItem(at: encryptedURL) }

        let result = try await makeDecryptionService(
            fileDecryptor: spyDecryptor,
            diskSpace: mockDisk,
            artifactRoot: artifactRoot
        ).decryptFileStreamingDetailed(
            phase1: FileDecryptionPhase1Result(
                matchedKey: recipient,
                inputPath: encryptedURL.path
            ),
            progress: nil
        )
        defer { result.artifact.cleanup() }

        XCTAssertEqual(spyDecryptor.callCount, 1, "Free space equal to the input must be enough")
    }

    /// Armored input is the same ciphertext in base64, so its file size overstates the
    /// plaintext by a third and the requirement is three quarters of it. Probing both
    /// sides of that boundary pins the correction in both directions: dropping it
    /// refuses at the first probe, overshooting it accepts at the second.
    func test_decryptFileStreaming_armoredInput_requiresThreeQuartersOfFileSize() async throws {
        let armoredByteCount = 4096
        let expectedRequirement = UInt64(armoredByteCount / 4 * 3)
        let artifactRoot = try makeIsolatedArtifactRoot()
        defer { try? FileManager.default.removeItem(at: artifactRoot) }

        let recipient = try await generateKeyAndContact(
            suite: .ed25519LegacyCurve25519Legacy,
            name: "Armored Input Recipient"
        )
        let armoredURL = try writeArmoredTempFile(totalBytes: armoredByteCount)
        defer { try? FileManager.default.removeItem(at: armoredURL) }
        let phase1 = FileDecryptionPhase1Result(
            matchedKey: recipient,
            inputPath: armoredURL.path
        )

        let atRequirement = MockDiskSpace()
        atRequirement.availableBytes = expectedRequirement
        let acceptingSpy = SpyStreamingFileDecryptor()
        let accepted = try await makeDecryptionService(
            fileDecryptor: acceptingSpy,
            diskSpace: atRequirement,
            artifactRoot: artifactRoot
        ).decryptFileStreamingDetailed(phase1: phase1, progress: nil)
        accepted.artifact.cleanup()
        XCTAssertEqual(
            acceptingSpy.callCount,
            1,
            "Three quarters of the armored file size must be enough"
        )

        let belowRequirement = MockDiskSpace()
        belowRequirement.availableBytes = expectedRequirement - 1
        let refusingSpy = SpyStreamingFileDecryptor()
        do {
            let result = try await makeDecryptionService(
                fileDecryptor: refusingSpy,
                diskSpace: belowRequirement,
                artifactRoot: artifactRoot
            ).decryptFileStreamingDetailed(phase1: phase1, progress: nil)
            result.artifact.cleanup()
            XCTFail("Expected insufficientDiskSpace error")
        } catch let error as CypherAirError {
            if case .insufficientDiskSpace = error {
                // Expected
            } else {
                XCTFail("Expected insufficientDiskSpace, got: \(error)")
            }
        }
        XCTAssertEqual(
            refusingSpy.callCount,
            0,
            "One byte below three quarters must still refuse"
        )
    }

    /// An input whose size cannot be read is not a reason to refuse: the pre-flight
    /// only ever fails for missing space, and the real problem with the file surfaces
    /// from the decrypt pipeline itself. Reported free space is zero here, so a
    /// pre-flight that ran anyway would refuse and fail this test.
    func test_decryptFileStreaming_unreadableInputSize_skipsPreflightAndProceeds() async throws {
        let mockDisk = MockDiskSpace()
        mockDisk.availableBytes = 0
        let spyDecryptor = SpyStreamingFileDecryptor()
        let artifactRoot = try makeIsolatedArtifactRoot()
        defer { try? FileManager.default.removeItem(at: artifactRoot) }

        let recipient = try await generateKeyAndContact(
            suite: .ed25519LegacyCurve25519Legacy,
            name: "Unreadable Input Recipient"
        )

        let decService = makeDecryptionService(
            fileDecryptor: spyDecryptor,
            diskSpace: mockDisk,
            artifactRoot: artifactRoot
        )

        let result = try await decService.decryptFileStreamingDetailed(
            phase1: FileDecryptionPhase1Result(
                matchedKey: recipient,
                inputPath: "/nonexistent/CypherAirDiskPreflightTests/missing.gpg"
            ),
            progress: nil
        )
        defer { result.artifact.cleanup() }

        XCTAssertEqual(spyDecryptor.callCount, 1, "Decryption should have proceeded to the pipeline")
        XCTAssertEqual(
            mockDisk.callCount,
            0,
            "The skip must happen before free space is ever consulted"
        )
    }

    private func makeDecryptionService(
        fileDecryptor: any StreamingFileDecrypting,
        diskSpace: any DiskSpaceProvidable,
        artifactRoot: URL
    ) -> DecryptionService {
        let messageAdapter = PGPMessageOperationAdapter(engine: stack.engine)
        return DecryptionService(
            messageAdapter: messageAdapter,
            keyManagement: stack.keyManagement,
            contactService: stack.contactService,
            messageDecryptor: TestHelpers.makeMessageDecryptor(
                engine: stack.engine,
                keyManagement: stack.keyManagement,
                messageAdapter: messageAdapter
            ),
            fileDecryptor: fileDecryptor,
            diskSpaceChecker: DiskSpaceChecker(diskSpace: diskSpace),
            temporaryArtifactStore: AppTemporaryArtifactStore(temporaryDirectory: artifactRoot)
        )
    }

    private func makeEncryptionService(
        fileEncryptor: any StreamingFileEncrypting,
        diskSpace: any DiskSpaceProvidable,
        artifactRoot: URL
    ) -> EncryptionService {
        EncryptionService(
            keyManagement: stack.keyManagement,
            contactService: stack.contactService,
            textEncryptor: stack.textEncryptor,
            fileEncryptor: fileEncryptor,
            diskSpaceChecker: DiskSpaceChecker(diskSpace: diskSpace),
            temporaryArtifactStore: AppTemporaryArtifactStore(temporaryDirectory: artifactRoot)
        )
    }

    /// A file that opens with the OpenPGP armor header and is padded with base64
    /// characters to an exact size. Only the head has to be real — the spy decryptor
    /// never parses the body.
    private func writeArmoredTempFile(totalBytes: Int) throws -> URL {
        var contents = Data("-----BEGIN PGP MESSAGE-----\n\n".utf8)
        contents.append(
            Data(repeating: UInt8(ascii: "A"), count: totalBytes - contents.count)
        )
        return try writeTempFile(contents, filename: "armored-\(UUID().uuidString).asc")
    }

    /// A per-test artifact root, so the assertions cannot be perturbed by another
    /// process sharing the app's temporary directory.
    private func makeIsolatedArtifactRoot() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirDiskPreflightTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func decryptedOperationArtifacts(in artifactRoot: URL) throws -> [URL] {
        let decryptedDirectory = artifactRoot.appendingPathComponent("decrypted", isDirectory: true)
        guard FileManager.default.fileExists(atPath: decryptedDirectory.path) else {
            return []
        }
        return try FileManager.default.contentsOfDirectory(
            at: decryptedDirectory,
            includingPropertiesForKeys: nil
        )
    }

    // MARK: - Tamper Detection

    func test_decryptFileStreaming_tamperedFile_throwsError() async throws {
        let key = try await generateKeyAndContact(suite: .ed448X448, name: "Tamper Test")

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
            validity: .never,
            suite: .ed25519LegacyCurve25519Legacy
        )

        // Parse the external public key and add as contact
        try stack.contactService.importContact(publicKeyData: externalKey.publicKeyData)

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
        let (emptyKeyMgmt, _, _, _, _) = TestHelpers.makeKeyManagement()
        let emptyMessageAdapter = PGPMessageOperationAdapter(engine: engine)
        let decSvc = DecryptionService(
            messageAdapter: emptyMessageAdapter,
            keyManagement: emptyKeyMgmt,
            contactService: stack.contactService,
            messageDecryptor: TestHelpers.makeMessageDecryptor(
                engine: engine,
                keyManagement: emptyKeyMgmt,
                messageAdapter: emptyMessageAdapter
            ),
            fileDecryptor: TestHelpers.makeFileDecryptor(
                engine: engine,
                keyManagement: emptyKeyMgmt,
                messageAdapter: emptyMessageAdapter
            )
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
        let identity = try await generateKeyAndContact(suite: .ed25519LegacyCurve25519Legacy)

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
        } catch let error as CypherAirError {
            guard case .fileIoError = error else {
                XCTFail("Expected fileIoError from the streaming pipeline, got: \(error)")
                return
            }
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

/// Records whether the streaming file encryptor was reached, which is what lets a
/// pre-flight test distinguish "refused up front" from "refused after the work".
/// Creates the output file on the way out because `EncryptionService` applies file
/// protection to it before returning.
///
/// `@unchecked Sendable`: the counter is written once inside the awaited call and
/// read after it returns, never concurrently.
private final class SpyStreamingFileEncryptor: StreamingFileEncrypting, @unchecked Sendable {
    private(set) var callCount = 0

    func encryptFile(
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signerFingerprint: String?,
        selfKey: Data?,
        progress: FileProgressReporter?
    ) async throws {
        callCount += 1
        try Data().write(to: URL(fileURLWithPath: outputPath))
    }
}

/// Records whether the streaming file decryptor was reached, which is what lets a
/// pre-flight test distinguish "refused up front" from "refused after the work".
/// Creates the output file on the way out because `DecryptionService` applies file
/// protection to it before returning.
///
/// `@unchecked Sendable`: the counter is written once inside the awaited call and
/// read after it returns, never concurrently.
private final class SpyStreamingFileDecryptor: StreamingFileDecrypting, @unchecked Sendable {
    private(set) var callCount = 0

    func decryptFile(
        inputPath: String,
        outputPath: String,
        recipientFingerprint: String,
        verificationContext: PGPMessageVerificationContext,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification {
        callCount += 1
        try Data().write(to: URL(fileURLWithPath: outputPath))
        return DetailedSignatureVerification(summaryState: .notSigned, signatures: [])
    }
}
