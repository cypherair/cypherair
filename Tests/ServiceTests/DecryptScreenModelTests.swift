import Foundation
import XCTest
@testable import CypherAir

private actor DecryptOperationGate {
    private var continuation: CheckedContinuation<Void, Never>?

    func suspend() async {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }

    func isSuspended() -> Bool {
        continuation != nil
    }

    func resume() {
        continuation?.resume()
        continuation = nil
    }
}

final class DecryptScreenModelTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!
    private var config: AppConfiguration!
    private var defaultsSuiteName: String!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
        defaultsSuiteName = "com.cypherair.tests.decryptscreen.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        config = AppConfiguration(defaults: defaults)
    }

    override func tearDown() {
        if let defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?
                .removePersistentDomain(forName: defaultsSuiteName)
        }
        stack.cleanup()
        stack = nil
        config = nil
        defaultsSuiteName = nil
        super.tearDown()
    }

    @MainActor
    func test_handleAppear_preservesEditedCiphertextInput_butReappliesInitialPhase1Result() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let initialPhase1Result = makePhase1Result(
            matchedKey: identity,
            ciphertext: Data("initial-ciphertext".utf8)
        )

        var configuration = DecryptView.Configuration()
        configuration.prefilledCiphertext = "Prefilled ciphertext"
        configuration.initialPhase1Result = initialPhase1Result

        let model = makeModel(configuration: configuration)

        model.handleAppear()

        XCTAssertEqual(model.ciphertextInput, "Prefilled ciphertext")
        XCTAssertEqual(model.phase1Result?.matchedKey?.fingerprint, identity.fingerprint)
        XCTAssertEqual(model.phase1Result?.ciphertext, Data("initial-ciphertext".utf8))

        model.ciphertextInput = "User edited ciphertext"
        model.phase1Result = makePhase1Result(
            matchedKey: nil,
            ciphertext: Data("override".utf8)
        )

        model.handleAppear()

        XCTAssertEqual(model.ciphertextInput, "User edited ciphertext")
        XCTAssertEqual(model.phase1Result?.matchedKey?.fingerprint, identity.fingerprint)
        XCTAssertEqual(model.phase1Result?.ciphertext, Data("initial-ciphertext".utf8))
    }

    @MainActor
    func test_setCiphertextInput_invalidatesImportedTextAndTextPhase1State() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let model = makeModel()
        model.importedCiphertext.setImportedFile(
            data: Data("old".utf8),
            fileName: "message.asc",
            text: "OLD"
        )
        model.phase1Result = makePhase1Result(matchedKey: identity)
        model.decryptedText = "Plaintext"
        model.signatureVerification = makeSignature(status: .valid)
        let startingEpoch = model.textInputSectionEpoch

        model.setCiphertextInput("NEW")

        XCTAssertEqual(model.ciphertextInput, "NEW")
        XCTAssertFalse(model.importedCiphertext.hasImportedFile)
        XCTAssertNil(model.phase1Result)
        XCTAssertNil(model.signatureVerification)
        XCTAssertNil(model.decryptedText)
        XCTAssertEqual(model.textInputSectionEpoch, startingEpoch + 1)
    }

    @MainActor
    func test_requestTextCiphertextImport_andHandleImportedFile_setsImportedState() {
        let inputURL = URL(fileURLWithPath: "/tmp/message.asc")
        let model = makeModel(
            textCiphertextFileImportAction: { url in
                XCTAssertEqual(url, inputURL)
                return (Data("ARMORED".utf8), "ARMORED")
            }
        )
        model.phase1Result = makePhase1Result()
        model.signatureVerification = makeSignature(status: .bad)

        model.requestTextCiphertextImport()
        XCTAssertEqual(model.fileImportTarget, .textCiphertextImport)
        XCTAssertTrue(model.showFileImporter)

        model.handleImportedFile(inputURL)
        model.finishFileImportRequest()

        XCTAssertEqual(model.ciphertextInput, "ARMORED")
        XCTAssertTrue(model.importedCiphertext.hasImportedFile)
        XCTAssertEqual(model.importedCiphertext.fileName, "message.asc")
        XCTAssertNil(model.phase1Result)
        XCTAssertNil(model.signatureVerification)
    }

    @MainActor
    func test_fileImportSuggestion_openPendingFileAsText_switchesModeAndImportsText() {
        let inputURL = URL(fileURLWithPath: "/tmp/message.asc")
        let armoredText = "-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----"
        let model = makeModel(
            ciphertextFileInspectionAction: { url in
                XCTAssertEqual(url, inputURL)
                return (Data(armoredText.utf8), armoredText)
            }
        )
        model.decryptMode = .file

        model.requestFileCiphertextImport()
        model.handleImportedFile(inputURL)
        model.finishFileImportRequest()

        XCTAssertTrue(model.showTextModeSuggestion)

        model.openPendingFileAsText()

        XCTAssertEqual(model.decryptMode, .text)
        XCTAssertEqual(model.ciphertextInput, armoredText)
        XCTAssertTrue(model.importedCiphertext.hasImportedFile)
        XCTAssertEqual(model.importedCiphertext.fileName, "message.asc")
        XCTAssertFalse(model.showTextModeSuggestion)
    }

    @MainActor
    func test_fileImportSuggestion_keepPendingFileAsFile_selectsFile() {
        let inputURL = URL(fileURLWithPath: "/tmp/message.asc")
        let model = makeModel(
            ciphertextFileInspectionAction: { url in
                XCTAssertEqual(url, inputURL)
                return (Data("cipher".utf8), "cipher")
            }
        )
        model.decryptMode = .file

        model.requestFileCiphertextImport()
        model.handleImportedFile(inputURL)
        model.finishFileImportRequest()

        XCTAssertTrue(model.showTextModeSuggestion)

        model.keepPendingFileAsFile()

        XCTAssertEqual(model.decryptMode, .file)
        XCTAssertEqual(model.selectedFileURL, inputURL)
        XCTAssertEqual(model.selectedFileName, "message.asc")
        XCTAssertFalse(model.showTextModeSuggestion)
        XCTAssertNil(model.filePhase1Result)
    }

    @MainActor
    func test_parseAndDecryptText_invokeCallbacks_andPublishResult() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let phase1Result = makePhase1Result(
            matchedKey: identity,
            ciphertext: Data("binary-ciphertext".utf8)
        )
        let signature = makeSignature(status: .valid, signerFingerprint: identity.fingerprint)

        var parsedFingerprint: String?
        var decryptedPlaintext: Data?
        var decryptedStatus: SignatureStatus?
        var configuration = DecryptView.Configuration()
        configuration.onParsed = { result in
            parsedFingerprint = result.matchedKey?.fingerprint
        }
        configuration.onDecrypted = { plaintext, signature in
            decryptedPlaintext = plaintext
            decryptedStatus = signature.status
        }

        let model = makeModel(
            configuration: configuration,
            parseTextRecipientsAction: { ciphertext in
                XCTAssertEqual(ciphertext, Data("ciphertext".utf8))
                return phase1Result
            },
            textDecryptionAction: { phase1 in
                XCTAssertEqual(phase1.ciphertext, Data("binary-ciphertext".utf8))
                return (Data("decrypted-text".utf8), signature)
            }
        )
        model.ciphertextInput = "ciphertext"

        model.parseRecipientsText()

        await waitUntil("text parse to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(model.phase1Result?.matchedKey?.fingerprint, identity.fingerprint)
        XCTAssertEqual(parsedFingerprint, identity.fingerprint)

        model.decryptText()

        await waitUntil("text decrypt to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(model.decryptedText, "decrypted-text")
        XCTAssertEqual(model.signatureVerification?.status, .valid)
        XCTAssertEqual(decryptedPlaintext, Data("decrypted-text".utf8))
        XCTAssertEqual(decryptedStatus, .valid)
    }

    @MainActor
    func test_parseAndDecryptFile_andExportRouteThroughInterceptionPolicy() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let inputURL = try makeTemporaryFile(
            named: "message.gpg",
            contents: Data("cipher".utf8)
        )
        let outputURL = try makeTemporaryFile(
            named: "message",
            contents: Data("plaintext".utf8)
        )
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let filePhase1Result = makeFilePhase1Result(
            matchedKey: identity,
            inputURL: inputURL
        )
        let signature = makeSignature(status: .unknownSigner)

        var interceptedURL: URL?
        var interceptedFilename: String?
        var configuration = DecryptView.Configuration()
        configuration.outputInterceptionPolicy = OutputInterceptionPolicy(
            interceptFileExport: { url, filename, kind in
                XCTAssertEqual(kind, .generic)
                interceptedURL = url
                interceptedFilename = filename
                return true
            }
        )

        let model = makeModel(
            configuration: configuration,
            parseFileRecipientsAction: { url in
                XCTAssertEqual(url, inputURL)
                return filePhase1Result
            },
            fileDecryptionAction: { url, phase1, _ in
                XCTAssertEqual(url, inputURL)
                XCTAssertEqual(phase1.inputPath, inputURL.path)
                return (outputURL, signature)
            }
        )
        model.decryptMode = .file
        model.selectedFileURL = inputURL
        model.selectedFileName = inputURL.lastPathComponent

        model.parseRecipientsFile()

        await waitUntil("file parse to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(model.filePhase1Result?.matchedKey?.fingerprint, identity.fingerprint)

        model.decryptFile()

        await waitUntil("file decrypt to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(model.decryptedFileURL, outputURL)
        XCTAssertEqual(model.signatureVerification?.status, .unknownSigner)

        model.exportDecryptedFile()

        XCTAssertEqual(interceptedURL, outputURL)
        XCTAssertEqual(
            interceptedFilename,
            (inputURL.lastPathComponent as NSString).deletingPathExtension
        )
    }

    @MainActor
    func test_decryptFile_cancellation_clearsProgress_andDoesNotPublishOutputURL() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let inputURL = try makeTemporaryFile(
            named: "cancel.gpg",
            contents: Data("cipher".utf8)
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let gate = DecryptOperationGate()
        let model = makeModel(
            fileDecryptionAction: { _, _, progress in
                _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
                await gate.suspend()
                try Task.checkCancellation()
                return (inputURL, self.makeSignature(status: .valid))
            }
        )
        model.decryptMode = .file
        model.selectedFileURL = inputURL
        model.selectedFileName = inputURL.lastPathComponent
        model.filePhase1Result = makeFilePhase1Result(
            matchedKey: identity,
            inputURL: inputURL
        )

        model.decryptFile()

        await waitUntil("file decrypt to suspend") {
            guard model.operation.isRunning, model.operation.progress != nil else {
                return false
            }
            return await gate.isSuspended()
        }

        model.operation.cancel()

        XCTAssertTrue(model.operation.isRunning)
        XCTAssertTrue(model.operation.isCancelling)

        await gate.resume()

        await waitUntil("cancelled file decrypt to finish") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.decryptedFileURL)
        XCTAssertNil(model.operation.progress)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_handleContentClearGenerationChange_andHandleDisappear_haveDifferentCleanupScopes() throws {
        let contentClearURL = try makeTemporaryFile(
            named: "content-clear.tmp",
            contents: Data("plaintext".utf8)
        )
        defer { try? FileManager.default.removeItem(at: contentClearURL) }

        let model = makeModel()
        model.decryptedText = "Plaintext"
        model.signatureVerification = makeSignature(status: .valid)
        model.phase1Result = makePhase1Result()
        model.filePhase1Result = makeFilePhase1Result(
            matchedKey: nil,
            inputURL: contentClearURL
        )
        model.decryptedFileURL = contentClearURL
        model.importedCiphertext.setImportedFile(
            data: Data("cipher".utf8),
            fileName: "message.asc",
            text: "cipher"
        )
        model.fileImportTarget = .fileCiphertextImport

        model.handleContentClearGenerationChange()

        XCTAssertNil(model.decryptedText)
        XCTAssertNil(model.signatureVerification)
        XCTAssertNil(model.phase1Result)
        XCTAssertNil(model.filePhase1Result)
        XCTAssertFalse(FileManager.default.fileExists(atPath: contentClearURL.path))
        XCTAssertTrue(model.importedCiphertext.hasImportedFile)
        XCTAssertEqual(model.fileImportTarget, .fileCiphertextImport)

        let disappearURL = try makeTemporaryFile(
            named: "disappear.tmp",
            contents: Data("plaintext".utf8)
        )
        defer { try? FileManager.default.removeItem(at: disappearURL) }

        model.decryptedFileURL = disappearURL
        model.importedCiphertext.setImportedFile(
            data: Data("cipher".utf8),
            fileName: "message.asc",
            text: "cipher"
        )
        model.fileImportTarget = .textCiphertextImport

        model.handleDisappear()

        XCTAssertNil(model.decryptedFileURL)
        XCTAssertFalse(FileManager.default.fileExists(atPath: disappearURL.path))
        XCTAssertFalse(model.importedCiphertext.hasImportedFile)
        XCTAssertNil(model.fileImportTarget)
    }

    @MainActor
    private func makeModel(
        configuration: DecryptView.Configuration = .default,
        operation: OperationController = OperationController(),
        parseTextRecipientsAction: DecryptScreenModel.ParseTextRecipientsAction? = nil,
        parseFileRecipientsAction: DecryptScreenModel.ParseFileRecipientsAction? = nil,
        textCiphertextFileImportAction: DecryptScreenModel.TextCiphertextFileImportAction? = nil,
        ciphertextFileInspectionAction: DecryptScreenModel.CiphertextFileInspectionAction? = nil,
        textDecryptionAction: DecryptScreenModel.TextDecryptionAction? = nil,
        fileDecryptionAction: DecryptScreenModel.FileDecryptionAction? = nil
    ) -> DecryptScreenModel {
        DecryptScreenModel(
            decryptionService: stack.decryptionService,
            configuration: configuration,
            operation: operation,
            parseTextRecipientsAction: parseTextRecipientsAction,
            parseFileRecipientsAction: parseFileRecipientsAction,
            textCiphertextFileImportAction: textCiphertextFileImportAction,
            ciphertextFileInspectionAction: ciphertextFileInspectionAction,
            textDecryptionAction: textDecryptionAction,
            fileDecryptionAction: fileDecryptionAction
        )
    }

    private func makeTemporaryFile(named name: String, contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirDecryptScreenTests-\(UUID().uuidString)-\(name)")
        try contents.write(to: url, options: .atomic)
        return url
    }

    private func makePhase1Result(
        matchedKey: PGPKeyIdentity? = nil,
        ciphertext: Data = Data("ciphertext".utf8)
    ) -> DecryptionService.Phase1Result {
        DecryptionService.Phase1Result(
            recipientKeyIds: ["ABCD1234"],
            matchedKey: matchedKey,
            ciphertext: ciphertext
        )
    }

    private func makeFilePhase1Result(
        matchedKey: PGPKeyIdentity?,
        inputURL: URL
    ) -> DecryptionService.FilePhase1Result {
        DecryptionService.FilePhase1Result(
            recipientKeyIds: ["ABCD1234"],
            matchedKey: matchedKey,
            inputPath: inputURL.path
        )
    }

    private func makeSignature(
        status: SignatureStatus,
        signerFingerprint: String? = nil
    ) -> SignatureVerification {
        SignatureVerification(
            status: status,
            signerFingerprint: signerFingerprint,
            signerContact: nil
        )
    }

    @MainActor
    private func waitUntil(
        _ description: String,
        timeout: TimeInterval = 2,
        condition: @escaping @MainActor () async -> Bool
    ) async {
        let deadline = Date().addingTimeInterval(timeout)

        while Date() < deadline {
            if await condition() {
                return
            }
            await Task.yield()
        }

        XCTFail("Timed out waiting for \(description)")
    }
}
