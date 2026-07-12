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
    private var defaultsSuiteName: String!

    override func setUp() async throws {
        try await super.setUp()
        stack = await TestHelpers.makeServiceStack()
        defaultsSuiteName = "com.cypherair.tests.decryptscreen.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
    }

    override func tearDown() {
        if let defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?
                .removePersistentDomain(forName: defaultsSuiteName)
        }
        stack.cleanup()
        stack = nil
        defaultsSuiteName = nil
        super.tearDown()
    }

    @MainActor
    func test_handleAppear_preservesEditedCiphertextInput_butReappliesInitialPhase1Result() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
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
    func test_updateConfiguration_updatesTutorialState_withoutOverwritingEditedCiphertext() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let initialPhase1Result = makePhase1Result(
            matchedKey: identity,
            ciphertext: Data("initial-ciphertext".utf8)
        )

        let model = makeModel()
        model.ciphertextInput = "User edited ciphertext"
        model.phase1Result = makePhase1Result(
            matchedKey: nil,
            ciphertext: Data("override".utf8)
        )

        var configuration = DecryptView.Configuration()
        configuration.prefilledCiphertext = "Prefilled ciphertext"
        configuration.initialPhase1Result = initialPhase1Result
        configuration.allowsFileResultExport = false

        model.updateConfiguration(configuration)

        XCTAssertEqual(model.ciphertextInput, "User edited ciphertext")
        XCTAssertEqual(model.phase1Result?.matchedKey?.fingerprint, identity.fingerprint)
        XCTAssertEqual(model.phase1Result?.ciphertext, Data("initial-ciphertext".utf8))
        XCTAssertFalse(model.configuration.allowsFileResultExport)
    }

    @MainActor
    func test_updateConfiguration_clearsTutorialPhase1Seed_whenConfigurationBecomesInactive() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let initialPhase1Result = makePhase1Result(
            matchedKey: identity,
            ciphertext: Data("initial-ciphertext".utf8)
        )

        let model = makeModel()
        model.ciphertextInput = "User edited ciphertext"

        var activeConfiguration = DecryptView.Configuration()
        activeConfiguration.prefilledCiphertext = "Prefilled ciphertext"
        activeConfiguration.initialPhase1Result = initialPhase1Result

        model.updateConfiguration(activeConfiguration)

        XCTAssertEqual(model.ciphertextInput, "User edited ciphertext")
        XCTAssertEqual(model.phase1Result?.matchedKey?.fingerprint, identity.fingerprint)

        model.updateConfiguration(.default)

        XCTAssertEqual(model.ciphertextInput, "User edited ciphertext")
        XCTAssertNil(model.phase1Result)
    }

    @MainActor
    func test_parseRecipientsText_usesCallbackCapturedAtOperationStart_whenConfigurationChangesMidFlight() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let gate = DecryptOperationGate()
        let phase1Result = makePhase1Result(
            matchedKey: identity,
            ciphertext: Data("ciphertext".utf8)
        )

        var firstParsedFingerprint: String?
        var secondParsedFingerprint: String?
        var configuration = DecryptView.Configuration()
        configuration.onParsed = { result in
            firstParsedFingerprint = result.matchedKey?.fingerprint
        }

        let model = makeModel(
            configuration: configuration,
            parseTextRecipientsAction: { _ in
                await gate.suspend()
                return phase1Result
            }
        )
        model.ciphertextInput = "ciphertext"

        model.parseRecipientsText()

        await waitUntil("text parse to suspend") {
            guard model.operation.isRunning else {
                return false
            }
            return await gate.isSuspended()
        }

        configuration.onParsed = { result in
            secondParsedFingerprint = result.matchedKey?.fingerprint
        }
        configuration.allowsFileInput = false
        model.updateConfiguration(configuration)

        await gate.resume()

        await waitUntil("text parse to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(firstParsedFingerprint, identity.fingerprint)
        XCTAssertNil(secondParsedFingerprint)
    }

    @MainActor
    func test_decryptText_usesCallbackCapturedAtOperationStart_whenConfigurationChangesMidFlight() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let gate = DecryptOperationGate()
        let detailedVerification = makeDetailedVerification(
            verificationState: .verified,
            signerFingerprint: identity.fingerprint
        )

        var firstDecryptedPlaintext: Data?
        var secondDecryptedPlaintext: Data?
        var configuration = DecryptView.Configuration()
        configuration.onDecrypted = { plaintext, _ in
            firstDecryptedPlaintext = plaintext
        }

        let model = makeModel(
            configuration: configuration,
            textDecryptionAction: { _ in
                await gate.suspend()
                return (Data("decrypted-text".utf8), detailedVerification)
            }
        )
        model.phase1Result = makePhase1Result(
            matchedKey: identity,
            ciphertext: Data("ciphertext".utf8)
        )

        model.decryptText()

        await waitUntil("text decrypt to suspend") {
            guard model.operation.isRunning else {
                return false
            }
            return await gate.isSuspended()
        }

        configuration.onDecrypted = { plaintext, _ in
            secondDecryptedPlaintext = plaintext
        }
        configuration.allowsFileResultExport = false
        model.updateConfiguration(configuration)

        await gate.resume()

        await waitUntil("text decrypt to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(firstDecryptedPlaintext, Data("decrypted-text".utf8))
        XCTAssertNil(secondDecryptedPlaintext)
    }

    @MainActor
    func test_contentClearDuringTextParseSuppressesLatePhase1ResultAndCallback() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Parse Privacy"
        )
        let phase1Result = makePhase1Result(matchedKey: identity)
        let gate = DecryptOperationGate()
        var parsedResult: DecryptionPhase1Result?
        var configuration = DecryptView.Configuration()
        configuration.onParsed = { parsedResult = $0 }

        let model = makeModel(
            configuration: configuration,
            parseTextRecipientsAction: { _ in
                await gate.suspend()
                return phase1Result
            }
        )
        model.ciphertextInput = "ciphertext"

        model.parseRecipientsText()

        await waitUntil("text parse to suspend for content clear") {
            guard model.operation.isRunning else {
                return false
            }
            return await gate.isSuspended()
        }

        model.handleContentClearGenerationChange()
        XCTAssertFalse(model.operation.isRunning)
        XCTAssertNil(model.phase1Result)

        await gate.resume()
        await settleAsyncWork()

        XCTAssertNil(model.phase1Result)
        XCTAssertNil(parsedResult)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_contentClearDuringTextDecryptSuppressesLatePlaintextAndCallback() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Decrypt Privacy"
        )
        let detailedVerification = makeDetailedVerification(verificationState: .verified)
        let gate = DecryptOperationGate()
        var decryptedPlaintext: Data?
        var configuration = DecryptView.Configuration()
        configuration.onDecrypted = { plaintext, _ in decryptedPlaintext = plaintext }

        let model = makeModel(
            configuration: configuration,
            textDecryptionAction: { _ in
                await gate.suspend()
                return (Data("late-plaintext".utf8), detailedVerification)
            }
        )
        model.phase1Result = makePhase1Result(matchedKey: identity)

        model.decryptText()

        await waitUntil("text decrypt to suspend for content clear") {
            guard model.operation.isRunning else {
                return false
            }
            return await gate.isSuspended()
        }

        model.handleContentClearGenerationChange()
        XCTAssertFalse(model.operation.isRunning)

        await gate.resume()
        await settleAsyncWork()

        XCTAssertNil(model.activeDetailedSignatureVerification)
        XCTAssertNil(decryptedPlaintext)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_setCiphertextInput_invalidatesImportedTextAndTextPhase1State() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
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
        model.textDecryptionResult = makeTextDecryptionResult(
            plaintext: "Plaintext",
            verificationState: .verified
        )
        let startingEpoch = model.textInputSectionEpoch

        model.setCiphertextInput("NEW")

        XCTAssertEqual(model.ciphertextInput, "NEW")
        XCTAssertFalse(model.importedCiphertext.hasImportedFile)
        XCTAssertNil(model.phase1Result)
        XCTAssertNil(model.activeDetailedSignatureVerification)
        XCTAssertEqual(model.textInputSectionEpoch, startingEpoch)
    }

    @MainActor
    func test_requestTextCiphertextImport_andHandleFileImporterResult_setsImportedState() throws {
        let inputURL = URL(fileURLWithPath: "/tmp/message.asc")
        let model = makeModel(
            textCiphertextFileImportAction: { url in
                XCTAssertEqual(url, inputURL)
                return (Data("ARMORED".utf8), "ARMORED")
            }
        )
        model.phase1Result = makePhase1Result()
        model.textDecryptionResult = makeTextDecryptionResult(verificationState: .invalid)

        model.requestTextCiphertextImport()
        XCTAssertEqual(model.fileImportTarget, .textCiphertextImport)
        XCTAssertTrue(model.showFileImporter)

        let token = try XCTUnwrap(model.fileImportRequestToken)
        model.handleFileImporterResult(.success([inputURL]), token: token)

        XCTAssertEqual(model.ciphertextInput, "ARMORED")
        XCTAssertTrue(model.importedCiphertext.hasImportedFile)
        XCTAssertEqual(model.importedCiphertext.fileName, "message.asc")
        XCTAssertNil(model.fileImportTarget)
        XCTAssertNil(model.phase1Result)
        XCTAssertNil(model.activeDetailedSignatureVerification)
    }

    @MainActor
    func test_handleFileImporterResult_afterContentClear_ignoresStaleTextSelection() throws {
        let inputURL = URL(fileURLWithPath: "/tmp/message.asc")
        let model = makeModel(
            textCiphertextFileImportAction: { _ in
                (Data("ARMORED".utf8), "ARMORED")
            }
        )

        model.requestTextCiphertextImport()
        let token = try XCTUnwrap(model.fileImportRequestToken)
        model.clearTransientInput()
        model.handleFileImporterResult(.success([inputURL]), token: token)

        XCTAssertEqual(model.ciphertextInput, "")
        XCTAssertFalse(model.importedCiphertext.hasImportedFile)
        XCTAssertNil(model.fileImportTarget)
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
        model.fileDecryptionResult = makeFileDecryptionResult(
            outputURL: inputURL,
            verificationState: .verified
        )

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
        XCTAssertNil(model.activeDetailedSignatureVerification)
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
        model.fileDecryptionResult = makeFileDecryptionResult(
            outputURL: inputURL,
            verificationState: .verified
        )

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
        XCTAssertNil(model.activeDetailedSignatureVerification)
    }

    @MainActor
    func test_parseAndDecryptText_invokeCallbacks_andPublishResult() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let phase1Result = makePhase1Result(
            matchedKey: identity,
            ciphertext: Data("binary-ciphertext".utf8)
        )
        let detailedVerification = makeDetailedVerification(
            verificationState: .verified,
            signerFingerprint: identity.fingerprint
        )

        var parsedFingerprint: String?
        var decryptedPlaintext: Data?
        var decryptedSummaryState: SignatureVerification.VerificationState?
        var configuration = DecryptView.Configuration()
        configuration.onParsed = { result in
            parsedFingerprint = result.matchedKey?.fingerprint
        }
        configuration.onDecrypted = { plaintext, verification in
            decryptedPlaintext = plaintext
            decryptedSummaryState = verification.summaryState
        }

        let model = makeModel(
            configuration: configuration,
            parseTextRecipientsAction: { ciphertext in
                XCTAssertEqual(ciphertext, Data("ciphertext".utf8))
                return phase1Result
            },
            textDecryptionAction: { phase1 in
                XCTAssertEqual(phase1.ciphertext, Data("binary-ciphertext".utf8))
                return (Data("decrypted-text".utf8), detailedVerification)
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

        XCTAssertEqual(model.textDecryptionResult?.plaintext, "decrypted-text")
        XCTAssertEqual(model.textDecryptionResult?.verification.summaryState, .verified)
        XCTAssertEqual(model.activeDetailedSignatureVerification?.summaryState, .verified)
        XCTAssertEqual(decryptedPlaintext, Data("decrypted-text".utf8))
        XCTAssertEqual(decryptedSummaryState, .verified)
    }

    @MainActor
    func test_parseAndDecryptFile_andExportRouteThroughInterceptionPolicy() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
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
        let detailedVerification = makeDetailedVerification(verificationState: .signerCertificateUnavailable)

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
            fileDecryptionAction: { request in
                XCTAssertEqual(request.fileURL, inputURL)
                XCTAssertEqual(request.phase1Result.inputPath, inputURL.path)
                return DecryptScreenModel.FileDecryptionResult(
                    output: TemporaryFileOutput(fileURL: outputURL),
                    verification: detailedVerification
                )
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

        XCTAssertEqual(model.fileDecryptionResult?.output.fileURL, outputURL)
        XCTAssertEqual(model.fileDecryptionResult?.verification.summaryState, .signerCertificateUnavailable)
        XCTAssertEqual(model.activeDetailedSignatureVerification?.summaryState, .signerCertificateUnavailable)

        model.exportDecryptedFile()

        XCTAssertEqual(interceptedURL, outputURL)
        XCTAssertEqual(
            interceptedFilename,
            (inputURL.lastPathComponent as NSString).deletingPathExtension
        )
    }

    @MainActor
    func test_decryptFile_cancellation_clearsProgress_andDoesNotPublishOutputURL() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let inputURL = try makeTemporaryFile(
            named: "cancel.gpg",
            contents: Data("cipher".utf8)
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let gate = DecryptOperationGate()
        var capturedProgress: FileProgressReporter?
        let operation = OperationController(progressFactory: {
            let reporter = FileProgressReporter()
            capturedProgress = reporter
            return reporter
        })
        let model = makeModel(
            operation: operation,
            fileDecryptionAction: { _ in
                _ = capturedProgress?.onProgress(bytesProcessed: 5, totalBytes: 10)
                await gate.suspend()
                try Task.checkCancellation()
                return DecryptScreenModel.FileDecryptionResult(
                    output: TemporaryFileOutput(fileURL: inputURL),
                    verification: self.makeDetailedVerification(verificationState: .verified)
                )
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

        XCTAssertNil(model.fileDecryptionResult)
        XCTAssertNil(model.operation.progress)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_decryptFile_cancellationAfterServiceSuccess_cleansUnpublishedOutput() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let operation = OperationController()
        let inputURL = try makeTemporaryFile(
            named: "cancel-after-success.gpg",
            contents: Data("cipher".utf8)
        )
        let outputURL = try makeTemporaryFile(
            named: "cancel-after-success",
            contents: Data("plaintext".utf8)
        )
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let model = makeModel(
            operation: operation,
            fileDecryptionAction: { _ in
                operation.cancel()
                return DecryptScreenModel.FileDecryptionResult(
                    output: TemporaryFileOutput(fileURL: outputURL),
                    verification: self.makeDetailedVerification(verificationState: .verified)
                )
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

        await waitUntil("cancelled after service success") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.fileDecryptionResult)
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))
        XCTAssertNil(model.activeDetailedSignatureVerification)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_handleDisappearCancelsInFlightFileDecryptAndCleansLateOutput() async throws {
        let identity = try await TestHelpers.generateLegacyKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        let inputURL = try makeTemporaryFile(
            named: "abandoned.gpg",
            contents: Data("cipher".utf8)
        )
        let outputURL = try makeTemporaryFile(
            named: "abandoned",
            contents: Data("plaintext".utf8)
        )
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let gate = DecryptOperationGate()
        let model = makeModel(
            fileDecryptionAction: { _ in
                await gate.suspend()
                return DecryptScreenModel.FileDecryptionResult(
                    output: TemporaryFileOutput(fileURL: outputURL),
                    verification: self.makeDetailedVerification(verificationState: .verified)
                )
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

        await waitUntil("file decrypt to suspend before disappearance") {
            guard model.operation.isRunning else {
                return false
            }
            return await gate.isSuspended()
        }

        model.handleDisappear()

        XCTAssertFalse(model.operation.isRunning)

        await gate.resume()
        await settleAsyncWork()

        XCTAssertNil(model.fileDecryptionResult)
        XCTAssertNil(model.activeDetailedSignatureVerification)
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_textAndFileDecryptResultsKeepSeparateVerificationState() throws {
        let fileOutputURL = try makeTemporaryFile(
            named: "separate-mode-output",
            contents: Data("plaintext".utf8)
        )
        defer { try? FileManager.default.removeItem(at: fileOutputURL) }

        let model = makeModel()
        model.textDecryptionResult = makeTextDecryptionResult(
            plaintext: "Text plaintext",
            verificationState: .verified
        )
        model.fileDecryptionResult = makeFileDecryptionResult(
            outputURL: fileOutputURL,
            verificationState: .invalid
        )

        model.decryptMode = .text

        XCTAssertEqual(model.activeDetailedSignatureVerification?.summaryState, .verified)

        model.decryptMode = .file

        XCTAssertEqual(model.activeDetailedSignatureVerification?.summaryState, .invalid)

        model.setCiphertextInput("edited text")

        XCTAssertNil(model.textDecryptionResult)
        XCTAssertEqual(model.fileDecryptionResult?.verification.summaryState, .invalid)
        XCTAssertEqual(model.activeDetailedSignatureVerification?.summaryState, .invalid)
    }

    @MainActor
    func test_fileInputInvalidationDoesNotClearTextResult() async throws {
        let inputURL = try makeTemporaryFile(
            named: "file-input-change.gpg",
            contents: Data("cipher".utf8)
        )
        let fileOutputURL = try makeTemporaryFile(
            named: "file-input-change-output",
            contents: Data("plaintext".utf8)
        )
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: fileOutputURL)
        }

        let model = makeModel(
            parseFileRecipientsAction: { url in
                XCTAssertEqual(url, inputURL)
                return self.makeFilePhase1Result(matchedKey: nil, inputURL: inputURL)
            }
        )
        model.textDecryptionResult = makeTextDecryptionResult(
            plaintext: "Text plaintext",
            verificationState: .verified
        )
        model.fileDecryptionResult = makeFileDecryptionResult(
            outputURL: fileOutputURL,
            verificationState: .invalid
        )
        model.decryptMode = .file
        model.selectedFileURL = inputURL
        model.selectedFileName = inputURL.lastPathComponent

        model.parseRecipientsFile()

        await waitUntil("file parse to finish") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.fileDecryptionResult)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileOutputURL.path))

        model.decryptMode = .text

        XCTAssertEqual(model.textDecryptionResult?.plaintext, "Text plaintext")
        XCTAssertEqual(model.activeDetailedSignatureVerification?.summaryState, .verified)
    }

    @MainActor
    func test_handleContentClearGenerationChange_andHandleDisappear_haveDifferentCleanupScopes() throws {
        let contentClearURL = try makeTemporaryFile(
            named: "content-clear.tmp",
            contents: Data("plaintext".utf8)
        )
        defer { try? FileManager.default.removeItem(at: contentClearURL) }

        let model = makeModel()
        model.textDecryptionResult = makeTextDecryptionResult(
            plaintext: "Plaintext",
            verificationState: .verified
        )
        model.phase1Result = makePhase1Result()
        model.filePhase1Result = makeFilePhase1Result(
            matchedKey: nil,
            inputURL: contentClearURL
        )
        model.fileDecryptionResult = makeFileDecryptionResult(
            outputURL: contentClearURL,
            verificationState: .signerCertificateUnavailable
        )
        model.importedCiphertext.setImportedFile(
            data: Data("cipher".utf8),
            fileName: "message.asc",
            text: "cipher"
        )
        model.fileImportTarget = .fileCiphertextImport

        model.handleContentClearGenerationChange()

        XCTAssertEqual(model.ciphertextInput, "")
        XCTAssertNil(model.textDecryptionResult)
        XCTAssertNil(model.activeDetailedSignatureVerification)
        XCTAssertNil(model.phase1Result)
        XCTAssertNil(model.filePhase1Result)
        XCTAssertFalse(FileManager.default.fileExists(atPath: contentClearURL.path))
        XCTAssertFalse(model.importedCiphertext.hasImportedFile)
        XCTAssertNil(model.fileImportTarget)
        XCTAssertNil(model.selectedFileURL)
        XCTAssertNil(model.selectedFileName)
        XCTAssertFalse(model.showFileImporter)
        XCTAssertFalse(model.showTextModeSuggestion)

        let disappearURL = try makeTemporaryFile(
            named: "disappear.tmp",
            contents: Data("plaintext".utf8)
        )
        defer { try? FileManager.default.removeItem(at: disappearURL) }

        model.fileDecryptionResult = makeFileDecryptionResult(
            outputURL: disappearURL,
            verificationState: .invalid
        )
        model.importedCiphertext.setImportedFile(
            data: Data("cipher".utf8),
            fileName: "message.asc",
            text: "cipher"
        )
        model.fileImportTarget = .textCiphertextImport

        model.handleDisappear()

        XCTAssertNil(model.fileDecryptionResult)
        XCTAssertFalse(FileManager.default.fileExists(atPath: disappearURL.path))
        XCTAssertFalse(model.importedCiphertext.hasImportedFile)
        XCTAssertNil(model.fileImportTarget)
        XCTAssertNil(model.activeDetailedSignatureVerification)
    }

    @MainActor
    func test_parseRecipientsText_clearsDetailedVerificationBeforePublishingPhase1() async throws {
        let model = makeModel(
            parseTextRecipientsAction: { _ in
                self.makePhase1Result()
            }
        )
        model.ciphertextInput = "ciphertext"
        model.textDecryptionResult = makeTextDecryptionResult(
            plaintext: "Plaintext",
            verificationState: .verified
        )

        model.parseRecipientsText()

        await waitUntil("text parse to finish") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.textDecryptionResult)
        XCTAssertNil(model.activeDetailedSignatureVerification)
        XCTAssertNotNil(model.phase1Result)
    }

    @MainActor
    func test_parseRecipientsFile_clearsDetailedVerificationBeforePublishingPhase1() async throws {
        let inputURL = try makeTemporaryFile(
            named: "parse-file.gpg",
            contents: Data("cipher".utf8)
        )
        let outputURL = try makeTemporaryFile(
            named: "parse-file-output",
            contents: Data("plaintext".utf8)
        )
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let model = makeModel(
            parseFileRecipientsAction: { url in
                XCTAssertEqual(url, inputURL)
                return self.makeFilePhase1Result(matchedKey: nil, inputURL: inputURL)
            }
        )
        model.decryptMode = .file
        model.selectedFileURL = inputURL
        model.selectedFileName = inputURL.lastPathComponent
        model.fileDecryptionResult = makeFileDecryptionResult(
            outputURL: outputURL,
            verificationState: .signerCertificateUnavailable
        )

        model.parseRecipientsFile()

        await waitUntil("file parse to finish") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.activeDetailedSignatureVerification)
        XCTAssertEqual(model.filePhase1Result?.inputPath, inputURL.path)
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

    private func makeTextDecryptionResult(
        plaintext: String = "Plaintext",
        verificationState: SignatureVerification.VerificationState,
        signerFingerprint: String? = nil
    ) -> DecryptScreenModel.TextDecryptionResult {
        DecryptScreenModel.TextDecryptionResult(
            plaintext: plaintext,
            verification: makeDetailedVerification(
                verificationState: verificationState,
                signerFingerprint: signerFingerprint
            )
        )
    }

    private func makeFileDecryptionResult(
        outputURL: URL,
        verificationState: SignatureVerification.VerificationState,
        signerFingerprint: String? = nil
    ) -> DecryptScreenModel.FileDecryptionResult {
        DecryptScreenModel.FileDecryptionResult(
            output: TemporaryFileOutput(fileURL: outputURL),
            verification: makeDetailedVerification(
                verificationState: verificationState,
                signerFingerprint: signerFingerprint
            )
        )
    }

    private func makePhase1Result(
        matchedKey: PGPKeyIdentity? = nil,
        ciphertext: Data = Data("ciphertext".utf8)
    ) -> DecryptionPhase1Result {
        DecryptionPhase1Result(
            recipientKeyIds: ["ABCD1234"],
            matchedKey: matchedKey,
            ciphertext: ciphertext
        )
    }

    private func makeFilePhase1Result(
        matchedKey: PGPKeyIdentity?,
        inputURL: URL
    ) -> FileDecryptionPhase1Result {
        FileDecryptionPhase1Result(
            matchedKey: matchedKey,
            inputPath: inputURL.path
        )
    }

    private func makeDetailedVerification(
        verificationState: SignatureVerification.VerificationState,
        signerFingerprint: String? = nil
    ) -> DetailedSignatureVerification {
        let entries: [DetailedSignatureVerification.Entry] = verificationState == .notSigned ? [] : [
            DetailedSignatureVerification.Entry(
                verificationState: verificationState,
                signerPrimaryFingerprint: signerFingerprint,
                signerIdentity: nil
            )
        ]
        return DetailedSignatureVerification(
            summaryState: entries.first?.verificationState ?? .notSigned,
            summaryEntryIndex: entries.isEmpty ? nil : 0,
            signatures: entries
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

    private func settleAsyncWork() async {
        for _ in 0..<10 {
            await Task.yield()
        }
    }
}
