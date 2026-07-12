import Foundation
import XCTest
@testable import CypherAir

private actor VerifyOperationGate {
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

final class VerifyScreenModelTests: XCTestCase {
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

    @MainActor
    func test_verifyCleartext_importedFileAndEditedTextInvalidateImportedStateAndResult() async throws {
        let identity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Signer"
        )
        let signedMessage = try await stack.signingService.signCleartext(
            "Original signed message",
            signerFingerprint: identity.fingerprint
        )
        let fileURL = try makeTemporaryFile(
            named: "signed.asc",
            contents: signedMessage
        )
        defer { try? FileManager.default.removeItem(at: fileURL) }

        let model = makeModel(
            cleartextFileImportAction: { url in
                let data = try Data(contentsOf: url)
                let text = try XCTUnwrap(String(data: data, encoding: .utf8))
                return (data, text)
            }
        )

        model.requestCleartextFileImport()
        let token = try XCTUnwrap(model.fileImportRequestToken)
        model.handleFileImporterResult(.success([fileURL]), token: token)
        model.verifyCleartext()

        await waitUntil("cleartext verification to finish") {
            model.operation.isRunning == false
        }

        XCTAssertTrue(model.importedCleartext.hasImportedFile)
        XCTAssertNil(model.filePickerTarget)
        XCTAssertEqual(model.cleartextDetailedVerification?.summaryState, .verified)
        XCTAssertEqual(model.cleartextOriginalText, "Original signed message")
        let startingEpoch = model.textInputSectionEpoch

        model.setSignedInput("Edited signed message")

        XCTAssertFalse(model.importedCleartext.hasImportedFile)
        XCTAssertNil(model.cleartextDetailedVerification)
        XCTAssertNil(model.cleartextOriginalText)
        XCTAssertEqual(model.textInputSectionEpoch, startingEpoch)
    }

    @MainActor
    func test_handleFileImporterResult_afterContentClear_ignoresStaleCleartextSelection() throws {
        let fileURL = URL(fileURLWithPath: "/tmp/signed.asc")
        let model = makeModel(
            cleartextFileImportAction: { _ in
                (Data("SIGNED".utf8), "SIGNED")
            }
        )

        model.requestCleartextFileImport()
        let token = try XCTUnwrap(model.fileImportRequestToken)
        model.clearTransientInput()
        model.handleFileImporterResult(.success([fileURL]), token: token)

        XCTAssertEqual(model.signedInput, "")
        XCTAssertFalse(model.importedCleartext.hasImportedFile)
        XCTAssertNil(model.filePickerTarget)
    }

    @MainActor
    func test_detachedSelectionsAndModeSwitchPreservePerModeResults() throws {
        let originalURL = try makeTemporaryFile(
            named: "verify-original.bin",
            contents: Data("original".utf8)
        )
        let signatureURL = try makeTemporaryFile(
            named: "verify-signature.sig",
            contents: Data("signature".utf8)
        )
        defer {
            try? FileManager.default.removeItem(at: originalURL)
            try? FileManager.default.removeItem(at: signatureURL)
        }

        let model = makeModel()
        model.cleartextOriginalText = "Cleartext content"
        model.cleartextDetailedVerification = makeDetailedVerification(verificationState: .verified)

        model.requestOriginalFileImport()
        model.handleImportedFile(originalURL)
        model.finishFileImportRequest()
        model.requestSignatureFileImport()
        model.handleImportedFile(signatureURL)
        model.finishFileImportRequest()
        model.detachedDetailedVerification = makeDetailedVerification(verificationState: .invalid)

        XCTAssertEqual(model.originalFileName, originalURL.lastPathComponent)
        XCTAssertEqual(model.signatureFileName, signatureURL.lastPathComponent)

        model.verifyMode = .detached
        XCTAssertEqual(model.activeDetailedVerification?.summaryState, .invalid)

        model.verifyMode = .cleartext
        XCTAssertEqual(model.activeDetailedVerification?.summaryState, .verified)
        XCTAssertEqual(model.cleartextOriginalText, "Cleartext content")
        XCTAssertEqual(model.detachedDetailedVerification?.summaryState, .invalid)
    }

    @MainActor
    func test_setSignedInput_onlyClearsCleartextDetailedState() {
        let model = makeModel()
        model.cleartextOriginalText = "Original"
        model.cleartextDetailedVerification = makeDetailedVerification(verificationState: .verified)
        model.detachedDetailedVerification = makeDetailedVerification(verificationState: .invalid)
        let startingEpoch = model.textInputSectionEpoch

        model.setSignedInput("Edited signed message")

        XCTAssertNil(model.cleartextDetailedVerification)
        XCTAssertNil(model.cleartextOriginalText)
        XCTAssertEqual(model.detachedDetailedVerification?.summaryState, .invalid)
        XCTAssertEqual(model.textInputSectionEpoch, startingEpoch)
    }

    @MainActor
    func test_handleImportedFile_detachedReselectionImmediatelyClearsDetachedDetailedState() throws {
        let originalURL = try makeTemporaryFile(
            named: "verify-original-new.bin",
            contents: Data("original".utf8)
        )
        defer { try? FileManager.default.removeItem(at: originalURL) }

        let model = makeModel()
        model.verifyMode = .detached
        model.detachedDetailedVerification = makeDetailedVerification(verificationState: .invalid)

        model.requestOriginalFileImport()
        model.handleImportedFile(originalURL)
        model.finishFileImportRequest()

        XCTAssertEqual(model.originalFileName, originalURL.lastPathComponent)
        XCTAssertNil(model.detachedDetailedVerification)
    }

    @MainActor
    func test_handleDisappear_onlyClearsImportedCleartextAndPickerTarget() {
        let model = makeModel()
        model.importedCleartext.setImportedFile(
            data: Data("signed".utf8),
            fileName: "signed.asc",
            text: "signed"
        )
        model.filePickerTarget = .signature
        model.cleartextOriginalText = "Original"
        model.cleartextDetailedVerification = makeDetailedVerification(verificationState: .verified)
        model.detachedDetailedVerification = makeDetailedVerification(verificationState: .invalid)
        model.originalFileURL = URL(fileURLWithPath: "/tmp/original")
        model.originalFileName = "original"
        model.signatureFileURL = URL(fileURLWithPath: "/tmp/original.sig")
        model.signatureFileName = "original.sig"

        model.handleDisappear()

        XCTAssertFalse(model.importedCleartext.hasImportedFile)
        XCTAssertNil(model.filePickerTarget)
        XCTAssertEqual(model.cleartextOriginalText, "Original")
        XCTAssertEqual(model.cleartextDetailedVerification?.summaryState, .verified)
        XCTAssertEqual(model.detachedDetailedVerification?.summaryState, .invalid)
        XCTAssertEqual(model.originalFileName, "original")
        XCTAssertEqual(model.signatureFileName, "original.sig")
    }

    @MainActor
    func test_verifyDetached_cancellationClearsProgressWithoutPublishingResult() async {
        let gate = VerifyOperationGate()
        var capturedProgress: FileProgressReporter?
        let operation = OperationController(progressFactory: {
            let reporter = FileProgressReporter()
            capturedProgress = reporter
            return reporter
        })
        let model = makeModel(
            operation: operation,
            detachedVerificationAction: { _ in
                _ = capturedProgress?.onProgress(bytesProcessed: 5, totalBytes: 10)
                await gate.suspend()
                try Task.checkCancellation()
                return self.makeDetailedVerification(
                    verificationState: .verified
                )
            }
        )
        model.verifyMode = .detached
        model.originalFileURL = URL(fileURLWithPath: "/tmp/original.bin")
        model.signatureFileURL = URL(fileURLWithPath: "/tmp/original.sig")

        model.verifyDetached()

        await waitUntil("detached verification to suspend with progress") {
            guard model.operation.isRunning, model.operation.progress != nil else {
                return false
            }
            return await gate.isSuspended()
        }

        model.operation.cancel()
        XCTAssertTrue(model.operation.isCancelling)

        await gate.resume()

        await waitUntil("cancelled detached verification to finish") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.detachedDetailedVerification)
        XCTAssertNil(model.operation.progress)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_clearTransientInput_clearsCleartextDetachedImportsAndResults() {
        let model = makeModel()
        model.signedInput = "signed input"
        model.cleartextOriginalText = "original"
        model.cleartextDetailedVerification = makeDetailedVerification(verificationState: .verified)
        model.detachedDetailedVerification = makeDetailedVerification(verificationState: .invalid)
        model.importedCleartext.setImportedFile(
            data: Data("signed".utf8),
            fileName: "signed.asc",
            text: "signed input"
        )
        model.originalFileURL = URL(fileURLWithPath: "/tmp/original.txt")
        model.originalFileName = "original.txt"
        model.signatureFileURL = URL(fileURLWithPath: "/tmp/original.sig")
        model.signatureFileName = "original.sig"
        model.filePickerTarget = .signature
        model.showFileImporter = true

        model.clearTransientInput()

        XCTAssertEqual(model.signedInput, "")
        XCTAssertNil(model.cleartextOriginalText)
        XCTAssertNil(model.cleartextDetailedVerification)
        XCTAssertNil(model.detachedDetailedVerification)
        XCTAssertFalse(model.importedCleartext.hasImportedFile)
        XCTAssertNil(model.originalFileURL)
        XCTAssertNil(model.originalFileName)
        XCTAssertNil(model.signatureFileURL)
        XCTAssertNil(model.signatureFileName)
        XCTAssertNil(model.filePickerTarget)
        XCTAssertFalse(model.showFileImporter)
    }

    @MainActor
    func test_contentClearDuringCleartextVerifySuppressesLateVerification() async {
        let gate = VerifyOperationGate()
        let model = makeModel(
            cleartextVerificationAction: { _ in
                await gate.suspend()
                return (
                    Data("late-original-text".utf8),
                    self.makeDetailedVerification(verificationState: .verified)
                )
            }
        )
        model.signedInput = "signed message"

        model.verifyCleartext()

        await waitUntil("cleartext verification to suspend for content clear") {
            guard model.operation.isRunning else {
                return false
            }
            return await gate.isSuspended()
        }

        model.handleContentClearGenerationChange()
        XCTAssertFalse(model.operation.isRunning)
        XCTAssertNil(model.cleartextOriginalText)
        XCTAssertNil(model.cleartextDetailedVerification)

        await gate.resume()
        await settleAsyncWork()

        XCTAssertNil(model.cleartextOriginalText)
        XCTAssertNil(model.cleartextDetailedVerification)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    private func makeModel(
        configuration: VerifyView.Configuration = .default,
        operation: OperationController = OperationController(),
        cleartextVerificationAction: VerifyScreenModel.CleartextVerificationAction? = nil,
        detachedVerificationAction: VerifyScreenModel.DetachedVerificationAction? = nil,
        cleartextFileImportAction: VerifyScreenModel.CleartextFileImportAction? = nil
    ) -> VerifyScreenModel {
        VerifyScreenModel(
            signingService: stack.signingService,
            configuration: configuration,
            operation: operation,
            cleartextVerificationAction: cleartextVerificationAction,
            detachedVerificationAction: detachedVerificationAction,
            cleartextFileImportAction: cleartextFileImportAction
        )
    }

    private func makeTemporaryFile(named name: String, contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirVerifyScreenTests-\(UUID().uuidString)-\(name)")
        try contents.write(to: url, options: .atomic)
        return url
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
