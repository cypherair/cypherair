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

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
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
        model.handleImportedFile(fileURL)
        model.finishFileImportRequest()
        model.verifyCleartext()

        await waitUntil("cleartext verification to finish") {
            model.operation.isRunning == false
        }

        XCTAssertTrue(model.importedCleartext.hasImportedFile)
        XCTAssertEqual(model.cleartextVerification?.status, .valid)
        XCTAssertEqual(model.cleartextDetailedVerification?.legacyStatus, .valid)
        XCTAssertEqual(model.cleartextOriginalText, "Original signed message")

        model.setSignedInput("Edited signed message")

        XCTAssertFalse(model.importedCleartext.hasImportedFile)
        XCTAssertNil(model.cleartextVerification)
        XCTAssertNil(model.cleartextDetailedVerification)
        XCTAssertNil(model.cleartextOriginalText)
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
        model.cleartextDetailedVerification = makeDetailedVerification(status: .valid)

        model.requestOriginalFileImport()
        model.handleImportedFile(originalURL)
        model.finishFileImportRequest()
        model.requestSignatureFileImport()
        model.handleImportedFile(signatureURL)
        model.finishFileImportRequest()
        model.detachedDetailedVerification = makeDetailedVerification(status: .bad)

        XCTAssertEqual(model.originalFileName, originalURL.lastPathComponent)
        XCTAssertEqual(model.signatureFileName, signatureURL.lastPathComponent)

        model.verifyMode = .detached
        XCTAssertEqual(model.activeVerification?.status, .bad)
        XCTAssertEqual(model.activeDetailedVerification?.legacyStatus, .bad)

        model.verifyMode = .cleartext
        XCTAssertEqual(model.activeVerification?.status, .valid)
        XCTAssertEqual(model.activeDetailedVerification?.legacyStatus, .valid)
        XCTAssertEqual(model.cleartextOriginalText, "Cleartext content")
        XCTAssertEqual(model.detachedVerification?.status, .bad)
        XCTAssertEqual(model.detachedDetailedVerification?.legacyStatus, .bad)
    }

    @MainActor
    func test_setSignedInput_onlyClearsCleartextDetailedState() {
        let model = makeModel()
        model.cleartextOriginalText = "Original"
        model.cleartextDetailedVerification = makeDetailedVerification(status: .valid)
        model.detachedDetailedVerification = makeDetailedVerification(status: .bad)

        model.setSignedInput("Edited signed message")

        XCTAssertNil(model.cleartextVerification)
        XCTAssertNil(model.cleartextDetailedVerification)
        XCTAssertNil(model.cleartextOriginalText)
        XCTAssertEqual(model.detachedVerification?.status, .bad)
        XCTAssertEqual(model.detachedDetailedVerification?.legacyStatus, .bad)
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
        model.detachedDetailedVerification = makeDetailedVerification(status: .bad)

        model.requestOriginalFileImport()
        model.handleImportedFile(originalURL)
        model.finishFileImportRequest()

        XCTAssertEqual(model.originalFileName, originalURL.lastPathComponent)
        XCTAssertNil(model.detachedVerification)
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
        model.cleartextDetailedVerification = makeDetailedVerification(status: .valid)
        model.detachedDetailedVerification = makeDetailedVerification(status: .bad)
        model.originalFileURL = URL(fileURLWithPath: "/tmp/original")
        model.originalFileName = "original"
        model.signatureFileURL = URL(fileURLWithPath: "/tmp/original.sig")
        model.signatureFileName = "original.sig"

        model.handleDisappear()

        XCTAssertFalse(model.importedCleartext.hasImportedFile)
        XCTAssertNil(model.filePickerTarget)
        XCTAssertEqual(model.cleartextOriginalText, "Original")
        XCTAssertEqual(model.cleartextVerification?.status, .valid)
        XCTAssertEqual(model.cleartextDetailedVerification?.legacyStatus, .valid)
        XCTAssertEqual(model.detachedVerification?.status, .bad)
        XCTAssertEqual(model.detachedDetailedVerification?.legacyStatus, .bad)
        XCTAssertEqual(model.originalFileName, "original")
        XCTAssertEqual(model.signatureFileName, "original.sig")
    }

    @MainActor
    func test_verifyDetached_cancellationClearsProgressWithoutPublishingResult() async {
        let gate = VerifyOperationGate()
        let model = makeModel(
            detachedVerificationAction: { _, _, progress in
                _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
                await gate.suspend()
                try Task.checkCancellation()
                return self.makeDetailedVerification(
                    status: .valid
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

        XCTAssertNil(model.detachedVerification)
        XCTAssertNil(model.detachedDetailedVerification)
        XCTAssertNil(model.operation.progress)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_clearTransientInput_clearsCleartextDetachedImportsAndResults() {
        let model = makeModel()
        model.signedInput = "signed input"
        model.cleartextOriginalText = "original"
        model.cleartextDetailedVerification = makeDetailedVerification(status: .valid)
        model.detachedDetailedVerification = makeDetailedVerification(status: .bad)
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
        XCTAssertNil(model.cleartextVerification)
        XCTAssertNil(model.cleartextDetailedVerification)
        XCTAssertNil(model.detachedVerification)
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
        status: SignatureStatus,
        signerFingerprint: String? = nil
    ) -> DetailedSignatureVerification {
        DetailedSignatureVerification(
            legacyStatus: status,
            legacySignerFingerprint: signerFingerprint,
            legacySignerContact: nil,
            legacySignerIdentity: nil,
            signatures: status == .notSigned ? [] : [
                DetailedSignatureVerification.Entry(
                    status: makeDetailedEntryStatus(from: status),
                    signerPrimaryFingerprint: signerFingerprint,
                    signerIdentity: nil
                )
            ]
        )
    }

    private func makeDetailedEntryStatus(
        from status: SignatureStatus
    ) -> DetailedSignatureVerification.Entry.Status {
        switch status {
        case .valid:
            .valid
        case .bad:
            .bad
        case .unknownSigner:
            .unknownSigner
        case .expired:
            .expired
        case .notSigned:
            .unknownSigner
        }
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
