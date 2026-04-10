import Foundation
import XCTest
@testable import CypherAir

private actor SignOperationGate {
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

final class SignScreenModelTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!
    private var config: AppConfiguration!
    private var defaultsSuiteName: String!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
        defaultsSuiteName = "com.cypherair.tests.signscreen.\(UUID().uuidString)"
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
    func test_prepareIfNeeded_isIdempotent_afterUserSelectsDifferentSigner() async throws {
        let firstIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "First"
        )
        let secondIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Second"
        )
        let expectedDefault = try XCTUnwrap(stack.keyManagement.defaultKey?.fingerprint)
        let alternateFingerprint = [firstIdentity.fingerprint, secondIdentity.fingerprint]
            .first { $0 != expectedDefault }
        let model = makeModel()

        model.prepareIfNeeded()
        XCTAssertEqual(model.signerFingerprint, expectedDefault)

        model.signerFingerprint = try XCTUnwrap(alternateFingerprint)
        model.prepareIfNeeded()

        XCTAssertEqual(model.signerFingerprint, alternateFingerprint)
    }

    @MainActor
    func test_signText_updatesResult_and_routesClipboardAndExportThroughInterceptionPolicy() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")

        var interceptedClipboard: String?
        var interceptedExportFilename: String?
        var configuration = SignView.Configuration()
        configuration.outputInterceptionPolicy = OutputInterceptionPolicy(
            interceptClipboardCopy: { string, _, kind in
                XCTAssertEqual(kind, .generic)
                interceptedClipboard = string
                return true
            },
            interceptDataExport: { _, filename, kind in
                XCTAssertEqual(kind, .generic)
                interceptedExportFilename = filename
                return true
            }
        )

        let model = makeModel(configuration: configuration)
        model.text = "A screen-model signing message"
        model.prepareIfNeeded()
        model.signText()

        await waitUntil("text signing to finish") {
            model.operation.isRunning == false
        }

        guard let signedMessage = model.signedMessage else {
            return XCTFail("Expected a signed message")
        }
        XCTAssertTrue(signedMessage.contains("BEGIN PGP SIGNED MESSAGE"))

        model.copySignedMessageToClipboard()
        XCTAssertEqual(interceptedClipboard, signedMessage)
        XCTAssertFalse(model.operation.isShowingClipboardNotice)

        model.exportSignedMessage()
        XCTAssertEqual(interceptedExportFilename, "signed.asc")
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_signFile_handlesSelection_and_preparesSigExport() async throws {
        let model = makeModel(
            detachedFileSigningAction: { _, _, _ in
                Data("detached-signature".utf8)
            }
        )
        let fileURL = try makeTemporaryFile(
            named: "message.txt",
            contents: Data("File signing payload".utf8)
        )
        defer { try? FileManager.default.removeItem(at: fileURL) }

        model.signerFingerprint = "test-signer"
        model.handleImportedFile(fileURL)
        model.signMode = SignView.SignMode.file
        model.prepareIfNeeded()
        model.signFile()

        await waitUntil("file signing to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(model.selectedFileName, fileURL.lastPathComponent)
        XCTAssertNotNil(model.detachedSignature)

        model.exportDetachedSignature()

        XCTAssertNotNil(model.exportController.payload)
        XCTAssertEqual(
            model.exportController.defaultFilename,
            "\(fileURL.lastPathComponent).sig"
        )
        model.finishExport()
    }

    @MainActor
    func test_signFile_cancellation_clearsProgress_andDoesNotPublishSignature() async throws {
        let gate = SignOperationGate()
        let model = makeModel(
            detachedFileSigningAction: { _, _, progress in
                _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
                await gate.suspend()
                try Task.checkCancellation()
                return Data("signature".utf8)
            }
        )
        let fileURL = try makeTemporaryFile(
            named: "cancel-me.txt",
            contents: Data("cancel".utf8)
        )
        defer { try? FileManager.default.removeItem(at: fileURL) }

        model.signerFingerprint = "test-signer"
        model.handleImportedFile(fileURL)
        model.signMode = SignView.SignMode.file
        model.signFile()

        await waitUntil("file signing to suspend with progress") {
            guard model.operation.isRunning, model.operation.progress != nil else {
                return false
            }
            return await gate.isSuspended()
        }

        model.operation.cancel()

        XCTAssertTrue(model.operation.isRunning)
        XCTAssertTrue(model.operation.isCancelling)

        await gate.resume()

        await waitUntil("cancelled file signing to finish") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.detachedSignature)
        XCTAssertNil(model.operation.progress)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_configurationFlags_stillGateFileImportAndDetachedExport() {
        var configuration = SignView.Configuration()
        configuration.allowsFileInput = false
        configuration.allowsFileResultExport = false

        let model = makeModel(configuration: configuration)

        model.requestFileImport()
        XCTAssertFalse(model.showFileImporter)

        model.detachedSignature = Data("signature".utf8)
        model.selectedFileName = "blocked.txt"
        model.exportDetachedSignature()

        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    private func makeModel(
        configuration: SignView.Configuration = .default,
        operation: OperationController = OperationController(),
        cleartextSigningAction: SignScreenModel.CleartextSigningAction? = nil,
        detachedFileSigningAction: SignScreenModel.DetachedFileSigningAction? = nil
    ) -> SignScreenModel {
        SignScreenModel(
            signingService: stack.signingService,
            keyManagement: stack.keyManagement,
            config: config,
            configuration: configuration,
            operation: operation,
            cleartextSigningAction: cleartextSigningAction,
            detachedFileSigningAction: detachedFileSigningAction
        )
    }

    private func makeTemporaryFile(named name: String, contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirSignScreenTests-\(UUID().uuidString)-\(name)")
        try contents.write(to: url, options: .atomic)
        return url
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
