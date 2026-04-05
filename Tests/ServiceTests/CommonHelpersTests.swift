import Foundation
import XCTest
@testable import CypherAir

private final class MockScopedResource: SecurityScopedResource {
    var startResult = true
    private(set) var startCalls = 0
    private(set) var stopCalls = 0

    func startAccessingSecurityScopedResource() -> Bool {
        startCalls += 1
        return startResult
    }

    func stopAccessingSecurityScopedResource() {
        stopCalls += 1
    }
}

private actor RunnerCallCounter {
    var count = 0

    func increment() {
        count += 1
    }

    func currentValue() -> Int {
        count
    }
}

private actor OperationGate {
    private var continuations: [Int: CheckedContinuation<Void, Never>] = [:]

    func suspend(operationID: Int) async {
        await withCheckedContinuation { continuation in
            continuations[operationID] = continuation
        }
    }

    func isSuspended(operationID: Int) -> Bool {
        continuations[operationID] != nil
    }

    func resume(operationID: Int) {
        continuations.removeValue(forKey: operationID)?.resume()
    }
}

private enum CommonHelpersTestError: Error {
    case delayedFailure
}

@MainActor
final class CommonHelpersTests: XCTestCase {
    func test_securityScopedFileAccess_failure_stopsPreviouslyStartedResources() async {
        let first = MockScopedResource()
        let second = MockScopedResource()
        second.startResult = false

        do {
            _ = try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(resource: first, failure: .internalError(reason: "first")),
                    SecurityScopedAccessRequest(resource: second, failure: .internalError(reason: "second"))
                ]
            ) {
                XCTFail("Operation should not run when a resource cannot be accessed")
                return ()
            }
            XCTFail("Expected an access failure")
        } catch let error as CypherAirError {
            XCTAssertEqual(error.localizedDescription, CypherAirError.internalError(reason: "second").localizedDescription)
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }

        XCTAssertEqual(first.startCalls, 1)
        XCTAssertEqual(first.stopCalls, 1)
        XCTAssertEqual(second.startCalls, 1)
        XCTAssertEqual(second.stopCalls, 0)
    }

    func test_securityScopedFileAccess_success_stopsAllResources() async throws {
        let first = MockScopedResource()
        let second = MockScopedResource()
        var didRun = false

        try await SecurityScopedFileAccess.withAccess(
            to: [
                SecurityScopedAccessRequest(resource: first, failure: .internalError(reason: "first")),
                SecurityScopedAccessRequest(resource: second, failure: .internalError(reason: "second"))
            ]
        ) {
            didRun = true
        }

        XCTAssertTrue(didRun)
        XCTAssertEqual(first.stopCalls, 1)
        XCTAssertEqual(second.stopCalls, 1)
    }

    func test_fileExportController_prepareDataExport_finishRemovesTemporaryFile() throws {
        let controller = FileExportController()

        try controller.prepareDataExport(
            Data("export me".utf8),
            suggestedFilename: "sample.asc"
        )

        guard let url = controller.payload?.url else {
            XCTFail("Expected a payload URL")
            return
        }

        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        controller.finish()
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    func test_operationController_runFileOperation_usesBackgroundRunnerAndClearsState() async {
        let runnerCallCounter = RunnerCallCounter()
        let controller = OperationController(
            backgroundRunner: { operation in
                await runnerCallCounter.increment()
                try await operation()
            }
        )

        controller.runFileOperation(
            mapError: { _ in .internalError(reason: "unexpected") }
        ) { progress in
            _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
        }

        while controller.isRunning {
            await Task.yield()
        }

        let runnerCallCount = await runnerCallCounter.currentValue()
        XCTAssertEqual(runnerCallCount, 1)
        XCTAssertNil(controller.progress)
        XCTAssertFalse(controller.isShowingError)
    }

    func test_operationController_cancel_keepsBusyUntilTaskFinishes() async {
        let gate = OperationGate()
        let controller = OperationController()

        controller.runFileOperation(mapError: { _ in .internalError(reason: "unexpected") }) { progress in
            _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
            await gate.suspend(operationID: 1)
        }

        await waitUntil("operation to suspend before cancellation") {
            guard controller.isRunning, controller.progress != nil else { return false }
            return await gate.isSuspended(operationID: 1)
        }

        controller.cancel()

        XCTAssertTrue(controller.isRunning)
        XCTAssertTrue(controller.isCancelling)
        XCTAssertNotNil(controller.progress)

        await gate.resume(operationID: 1)

        await waitUntil("controller to finish cancelling") {
            controller.isRunning == false
        }

        XCTAssertFalse(controller.isCancelling)
        XCTAssertNil(controller.progress)
        XCTAssertFalse(controller.isShowingError)
    }

    func test_operationController_staleCompletionDoesNotClearReplacementOperation() async {
        let gate = OperationGate()
        let controller = OperationController()
        var startedOperations = 0

        controller.runFileOperation(mapError: { _ in .internalError(reason: "unexpected") }) { progress in
            startedOperations += 1
            let operationID = startedOperations
            _ = progress.onProgress(bytesProcessed: UInt64(operationID), totalBytes: 10)
            await gate.suspend(operationID: operationID)
        }

        await waitUntil("first operation to suspend") {
            guard controller.isRunning, controller.progress != nil else { return false }
            return await gate.isSuspended(operationID: 1)
        }

        controller.cancel()
        controller.runFileOperation(mapError: { _ in .internalError(reason: "unexpected") }) { progress in
            startedOperations += 1
            let operationID = startedOperations
            _ = progress.onProgress(bytesProcessed: UInt64(operationID), totalBytes: 10)
            await gate.suspend(operationID: operationID)
        }

        await waitUntil("replacement operation to suspend") {
            guard controller.isRunning, !controller.isCancelling else { return false }
            return await gate.isSuspended(operationID: 2)
        }

        let replacementProgress = controller.progress
        await gate.resume(operationID: 1)
        await Task.yield()
        await Task.yield()

        XCTAssertTrue(controller.isRunning)
        XCTAssertFalse(controller.isCancelling)
        XCTAssertTrue(controller.progress === replacementProgress)

        await gate.resume(operationID: 2)
        await waitUntil("replacement operation to finish") {
            controller.isRunning == false
        }
    }

    func test_operationController_staleErrorDoesNotSurfaceForReplacementOperation() async {
        let gate = OperationGate()
        let controller = OperationController()
        var startedOperations = 0

        controller.run(mapError: { _ in .internalError(reason: "stale failure") }) {
            startedOperations += 1
            let operationID = startedOperations
            await gate.suspend(operationID: operationID)
            if operationID == 1 {
                throw CommonHelpersTestError.delayedFailure
            }
        }

        await waitUntil("first operation to suspend") {
            guard controller.isRunning else { return false }
            return await gate.isSuspended(operationID: 1)
        }

        controller.cancel()
        controller.run(mapError: { _ in .internalError(reason: "replacement failure") }) {
            startedOperations += 1
            let operationID = startedOperations
            await gate.suspend(operationID: operationID)
        }

        await waitUntil("replacement operation to suspend") {
            guard controller.isRunning, !controller.isCancelling else { return false }
            return await gate.isSuspended(operationID: 2)
        }

        await gate.resume(operationID: 1)
        await Task.yield()
        await Task.yield()

        XCTAssertFalse(controller.isShowingError)
        XCTAssertNil(controller.error)

        await gate.resume(operationID: 2)
        await waitUntil("replacement operation to finish") {
            controller.isRunning == false
        }

        XCTAssertFalse(controller.isShowingError)
        XCTAssertNil(controller.error)
    }

    func test_appStartupCoordinator_mergedStartupMessages_appendsRecoveryDiagnostics() {
        let coordinator = AppStartupCoordinator()
        let merged = coordinator.mergedStartupMessages(
            loadErrors: ["Contacts failed to load"],
            recoveryDiagnostics: [
                "A previous secure key migration could not be recovered. Restore from backup if private-key operations fail."
            ]
        )

        XCTAssertEqual(
            merged,
            """
            Contacts failed to load
            A previous secure key migration could not be recovered. Restore from backup if private-key operations fail.
            """
        )
    }

    func test_appStartupCoordinator_mergedStartupMessages_recoveryDiagnostic_isGeneric() {
        let coordinator = AppStartupCoordinator()
        let merged = coordinator.mergedStartupMessages(
            loadErrors: [],
            recoveryDiagnostics: [
                "A previous secure key migration could not be fully recovered. CypherAir will retry recovery on next launch."
            ]
        )

        XCTAssertNotNil(merged)
        XCTAssertFalse(merged?.contains("fingerprint") == true)
        XCTAssertFalse(merged?.contains("89abcdef") == true)
    }

    func test_importedTextInputState_preservesRawData_untilVisibleTextChanges() {
        var state = ImportedTextInputState()
        let text = "-----BEGIN PGP MESSAGE-----\nVersion: Test\n\nabc\n-----END PGP MESSAGE-----"
        let data = Data(text.utf8)

        state.setImportedFile(data: data, fileName: "encrypted.asc", text: text)

        XCTAssertTrue(state.hasImportedFile)
        XCTAssertEqual(state.rawData, data)
        XCTAssertEqual(state.fileName, "encrypted.asc")
        XCTAssertEqual(state.textSnapshot, text)
        XCTAssertFalse(state.invalidateIfEditedTextDiffers(text))
        XCTAssertEqual(state.rawData, data)

        XCTAssertTrue(state.invalidateIfEditedTextDiffers(text + "\n"))
        XCTAssertFalse(state.hasImportedFile)
        XCTAssertNil(state.rawData)
        XCTAssertNil(state.fileName)
        XCTAssertNil(state.textSnapshot)
    }

    func test_importedTextInputState_clear_removesAuthoritativeData() {
        var state = ImportedTextInputState()
        let text = "-----BEGIN PGP SIGNED MESSAGE-----\n\nhello"
        state.setImportedFile(data: Data(text.utf8), fileName: "signed.asc", text: text)

        state.clear()

        XCTAssertFalse(state.hasImportedFile)
        XCTAssertNil(state.rawData)
        XCTAssertNil(state.fileName)
        XCTAssertNil(state.textSnapshot)
    }

    func test_importedTextInputState_reimport_replacesPreviousBytesAndSnapshot() {
        var state = ImportedTextInputState()
        state.setImportedFile(
            data: Data("old".utf8),
            fileName: "old.asc",
            text: "old"
        )

        state.setImportedFile(
            data: Data("new".utf8),
            fileName: "new.asc",
            text: "new"
        )

        XCTAssertTrue(state.hasImportedFile)
        XCTAssertEqual(state.rawData, Data("new".utf8))
        XCTAssertEqual(state.fileName, "new.asc")
        XCTAssertEqual(state.textSnapshot, "new")
    }

    func test_armoredTextMessageClassifier_armoredEncryptedMessage_matches() throws {
        let data = try FixtureLoader.loadData("gpg_encrypted_message", ext: "asc")

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .encryptedTextMessage)
    }

    func test_armoredTextMessageClassifier_cleartextSignedMessage_doesNotMatch() throws {
        let data = try FixtureLoader.loadData("gpg_cleartext_signed", ext: "asc")

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .other)
    }

    func test_armoredTextMessageClassifier_binaryMessage_doesNotMatch() throws {
        let data = try FixtureLoader.loadData("gpg_encrypted_message", ext: "gpg")

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .other)
    }

    func test_armoredTextMessageClassifier_oversizedArmoredMessage_doesNotMatch() {
        let oversizedText =
            "-----BEGIN PGP MESSAGE-----\n"
            + String(repeating: "A", count: ArmoredTextMessageClassifier.maxInspectableFileSize + 1)
        let data = Data(oversizedText.utf8)

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .other)
    }

    private func waitUntil(
        _ description: String,
        timeoutNanoseconds: UInt64 = 1_000_000_000,
        condition: @escaping @MainActor () async -> Bool
    ) async {
        let deadline = DispatchTime.now().uptimeNanoseconds + timeoutNanoseconds
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if await condition() {
                return
            }
            await Task.yield()
        }
        XCTFail("Timed out waiting for \(description)")
    }
}
