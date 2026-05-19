import Foundation
import XCTest
@testable import CypherAir

private struct ImportKeyScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

private actor ImportKeyTestGate {
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

@MainActor
final class ImportKeyScreenModelTests: XCTestCase {
    func test_loadFileContents_handlesTextAndBinaryInputs() {
        let textURL = URL(fileURLWithPath: "/tmp/alice.asc")
        let binaryURL = URL(fileURLWithPath: "/tmp/alice.gpg")
        let model = makeModel(loadFileAction: { url in
            if url == textURL {
                return ImportKeyScreenModel.ImportedKeyFile(
                    data: Data("armored".utf8),
                    text: "armored",
                    fileName: "alice.asc"
                )
            }
            return ImportKeyScreenModel.ImportedKeyFile(
                data: Data([0, 1, 2, 3]),
                text: nil,
                fileName: "alice.gpg"
            )
        })

        model.loadFileContents(from: textURL)

        XCTAssertEqual(model.armoredText, "armored")
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)

        model.loadFileContents(from: binaryURL)

        XCTAssertEqual(model.armoredText, "")
        XCTAssertEqual(model.importedKeyData, Data([0, 1, 2, 3]))
        XCTAssertEqual(model.importedFileName, "alice.gpg")
    }

    func test_staleFileImporterResultIsIgnoredAfterContentClear() {
        var loadCount = 0
        let model = makeModel(loadFileAction: { _ in
            loadCount += 1
            return ImportKeyScreenModel.ImportedKeyFile(
                data: Data("armored".utf8),
                text: "armored",
                fileName: "alice.asc"
            )
        })
        model.requestFileImport()
        let token = model.fileImportRequestToken

        model.clearTransientInput()
        model.handleFileImporterResult(.success([URL(fileURLWithPath: "/tmp/alice.asc")]), token: token)

        XCTAssertEqual(loadCount, 0)
        XCTAssertEqual(model.armoredText, "")
        XCTAssertNil(model.importedKeyData)
    }

    func test_importKey_successClearsSensitiveStateAndDismisses() async {
        let identity = makeKeyRouteTestIdentity(fingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
        var capturedData: Data?
        var capturedPassphrase: String?
        var dismissCount = 0
        let model = makeModel(
            dismissAction: {
                dismissCount += 1
            },
            importKeyAction: { data, passphrase in
                capturedData = data
                capturedPassphrase = passphrase
                return identity
            }
        )
        model.armoredText = "private-key"
        model.passphrase = "correct horse"

        model.importKey()

        await waitUntilKeyRoute("import to dismiss") {
            dismissCount == 1
        }

        XCTAssertEqual(capturedData, Data("private-key".utf8))
        XCTAssertEqual(capturedPassphrase, "correct horse")
        XCTAssertEqual(model.armoredText, "")
        XCTAssertEqual(model.passphrase, "")
        XCTAssertNil(model.importedKeyData)
        XCTAssertFalse(model.isImporting)
    }

    func test_contentClearSuppressesLateImportCompletion() async {
        let gate = ImportKeyTestGate()
        var dismissCount = 0
        let model = makeModel(
            dismissAction: {
                dismissCount += 1
            },
            importKeyAction: { _, _ in
                await gate.suspend()
                return makeKeyRouteTestIdentity(fingerprint: "ffffffffffffffffffffffffffffffffffffffff")
            }
        )
        model.armoredText = "private-key"
        model.passphrase = "secret"

        model.importKey()

        await waitUntilKeyRoute("import to suspend") {
            await gate.isSuspended()
        }

        model.handleContentClearGenerationChange()
        await gate.resume()
        await drainKeyRouteMainActor()

        XCTAssertEqual(dismissCount, 0)
        XCTAssertFalse(model.showError)
        XCTAssertFalse(model.isImporting)
        XCTAssertEqual(model.armoredText, "")
        XCTAssertEqual(model.passphrase, "")
    }

    func test_importFailureSurfacesMappedError() async {
        let model = makeModel(importKeyAction: { _, _ in
            throw ImportKeyScreenModelTestError(message: "import failed")
        })
        model.armoredText = "private-key"
        model.passphrase = "secret"

        model.importKey()

        await waitUntilKeyRoute("import failure to surface") {
            model.showError
        }

        XCTAssertTrue(model.showError)
        XCTAssertNotNil(model.error)
        XCTAssertFalse(model.isImporting)
    }

    private func makeModel(
        dismissAction: @escaping @MainActor () -> Void = {},
        importKeyAction: ImportKeyScreenModel.ImportKeyAction? = nil,
        loadFileAction: ImportKeyScreenModel.LoadFileAction? = nil
    ) -> ImportKeyScreenModel {
        ImportKeyScreenModel(
            keyManagement: TestHelpers.makeKeyManagement().service,
            dismissAction: dismissAction,
            importKeyAction: importKeyAction ?? { _, _ in
                makeKeyRouteTestIdentity(fingerprint: "1111111111111111111111111111111111111111")
            },
            loadFileAction: loadFileAction
        )
    }
}
