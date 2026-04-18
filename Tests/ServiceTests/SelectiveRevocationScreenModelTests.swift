import Foundation
import XCTest
@testable import CypherAir

private struct SelectiveRevocationScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

private actor SelectiveRevocationLoadGate {
    private var continuations: [Int: CheckedContinuation<Void, Never>] = [:]

    func suspend(attempt: Int) async {
        await withCheckedContinuation { continuation in
            continuations[attempt] = continuation
        }
    }

    func isSuspended(attempt: Int) -> Bool {
        continuations[attempt] != nil
    }

    func resume(attempt: Int) {
        continuations.removeValue(forKey: attempt)?.resume()
    }
}

private actor SelectiveRevocationExportGate {
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
final class SelectiveRevocationScreenModelTests: XCTestCase {
    private let fingerprint = "1111222233334444555566667777888899990000"

    func test_loadIfNeeded_loadsOnceAndPreservesSelectionOnRepeatAppearance() async {
        var loadCount = 0
        let catalog = makeCatalog()
        let model = makeModel(selectionCatalogAction: { _ in
            loadCount += 1
            return catalog
        })

        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }
        model.selectSubkey(catalog.subkeys[1])
        model.selectUserId(catalog.userIds[1])
        model.loadIfNeeded()

        XCTAssertEqual(loadCount, 1)
        assertLoaded(model)
        XCTAssertEqual(model.subkeys, catalog.subkeys)
        XCTAssertEqual(model.userIds, catalog.userIds)
        XCTAssertEqual(model.selectedSubkey, catalog.subkeys[1])
        XCTAssertEqual(model.selectedUserId, catalog.userIds[1])
    }

    func test_loadIfNeeded_showsLoadingBeforeCatalogArrives() async {
        let gate = SelectiveRevocationLoadGate()
        let catalog = makeCatalog()
        var loadCount = 0
        let model = makeModel(selectionCatalogAction: { _ in
            loadCount += 1
            let attempt = loadCount
            await gate.suspend(attempt: attempt)
            return catalog
        })

        model.loadIfNeeded()

        await waitUntil("catalog load to suspend") {
            let isSuspended = await gate.isSuspended(attempt: 1)
            return model.isLoading && isSuspended
        }

        XCTAssertTrue(model.isLoading)
        XCTAssertNil(model.catalog)
        XCTAssertNil(model.loadError)

        await gate.resume(attempt: 1)

        await waitUntil("catalog to finish loading") {
            model.catalog == catalog
        }

        assertLoaded(model)
    }

    func test_loadIfNeeded_failedLoadDoesNotAutoRetryOnRepeatAppearance() async {
        var loadCount = 0
        let model = makeModel(selectionCatalogAction: { _ in
            loadCount += 1
            throw SelectiveRevocationScreenModelTestError(message: "load failed")
        })

        model.loadIfNeeded()
        await waitUntil("failed load to finish") {
            if case .failed = model.loadState {
                return true
            }
            return false
        }
        model.loadIfNeeded()

        XCTAssertEqual(loadCount, 1)
        assertFailed(model)
        XCTAssertNotNil(model.loadError)
    }

    func test_retryRerunsDiscoveryAfterFailure() async {
        var loadCount = 0
        let catalog = makeCatalog()
        let model = makeModel(selectionCatalogAction: { _ in
            loadCount += 1
            if loadCount == 1 {
                throw SelectiveRevocationScreenModelTestError(message: "load failed")
            }
            return catalog
        })

        model.loadIfNeeded()
        await waitUntil("initial failure to finish") {
            if case .failed = model.loadState {
                return true
            }
            return false
        }

        model.retry()

        await waitUntil("retry to load catalog") {
            model.catalog == catalog
        }

        XCTAssertEqual(loadCount, 2)
        assertLoaded(model)
        XCTAssertEqual(model.subkeys, catalog.subkeys)
        XCTAssertNil(model.loadError)
    }

    func test_handleDisappear_cancelsInFlightLoadAndIgnoresLateFailure() async {
        let gate = SelectiveRevocationLoadGate()
        let model = makeModel(selectionCatalogAction: { _ in
            await gate.suspend(attempt: 1)
            throw SelectiveRevocationScreenModelTestError(message: "late failure")
        })

        model.loadIfNeeded()

        await waitUntil("load to suspend before disappearance") {
            let isSuspended = await gate.isSuspended(attempt: 1)
            return model.isLoading && isSuspended
        }

        model.handleDisappear()

        assertIdle(model)
        XCTAssertNil(model.catalog)
        XCTAssertNil(model.loadError)

        await gate.resume(attempt: 1)
        await drainMainActor()

        assertIdle(model)
        XCTAssertNil(model.catalog)
        XCTAssertNil(model.loadError)
    }

    func test_reenteredLoadWinsOverLateCompletionFromCancelledPreviousAttempt() async {
        let gate = SelectiveRevocationLoadGate()
        let firstCatalog = makeCatalog()
        let secondCatalog = makeAlternateCatalog()
        var loadCount = 0
        let model = makeModel(selectionCatalogAction: { _ in
            loadCount += 1
            let attempt = loadCount
            if attempt == 1 {
                await gate.suspend(attempt: attempt)
                return firstCatalog
            }
            return secondCatalog
        })

        model.loadIfNeeded()

        await waitUntil("first load to suspend") {
            let isSuspended = await gate.isSuspended(attempt: 1)
            return model.isLoading && isSuspended
        }

        model.handleDisappear()
        model.loadIfNeeded()

        await waitUntil("replacement load to win") {
            model.catalog == secondCatalog
        }

        await gate.resume(attempt: 1)
        await drainMainActor()

        XCTAssertEqual(model.catalog, secondCatalog)
        XCTAssertEqual(model.subkeys, secondCatalog.subkeys)
        XCTAssertEqual(model.userIds, secondCatalog.userIds)
        assertLoaded(model)
    }

    func test_loadedCatalogPreservesSelectorOrderAndDuplicateUserIds() async {
        let catalog = makeCatalog()
        let model = makeModel(selectionCatalogAction: { _ in catalog })

        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }

        XCTAssertEqual(model.subkeys.map(\.fingerprint), catalog.subkeys.map(\.fingerprint))
        XCTAssertEqual(model.userIds.map(\.occurrenceIndex), [0, 1])
        XCTAssertEqual(model.userIds[0].userIdData, model.userIds[1].userIdData)
        XCTAssertEqual(model.userIds[0].displayText, model.userIds[1].displayText)
    }

    func test_exportActionsAreDisabledUntilSelection() async {
        let catalog = makeCatalog()
        let model = makeModel(selectionCatalogAction: { _ in catalog })

        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }

        XCTAssertFalse(model.canExportSubkey)
        XCTAssertFalse(model.canExportUserId)

        model.selectSubkey(catalog.subkeys[0])
        XCTAssertTrue(model.canExportSubkey)
        XCTAssertFalse(model.canExportUserId)

        model.selectUserId(catalog.userIds[0])
        XCTAssertTrue(model.canExportSubkey)
        XCTAssertTrue(model.canExportUserId)
    }

    func test_runningExportDisablesBothExportActions() async {
        let gate = SelectiveRevocationExportGate()
        let catalog = makeCatalog()
        var userIdExportCount = 0
        let model = makeModel(
            selectionCatalogAction: { _ in catalog },
            subkeyRevocationExportAction: { _, _ in
                await gate.suspend()
                return Data("subkey".utf8)
            },
            userIdRevocationExportAction: { _, _ in
                userIdExportCount += 1
                return Data("userid".utf8)
            }
        )
        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }
        model.selectSubkey(catalog.subkeys[0])
        model.selectUserId(catalog.userIds[0])

        model.exportSelectedSubkey()

        await waitUntil("subkey export to suspend") {
            let isSuspended = await gate.isSuspended()
            return model.activeExportOperation == .subkey && isSuspended
        }

        XCTAssertFalse(model.canExportSubkey)
        XCTAssertFalse(model.canExportUserId)

        model.exportSelectedUserId()
        XCTAssertEqual(userIdExportCount, 0)

        await gate.resume()
        await waitUntil("subkey export to present file exporter") {
            model.activeExportOperation == nil && model.exportController.isPresented
        }
        model.finishExport()
    }

    func test_presentedFileExporterDisablesBothExportActionsUntilDismissed() async {
        let catalog = makeCatalog()
        let model = makeModel(selectionCatalogAction: { _ in catalog })
        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }
        model.selectSubkey(catalog.subkeys[0])
        model.selectUserId(catalog.userIds[0])

        model.exportSelectedSubkey()

        await waitUntil("file exporter to present") {
            model.activeExportOperation == nil && model.exportController.isPresented
        }

        XCTAssertFalse(model.canExportSubkey)
        XCTAssertFalse(model.canExportUserId)

        model.finishExport()

        XCTAssertTrue(model.canExportSubkey)
        XCTAssertTrue(model.canExportUserId)
    }

    func test_subkeyExportSuccessPreparesPayloadWithExpectedFilename() async {
        let catalog = makeCatalog()
        let subkey = catalog.subkeys[0]
        let model = makeModel(selectionCatalogAction: { _ in catalog })
        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }
        model.selectSubkey(subkey)

        model.exportSelectedSubkey()

        await waitUntil("subkey export to present file exporter") {
            model.activeExportOperation == nil && model.exportController.isPresented
        }

        XCTAssertNotNil(model.exportController.payload)
        XCTAssertEqual(
            model.exportController.defaultFilename,
            "subkey-revocation-\(IdentityPresentation.shortKeyId(from: fingerprint))-\(IdentityPresentation.shortKeyId(from: subkey.fingerprint)).asc"
        )
        model.finishExport()
    }

    func test_userIdExportSuccessPreparesPayloadWithExpectedFilename() async {
        let catalog = makeCatalog()
        let userId = catalog.userIds[1]
        let model = makeModel(selectionCatalogAction: { _ in catalog })
        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }
        model.selectUserId(userId)

        model.exportSelectedUserId()

        await waitUntil("User ID export to present file exporter") {
            model.activeExportOperation == nil && model.exportController.isPresented
        }

        XCTAssertNotNil(model.exportController.payload)
        XCTAssertEqual(
            model.exportController.defaultFilename,
            "userid-revocation-\(IdentityPresentation.shortKeyId(from: fingerprint))-\(userId.occurrenceIndex + 1).asc"
        )
        model.finishExport()
    }

    func test_exportFailurePreservesSelectionAndDoesNotLeaveStalePayload() async {
        let catalog = makeCatalog()
        let selected = catalog.subkeys[0]
        let model = makeModel(
            selectionCatalogAction: { _ in catalog },
            subkeyRevocationExportAction: { _, _ in
                throw SelectiveRevocationScreenModelTestError(message: "export failed")
            }
        )
        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }
        model.selectSubkey(selected)

        model.exportSelectedSubkey()

        await waitUntil("failed export to finish") {
            model.activeExportOperation == nil && model.showError
        }

        XCTAssertEqual(model.selectedSubkey, selected)
        XCTAssertNil(model.exportController.payload)
        XCTAssertFalse(model.exportController.isPresented)
    }

    func test_handleDisappear_cancelsInFlightSubkeyExportWithoutPresentingExporter() async {
        let gate = SelectiveRevocationExportGate()
        let catalog = makeCatalog()
        let selected = catalog.subkeys[0]
        let model = makeModel(
            selectionCatalogAction: { _ in catalog },
            subkeyRevocationExportAction: { _, _ in
                await gate.suspend()
                return Data("subkey".utf8)
            }
        )
        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }
        model.selectSubkey(selected)

        model.exportSelectedSubkey()

        await waitUntil("subkey export to suspend before disappearance") {
            let isSuspended = await gate.isSuspended()
            return model.activeExportOperation == .subkey && isSuspended
        }

        model.handleDisappear()

        XCTAssertNil(model.activeExportOperation)
        XCTAssertFalse(model.exportController.isPresented)
        XCTAssertNil(model.exportController.payload)
        XCTAssertEqual(model.selectedSubkey, selected)
        XCTAssertFalse(model.showError)

        await gate.resume()
        await drainMainActor()

        XCTAssertNil(model.activeExportOperation)
        XCTAssertFalse(model.exportController.isPresented)
        XCTAssertNil(model.exportController.payload)
        XCTAssertFalse(model.showError)
    }

    func test_handleDisappear_cancelsInFlightUserIdExportWithoutPresentingExporter() async {
        let gate = SelectiveRevocationExportGate()
        let catalog = makeCatalog()
        let selected = catalog.userIds[0]
        let model = makeModel(
            selectionCatalogAction: { _ in catalog },
            userIdRevocationExportAction: { _, _ in
                await gate.suspend()
                return Data("userid".utf8)
            }
        )
        model.loadIfNeeded()
        await waitUntil("catalog to load") {
            model.catalog == catalog
        }
        model.selectUserId(selected)

        model.exportSelectedUserId()

        await waitUntil("user ID export to suspend before disappearance") {
            let isSuspended = await gate.isSuspended()
            return model.activeExportOperation == .userId && isSuspended
        }

        model.handleDisappear()

        XCTAssertNil(model.activeExportOperation)
        XCTAssertFalse(model.exportController.isPresented)
        XCTAssertNil(model.exportController.payload)
        XCTAssertEqual(model.selectedUserId, selected)
        XCTAssertFalse(model.showError)

        await gate.resume()
        await drainMainActor()

        XCTAssertNil(model.activeExportOperation)
        XCTAssertFalse(model.exportController.isPresented)
        XCTAssertNil(model.exportController.payload)
        XCTAssertFalse(model.showError)
    }

    private func makeModel(
        selectionCatalogAction: SelectiveRevocationScreenModel.SelectionCatalogAction? = nil,
        subkeyRevocationExportAction: SelectiveRevocationScreenModel.SubkeyRevocationExportAction? = nil,
        userIdRevocationExportAction: SelectiveRevocationScreenModel.UserIdRevocationExportAction? = nil
    ) -> SelectiveRevocationScreenModel {
        let keyManagement = TestHelpers.makeKeyManagement().service

        return SelectiveRevocationScreenModel(
            fingerprint: fingerprint,
            keyManagement: keyManagement,
            selectionCatalogAction: selectionCatalogAction,
            subkeyRevocationExportAction: subkeyRevocationExportAction ?? { _, _ in
                Data("subkey-revocation".utf8)
            },
            userIdRevocationExportAction: userIdRevocationExportAction ?? { _, _ in
                Data("userid-revocation".utf8)
            }
        )
    }

    private func makeCatalog() -> CertificateSelectionCatalog {
        let duplicateUserIdData = Data("Alice <alice@example.com>".utf8)

        return CertificateSelectionCatalog(
            certificateFingerprint: fingerprint,
            subkeys: [
                SubkeySelectionOption(
                    fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    algorithmDisplay: "X25519",
                    isCurrentlyTransportEncryptionCapable: true,
                    isCurrentlyRevoked: false,
                    isCurrentlyExpired: false
                ),
                SubkeySelectionOption(
                    fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    algorithmDisplay: "X448",
                    isCurrentlyTransportEncryptionCapable: false,
                    isCurrentlyRevoked: true,
                    isCurrentlyExpired: true
                )
            ],
            userIds: [
                UserIdSelectionOption(
                    occurrenceIndex: 0,
                    userIdData: duplicateUserIdData,
                    displayText: "Alice <alice@example.com>",
                    isCurrentlyPrimary: true,
                    isCurrentlyRevoked: false
                ),
                UserIdSelectionOption(
                    occurrenceIndex: 1,
                    userIdData: duplicateUserIdData,
                    displayText: "Alice <alice@example.com>",
                    isCurrentlyPrimary: false,
                    isCurrentlyRevoked: true
                )
            ]
        )
    }

    private func makeAlternateCatalog() -> CertificateSelectionCatalog {
        CertificateSelectionCatalog(
            certificateFingerprint: fingerprint,
            subkeys: [
                SubkeySelectionOption(
                    fingerprint: "cccccccccccccccccccccccccccccccccccccccc",
                    algorithmDisplay: "X25519",
                    isCurrentlyTransportEncryptionCapable: true,
                    isCurrentlyRevoked: false,
                    isCurrentlyExpired: false
                )
            ],
            userIds: [
                UserIdSelectionOption(
                    occurrenceIndex: 0,
                    userIdData: Data("Bob <bob@example.com>".utf8),
                    displayText: "Bob <bob@example.com>",
                    isCurrentlyPrimary: true,
                    isCurrentlyRevoked: false
                )
            ]
        )
    }

    private func assertIdle(
        _ model: SelectiveRevocationScreenModel,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .idle = model.loadState else {
            return XCTFail("Expected idle state", file: file, line: line)
        }
    }

    private func assertLoaded(
        _ model: SelectiveRevocationScreenModel,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .loaded = model.loadState else {
            return XCTFail("Expected loaded state", file: file, line: line)
        }
    }

    private func assertFailed(
        _ model: SelectiveRevocationScreenModel,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .failed = model.loadState else {
            return XCTFail("Expected failed state", file: file, line: line)
        }
    }

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

    private func drainMainActor(iterations: Int = 5) async {
        for _ in 0..<iterations {
            await Task.yield()
        }
    }
}
