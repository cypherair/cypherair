import Foundation
import XCTest
@testable import CypherAir

private struct BackupKeyScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

private actor BackupKeyTestGate {
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
final class BackupKeyScreenModelTests: XCTestCase {
    private let fingerprint = "1234567890abcdef1234567890abcdef12345678"

    /// Shaped like the app's own generated passphrases, so it clears the export
    /// gate the way a real one does. The gate itself is exercised below.
    private static let exportablePassphrase = "Wd7f-Qm2k-Zt9x-Rb4v-Hn6p"

    func test_exportBackup_fileExporterPresentationConfirmsOnlyAfterSuccessfulSave() async {
        var exportedCallbackData: Data?
        var confirmedFingerprints: [String] = []
        var configuration = BackupKeyView.Configuration()
        configuration.onExported = { data in
            exportedCallbackData = data
        }
        let model = makeModel(
            configuration: configuration,
            confirmBackupExportedAction: { fingerprint in
                confirmedFingerprints.append(fingerprint)
            },
            exportBackupAction: { _, _ in Data("backup".utf8) }
        )
        model.passphrase = Self.exportablePassphrase
        model.passphraseConfirm = Self.exportablePassphrase

        model.exportBackup()

        await waitUntilKeyRoute("backup data to be ready") {
            model.exportedData == Data("backup".utf8)
        }

        XCTAssertTrue(confirmedFingerprints.isEmpty)
        XCTAssertNil(exportedCallbackData)

        model.handleFileExporterResult(.success(URL(fileURLWithPath: "/tmp/backup.asc")))

        XCTAssertEqual(confirmedFingerprints, [fingerprint])
        XCTAssertEqual(exportedCallbackData, Data("backup".utf8))
        XCTAssertNil(model.exportedData)
    }

    func test_exportBackup_inlinePreviewConfirmsImmediatelyAndKeepsPreviewData() async {
        var exportedCallbackData: Data?
        var confirmedFingerprints: [String] = []
        var configuration = BackupKeyView.Configuration(resultPresentation: .inlinePreview)
        configuration.onExported = { data in
            exportedCallbackData = data
        }
        let model = makeModel(
            configuration: configuration,
            confirmBackupExportedAction: { fingerprint in
                confirmedFingerprints.append(fingerprint)
            },
            exportBackupAction: { _, _ in Data("inline-backup".utf8) }
        )
        model.passphrase = Self.exportablePassphrase
        model.passphraseConfirm = Self.exportablePassphrase

        model.exportBackup()

        await waitUntilKeyRoute("inline backup to be ready") {
            model.exportedString == "inline-backup"
        }

        XCTAssertEqual(confirmedFingerprints, [fingerprint])
        XCTAssertEqual(exportedCallbackData, Data("inline-backup".utf8))
        XCTAssertEqual(model.exportedString, "inline-backup")
        XCTAssertEqual(model.passphrase, "")
        XCTAssertEqual(model.passphraseConfirm, "")
    }

    func test_fileExporterFailureDoesNotConfirmBackup() async {
        var confirmedFingerprints: [String] = []
        let model = makeModel(
            confirmBackupExportedAction: { fingerprint in
                confirmedFingerprints.append(fingerprint)
            },
            exportBackupAction: { _, _ in Data("backup".utf8) }
        )
        model.passphrase = Self.exportablePassphrase
        model.passphraseConfirm = Self.exportablePassphrase

        model.exportBackup()

        await waitUntilKeyRoute("backup data to be ready") {
            model.exportedData != nil
        }

        model.handleFileExporterResult(.failure(BackupKeyScreenModelTestError(message: "save failed")))

        XCTAssertTrue(confirmedFingerprints.isEmpty)
        XCTAssertTrue(model.showError)
        XCTAssertNil(model.exportedData)
    }

    func test_contentClearSuppressesLateExportCompletion() async {
        let gate = BackupKeyTestGate()
        var confirmedFingerprints: [String] = []
        let model = makeModel(
            confirmBackupExportedAction: { fingerprint in
                confirmedFingerprints.append(fingerprint)
            },
            exportBackupAction: { _, _ in
                await gate.suspend()
                return Data("backup".utf8)
            }
        )
        model.passphrase = Self.exportablePassphrase
        model.passphraseConfirm = Self.exportablePassphrase

        model.exportBackup()

        await waitUntilKeyRoute("backup export to suspend") {
            await gate.isSuspended()
        }

        model.handleContentClearGenerationChange()
        await gate.resume()
        await drainKeyRouteMainActor()

        XCTAssertTrue(confirmedFingerprints.isEmpty)
        XCTAssertNil(model.exportedData)
        XCTAssertFalse(model.showError)
        XCTAssertFalse(model.isExporting)
        XCTAssertEqual(model.passphrase, "")
        XCTAssertEqual(model.passphraseConfirm, "")
    }

    func test_exportBackup_refusesAWeakPassphrase() async {
        var exportAttempts = 0
        let model = makeModel(
            exportBackupAction: { _, _ in
                exportAttempts += 1
                return Data("backup".utf8)
            }
        )
        model.passphrase = "password123"
        model.passphraseConfirm = "password123"

        XCTAssertTrue(model.exportButtonDisabled)

        model.exportBackup()
        await drainKeyRouteMainActor()

        XCTAssertEqual(exportAttempts, 0)
        XCTAssertNil(model.exportedData)
        XCTAssertFalse(model.isExporting)
    }

    func test_exportBackup_acceptsAGeneratedPassphrase() async throws {
        let generated = try PassphraseGenerator.generate()
        let model = makeModel(exportBackupAction: { _, _ in Data("backup".utf8) })
        model.passphrase = generated
        model.passphraseConfirm = generated

        XCTAssertFalse(model.exportButtonDisabled)

        model.exportBackup()

        await waitUntilKeyRoute("backup data to be ready") {
            model.exportedData == Data("backup".utf8)
        }
    }

    func test_exportBackup_refusesAStrongPassphraseTypedTwiceDifferently() async {
        var exportAttempts = 0
        let model = makeModel(
            exportBackupAction: { _, _ in
                exportAttempts += 1
                return Data("backup".utf8)
            }
        )
        model.passphrase = Self.exportablePassphrase
        model.passphraseConfirm = Self.exportablePassphrase + "x"

        model.exportBackup()
        await drainKeyRouteMainActor()

        XCTAssertEqual(exportAttempts, 0)
        XCTAssertNil(model.exportedData)
    }

    func test_softwareOrUnknownKey_isNotDeviceBound() {
        // The passphrase form stays the backup surface for software custody;
        // only device-bound keys divert to the unavailable explanation.
        XCTAssertFalse(makeModel().isDeviceBound)
    }

    private func makeModel(
        configuration: BackupKeyView.Configuration = .default,
        confirmBackupExportedAction: BackupKeyScreenModel.ConfirmBackupExportedAction? = nil,
        exportBackupAction: BackupKeyScreenModel.ExportBackupAction? = nil
    ) -> BackupKeyScreenModel {
        BackupKeyScreenModel(
            fingerprint: fingerprint,
            keyManagement: TestHelpers.makeKeyManagement().service,
            configuration: configuration,
            exportBackupAction: exportBackupAction ?? { _, _ in Data("backup".utf8) },
            confirmBackupExportedAction: confirmBackupExportedAction
        )
    }
}
