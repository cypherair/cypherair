import Foundation
import XCTest
@testable import CypherAir

private actor AddContactAsyncGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var didResume = false

    func suspend() async {
        await withCheckedContinuation { continuation in
            if didResume {
                continuation.resume()
            } else {
                self.continuation = continuation
            }
        }
    }

    func isSuspended() -> Bool {
        continuation != nil
    }

    func resume() {
        didResume = true
        let continuation = continuation
        self.continuation = nil
        continuation?.resume()
    }
}

final class AddContactScreenModelTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!
    private var qrService: QRService!

    override func setUp() async throws {
        try await super.setUp()
        stack = await TestHelpers.makeServiceStack()
        qrService = QRService(contactImportAdapter: PGPContactImportAdapter(engine: stack.engine))
    }

    override func tearDown() {
        stack.cleanup()
        stack = nil
        qrService = nil
        super.tearDown()
    }

    @MainActor
    func test_handleAppear_resetsModeToFirstAllowedMode_andPrefillsOnlyWhenInputIsEmpty() {
        let configuration = AddContactView.Configuration(
            allowedImportModes: [.file, .paste],
            prefilledArmoredText: "Prefilled key",
            verificationPolicy: .allowUnverified,
            onImported: nil,
            onImportConfirmationRequested: nil
        )
        let model = makeModel(configuration: configuration)

        model.importMode = .paste
        model.importedKeyData = Data("binary".utf8)
        model.importedFileName = "existing.gpg"
        model.handleAppear()

        XCTAssertEqual(model.importMode, .file)
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)
        XCTAssertEqual(model.armoredText, "Prefilled key")

        model.importMode = .paste
        model.importedKeyData = Data("binary".utf8)
        model.importedFileName = "existing.gpg"
        model.armoredText = "User-entered key"
        model.handleAppear()

        XCTAssertEqual(model.importMode, .file)
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)
        XCTAssertEqual(model.armoredText, "User-entered key")
    }

    @MainActor
    func test_updateConfiguration_onlyReconcilesDisallowedMode_withoutApplyingPrefill() {
        let model = makeModel()
        model.importMode = .qrPhoto
        model.importedKeyData = Data("binary".utf8)
        model.importedFileName = "existing.gpg"

        let configuration = AddContactView.Configuration(
            allowedImportModes: [.paste],
            prefilledArmoredText: "Runtime prefill",
            verificationPolicy: .verifiedOnly,
            onImported: nil,
            onImportConfirmationRequested: nil
        )
        model.updateConfiguration(configuration)

        XCTAssertEqual(model.importMode, .paste)
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)
        XCTAssertEqual(model.armoredText, "")
        XCTAssertEqual(model.configuration.verificationPolicy, .verifiedOnly)
    }

    @MainActor
    func test_addContact_routesConfirmationAndCompletionThroughHostActions() throws {
        let generated = try stack.engine.generateKey(
            name: "Contact",
            email: "contact@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let armoredPublicKeyData = try stack.engine.armorPublicKey(certData: generated.publicKeyData)
        let armoredPublicKey = try XCTUnwrap(String(data: armoredPublicKeyData, encoding: .utf8))
        let model = makeModel()
        model.armoredText = armoredPublicKey

        var presentedRequest: ImportConfirmationRequest?
        var dismissCount = 0
        var completedContact: ContactIdentitySummary?
        let hostActions = makeHostActions(
            onPresent: { presentedRequest = $0 },
            onDismiss: { dismissCount += 1 },
            onComplete: { completedContact = $0 }
        )

        model.addContact(actions: hostActions)

        let request = try XCTUnwrap(presentedRequest)
        XCTAssertNil(request.candidateMatch)
        request.onImportVerified()

        XCTAssertEqual(dismissCount, 1)
        XCTAssertEqual(completedContact?.preferredKey?.fingerprint, generated.fingerprint)
        XCTAssertEqual(stack.contactService.testContactKeyRecords.count, 1)
    }

    @MainActor
    func test_addContact_sameUserIDImportCompletesWithoutReplacementPrompt() throws {
        let firstKey = try stack.engine.generateKey(
            name: "Carol",
            email: "carol@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let secondKey = try stack.engine.generateKey(
            name: "Carol",
            email: "carol@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try stack.contactService.importContact(publicKeyData: firstKey.publicKeyData)

        let model = makeModel()
        model.importedKeyData = secondKey.publicKeyData

        var presentedRequest: ImportConfirmationRequest?
        var dismissCount = 0
        var completedContact: ContactIdentitySummary?
        let hostActions = makeHostActions(
            onPresent: { presentedRequest = $0 },
            onDismiss: { dismissCount += 1 },
            onComplete: { completedContact = $0 }
        )

        model.addContact(actions: hostActions)

        let request = try XCTUnwrap(presentedRequest)
        let candidate = try XCTUnwrap(request.candidateMatch)
        XCTAssertEqual(candidate.strength, .strong)
        request.onImportVerified()

        XCTAssertEqual(dismissCount, 1)
        XCTAssertEqual(completedContact?.preferredKey?.fingerprint, secondKey.fingerprint)
        XCTAssertEqual(stack.contactService.testContactKeyRecords.count, 2)
        XCTAssertNotNil(stack.contactService.availableContactKeyRecord(fingerprint: firstKey.fingerprint))
        XCTAssertNotNil(stack.contactService.availableContactKeyRecord(fingerprint: secondKey.fingerprint))
    }

    @MainActor
    func test_addContact_duplicateFingerprintImportDoesNotShowCandidateConflict() throws {
        let generated = try stack.engine.generateKey(
            name: "Duplicate",
            email: "duplicate@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try stack.contactService.importContact(publicKeyData: generated.publicKeyData)

        let model = makeModel()
        model.importedKeyData = generated.publicKeyData

        var presentedRequest: ImportConfirmationRequest?
        let hostActions = makeHostActions(
            onPresent: { presentedRequest = $0 },
            onDismiss: {},
            onComplete: { _ in }
        )

        model.addContact(actions: hostActions)

        let request = try XCTUnwrap(presentedRequest)
        XCTAssertNil(request.candidateMatch)
    }

    @MainActor
    func test_addContact_staleCandidateWarningFailsClosedWithoutImportingDisplayedKey() throws {
        let firstKey = try stack.engine.generateKey(
            name: "Stale Candidate",
            email: "stale-candidate@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let secondKey = try stack.engine.generateKey(
            name: "Stale Candidate",
            email: "stale-candidate@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let model = makeModel()
        model.importedKeyData = secondKey.publicKeyData

        var presentedRequest: ImportConfirmationRequest?
        var dismissCount = 0
        var completedContact: ContactIdentitySummary?
        let hostActions = makeHostActions(
            onPresent: { presentedRequest = $0 },
            onDismiss: { dismissCount += 1 },
            onComplete: { completedContact = $0 }
        )

        model.addContact(actions: hostActions)
        let request = try XCTUnwrap(presentedRequest)
        XCTAssertNil(request.candidateMatch)

        _ = try stack.contactService.importContact(publicKeyData: firstKey.publicKeyData)
        request.onImportVerified()

        XCTAssertEqual(dismissCount, 1)
        XCTAssertNil(completedContact)
        XCTAssertTrue(model.showError)
        if case .contactImportConfirmationStale? = model.error {
            // Expected.
        } else {
            XCTFail("Expected stale import confirmation error, got \(String(describing: model.error))")
        }
        XCTAssertNil(stack.contactService.availableContactKeyRecord(fingerprint: secondKey.fingerprint))
        XCTAssertEqual(stack.contactService.testContactKeyRecords.count, 1)
    }

    @MainActor
    func test_addContact_whenConfirmationAlreadyPendingReportsErrorWithoutReplacingRequest() throws {
        let generated = try stack.engine.generateKey(
            name: "Pending",
            email: "pending@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let model = makeModel()
        model.importedKeyData = generated.publicKeyData

        var presentedRequest: ImportConfirmationRequest?
        let hostActions = AddContactScreenHostActions(
            presentImportConfirmation: { request in
                presentedRequest = request
                return false
            },
            dismissPresentedImportConfirmation: {},
            completeImportedContact: { _ in }
        )

        model.addContact(actions: hostActions)

        XCTAssertNotNil(presentedRequest)
        XCTAssertTrue(model.showError)
        if case .contactImportConfirmationAlreadyPending? = model.error {
            // Expected.
        } else {
            XCTFail("Expected already-pending import confirmation error, got \(String(describing: model.error))")
        }
        XCTAssertTrue(stack.contactService.testContactKeyRecords.isEmpty)
    }

    @MainActor
    func test_processSelectedQRPhoto_successAndFailure_updateState() async {
        let model = makeModel(
            qrPhotoKeyDataLoader: { selection in
                XCTAssertEqual(selection.identifier, "armored-success")
                return try await selection.loadKeyData()
            }
        )

        model.processSelectedQRPhoto(
            makeQRPhotoSelection(identifier: "armored-success") {
                Data("-----BEGIN PGP PUBLIC KEY BLOCK-----".utf8)
            }
        )

        await waitUntil("QR photo success handling") {
            model.isProcessingQR == false
        }

        XCTAssertEqual(model.armoredText, "-----BEGIN PGP PUBLIC KEY BLOCK-----")
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)

        model.dismissError()

        let failingModel = makeModel(
            qrPhotoKeyDataLoader: { selection in
                XCTAssertEqual(selection.identifier, "invalid-qr")
                return try await selection.loadKeyData()
            }
        )
        failingModel.processSelectedQRPhoto(
            makeQRPhotoSelection(identifier: "invalid-qr") {
                throw CypherAirError.invalidQRCode
            }
        )

        await waitUntil("QR photo failure handling") {
            failingModel.isProcessingQR == false
        }

        XCTAssertTrue(failingModel.showError)
        if case .invalidQRCode? = failingModel.error {
            // Expected
        } else {
            XCTFail("Expected invalid QR code error")
        }
    }

    @MainActor
    func test_processSelectedQRPhoto_binaryData_usesInjectedLoaderAndStoresImportedFile() async {
        let binaryKeyData = Data([0xff, 0xfe, 0xfd])
        let model = makeModel(
            qrPhotoKeyDataLoader: { selection in
                XCTAssertEqual(selection.identifier, "binary-success")
                return try await selection.loadKeyData()
            }
        )

        model.processSelectedQRPhoto(
            makeQRPhotoSelection(identifier: "binary-success") {
                binaryKeyData
            }
        )

        await waitUntil("QR photo binary success handling") {
            model.isProcessingQR == false
        }

        XCTAssertEqual(model.armoredText, "")
        XCTAssertEqual(model.importedKeyData, binaryKeyData)
        XCTAssertEqual(model.importedFileName, "Binary key from QR")
        XCTAssertFalse(model.showError)
    }

    @MainActor
    func test_clearTransientInputDuringQRProcessingSuppressesLateLoadedKey() async {
        let gate = AddContactAsyncGate()
        let model = makeModel(
            qrPhotoKeyDataLoader: { selection in
                try await selection.loadKeyData()
            }
        )

        model.processSelectedQRPhoto(
            makeQRPhotoSelection(identifier: "late-key") {
                await gate.suspend()
                return Data("late-public-key".utf8)
            }
        )

        await waitUntil("QR processing to suspend") {
            guard model.isProcessingQR else {
                return false
            }
            return await gate.isSuspended()
        }

        model.clearTransientInput()
        XCTAssertFalse(model.isProcessingQR)
        XCTAssertEqual(model.armoredText, "")
        XCTAssertNil(model.importedKeyData)

        await gate.resume()
        await settleAsyncWork()

        XCTAssertEqual(model.armoredText, "")
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)
        XCTAssertFalse(model.showError)
    }

    @MainActor
    func test_handleDisappearDuringQRProcessingCancelsAndSuppressesLateLoadedKey() async {
        let gate = AddContactAsyncGate()
        let model = makeModel(
            qrPhotoKeyDataLoader: { selection in
                try await selection.loadKeyData()
            }
        )

        model.processSelectedQRPhoto(
            makeQRPhotoSelection(identifier: "disappear-late-key") {
                await gate.suspend()
                return Data("late-public-key".utf8)
            }
        )

        await waitUntil("QR processing to suspend before disappear") {
            guard model.isProcessingQR else {
                return false
            }
            return await gate.isSuspended()
        }

        model.handleDisappear()
        XCTAssertFalse(model.isProcessingQR)
        XCTAssertEqual(model.armoredText, "")
        XCTAssertNil(model.importedKeyData)

        await gate.resume()
        await settleAsyncWork()

        XCTAssertEqual(model.armoredText, "")
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)
        XCTAssertFalse(model.showError)
    }

    @MainActor
    func test_processSelectedQRPhoto_doesNotRetainScreenModelWhileLoaderIsSuspended() async {
        let gate = AddContactAsyncGate()
        var model: AddContactScreenModel? = makeModel(
            qrPhotoKeyDataLoader: { selection in
                try await selection.loadKeyData()
            }
        )
        weak var weakModel = model

        model?.processSelectedQRPhoto(
            makeQRPhotoSelection(identifier: "suspended-loader") {
                await gate.suspend()
                return Data("late-public-key".utf8)
            }
        )

        await waitUntil("QR processing loader to suspend") {
            await gate.isSuspended()
        }

        model = nil

        await waitUntil("QR processing should not retain model") {
            weakModel == nil
        }

        await gate.resume()
        await settleAsyncWork()
        XCTAssertNil(weakModel)
    }

    @MainActor
    func test_loadFileContents_successAndFailure_updateImportState() throws {
        let armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        let expectedFileName = "contact.asc"
        let model = makeModel(
            loadFileAction: { url in
                if url.lastPathComponent == expectedFileName {
                    return LoadedPublicKeyFile(
                        data: Data(armoredPublicKey.utf8),
                        text: armoredPublicKey,
                        fileName: expectedFileName
                    )
                }

                throw CypherAirError.invalidKeyData(
                    reason: String(
                        localized: "addcontact.file.readFailed",
                        defaultValue: "Could not read key file"
                    )
                )
            }
        )
        let fileURL = URL(fileURLWithPath: "/tmp/\(expectedFileName)")
        model.loadFileContents(from: fileURL)

        XCTAssertEqual(model.armoredText, armoredPublicKey)
        XCTAssertNil(model.importedKeyData)
        XCTAssertEqual(model.importedFileName, expectedFileName)

        model.dismissError()
        model.loadFileContents(from: fileURL.deletingLastPathComponent().appendingPathComponent("missing.asc"))

        XCTAssertTrue(model.showError)
        XCTAssertNotNil(model.error)
    }

    @MainActor
    func test_handleFileImporterResult_afterClearTransientInput_ignoresStaleSelection() throws {
        let armoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        let fileURL = URL(fileURLWithPath: "/tmp/contact.asc")
        let model = makeModel(
            loadFileAction: { _ in
                LoadedPublicKeyFile(
                    data: Data(armoredPublicKey.utf8),
                    text: armoredPublicKey,
                    fileName: fileURL.lastPathComponent
                )
            }
        )

        model.requestFileImport()
        let token = try XCTUnwrap(model.fileImportRequestToken)
        model.clearTransientInput()
        model.handleFileImporterResult(.success([fileURL]), token: token)

        XCTAssertEqual(model.armoredText, "")
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)
        XCTAssertFalse(model.showError)
    }

    @MainActor
    func test_clearTransientInput_clearsPastedAndImportedKeyState() {
        let model = makeModel()
        model.armoredText = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        model.importedKeyData = Data("binary-key".utf8)
        model.importedFileName = "contact.gpg"
        model.showFileImporter = true
        model.error = .invalidQRCode
        model.showError = true

        model.clearTransientInput()

        XCTAssertEqual(model.armoredText, "")
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)
        XCTAssertFalse(model.showFileImporter)
        XCTAssertNil(model.error)
        XCTAssertFalse(model.showError)
    }

    @MainActor
    private func makeModel(
        configuration: AddContactView.Configuration = .default,
        inspectKeyDataAction: AddContactScreenModel.InspectKeyDataAction? = nil,
        loadFileAction: AddContactScreenModel.LoadFileAction? = nil,
        qrPhotoKeyDataLoader: AddContactScreenModel.QRPhotoKeyDataLoader? = nil
    ) -> AddContactScreenModel {
        AddContactScreenModel(
            importLoader: PublicKeyImportLoader(qrService: qrService),
            importWorkflow: ContactImportWorkflow(contactService: stack.contactService),
            configuration: configuration,
            inspectKeyDataAction: inspectKeyDataAction,
            loadFileAction: loadFileAction,
            qrPhotoKeyDataLoader: qrPhotoKeyDataLoader
        )
    }

    @MainActor
    private func makeQRPhotoSelection(
        identifier: String,
        loadKeyData: @escaping @MainActor () async throws -> Data
    ) -> AddContactQRPhotoSelection {
        AddContactQRPhotoSelection(identifier: identifier, loadKeyData: loadKeyData)
    }

    private func makeHostActions(
        onPresent: @escaping @MainActor (ImportConfirmationRequest) -> Void,
        onDismiss: @escaping @MainActor () -> Void,
        onComplete: @escaping @MainActor (ContactIdentitySummary) -> Void
    ) -> AddContactScreenHostActions {
        AddContactScreenHostActions(
            presentImportConfirmation: { request in
                onPresent(request)
                return true
            },
            dismissPresentedImportConfirmation: onDismiss,
            completeImportedContact: onComplete
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
