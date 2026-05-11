import Foundation
import XCTest
@testable import CypherAir

final class AddContactScreenModelTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!
    private var qrService: QRService!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
        qrService = QRService(engine: stack.engine)
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
        var completedContact: Contact?
        let hostActions = makeHostActions(
            onPresent: { presentedRequest = $0 },
            onDismiss: { dismissCount += 1 },
            onComplete: { completedContact = $0 }
        )

        model.addContact(actions: hostActions)

        let request = try XCTUnwrap(presentedRequest)
        request.onImportVerified()

        XCTAssertEqual(dismissCount, 1)
        XCTAssertEqual(completedContact?.fingerprint, generated.fingerprint)
        XCTAssertEqual(stack.contactService.availableContacts.count, 1)
    }

    @MainActor
    func test_addContact_keyUpdateFlow_surfacesPendingAlert_andConfirmCompletesReplacement() throws {
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
        _ = try stack.contactService.addContact(publicKeyData: firstKey.publicKeyData)

        let model = makeModel()
        model.importedKeyData = secondKey.publicKeyData

        var presentedRequest: ImportConfirmationRequest?
        var dismissCount = 0
        var completedContact: Contact?
        let hostActions = makeHostActions(
            onPresent: { presentedRequest = $0 },
            onDismiss: { dismissCount += 1 },
            onComplete: { completedContact = $0 }
        )

        model.addContact(actions: hostActions)

        let request = try XCTUnwrap(presentedRequest)
        request.onImportVerified()

        XCTAssertEqual(dismissCount, 1)
        XCTAssertNil(completedContact)
        XCTAssertTrue(model.showKeyUpdateAlert)
        XCTAssertNotNil(model.pendingKeyUpdateRequest)

        model.confirmPendingKeyUpdate()

        XCTAssertFalse(model.showKeyUpdateAlert)
        XCTAssertNil(model.pendingKeyUpdateRequest)
        XCTAssertEqual(completedContact?.fingerprint, secondKey.fingerprint)
        XCTAssertEqual(stack.contactService.availableContacts.count, 1)
        XCTAssertNotNil(stack.contactService.availableContact(forFingerprint: secondKey.fingerprint))
    }

    @MainActor
    func test_processSelectedQRPhoto_successAndFailure_updateState() async {
        let model = makeModel()

        model.processSelectedQRPhoto {
            Data("-----BEGIN PGP PUBLIC KEY BLOCK-----".utf8)
        }

        await waitUntil("QR photo success handling") {
            model.isProcessingQR == false
        }

        XCTAssertEqual(model.armoredText, "-----BEGIN PGP PUBLIC KEY BLOCK-----")
        XCTAssertNil(model.importedKeyData)
        XCTAssertNil(model.importedFileName)

        model.dismissError()

        model.processSelectedQRPhoto {
            throw CypherAirError.invalidQRCode
        }

        await waitUntil("QR photo failure handling") {
            model.isProcessingQR == false
        }

        XCTAssertTrue(model.showError)
        if case .invalidQRCode? = model.error {
            // Expected
        } else {
            XCTFail("Expected invalid QR code error")
        }
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
        loadFileAction: AddContactScreenModel.LoadFileAction? = nil
    ) -> AddContactScreenModel {
        AddContactScreenModel(
            importLoader: PublicKeyImportLoader(qrService: qrService),
            importWorkflow: ContactImportWorkflow(contactService: stack.contactService),
            configuration: configuration,
            inspectKeyDataAction: inspectKeyDataAction,
            loadFileAction: loadFileAction
        )
    }

    private func makeHostActions(
        onPresent: @escaping @MainActor (ImportConfirmationRequest) -> Void,
        onDismiss: @escaping @MainActor () -> Void,
        onComplete: @escaping @MainActor (Contact) -> Void
    ) -> AddContactScreenHostActions {
        AddContactScreenHostActions(
            presentImportConfirmation: onPresent,
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
}
