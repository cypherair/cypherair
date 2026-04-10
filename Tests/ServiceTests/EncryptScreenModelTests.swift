import Foundation
import XCTest
@testable import CypherAir

private actor EncryptOperationGate {
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

final class EncryptScreenModelTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!
    private var config: AppConfiguration!
    private var defaultsSuiteName: String!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
        defaultsSuiteName = "com.cypherair.tests.encryptscreen.\(UUID().uuidString)"
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
    func test_handleAppear_preservesCurrentPlaintext_butResetsRecipientsAndSigningState() async throws {
        let signerIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Signer"
        )
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Recipient"
        )

        var configuration = EncryptView.Configuration()
        configuration.prefilledPlaintext = "Prefilled message"
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
        configuration.signingPolicy = .initial(false)
        configuration.encryptToSelfPolicy = .initial(true)

        let model = makeModel(configuration: configuration)

        model.handleAppear()

        XCTAssertEqual(model.plaintext, "Prefilled message")
        XCTAssertEqual(model.selectedRecipients, [recipientIdentity.fingerprint])
        XCTAssertEqual(model.signerFingerprint, signerIdentity.fingerprint)
        XCTAssertEqual(model.encryptToSelfFingerprint, signerIdentity.fingerprint)
        XCTAssertFalse(model.signMessage)
        XCTAssertEqual(model.encryptToSelf, true)

        model.plaintext = "User edited plaintext"
        model.selectedRecipients = ["override"]
        model.signerFingerprint = "override"
        model.encryptToSelfFingerprint = "override"
        model.signMessage = true
        model.encryptToSelf = false

        model.handleAppear()

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertEqual(model.selectedRecipients, [recipientIdentity.fingerprint])
        XCTAssertEqual(model.signerFingerprint, signerIdentity.fingerprint)
        XCTAssertEqual(model.encryptToSelfFingerprint, signerIdentity.fingerprint)
        XCTAssertFalse(model.signMessage)
        XCTAssertEqual(model.encryptToSelf, true)
    }

    @MainActor
    func test_updateConfiguration_updatesTutorialState_withoutOverwritingEditedPlaintext() async throws {
        let signerIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Signer"
        )
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Recipient"
        )

        let model = makeModel()
        model.plaintext = "User edited plaintext"
        model.selectedRecipients = ["manual-recipient"]
        model.signerFingerprint = "manual-signer"
        model.encryptToSelfFingerprint = "manual-self"
        model.signMessage = true
        model.encryptToSelf = false

        var configuration = EncryptView.Configuration()
        configuration.prefilledPlaintext = "Prefilled message"
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
        configuration.initialSignerFingerprint = signerIdentity.fingerprint
        configuration.signingPolicy = .initial(false)
        configuration.encryptToSelfPolicy = .initial(true)
        configuration.allowsResultExport = false

        model.updateConfiguration(configuration)

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertEqual(model.selectedRecipients, [recipientIdentity.fingerprint])
        XCTAssertEqual(model.signerFingerprint, signerIdentity.fingerprint)
        XCTAssertEqual(model.encryptToSelfFingerprint, signerIdentity.fingerprint)
        XCTAssertFalse(model.signMessage)
        XCTAssertEqual(model.encryptToSelf, true)
        XCTAssertFalse(model.configuration.allowsResultExport)
    }

    @MainActor
    func test_updateConfiguration_clearsTutorialRecipientSeed_whenConfigurationBecomesInactive() async throws {
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Recipient"
        )

        let model = makeModel()
        model.plaintext = "User edited plaintext"

        var activeConfiguration = EncryptView.Configuration()
        activeConfiguration.prefilledPlaintext = "Prefilled message"
        activeConfiguration.initialRecipientFingerprints = [recipientIdentity.fingerprint]

        model.updateConfiguration(activeConfiguration)

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertEqual(model.selectedRecipients, [recipientIdentity.fingerprint])

        model.updateConfiguration(.default)

        XCTAssertEqual(model.plaintext, "User edited plaintext")
        XCTAssertTrue(model.selectedRecipients.isEmpty)
    }

    @MainActor
    func test_encryptText_usesCallbackCapturedAtOperationStart_whenConfigurationChangesMidFlight() async {
        let gate = EncryptOperationGate()
        var firstCallbackCiphertext: Data?
        var secondCallbackCiphertext: Data?

        var configuration = EncryptView.Configuration()
        configuration.onEncrypted = { firstCallbackCiphertext = $0 }

        let model = makeModel(
            configuration: configuration,
            textEncryptionAction: { _, _, _, _, _ in
                await gate.suspend()
                return Data("ciphertext".utf8)
            }
        )
        model.plaintext = "Secret"
        model.selectedRecipients = ["recipient"]

        model.encryptText()

        await waitUntil("text encryption to suspend") {
            guard model.operation.isRunning else {
                return false
            }
            return await gate.isSuspended()
        }

        configuration.onEncrypted = { secondCallbackCiphertext = $0 }
        configuration.allowsResultExport = false
        model.updateConfiguration(configuration)

        await gate.resume()

        await waitUntil("text encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(firstCallbackCiphertext, Data("ciphertext".utf8))
        XCTAssertNil(secondCallbackCiphertext)
    }

    @MainActor
    func test_requestEncrypt_withUnverifiedRecipients_showsWarningUntilConfirmed() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Unverified Recipient"
        )
        try stack.contactService.addContact(
            publicKeyData: recipientIdentity.publicKeyData,
            verificationState: .unverified
        )

        var encryptCount = 0
        var callbackCiphertext: Data?
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
        configuration.onEncrypted = { callbackCiphertext = $0 }

        let model = makeModel(
            configuration: configuration,
            textEncryptionAction: { _, _, _, _, _ in
                encryptCount += 1
                return Data("ciphertext".utf8)
            }
        )
        model.plaintext = "Secret"
        model.handleAppear()

        model.requestEncrypt()

        XCTAssertTrue(model.showUnverifiedRecipientsWarning)
        XCTAssertEqual(encryptCount, 0)
        XCTAssertNil(model.ciphertext)

        model.confirmEncryptWithUnverifiedRecipients()

        await waitUntil("confirmed encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertFalse(model.showUnverifiedRecipientsWarning)
        XCTAssertEqual(encryptCount, 1)
        XCTAssertEqual(model.ciphertext, Data("ciphertext".utf8))
        XCTAssertEqual(callbackCiphertext, Data("ciphertext".utf8))
    }

    @MainActor
    func test_encryptText_routesClipboardAndExportThroughInterceptionPolicy() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateProfileBKey(
            service: stack.keyManagement,
            name: "Verified Recipient"
        )
        try stack.contactService.addContact(publicKeyData: recipientIdentity.publicKeyData)

        var interceptedClipboard: String?
        var interceptedExportFilename: String?
        var callbackCiphertext: Data?
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
        configuration.outputInterceptionPolicy = OutputInterceptionPolicy(
            interceptClipboardCopy: { string, _, kind in
                XCTAssertEqual(kind, .ciphertext)
                interceptedClipboard = string
                return true
            },
            interceptDataExport: { _, filename, kind in
                XCTAssertEqual(kind, .ciphertext)
                interceptedExportFilename = filename
                return true
            }
        )
        configuration.onEncrypted = { callbackCiphertext = $0 }

        let model = makeModel(
            configuration: configuration,
            textEncryptionAction: { _, _, _, _, _ in
                Data("ciphertext-body".utf8)
            }
        )
        model.plaintext = "Hello"
        model.handleAppear()

        model.requestEncrypt()

        await waitUntil("text encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(model.ciphertextString, "ciphertext-body")
        XCTAssertEqual(callbackCiphertext, Data("ciphertext-body".utf8))

        model.copyCiphertextToClipboard()
        XCTAssertEqual(interceptedClipboard, "ciphertext-body")
        XCTAssertFalse(model.operation.isShowingClipboardNotice)

        model.exportCiphertext()
        XCTAssertEqual(interceptedExportFilename, "encrypted.asc")
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_encryptFile_handlesSelection_andRoutesFileExportThroughInterceptionPolicy() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        try stack.contactService.addContact(publicKeyData: recipientIdentity.publicKeyData)

        let inputURL = try makeTemporaryFile(
            named: "message.txt",
            contents: Data("plaintext".utf8)
        )
        let outputURL = try makeTemporaryFile(
            named: "message.txt.gpg",
            contents: Data("ciphertext".utf8)
        )
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        var interceptedURL: URL?
        var interceptedFilename: String?
        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]
        configuration.outputInterceptionPolicy = OutputInterceptionPolicy(
            interceptFileExport: { url, filename, kind in
                XCTAssertEqual(kind, .ciphertext)
                interceptedURL = url
                interceptedFilename = filename
                return true
            }
        )

        let model = makeModel(
            configuration: configuration,
            fileEncryptionAction: { _, _, _, _, _, _ in outputURL }
        )
        model.encryptMode = .file
        model.handleAppear()
        model.handleImportedFile(inputURL)

        model.encryptFile()

        await waitUntil("file encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertEqual(model.selectedFileName, inputURL.lastPathComponent)
        XCTAssertEqual(model.encryptedFileURL, outputURL)

        model.exportEncryptedFile()

        XCTAssertEqual(interceptedURL, outputURL)
        XCTAssertEqual(interceptedFilename, "\(inputURL.lastPathComponent).gpg")
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_encryptFile_cancellation_clearsProgress_andDoesNotPublishOutputURL() async throws {
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        let recipientIdentity = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Recipient"
        )
        try stack.contactService.addContact(publicKeyData: recipientIdentity.publicKeyData)

        let gate = EncryptOperationGate()
        let inputURL = try makeTemporaryFile(
            named: "cancel.txt",
            contents: Data("cancel".utf8)
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        var configuration = EncryptView.Configuration()
        configuration.initialRecipientFingerprints = [recipientIdentity.fingerprint]

        let model = makeModel(
            configuration: configuration,
            fileEncryptionAction: { _, _, _, _, _, progress in
                _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
                await gate.suspend()
                try Task.checkCancellation()
                return inputURL
            }
        )
        model.encryptMode = .file
        model.handleAppear()
        model.handleImportedFile(inputURL)

        model.encryptFile()

        await waitUntil("file encryption to suspend") {
            guard model.operation.isRunning, model.operation.progress != nil else {
                return false
            }
            return await gate.isSuspended()
        }

        model.operation.cancel()

        XCTAssertTrue(model.operation.isRunning)
        XCTAssertTrue(model.operation.isCancelling)

        await gate.resume()

        await waitUntil("cancelled file encryption to finish") {
            model.operation.isRunning == false
        }

        XCTAssertNil(model.encryptedFileURL)
        XCTAssertNil(model.operation.progress)
        XCTAssertFalse(model.operation.isShowingError)
    }

    @MainActor
    func test_configurationFlags_gateFileImportAndExports() {
        var configuration = EncryptView.Configuration()
        configuration.allowsFileInput = false
        configuration.allowsResultExport = false
        configuration.allowsFileResultExport = false

        let model = makeModel(configuration: configuration)

        model.requestFileImport()
        XCTAssertFalse(model.showFileImporter)

        model.ciphertext = Data("ciphertext".utf8)
        model.exportCiphertext()
        XCTAssertNil(model.exportController.payload)

        model.encryptedFileURL = URL(fileURLWithPath: "/tmp/encrypted.gpg")
        model.exportEncryptedFile()
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    private func makeModel(
        configuration: EncryptView.Configuration = .default,
        operation: OperationController = OperationController(),
        textEncryptionAction: EncryptScreenModel.TextEncryptionAction? = nil,
        fileEncryptionAction: EncryptScreenModel.FileEncryptionAction? = nil
    ) -> EncryptScreenModel {
        EncryptScreenModel(
            encryptionService: stack.encryptionService,
            keyManagement: stack.keyManagement,
            contactService: stack.contactService,
            config: config,
            configuration: configuration,
            operation: operation,
            textEncryptionAction: textEncryptionAction,
            fileEncryptionAction: fileEncryptionAction
        )
    }

    private func makeTemporaryFile(named name: String, contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirEncryptScreenTests-\(UUID().uuidString)-\(name)")
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
