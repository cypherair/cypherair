import Foundation
import XCTest
@testable import CypherAir

private struct KeyDetailScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

final class KeyDetailScreenModelTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!
    private var config: AppConfiguration!
    private var defaultsSuiteName: String!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
        defaultsSuiteName = "com.cypherair.tests.keydetailscreen.\(UUID().uuidString)"
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
    func test_prepareIfNeeded_publicKeyExportFailure_doesNotBlockScreenState() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        let model = makeModel(
            fingerprint: identity.fingerprint,
            publicKeyExportAction: { _ in
                throw KeyDetailScreenModelTestError(message: "public-key failed")
            }
        )

        model.prepareIfNeeded()

        XCTAssertNil(model.armoredPublicKey)
        XCTAssertFalse(model.showError)
        XCTAssertEqual(model.key?.fingerprint, identity.fingerprint)
    }

    @MainActor
    func test_copyAndSavePublicKey_routeThroughInterceptionPolicy() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        var interceptedClipboard: String?
        var interceptedExportFilename: String?
        var configuration = KeyDetailView.Configuration()
        configuration.outputInterceptionPolicy = OutputInterceptionPolicy(
            interceptClipboardCopy: { string, _, kind in
                XCTAssertEqual(kind, .publicKey)
                interceptedClipboard = string
                return true
            },
            interceptDataExport: { _, filename, kind in
                XCTAssertEqual(kind, .publicKey)
                interceptedExportFilename = filename
                return true
            }
        )

        let model = makeModel(
            fingerprint: identity.fingerprint,
            configuration: configuration
        )
        model.prepareIfNeeded()
        model.copyPublicKey()
        model.exportPublicKey()

        XCTAssertEqual(
            interceptedClipboard,
            String(data: try XCTUnwrap(model.armoredPublicKey), encoding: .utf8)
        )
        XCTAssertEqual(interceptedExportFilename, "\(identity.shortKeyId).asc")
        XCTAssertFalse(model.showCopiedNotice)
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_configurationFlags_gateCopyAndSave() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")

        var configuration = KeyDetailView.Configuration()
        configuration.allowsPublicKeyCopy = false
        configuration.allowsPublicKeySave = false

        let model = makeModel(
            fingerprint: identity.fingerprint,
            configuration: configuration,
            clipboardCopyAction: { _ in
                XCTFail("Clipboard should not be written when copy is disabled")
            }
        )
        model.prepareIfNeeded()
        model.copyPublicKey()
        model.exportPublicKey()

        XCTAssertFalse(model.showCopiedNotice)
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_exportRevocationCertificate_preparesExportPayload() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        let model = makeModel(
            fingerprint: identity.fingerprint,
            revocationExportAction: { _ in
                Data("armored-revocation".utf8)
            }
        )

        model.exportRevocationCertificate()

        await waitUntil("revocation export to finish") {
            model.isPreparingRevocationExport == false
        }

        XCTAssertNotNil(model.exportController.payload)
        XCTAssertEqual(model.exportController.defaultFilename, "revocation-\(identity.shortKeyId).asc")
        model.finishExport()
    }

    @MainActor
    func test_exportRevocationCertificate_failure_surfacesError() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        let model = makeModel(
            fingerprint: identity.fingerprint,
            revocationExportAction: { _ in
                throw KeyDetailScreenModelTestError(message: "revocation failed")
            }
        )

        model.exportRevocationCertificate()

        await waitUntil("failed revocation export to finish") {
            model.isPreparingRevocationExport == false
        }

        XCTAssertTrue(model.showError)
        XCTAssertNotNil(model.error)
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_setDefaultAndDelete_invokeInjectedActionsAndDismiss() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        var defaultFingerprint: String?
        var deletedFingerprint: String?
        var dismissCount = 0

        let model = makeModel(
            fingerprint: identity.fingerprint,
            dismissAction: {
                dismissCount += 1
            },
            defaultKeyAction: { fingerprint in
                defaultFingerprint = fingerprint
            },
            deleteKeyAction: { fingerprint in
                deletedFingerprint = fingerprint
            }
        )

        model.setDefaultKey()
        model.deleteKey()

        XCTAssertEqual(defaultFingerprint, identity.fingerprint)
        XCTAssertEqual(deletedFingerprint, identity.fingerprint)
        XCTAssertEqual(dismissCount, 1)
        XCTAssertFalse(model.showError)
    }

    @MainActor
    func test_presentModifyExpiry_withoutMacController_keepsLocalRequest_andReloadsAfterCompletion() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        var exportCount = 0
        let model = makeModel(
            fingerprint: identity.fingerprint,
            publicKeyExportAction: { _ in
                exportCount += 1
                return Data("public-\(exportCount)".utf8)
            }
        )
        model.prepareIfNeeded()

        model.presentModifyExpiry()

        let request = try XCTUnwrap(model.localModifyExpiryRequest)
        XCTAssertEqual(request.fingerprint, identity.fingerprint)
        XCTAssertEqual(model.armoredPublicKey, Data("public-1".utf8))

        request.onComplete()

        XCTAssertNil(model.localModifyExpiryRequest)
        XCTAssertEqual(model.armoredPublicKey, Data("public-2".utf8))
    }

    @MainActor
    func test_presentModifyExpiry_withMacController_routesRequestThroughPresentationHost() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        var capturedPresentation: MacPresentation?
        let macPresentationController = MacPresentationController(
            present: { presentation in
                capturedPresentation = presentation
            },
            dismiss: {}
        )

        let model = makeModel(
            fingerprint: identity.fingerprint,
            macPresentationController: macPresentationController
        )
        model.presentModifyExpiry()

        guard case .modifyExpiry(let request) = capturedPresentation else {
            return XCTFail("Expected modify-expiry presentation")
        }

        XCTAssertEqual(request.fingerprint, identity.fingerprint)
        XCTAssertNil(model.localModifyExpiryRequest)
    }

    @MainActor
    private func makeModel(
        fingerprint: String,
        configuration: KeyDetailView.Configuration = .default,
        macPresentationController: MacPresentationController? = nil,
        dismissAction: @escaping @MainActor () -> Void = {},
        publicKeyExportAction: KeyDetailScreenModel.PublicKeyExportAction? = nil,
        revocationExportAction: KeyDetailScreenModel.RevocationExportAction? = nil,
        defaultKeyAction: KeyDetailScreenModel.DefaultKeyAction? = nil,
        deleteKeyAction: KeyDetailScreenModel.DeleteKeyAction? = nil,
        clipboardCopyAction: KeyDetailScreenModel.ClipboardCopyAction? = nil
    ) -> KeyDetailScreenModel {
        KeyDetailScreenModel(
            fingerprint: fingerprint,
            config: config,
            keyManagement: stack.keyManagement,
            macPresentationController: macPresentationController,
            configuration: configuration,
            dismissAction: dismissAction,
            publicKeyExportAction: publicKeyExportAction,
            revocationExportAction: revocationExportAction,
            defaultKeyAction: defaultKeyAction,
            deleteKeyAction: deleteKeyAction,
            clipboardCopyAction: clipboardCopyAction
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
