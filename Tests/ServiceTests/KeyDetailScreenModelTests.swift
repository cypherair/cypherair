import Foundation
import XCTest
@testable import CypherAir

private struct KeyDetailScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

private actor KeyDetailRevocationExportGate {
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

final class KeyDetailScreenModelTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!
    private var config: AppConfiguration!
    private var defaultsSuiteName: String!

    override func setUp() async throws {
        try await super.setUp()
        stack = await TestHelpers.makeServiceStack()
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
    func test_handleDisappear_suppressesLateRevocationExportPayloadAndError() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        let gate = KeyDetailRevocationExportGate()
        let model = makeModel(
            fingerprint: identity.fingerprint,
            revocationExportAction: { _ in
                await gate.suspend()
                return Data("late-revocation".utf8)
            }
        )

        model.exportRevocationCertificate()

        await waitUntil("revocation export to suspend") {
            let isSuspended = await gate.isSuspended()
            return model.isPreparingRevocationExport && isSuspended
        }

        model.handleDisappear()

        XCTAssertFalse(model.isPreparingRevocationExport)
        XCTAssertNil(model.exportController.payload)
        XCTAssertFalse(model.showError)

        await gate.resume()
        await drainMainActor()

        XCTAssertFalse(model.isPreparingRevocationExport)
        XCTAssertNil(model.exportController.payload)
        XCTAssertFalse(model.showError)
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

    // MARK: - Device-bound custody presentation (7B)

    @MainActor
    func test_softwareKey_isNotDeviceBoundAndNeverShowsDegradedRow() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        // Even a maximally degraded report must not surface for software keys.
        let degradedReport = SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: [],
            inventorySummary: .empty,
            inventoryFailureCategory: .privateHandleInaccessible
        )
        let model = KeyDetailScreenModel(
            fingerprint: identity.fingerprint,
            config: config,
            keyManagement: stack.keyManagement,
            macPresentationController: nil,
            configuration: KeyDetailView.Configuration(),
            dismissAction: {},
            recoveryReportProvider: { degradedReport }
        )

        XCTAssertFalse(model.isDeviceBound)
        XCTAssertFalse(model.deviceBoundAvailabilityIsDegraded)
    }

    @MainActor
    func test_deleteConfirmationMessage_branchesOnCustody() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Alice")
        let model = makeModel(fingerprint: identity.fingerprint)

        // The instance property delegates to the custody branch for a real
        // (software) key.
        XCTAssertFalse(model.isDeviceBound)
        XCTAssertEqual(
            model.deleteConfirmationMessage,
            KeyDetailScreenModel.deleteConfirmationMessage(isDeviceBound: false)
        )
        // Device-bound keys get distinct, custody-appropriate copy. (#512: the
        // shared message wrongly told device-bound users to back up a key that
        // cannot be exported or backed up.)
        XCTAssertNotEqual(
            KeyDetailScreenModel.deleteConfirmationMessage(isDeviceBound: true),
            KeyDetailScreenModel.deleteConfirmationMessage(isDeviceBound: false)
        )
    }

    func test_deviceBoundDegradedMapping_usesOrdinalAmongSecureEnclaveKeysOnly() {
        let softwareKey = makeCustodyMappingIdentity(
            fingerprint: "aaaa", custody: .softwareSecretCertificate
        )
        let firstSecureEnclaveKey = makeCustodyMappingIdentity(
            fingerprint: "bbbb", custody: .appleSecureEnclavePrivateOperations
        )
        let secondSecureEnclaveKey = makeCustodyMappingIdentity(
            fingerprint: "cccc", custody: .appleSecureEnclavePrivateOperations
        )
        let keys = [softwareKey, firstSecureEnclaveKey, secondSecureEnclaveKey]
        let report = SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: [
                makeAssessment(ordinal: 0, handleAvailability: .available),
                makeAssessment(ordinal: 1, handleAvailability: .unavailable(.privateHandleMissing)),
            ],
            inventorySummary: .empty,
            inventoryFailureCategory: nil
        )

        // Ordinals count Secure Enclave keys only: the software key at index 0
        // must not shift the mapping.
        XCTAssertFalse(KeyDetailScreenModel.isDeviceBoundAvailabilityDegraded(
            fingerprint: "bbbb", keys: keys, report: report
        ))
        XCTAssertTrue(KeyDetailScreenModel.isDeviceBoundAvailabilityDegraded(
            fingerprint: "cccc", keys: keys, report: report
        ))
    }

    func test_deviceBoundDegradedMapping_failsVisibleForMissingAssessmentAndInventoryFailure() {
        let secureEnclaveKey = makeCustodyMappingIdentity(
            fingerprint: "bbbb", custody: .appleSecureEnclavePrivateOperations
        )

        // No assessment row for an SE key: degraded, never silently healthy.
        XCTAssertTrue(KeyDetailScreenModel.isDeviceBoundAvailabilityDegraded(
            fingerprint: "bbbb",
            keys: [secureEnclaveKey],
            report: .empty
        ))

        // Inventory failure degrades every device-bound key.
        let inventoryFailureReport = SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: [makeAssessment(ordinal: 0, handleAvailability: .available)],
            inventorySummary: .empty,
            inventoryFailureCategory: .privateHandleInaccessible
        )
        XCTAssertTrue(KeyDetailScreenModel.isDeviceBoundAvailabilityDegraded(
            fingerprint: "bbbb",
            keys: [secureEnclaveKey],
            report: inventoryFailureReport
        ))
    }

    func test_deviceBoundDegradedMapping_flagsUnavailablePublicAndRevocationMaterial() {
        let secureEnclaveKey = makeCustodyMappingIdentity(
            fingerprint: "bbbb", custody: .appleSecureEnclavePrivateOperations
        )

        // Each material disjunct must degrade on its own.
        let publicMaterialReport = SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: [
                SecureEnclaveCustodyGenerationRecoveryAssessment(
                    identityOrdinal: 0,
                    configurationIdentity: .compatibleP256V4,
                    publicMaterialAvailability: .unavailable(.publicMaterialUnavailable),
                    revocationArtifactAvailability: .available,
                    handleAvailability: .available
                ),
            ],
            inventorySummary: .empty,
            inventoryFailureCategory: nil
        )
        XCTAssertTrue(KeyDetailScreenModel.isDeviceBoundAvailabilityDegraded(
            fingerprint: "bbbb",
            keys: [secureEnclaveKey],
            report: publicMaterialReport
        ))

        let revocationArtifactReport = SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: [
                SecureEnclaveCustodyGenerationRecoveryAssessment(
                    identityOrdinal: 0,
                    configurationIdentity: .compatibleP256V4,
                    publicMaterialAvailability: .available,
                    revocationArtifactAvailability: .unavailable(.revocationArtifactUnavailable),
                    handleAvailability: .available
                ),
            ],
            inventorySummary: .empty,
            inventoryFailureCategory: nil
        )
        XCTAssertTrue(KeyDetailScreenModel.isDeviceBoundAvailabilityDegraded(
            fingerprint: "bbbb",
            keys: [secureEnclaveKey],
            report: revocationArtifactReport
        ))
    }

    private func makeCustodyMappingIdentity(
        fingerprint: String,
        custody: PGPPrivateKeyCustodyKind
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: 4,
            profile: .universal,
            userId: nil,
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data("public-\(fingerprint)".utf8),
            revocationCert: Data("revocation-\(fingerprint)".utf8),
            primaryAlgo: "P-256",
            subkeyAlgo: "P-256",
            expiryDate: nil,
            openPGPConfigurationIdentity: custody == .appleSecureEnclavePrivateOperations
                ? .compatibleP256V4
                : .compatibleSoftwareV4,
            privateKeyCustodyKind: custody
        )
    }

    private func makeAssessment(
        ordinal: Int,
        handleAvailability: SecureEnclaveCustodyHandleAvailability
    ) -> SecureEnclaveCustodyGenerationRecoveryAssessment {
        SecureEnclaveCustodyGenerationRecoveryAssessment(
            identityOrdinal: ordinal,
            configurationIdentity: .compatibleP256V4,
            publicMaterialAvailability: .available,
            revocationArtifactAvailability: .available,
            handleAvailability: handleAvailability
        )
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

    @MainActor
    private func drainMainActor() async {
        for _ in 0..<5 {
            await Task.yield()
        }
    }
}
