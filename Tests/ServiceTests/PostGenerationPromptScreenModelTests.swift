import Foundation
import XCTest
@testable import CypherAir

private struct PostGenerationPromptScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

@MainActor
final class PostGenerationPromptScreenModelTests: XCTestCase {
    func test_isDeviceBound_reflectsIdentityCustody() {
        XCTAssertTrue(makeModel(identity: makeDeviceBoundIdentity()).isDeviceBound)
        XCTAssertFalse(
            makeModel(
                identity: makeKeyRouteTestIdentity(
                    fingerprint: "1111111111111111111111111111111111111111"
                )
            ).isDeviceBound
        )
    }

    func test_exportRevocationCertificate_preparesExportPayload() async {
        let identity = makeDeviceBoundIdentity()
        var exportedFingerprint: String?
        let model = makeModel(
            identity: identity,
            revocationExportAction: { fingerprint in
                exportedFingerprint = fingerprint
                return Data("armored-revocation".utf8)
            }
        )

        model.exportRevocationCertificate()

        await waitUntilKeyRoute("revocation export to finish") {
            model.isPreparingRevocationExport == false
        }

        XCTAssertEqual(exportedFingerprint, identity.fingerprint)
        XCTAssertNotNil(model.exportController.payload)
        XCTAssertEqual(
            model.exportController.defaultFilename,
            "revocation-\(identity.shortKeyId).asc"
        )
        XCTAssertFalse(model.showError)
        model.finishExport()
    }

    func test_exportRevocationCertificate_failureSurfacesError() async {
        let model = makeModel(
            identity: makeDeviceBoundIdentity(),
            revocationExportAction: { _ in
                throw PostGenerationPromptScreenModelTestError(message: "revocation failed")
            }
        )

        model.exportRevocationCertificate()

        await waitUntilKeyRoute("failed revocation export to finish") {
            model.isPreparingRevocationExport == false
        }

        XCTAssertTrue(model.showError)
        XCTAssertNotNil(model.error)
        XCTAssertNil(model.exportController.payload)
    }

    func test_exportRevocationCertificate_neverMarksKeyBackedUp() async {
        // The post-generation surface must not produce any "backup complete"
        // signal: revocation-artifact export is not a private-key backup.
        let keyManagement = TestHelpers.makeKeyManagement().service
        let model = PostGenerationPromptScreenModel(
            identity: makeDeviceBoundIdentity(),
            keyManagement: keyManagement,
            revocationExportAction: { _ in Data("armored-revocation".utf8) }
        )

        model.exportRevocationCertificate()

        await waitUntilKeyRoute("revocation export to finish") {
            model.isPreparingRevocationExport == false
        }

        XCTAssertFalse(keyManagement.keys.contains { $0.isBackedUp })
        model.finishExport()
    }

    func test_handleDisappear_suppressesLateExportPayload() async {
        let model = makeModel(
            identity: makeDeviceBoundIdentity(),
            revocationExportAction: { _ in
                try await Task.sleep(nanoseconds: 200_000_000)
                return Data("late-revocation".utf8)
            }
        )

        model.exportRevocationCertificate()
        model.handleDisappear()

        XCTAssertFalse(model.isPreparingRevocationExport)
        await drainKeyRouteMainActor()

        XCTAssertNil(model.exportController.payload)
        XCTAssertFalse(model.showError)
    }

    private func makeModel(
        identity: PGPKeyIdentity,
        revocationExportAction: PostGenerationPromptScreenModel.RevocationExportAction? = nil
    ) -> PostGenerationPromptScreenModel {
        PostGenerationPromptScreenModel(
            identity: identity,
            keyManagement: TestHelpers.makeKeyManagement().service,
            revocationExportAction: revocationExportAction
        )
    }

    private func makeDeviceBoundIdentity() -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: "2222222222222222222222222222222222222222",
            keyVersion: 4,
            userId: "Alice <alice@example.com>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: true,
            isBackedUp: false,
            publicKeyData: Data("public-device-bound".utf8),
            revocationCert: Data("revocation-device-bound".utf8),
            primaryAlgo: "P-256",
            subkeyAlgo: "P-256",
            expiryDate: nil,
            openPGPConfigurationIdentity: .compatibleP256V4,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
    }
}
