import Foundation
import XCTest
@testable import CypherAir

/// Screen-model presentation behavior for device-bound Secure Enclave custody
/// keys (stage 7B): key-detail custody flags, degraded-availability mapping,
/// and the backup-surface fail-closed flag.
final class DeviceBoundKeyPresentationModelTests: KeyManagementServiceTestCase {
    private var defaultsSuiteName: String!
    private var config: AppConfiguration!

    override func setUp() {
        super.setUp()
        defaultsSuiteName = "com.cypherair.tests.devicebound-presentation.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        config = AppConfiguration(defaults: defaults)
    }

    override func tearDown() {
        if let defaultsSuiteName {
            UserDefaults(suiteName: defaultsSuiteName)?
                .removePersistentDomain(forName: defaultsSuiteName)
        }
        defaultsSuiteName = nil
        config = nil
        super.tearDown()
    }

    @MainActor
    func test_keyDetailModel_deviceBoundKey_flagsCustodyAndStaysQuietWhenHealthy() async throws {
        let target = makeHiddenSecureEnclaveGenerationService()
        let identity = try await target.service.generateHiddenSecureEnclaveCustodyKey(
            name: "Device Bound",
            email: nil,
            expirySeconds: nil,
            configurationIdentity: .compatibleP256V4
        )

        // The hidden-generation test rig wires no recovery classifier, so the
        // healthy report is injected; production always computes one on sync.
        let healthyReport = SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: [
                SecureEnclaveCustodyGenerationRecoveryAssessment(
                    identityOrdinal: 0,
                    configurationIdentity: .compatibleP256V4,
                    publicMaterialAvailability: .available,
                    revocationArtifactAvailability: .available,
                    handleAvailability: .available
                ),
            ],
            inventorySummary: .empty,
            inventoryFailureCategory: nil
        )
        let model = makeDetailModel(
            fingerprint: identity.fingerprint,
            keyManagement: target.service,
            recoveryReportProvider: { healthyReport }
        )

        XCTAssertTrue(model.isDeviceBound)
        XCTAssertFalse(
            model.deviceBoundAvailabilityIsDegraded,
            "A healthy device-bound key must not surface a degraded row."
        )
    }

    @MainActor
    func test_keyDetailModel_deviceBoundKey_missingReportFailsVisible() async throws {
        let target = makeHiddenSecureEnclaveGenerationService()
        let identity = try await target.service.generateHiddenSecureEnclaveCustodyKey(
            name: "Device Bound",
            email: nil,
            expirySeconds: nil,
            configurationIdentity: .compatibleP256V4
        )

        // A device-bound key with no recovery assessment must read as degraded,
        // never as silently healthy.
        let model = makeDetailModel(fingerprint: identity.fingerprint, keyManagement: target.service)

        XCTAssertTrue(model.isDeviceBound)
        XCTAssertTrue(model.deviceBoundAvailabilityIsDegraded)
    }

    @MainActor
    func test_keyDetailModel_deviceBoundKey_degradedReportSurfacesDegradedState() async throws {
        let target = makeHiddenSecureEnclaveGenerationService()
        let identity = try await target.service.generateHiddenSecureEnclaveCustodyKey(
            name: "Device Bound",
            email: nil,
            expirySeconds: nil,
            configurationIdentity: .compatibleP256V4
        )

        let degradedReport = SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: [
                SecureEnclaveCustodyGenerationRecoveryAssessment(
                    identityOrdinal: 0,
                    configurationIdentity: .compatibleP256V4,
                    publicMaterialAvailability: .available,
                    revocationArtifactAvailability: .available,
                    handleAvailability: .unavailable(.privateHandleMissing)
                ),
            ],
            inventorySummary: .empty,
            inventoryFailureCategory: nil
        )
        let model = makeDetailModel(
            fingerprint: identity.fingerprint,
            keyManagement: target.service,
            recoveryReportProvider: { degradedReport }
        )

        XCTAssertTrue(model.deviceBoundAvailabilityIsDegraded)
    }

    @MainActor
    func test_backupModel_deviceBoundKey_failsClosed() async throws {
        let target = makeHiddenSecureEnclaveGenerationService()
        let identity = try await target.service.generateHiddenSecureEnclaveCustodyKey(
            name: "Device Bound",
            email: nil,
            expirySeconds: nil,
            configurationIdentity: .compatibleP256V4
        )

        let model = BackupKeyScreenModel(
            fingerprint: identity.fingerprint,
            keyManagement: target.service,
            configuration: .default
        )

        XCTAssertTrue(
            model.isDeviceBound,
            "Backup surface must recognize device-bound custody and never present the passphrase form."
        )
    }

    @MainActor
    private func makeDetailModel(
        fingerprint: String,
        keyManagement: KeyManagementService,
        recoveryReportProvider: KeyDetailScreenModel.RecoveryReportProvider? = nil
    ) -> KeyDetailScreenModel {
        KeyDetailScreenModel(
            fingerprint: fingerprint,
            config: config,
            keyManagement: keyManagement,
            macPresentationController: nil,
            configuration: KeyDetailView.Configuration(),
            dismissAction: {},
            recoveryReportProvider: recoveryReportProvider
        )
    }
}
