import Foundation
import XCTest
@testable import CypherAir

/// Reset All Local Data must leave nothing behind that the next first run
/// could find: no sealed root, no rows, no domain files, no session state.
@MainActor
final class LocalDataResetServiceTests: XCTestCase {
    func test_reset_leavesNoResidue_andReturnsEveryServiceToFirstRun() async throws {
        let stack = try await TestHelpers.makeServiceStack()
        defer { stack.cleanup() }
        let key = try await TestHelpers.generateLegacyKey(service: stack.keyManagement)
        let contactKey = try await TestHelpers.generateLegacyKey(service: stack.keyManagement, name: "Contact")
        try stack.contactService.importContact(publicKeyData: try stack.keyManagement.exportPublicKey(fingerprint: contactKey.fingerprint))
        XCTAssertTrue(try stack.sandbox.vault.portableKeys.contains(fingerprint: key.fingerprint))

        let appSettings = AppSettingsCoordinator(persistence: VaultSettingsPersistence(vault: stack.sandbox.vault))
        appSettings.load()
        XCTAssertNotNil(appSettings.snapshot)
        let appSessionOrchestrator = AppSessionOrchestrator()
        let appLockController = AppLockController(
            vault: stack.sandbox.vault,
            gracePeriodProvider: { appSettings.gracePeriodForSession },
            lastAuthenticationDateProvider: { appSessionOrchestrator.lastAuthenticationDate },
            recordSuccessfulAuthentication: { appSessionOrchestrator.recordAuthentication() },
            loadServices: {},
            relockServices: {}
        )
        appLockController.noteSessionOpened()
        let service = LocalDataResetService(
            vault: stack.sandbox.vault,
            appSettings: appSettings,
            keyManagement: stack.keyManagement,
            contactService: stack.contactService,
            appSessionOrchestrator: appSessionOrchestrator,
            appLockController: appLockController,
            temporaryArtifactStore: stack.temporaryArtifactStore
        )

        try await service.resetAllLocalData()

        XCTAssertEqual(stack.sandbox.vault.residue(), [])
        XCTAssertFalse(stack.sandbox.vault.hasSealedRoot)
        XCTAssertFalse(stack.sandbox.vault.isUnlocked)
        XCTAssertTrue(stack.keyManagement.keys.isEmpty)
        XCTAssertEqual(stack.keyManagement.metadataLoadState, .locked)
        XCTAssertEqual(stack.contactService.contactsAvailability, .locked)
        XCTAssertNil(appSettings.snapshot)
        XCTAssertEqual(appLockController.lockState, .setupRequired)
    }
}
