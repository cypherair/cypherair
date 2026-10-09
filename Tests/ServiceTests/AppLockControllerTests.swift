import Foundation
import Sealing
import Vault
import XCTest
@testable import CypherAir

/// The lock lifecycle over a sandbox vault: what opens it, what closes it,
/// and what a wrong passphrase or damaged data leaves behind.
@MainActor
final class AppLockControllerTests: XCTestCase {
    private final class Services {
        var loads = 0
        var relocks = 0
        var contentClears = 0
    }

    private var directory: URL!
    private var vault: AppVault!
    private var services: Services!
    private var gracePeriod: Int? = 0
    private var lastAuthentication: Date?

    override func setUp() async throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirLockTests-\(UUID().uuidString)", isDirectory: true)
        vault = try AppVault.sandbox(directory: directory)
        services = Services()
    }

    override func tearDown() async throws {
        vault.relock()
        try? FileManager.default.removeItem(at: directory)
    }

    private func makeController() -> AppLockController {
        let services = services!
        return AppLockController(
            vault: vault,
            gracePeriodProvider: { [self] in gracePeriod },
            lastAuthenticationDateProvider: { [self] in lastAuthentication },
            recordSuccessfulAuthentication: { [self] in lastAuthentication = Date() },
            loadServices: { services.loads += 1 },
            relockServices: { services.relocks += 1 },
            contentClearHandler: { services.contentClears += 1 }
        )
    }

    private func waitUntil(_ condition: @escaping @MainActor () -> Bool) async {
        for _ in 0..<200 where !condition() {
            try? await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertTrue(condition())
    }

    func test_firstRun_createsTheVault_thenLocksAndUnlocksThroughThePassphrase() async {
        let controller = makeController()
        XCTAssertEqual(controller.lockState, .setupRequired)

        await controller.createVault(passphrase: .utf8("correct horse battery staple"))
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertTrue(vault.isUnlocked)
        XCTAssertEqual(services.loads, 1)

        controller.lockNow()
        await waitUntil { controller.lockState == .locked }
        XCTAssertFalse(vault.isUnlocked)
        XCTAssertEqual(services.relocks, 1)
        XCTAssertEqual(services.contentClears, 1)

        await controller.unlock(passphrase: .utf8("wrong"))
        XCTAssertEqual(controller.lockState, .failed(.wrongPassphrase))
        XCTAssertFalse(vault.isUnlocked)

        await controller.unlock(passphrase: .utf8("correct horse battery staple"))
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertTrue(vault.isUnlocked)
        XCTAssertEqual(services.loads, 2)
    }

    func test_awayWithNoGracePeriod_locks_andAwayWithinGracePeriodDoesNot() async {
        let controller = makeController()
        await controller.createVault(passphrase: .utf8("correct horse battery staple"))

        gracePeriod = 300
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        controller.noteForegroundActive(true)
        await controller.handleForegroundActive()
        XCTAssertEqual(controller.lockState, .unlocked)

        gracePeriod = 0
        controller.noteForegroundActive(false)
        controller.handleAwayEvent()
        await waitUntil { controller.lockState == .locked }
        XCTAssertFalse(vault.isUnlocked)
    }

    func test_damagedDomain_opensIntoIntegrityFailure_withTheSessionStillAvailable() async throws {
        let controller = makeController()
        await controller.createVault(passphrase: .utf8("correct horse battery staple"))
        controller.lockNow()
        await waitUntil { controller.lockState == .locked }

        try Data("not a sealed snapshot".utf8).write(to: vault.directory.url.appending(path: "keys.sealed"))

        await controller.unlock(passphrase: .utf8("correct horse battery staple"))
        XCTAssertEqual(
            controller.lockState,
            .integrityFailure(VaultIntegrityReport(settings: .intact, contacts: .intact, keys: .damaged))
        )
        XCTAssertTrue(vault.isUnlocked, "intact portable keys can still be exported before the reset")
        XCTAssertNil(vault.keys)
        XCTAssertNotNil(vault.contacts)
    }

    func test_resetAfterLocalDataReset_returnsToSetup() async {
        let controller = makeController()
        await controller.createVault(passphrase: .utf8("correct horse battery staple"))
        try? vault.reset()
        controller.resetAfterLocalDataReset()
        XCTAssertEqual(controller.lockState, .setupRequired)
        XCTAssertFalse(controller.isUnlocking)
        XCTAssertTrue(controller.isLocked)
    }
}
