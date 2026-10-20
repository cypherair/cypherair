import Foundation
import Sealing
import Vault
import XCTest
@testable import CypherAir
import Stores

/// The lock lifecycle over a sandbox vault: what opens it, what closes it,
/// and what a wrong passphrase or damaged data leaves behind.
@MainActor
final class AppLockControllerTests: XCTestCase {

    private var directory: URL!
    private var vault: AppVault!
    private var gracePeriod: Int? = 0
    private var lastAuthentication: Date?

    override func setUp() async throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirLockTests-\(UUID().uuidString)", isDirectory: true)
        vault = try AppVault.sandbox(directory: directory)
    }

    override func tearDown() async throws {
        vault.relock()
        try? FileManager.default.removeItem(at: directory)
    }

    private func makeController() -> AppLockController {
        return AppLockController(
            vault: vault,
            gracePeriodProvider: { [self] in gracePeriod },
            lastAuthenticationDateProvider: { [self] in lastAuthentication },
            recordSuccessfulAuthentication: { [self] in lastAuthentication = Date() },
            loadServices: {},
            relockServices: {},
            contentClearHandler: {}
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

        controller.lockNow()
        await waitUntil { controller.lockState == .locked }
        XCTAssertFalse(vault.isUnlocked)

        await controller.unlock(passphrase: .utf8("wrong"))
        XCTAssertEqual(controller.lockState, .failed(.wrongPassphrase))
        XCTAssertFalse(vault.isUnlocked)

        await controller.unlock(passphrase: .utf8("correct horse battery staple"))
        XCTAssertEqual(controller.lockState, .unlocked)
        XCTAssertTrue(vault.isUnlocked)
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

}
