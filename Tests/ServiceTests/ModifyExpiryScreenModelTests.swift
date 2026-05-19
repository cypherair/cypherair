import Foundation
import XCTest
@testable import CypherAir

private struct ModifyExpiryScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

private actor ModifyExpiryTestGate {
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

@MainActor
final class ModifyExpiryScreenModelTests: XCTestCase {
    private let fingerprint = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"

    func test_saveSelectedExpiryDate_invokesModifyCompletesAndDismisses() async {
        var capturedFingerprint: String?
        var capturedSeconds: UInt64?
        var completeCount = 0
        var dismissCount = 0
        let model = makeModel(
            request: ModifyExpiryRequest(
                fingerprint: fingerprint,
                initialDate: Date().addingTimeInterval(60 * 60 * 24 * 30),
                onComplete: {
                    completeCount += 1
                }
            ),
            dismissAction: {
                dismissCount += 1
            },
            modifyExpiryAction: { fingerprint, seconds in
                capturedFingerprint = fingerprint
                capturedSeconds = seconds
                return makeKeyRouteTestIdentity(fingerprint: fingerprint)
            }
        )

        model.saveSelectedExpiryDate()

        await waitUntilKeyRoute("modify expiry to dismiss") {
            dismissCount == 1
        }

        XCTAssertEqual(capturedFingerprint, fingerprint)
        XCTAssertNotNil(capturedSeconds)
        XCTAssertEqual(completeCount, 1)
        XCTAssertFalse(model.isModifyingExpiry)
    }

    func test_removeExpiry_invokesModifyWithNilExpiry() async {
        var capturedSeconds: UInt64?
        var dismissCount = 0
        let model = makeModel(
            dismissAction: {
                dismissCount += 1
            },
            modifyExpiryAction: { fingerprint, seconds in
                capturedSeconds = seconds
                return makeKeyRouteTestIdentity(fingerprint: fingerprint)
            }
        )

        model.removeExpiry()

        await waitUntilKeyRoute("remove expiry to dismiss") {
            dismissCount == 1
        }

        XCTAssertNil(capturedSeconds)
        XCTAssertFalse(model.isModifyingExpiry)
    }

    func test_modifyFailureSurfacesMappedError() async {
        let model = makeModel(modifyExpiryAction: { _, _ in
            throw ModifyExpiryScreenModelTestError(message: "modify failed")
        })

        model.removeExpiry()

        await waitUntilKeyRoute("modify failure to surface") {
            model.showError
        }

        XCTAssertTrue(model.showError)
        XCTAssertNotNil(model.error)
        XCTAssertFalse(model.isModifyingExpiry)
    }

    func test_handleDisappearSuppressesLateModifyCompletion() async {
        let gate = ModifyExpiryTestGate()
        var completeCount = 0
        var dismissCount = 0
        let model = makeModel(
            request: ModifyExpiryRequest(
                fingerprint: fingerprint,
                initialDate: Date().addingTimeInterval(60 * 60 * 24),
                onComplete: {
                    completeCount += 1
                }
            ),
            dismissAction: {
                dismissCount += 1
            },
            modifyExpiryAction: { fingerprint, _ in
                await gate.suspend()
                return makeKeyRouteTestIdentity(fingerprint: fingerprint)
            }
        )

        model.removeExpiry()

        await waitUntilKeyRoute("modify expiry to suspend") {
            await gate.isSuspended()
        }

        model.handleDisappear()
        await gate.resume()
        await drainKeyRouteMainActor()

        XCTAssertEqual(completeCount, 0)
        XCTAssertEqual(dismissCount, 0)
        XCTAssertFalse(model.showError)
        XCTAssertFalse(model.isModifyingExpiry)
    }

    private func makeModel(
        request: ModifyExpiryRequest? = nil,
        dismissAction: @escaping @MainActor () -> Void = {},
        modifyExpiryAction: ModifyExpiryScreenModel.ModifyExpiryAction? = nil
    ) -> ModifyExpiryScreenModel {
        ModifyExpiryScreenModel(
            request: request ?? ModifyExpiryRequest(
                fingerprint: fingerprint,
                initialDate: Date().addingTimeInterval(60 * 60 * 24)
            ),
            keyManagement: TestHelpers.makeKeyManagement().service,
            dismissAction: dismissAction,
            modifyExpiryAction: modifyExpiryAction ?? { fingerprint, _ in
                makeKeyRouteTestIdentity(fingerprint: fingerprint)
            }
        )
    }
}
