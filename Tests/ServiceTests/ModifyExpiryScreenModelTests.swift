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

    func test_saveSelectedExpiryDate_invokesModifyCompletesAndDismisses() async throws {
        var capturedFingerprint: String?
        var capturedValidity: PGPKeyValidity?
        var completeCount = 0
        var dismissCount = 0
        let model = makeModel(
            request: ModifyExpiryRequest(
                fingerprint: fingerprint,
                onComplete: {
                    completeCount += 1
                }
            ),
            dismissAction: {
                dismissCount += 1
            },
            modifyExpiryAction: { fingerprint, validity in
                capturedFingerprint = fingerprint
                capturedValidity = validity
                return makeKeyRouteTestIdentity(fingerprint: fingerprint)
            }
        )

        model.saveSelectedExpiryDate()

        await waitUntilKeyRoute("modify expiry to dismiss") {
            dismissCount == 1
        }

        XCTAssertEqual(capturedFingerprint, fingerprint)
        guard case .expiresIn(let seconds) = try XCTUnwrap(capturedValidity) else {
            return XCTFail("saving a date should state an expiry rather than remove one")
        }
        XCTAssertEqual(Double(seconds), model.newExpiryDate.timeIntervalSinceNow, accuracy: 60)
        XCTAssertEqual(completeCount, 1)
        XCTAssertFalse(model.isModifyingExpiry)
    }

    func test_removeExpiry_invokesModifyWithNoExpiry() async {
        var capturedValidity: PGPKeyValidity?
        var dismissCount = 0
        let model = makeModel(
            dismissAction: {
                dismissCount += 1
            },
            modifyExpiryAction: { fingerprint, validity in
                capturedValidity = validity
                return makeKeyRouteTestIdentity(fingerprint: fingerprint)
            }
        )

        model.removeExpiry()

        await waitUntilKeyRoute("remove expiry to dismiss") {
            dismissCount == 1
        }

        XCTAssertEqual(capturedValidity, .never)
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
                fingerprint: fingerprint
            ),
            keyManagement: TestHelpers.makeKeyManagement().service,
            dismissAction: dismissAction,
            modifyExpiryAction: modifyExpiryAction ?? { fingerprint, _ in
                makeKeyRouteTestIdentity(fingerprint: fingerprint)
            }
        )
    }
}
