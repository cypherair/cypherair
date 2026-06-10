import Foundation
import XCTest
@testable import CypherAir

private struct KeyGenerationScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

private actor KeyGenerationTestGate {
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
final class KeyGenerationScreenModelTests: XCTestCase {
    func test_handleAppear_appliesPrefillAndLockedConfiguration() {
        let model = makeModel(
            configuration: KeyGenerationView.Configuration(
                prefilledName: "Alice",
                prefilledEmail: "alice@example.com",
                lockedProfile: .advanced,
                lockedExpiryMonths: 36,
                postGenerationBehavior: .suppressPrompt
            )
        )

        model.handleAppear()

        XCTAssertEqual(model.name, "Alice")
        XCTAssertEqual(model.email, "alice@example.com")
        XCTAssertEqual(model.profile, .advanced)
        XCTAssertEqual(model.expiryMonths, 36)
    }

    func test_generate_successCallsCallbacksAndPresentsLocalPrompt() async {
        let identity = makeKeyRouteTestIdentity(fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        var generatedIdentity: PGPKeyIdentity?
        var capturedName: String?
        var capturedEmail: String?
        var capturedProfile: PGPKeyProfile?
        var capturedExpirySeconds: UInt64?
        var configuration = KeyGenerationView.Configuration()
        configuration.onGenerated = { identity in
            generatedIdentity = identity
        }

        let model = makeModel(
            configuration: configuration,
            generateKeyAction: { name, email, expirySeconds, profile in
                capturedName = name
                capturedEmail = email
                capturedExpirySeconds = expirySeconds
                capturedProfile = profile
                return identity
            }
        )
        model.name = "  Alice  "
        model.email = " alice@example.com "
        model.profile = .advanced

        model.generate()

        await waitUntilKeyRoute("key generation to finish") {
            model.generatedIdentity == identity
        }

        XCTAssertEqual(generatedIdentity, identity)
        XCTAssertEqual(capturedName, "Alice")
        XCTAssertEqual(capturedEmail, "alice@example.com")
        XCTAssertEqual(capturedProfile, .advanced)
        XCTAssertNotNil(capturedExpirySeconds)
        XCTAssertFalse(model.isGenerating)
        XCTAssertFalse(model.showError)
    }

    func test_generate_routesMacPromptThroughInjectedAction() async {
        let identity = makeKeyRouteTestIdentity(fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        var promptedIdentity: PGPKeyIdentity?
        let model = makeModel(
            postGenerationPromptAction: { identity in
                promptedIdentity = identity
            },
            generateKeyAction: { _, _, _, _ in identity }
        )
        model.name = "Alice"

        model.generate()

        await waitUntilKeyRoute("prompt action to run") {
            promptedIdentity == identity
        }

        XCTAssertNil(model.generatedIdentity)
        XCTAssertEqual(promptedIdentity, identity)
    }

    func test_generate_contentClearSuppressesLateResult() async {
        let gate = KeyGenerationTestGate()
        let identity = makeKeyRouteTestIdentity(fingerprint: "cccccccccccccccccccccccccccccccccccccccc")
        var callbackCount = 0
        var configuration = KeyGenerationView.Configuration()
        configuration.onGenerated = { _ in
            callbackCount += 1
        }
        let model = makeModel(
            configuration: configuration,
            generateKeyAction: { _, _, _, _ in
                await gate.suspend()
                return identity
            }
        )
        model.name = "Alice"

        model.generate()

        await waitUntilKeyRoute("generation to suspend") {
            await gate.isSuspended()
        }

        model.handleContentClearGenerationChange()
        await gate.resume()
        await drainKeyRouteMainActor()

        XCTAssertNil(model.generatedIdentity)
        XCTAssertEqual(callbackCount, 0)
        XCTAssertFalse(model.showError)
        XCTAssertFalse(model.isGenerating)
        XCTAssertEqual(model.name, "")
    }

    func test_generate_failureSurfacesMappedError() async {
        let model = makeModel(generateKeyAction: { _, _, _, _ in
            throw KeyGenerationScreenModelTestError(message: "generation failed")
        })
        model.name = "Alice"

        model.generate()

        await waitUntilKeyRoute("generation failure to surface") {
            model.showError
        }

        XCTAssertTrue(model.showError)
        XCTAssertNotNil(model.error)
        XCTAssertFalse(model.isGenerating)
    }

    private func makeModel(
        configuration: KeyGenerationView.Configuration = .default,
        postGenerationPromptAction: KeyGenerationScreenModel.PostGenerationPromptAction? = nil,
        generateKeyAction: KeyGenerationScreenModel.GenerateKeyAction? = nil
    ) -> KeyGenerationScreenModel {
        KeyGenerationScreenModel(
            keyManagement: TestHelpers.makeKeyManagement().service,
            configuration: configuration,
            postGenerationPromptAction: postGenerationPromptAction,
            generateKeyAction: generateKeyAction ?? { _, _, _, _ in
                makeKeyRouteTestIdentity(fingerprint: "dddddddddddddddddddddddddddddddddddddddd")
            }
        )
    }
}

func makeKeyRouteTestIdentity(fingerprint: String) -> PGPKeyIdentity {
    PGPKeyIdentity(
        fingerprint: fingerprint,
        keyVersion: 6,
        profile: .advanced,
        userId: "Alice <alice@example.com>",
        hasEncryptionSubkey: true,
        isRevoked: false,
        isExpired: false,
        isDefault: true,
        isBackedUp: false,
        publicKeyData: Data("public-\(fingerprint)".utf8),
        revocationCert: Data("revocation-\(fingerprint)".utf8),
        primaryAlgo: "Ed448",
        subkeyAlgo: "X448",
        expiryDate: nil,
        openPGPConfigurationIdentity: .modernSoftwareV6,
        privateKeyCustodyKind: .softwareSecretCertificate
    )
}

@MainActor
func waitUntilKeyRoute(
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
func drainKeyRouteMainActor() async {
    for _ in 0..<5 {
        await Task.yield()
    }
}
