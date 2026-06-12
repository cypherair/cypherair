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
                lockedFamily: .modernSoftwareV6,
                lockedExpiryMonths: 36,
                postGenerationBehavior: .suppressPrompt
            )
        )

        model.handleAppear()

        XCTAssertEqual(model.name, "Alice")
        XCTAssertEqual(model.email, "alice@example.com")
        XCTAssertEqual(model.selectedFamily, .modernSoftwareV6)
        XCTAssertEqual(model.expiryMonths, 36)
    }

    func test_selectFamily_isIgnoredWhenFamilyIsLocked() {
        let model = makeModel(
            configuration: KeyGenerationView.Configuration(
                lockedFamily: .modernSoftwareV6
            )
        )
        model.handleAppear()

        model.selectFamily(.compatibleSoftwareV4)

        XCTAssertEqual(model.selectedFamily, .modernSoftwareV6)
    }

    func test_presentFamilyDetail_doesNotSelectFamilyAndCanDismiss() {
        let model = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        XCTAssertEqual(model.selectedFamily, .compatibleSoftwareV4)

        model.presentFamilyDetail(.modernP256V6)

        XCTAssertEqual(model.selectedFamily, .compatibleSoftwareV4)
        XCTAssertEqual(model.presentedFamilyDetail, .modernP256V6)

        model.dismissFamilyDetail()

        XCTAssertNil(model.presentedFamilyDetail)
    }

    func test_presentFamilyDetail_stillWorksWhenFamilySelectionIsLocked() {
        let model = makeModel(
            configuration: KeyGenerationView.Configuration(
                lockedFamily: .modernSoftwareV6
            ),
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        model.handleAppear()

        model.presentFamilyDetail(.compatibleP256V4)

        XCTAssertEqual(model.selectedFamily, .modernSoftwareV6)
        XCTAssertEqual(model.presentedFamilyDetail, .compatibleP256V4)
    }

    func test_availableFamilies_productionPolicyExposesDeviceBoundFamiliesWhenServiceWired() {
        // No wired generation service (this test container): device-bound
        // families stay hidden even under the exposed production policy.
        let defaultModel = makeModel()
        XCTAssertEqual(
            defaultModel.availableFamilies,
            [.compatibleSoftwareV4, .modernSoftwareV6]
        )

        // Production policy + wired service (the shipping configuration since
        // P7D): all four families are offered, in stable order.
        let availableServiceModel = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(),
            isSecureEnclaveGenerationAvailable: true
        )
        XCTAssertEqual(
            availableServiceModel.availableFamilies,
            [.compatibleSoftwareV4, .modernSoftwareV6, .compatibleP256V4, .modernP256V6]
        )
    }

    func test_availableFamilies_requireBothResolverPolicyAndWiredService() {
        let exposedModel = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        XCTAssertEqual(
            exposedModel.availableFamilies,
            [.compatibleSoftwareV4, .modernSoftwareV6, .compatibleP256V4, .modernP256V6]
        )

        // Resolver policy alone is not enough without a wired generation service.
        let unwiredModel = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: false
        )
        XCTAssertEqual(
            unwiredModel.availableFamilies,
            [.compatibleSoftwareV4, .modernSoftwareV6]
        )
    }

    func test_generate_deviceBoundFamilyRequiresCommitmentConfirmation() async {
        let identity = makeKeyRouteTestIdentity(fingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
        var capturedFamily: PGPKeyConfiguration.Identity?
        var actionCallCount = 0
        let model = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true,
            generateKeyAction: { _, _, _, family in
                actionCallCount += 1
                capturedFamily = family
                return identity
            }
        )
        model.name = "Alice"
        model.selectFamily(.compatibleP256V4)

        model.generate()

        XCTAssertTrue(model.deviceBoundCommitmentPending)
        XCTAssertFalse(model.isGenerating)
        XCTAssertEqual(actionCallCount, 0)

        model.cancelDeviceBoundCommitment()
        XCTAssertFalse(model.deviceBoundCommitmentPending)
        XCTAssertEqual(actionCallCount, 0)

        model.generate()
        XCTAssertTrue(model.deviceBoundCommitmentPending)
        model.confirmDeviceBoundGeneration()
        XCTAssertFalse(model.deviceBoundCommitmentPending)

        await waitUntilKeyRoute("device-bound generation to finish") {
            model.generatedIdentity == identity
        }

        XCTAssertEqual(actionCallCount, 1)
        XCTAssertEqual(capturedFamily, .compatibleP256V4)
    }

    func test_confirmDeviceBoundGeneration_withoutPendingCommitmentDoesNothing() async {
        var actionCallCount = 0
        let model = makeModel(generateKeyAction: { _, _, _, _ in
            actionCallCount += 1
            return makeKeyRouteTestIdentity(fingerprint: "ffffffffffffffffffffffffffffffffffffffff")
        })
        model.name = "Alice"

        model.confirmDeviceBoundGeneration()
        await drainKeyRouteMainActor()

        XCTAssertEqual(actionCallCount, 0)
        XCTAssertFalse(model.isGenerating)
    }

    func test_generate_softwareFamilyStartsImmediatelyAndPresentsLocalPrompt() async {
        let identity = makeKeyRouteTestIdentity(fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        var generatedIdentity: PGPKeyIdentity?
        var capturedName: String?
        var capturedEmail: String?
        var capturedFamily: PGPKeyConfiguration.Identity?
        var capturedExpirySeconds: UInt64?
        var configuration = KeyGenerationView.Configuration()
        configuration.onGenerated = { identity in
            generatedIdentity = identity
        }

        let model = makeModel(
            configuration: configuration,
            generateKeyAction: { name, email, expirySeconds, family in
                capturedName = name
                capturedEmail = email
                capturedExpirySeconds = expirySeconds
                capturedFamily = family
                return identity
            }
        )
        model.name = "  Alice  "
        model.email = " alice@example.com "
        model.selectFamily(.modernSoftwareV6)

        model.generate()

        XCTAssertFalse(model.deviceBoundCommitmentPending)

        await waitUntilKeyRoute("key generation to finish") {
            model.generatedIdentity == identity
        }

        XCTAssertEqual(generatedIdentity, identity)
        XCTAssertEqual(capturedName, "Alice")
        XCTAssertEqual(capturedEmail, "alice@example.com")
        XCTAssertEqual(capturedFamily, .modernSoftwareV6)
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

    func test_handleContentClear_dismissesPendingCommitment() {
        let model = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        model.name = "Alice"
        model.selectFamily(.modernP256V6)
        model.generate()
        XCTAssertTrue(model.deviceBoundCommitmentPending)

        model.presentFamilyDetail(.modernP256V6)
        XCTAssertEqual(model.presentedFamilyDetail, .modernP256V6)

        model.handleContentClearGenerationChange()

        XCTAssertFalse(model.deviceBoundCommitmentPending)
        XCTAssertNil(model.presentedFamilyDetail)
        XCTAssertFalse(model.isGenerating)
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
        capabilityResolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        isSecureEnclaveGenerationAvailable: Bool? = nil,
        generateKeyAction: KeyGenerationScreenModel.GenerateKeyAction? = nil
    ) -> KeyGenerationScreenModel {
        KeyGenerationScreenModel(
            keyManagement: TestHelpers.makeKeyManagement().service,
            configuration: configuration,
            postGenerationPromptAction: postGenerationPromptAction,
            generateKeyAction: generateKeyAction ?? { _, _, _, _ in
                makeKeyRouteTestIdentity(fingerprint: "dddddddddddddddddddddddddddddddddddddddd")
            },
            capabilityResolver: capabilityResolver,
            isSecureEnclaveGenerationAvailable: isSecureEnclaveGenerationAvailable
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
