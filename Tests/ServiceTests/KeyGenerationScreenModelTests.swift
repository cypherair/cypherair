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
                lockedFamily: .portableEd25519X25519,
                lockedExpiryMonths: 36,
                postGenerationBehavior: .suppressPrompt
            )
        )

        model.handleAppear()

        XCTAssertEqual(model.name, "Alice")
        XCTAssertEqual(model.email, "alice@example.com")
        XCTAssertEqual(model.selectedFamily, .portableEd25519X25519)
        XCTAssertEqual(model.expiryMonths, 36)
    }

    func test_selectFamily_isIgnoredWhenFamilyIsLocked() {
        let model = makeModel(
            configuration: KeyGenerationView.Configuration(
                lockedFamily: .portableEd25519X25519
            )
        )
        model.handleAppear()

        model.selectFamily(.portableEd25519LegacyCurve25519Legacy)

        XCTAssertEqual(model.selectedFamily, .portableEd25519X25519)
    }

    func test_presentFamilyDetail_doesNotSelectFamilyAndCanDismiss() {
        let model = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        XCTAssertEqual(model.selectedFamily, .portableMlDsa65Ed25519MlKem768X25519)

        model.presentFamilyDetail(.deviceBoundEcdsaNistP256EcdhNistP256)

        XCTAssertEqual(model.selectedFamily, .portableMlDsa65Ed25519MlKem768X25519)
        XCTAssertEqual(model.presentedFamilyDetail, .deviceBoundEcdsaNistP256EcdhNistP256)

        model.dismissFamilyDetail()

        XCTAssertNil(model.presentedFamilyDetail)
    }

    func test_presentFamilyDetail_stillWorksWhenFamilySelectionIsLocked() {
        let model = makeModel(
            configuration: KeyGenerationView.Configuration(
                lockedFamily: .portableEd25519X25519
            ),
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        model.handleAppear()

        model.presentFamilyDetail(.deviceBoundEcdsaNistP256EcdhNistP256V4)

        XCTAssertEqual(model.selectedFamily, .portableEd25519X25519)
        XCTAssertEqual(model.presentedFamilyDetail, .deviceBoundEcdsaNistP256EcdhNistP256V4)
    }

    func test_availableFamilies_productionPolicyExposesDeviceBoundFamiliesWhenServiceWired() {
        // No wired generation service (this test container): device-bound
        // families stay hidden even under the exposed production policy;
        // all five software families are always offered.
        let defaultModel = makeModel()
        XCTAssertEqual(
            defaultModel.availableFamilies,
            [.portableEd25519LegacyCurve25519Legacy, .portableEd25519X25519, .portableEd448X448, .portableMlDsa65Ed25519MlKem768X25519, .portableMlDsa87Ed448MlKem1024X448]
        )

        // Production policy + wired service: all nine families are offered, in
        // stable order.
        let availableServiceModel = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(),
            isSecureEnclaveGenerationAvailable: true
        )
        XCTAssertEqual(
            availableServiceModel.availableFamilies,
            [
                .portableEd25519LegacyCurve25519Legacy,
                .portableEd25519X25519,
                .portableEd448X448,
                .portableMlDsa65Ed25519MlKem768X25519,
                .portableMlDsa87Ed448MlKem1024X448,
                .deviceBoundEcdsaNistP256EcdhNistP256V4,
                .deviceBoundEcdsaNistP256EcdhNistP256,
                .deviceBoundMlDsa65Ed25519MlKem768X25519,
                .deviceBoundMlDsa87Ed448MlKem1024X448
            ]
        )
    }

    func test_availableFamilies_requireBothResolverPolicyAndWiredService() {
        let exposedModel = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        XCTAssertEqual(
            exposedModel.availableFamilies,
            [
                .portableEd25519LegacyCurve25519Legacy,
                .portableEd25519X25519,
                .portableEd448X448,
                .portableMlDsa65Ed25519MlKem768X25519,
                .portableMlDsa87Ed448MlKem1024X448,
                .deviceBoundEcdsaNistP256EcdhNistP256V4,
                .deviceBoundEcdsaNistP256EcdhNistP256,
                .deviceBoundMlDsa65Ed25519MlKem768X25519,
                .deviceBoundMlDsa87Ed448MlKem1024X448
            ]
        )

        // Resolver policy alone is not enough without a wired generation service.
        let unwiredModel = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: false
        )
        XCTAssertEqual(
            unwiredModel.availableFamilies,
            [.portableEd25519LegacyCurve25519Legacy, .portableEd25519X25519, .portableEd448X448, .portableMlDsa65Ed25519MlKem768X25519, .portableMlDsa87Ed448MlKem1024X448]
        )
    }

    func test_availableFamilies_lockedConfigurationShowsFullCatalogWithoutWiredService() {
        // Locked mode (tutorial sandbox) is display-only: the full eight-family
        // catalog is listed even though this container has no wired Secure
        // Enclave generation service, because every row renders disabled and
        // generation never leaves the locked family.
        let lockedModel = makeModel(
            configuration: KeyGenerationView.Configuration(lockedFamily: .portableEd25519X25519),
            isSecureEnclaveGenerationAvailable: false
        )
        XCTAssertEqual(
            lockedModel.availableFamilies,
            PGPKeyFamily.orderedFamilies
        )
    }

    func test_generate_deviceBoundFamilyRequiresCommitmentConfirmation() async {
        let identity = makeKeyRouteTestIdentity(fingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
        var capturedFamily: PGPKeyFamily?
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
        model.selectFamily(.deviceBoundEcdsaNistP256EcdhNistP256V4)

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
        XCTAssertEqual(capturedFamily, .deviceBoundEcdsaNistP256EcdhNistP256V4)
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
        var capturedFamily: PGPKeyFamily?
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
        model.selectFamily(.portableEd25519X25519)

        model.generate()

        XCTAssertFalse(model.deviceBoundCommitmentPending)

        await waitUntilKeyRoute("key generation to finish") {
            model.generatedIdentity == identity
        }

        XCTAssertEqual(generatedIdentity, identity)
        XCTAssertEqual(capturedName, "Alice")
        XCTAssertEqual(capturedEmail, "alice@example.com")
        XCTAssertEqual(capturedFamily, .portableEd25519X25519)
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
        model.selectFamily(.deviceBoundEcdsaNistP256EcdhNistP256)
        model.generate()
        XCTAssertTrue(model.deviceBoundCommitmentPending)

        model.presentFamilyDetail(.deviceBoundEcdsaNistP256EcdhNistP256)
        XCTAssertEqual(model.presentedFamilyDetail, .deviceBoundEcdsaNistP256EcdhNistP256)

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

    func test_defaultSelection_isRecommendedPortablePostQuantum() {
        let model = makeModel()

        XCTAssertEqual(model.selectedFamily, .portableMlDsa65Ed25519MlKem768X25519)
        XCTAssertEqual(model.selectedFamily, PGPKeyFamily.recommendedDefault)
        XCTAssertTrue(model.selectedFamily.isRecommended)
        XCTAssertEqual(model.selectedCustody, .portable)
        XCTAssertNil(model.detailFamily)
    }

    func test_continueToDetails_pushesSelectedFamily() {
        let model = makeModel()
        model.selectFamily(.portableEd25519X25519)

        model.continueToDetails()
        XCTAssertEqual(model.detailFamily, .portableEd25519X25519)
    }

    func test_continueToDetails_clearsStaleGenerationFlags() {
        let model = makeModel()
        model.selectFamily(.portableEd25519X25519)
        model.deviceBoundCommitmentPending = true
        model.generatedIdentity = makeKeyRouteTestIdentity(
            fingerprint: "1111111111111111111111111111111111111111"
        )

        model.continueToDetails()

        XCTAssertEqual(model.detailFamily, .portableEd25519X25519)
        XCTAssertFalse(model.deviceBoundCommitmentPending)
        XCTAssertNil(model.generatedIdentity)
    }

    func test_selectCustody_landsOnRecommendedOrFirstFamilyInCustody() {
        let model = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        XCTAssertEqual(model.selectedCustody, .portable)

        // Device-bound has no recommended family, so it lands on the first offered.
        model.selectCustody(.deviceBound)
        XCTAssertEqual(model.selectedFamily, .deviceBoundEcdsaNistP256EcdhNistP256V4)
        XCTAssertEqual(model.selectedCustody, .deviceBound)

        // Portable has a recommended family (Portable Post-Quantum).
        model.selectCustody(.portable)
        XCTAssertEqual(model.selectedFamily, .portableMlDsa65Ed25519MlKem768X25519)
    }

    func test_selectCustody_isNoOpForSameCustodyOrWhenLocked() {
        let model = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        model.selectFamily(.portableEd25519LegacyCurve25519Legacy)
        model.selectCustody(.portable) // already portable
        XCTAssertEqual(model.selectedFamily, .portableEd25519LegacyCurve25519Legacy)

        let lockedModel = makeModel(
            configuration: KeyGenerationView.Configuration(lockedFamily: .portableEd25519X25519),
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        lockedModel.handleAppear()
        lockedModel.selectCustody(.deviceBound)
        XCTAssertEqual(lockedModel.selectedFamily, .portableEd25519X25519)
    }

    func test_availableCustodies_reflectOfferedFamilies() {
        let softwareModel = makeModel()
        XCTAssertEqual(softwareModel.availableCustodies, [.portable])

        let fullModel = makeModel(
            capabilityResolver: PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration),
            isSecureEnclaveGenerationAvailable: true
        )
        XCTAssertEqual(fullModel.availableCustodies, [.portable, .deviceBound])
        XCTAssertEqual(
            fullModel.families(for: .deviceBound),
            [.deviceBoundEcdsaNistP256EcdhNistP256V4, .deviceBoundEcdsaNistP256EcdhNistP256, .deviceBoundMlDsa65Ed25519MlKem768X25519, .deviceBoundMlDsa87Ed448MlKem1024X448]
        )
    }

    func test_handleContentClear_dismissesDetailStep() {
        let model = makeModel()
        model.continueToDetails()
        XCTAssertNotNil(model.detailFamily)

        model.handleContentClearGenerationChange()
        XCTAssertNil(model.detailFamily)
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
        keyFamily: .portableEd448X448,
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
