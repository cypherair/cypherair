import Foundation
import XCTest
@testable import CypherAir

final class IncomingURLImportCoordinatorTests: TutorialSandboxDefaultsSerializedTestCase {
    private var stack: TestHelpers.ServiceStack!

    override func setUp() async throws {
        try await super.setUp()
        stack = await TestHelpers.makeServiceStack()
    }

    override func tearDown() {
        stack.cleanup()
        stack = nil
        super.tearDown()
    }

    @MainActor
    func test_handleIncomingURL_nonCypherAirURL_ignoresWithoutAlert() {
        let coordinator = makeCoordinator()
        let url = URL(string: "https://example.com/import/v1/AAAA")!

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: true)

        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertNil(coordinator.importError)
        XCTAssertFalse(coordinator.isTutorialImportBlocked)
    }

    @MainActor
    func test_handleIncomingURL_invalidCypherAirURL_setsImportError() {
        let coordinator = makeCoordinator()
        let url = URL(string: "cypherair://import/v1/not-a-valid-key")!

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertTrue(isInvalidQRCode(coordinator.importError))
        XCTAssertFalse(coordinator.isTutorialImportBlocked)
    }

    @MainActor
    func test_handleIncomingURL_validURL_presentsConfirmationAndConfirmedImportStoresContact() throws {
        let coordinator = makeCoordinator()
        let generated = try stack.engine.generateKey(
            name: "URL Contact",
            email: "url@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let url = try makeImportURL(publicKeyData: generated.publicKeyData)

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        let request = try XCTUnwrap(coordinator.importConfirmationCoordinator.request)
        XCTAssertNil(request.candidateMatch)
        request.onImportVerified()

        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertNil(coordinator.importError)
        XCTAssertEqual(stack.contactService.testContactKeyRecords.count, 1)
        XCTAssertNotNil(stack.contactService.availableContactKeyRecord(fingerprint: generated.fingerprint))
    }

    @MainActor
    func test_handleIncomingURL_sameUserIDImportAddsCandidateContactWithoutReplacementPrompt() throws {
        let coordinator = makeCoordinator()
        let firstKey = try stack.engine.generateKey(
            name: "Carol",
            email: "carol@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let secondKey = try stack.engine.generateKey(
            name: "Carol",
            email: "carol@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        _ = try stack.contactService.importContact(publicKeyData: firstKey.publicKeyData)
        let url = try makeImportURL(publicKeyData: secondKey.publicKeyData)

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)
        let request = try XCTUnwrap(coordinator.importConfirmationCoordinator.request)
        let candidate = try XCTUnwrap(request.candidateMatch)
        XCTAssertEqual(candidate.strength, .strong)
        request.onImportVerified()

        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertEqual(stack.contactService.testContactKeyRecords.count, 2)
        XCTAssertNotNil(stack.contactService.availableContactKeyRecord(fingerprint: firstKey.fingerprint))
        XCTAssertNotNil(stack.contactService.availableContactKeyRecord(fingerprint: secondKey.fingerprint))
    }

    @MainActor
    func test_handleIncomingURL_whileConfirmationPendingKeepsCurrentRequestAndReportsError() throws {
        let coordinator = makeCoordinator()
        let firstKey = try stack.engine.generateKey(
            name: "First Pending",
            email: "first-pending@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let secondKey = try stack.engine.generateKey(
            name: "Second Pending",
            email: "second-pending@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        coordinator.handleIncomingURL(
            try makeImportURL(publicKeyData: firstKey.publicKeyData),
            isTutorialPresentationActive: false
        )
        let firstRequest = try XCTUnwrap(coordinator.importConfirmationCoordinator.request)

        coordinator.handleIncomingURL(
            try makeImportURL(publicKeyData: secondKey.publicKeyData),
            isTutorialPresentationActive: false
        )

        XCTAssertEqual(coordinator.importConfirmationCoordinator.request?.id, firstRequest.id)
        if case .contactImportConfirmationAlreadyPending? = coordinator.importError {
            // Expected.
        } else {
            XCTFail("Expected already-pending import confirmation error, got \(String(describing: coordinator.importError))")
        }

        firstRequest.onImportVerified()

        XCTAssertNotNil(stack.contactService.availableContactKeyRecord(fingerprint: firstKey.fingerprint))
        XCTAssertNil(stack.contactService.availableContactKeyRecord(fingerprint: secondKey.fingerprint))
        XCTAssertEqual(stack.contactService.testContactKeyRecords.count, 1)
    }

    @MainActor
    func test_handleIncomingURL_whileConfirmationPendingRejectsBeforeParsingLaterURL() throws {
        let coordinator = makeCoordinator()
        let firstKey = try stack.engine.generateKey(
            name: "First Pending",
            email: "first-pending@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )

        coordinator.handleIncomingURL(
            try makeImportURL(publicKeyData: firstKey.publicKeyData),
            isTutorialPresentationActive: false
        )
        let firstRequest = try XCTUnwrap(coordinator.importConfirmationCoordinator.request)

        coordinator.handleIncomingURL(
            URL(string: "cypherair://import/v1/not-a-valid-key")!,
            isTutorialPresentationActive: false
        )

        XCTAssertEqual(coordinator.importConfirmationCoordinator.request?.id, firstRequest.id)
        if case .contactImportConfirmationAlreadyPending? = coordinator.importError {
            // Expected.
        } else {
            XCTFail("Expected already-pending import confirmation error, got \(String(describing: coordinator.importError))")
        }
    }

    @MainActor
    func test_importConfirmationCoordinatorRefusesReplacementWhileRequestIsPending() throws {
        let coordinator = ImportConfirmationCoordinator()
        let first = makeRequest(fingerprintSeed: "a")
        let second = makeRequest(fingerprintSeed: "b")

        XCTAssertTrue(coordinator.present(first))
        XCTAssertFalse(coordinator.present(second))
        XCTAssertEqual(coordinator.request?.id, first.id)

        coordinator.dismiss(first)

        XCTAssertNil(coordinator.request)
        XCTAssertTrue(coordinator.present(second))
        XCTAssertEqual(coordinator.request?.id, second.id)
    }

    @MainActor
    func test_handleIncomingURL_sameUserIDImportDoesNotRequireCancellation() throws {
        let coordinator = makeCoordinator()
        let firstKey = try stack.engine.generateKey(
            name: "Dana",
            email: "dana@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let secondKey = try stack.engine.generateKey(
            name: "Dana",
            email: "dana@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        _ = try stack.contactService.importContact(publicKeyData: firstKey.publicKeyData)
        let url = try makeImportURL(publicKeyData: secondKey.publicKeyData)

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)
        let request = try XCTUnwrap(coordinator.importConfirmationCoordinator.request)
        request.onImportVerified()

        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertEqual(stack.contactService.testContactKeyRecords.count, 2)
        XCTAssertNotNil(stack.contactService.availableContactKeyRecord(fingerprint: firstKey.fingerprint))
        XCTAssertNotNil(stack.contactService.availableContactKeyRecord(fingerprint: secondKey.fingerprint))
    }

    @MainActor
    func test_handleIncomingURL_whileTutorialPresentationIsActive_showsBlockedAlertAndDoesNotImport() throws {
        let coordinator = makeCoordinator()
        let generated = try stack.engine.generateKey(
            name: "Tutorial Blocked",
            email: "blocked@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let url = try makeImportURL(publicKeyData: generated.publicKeyData)

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: true)

        XCTAssertTrue(coordinator.isTutorialImportBlocked)
        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertNil(coordinator.importError)
        XCTAssertTrue(stack.contactService.testContactKeyRecords.isEmpty)
    }

    @MainActor
    func test_handleIncomingURL_afterTutorialDismissal_allowsImportEvenWhenSessionHadStarted() async throws {
        let tutorialStore = TutorialSessionStore()
        await tutorialStore.openModule(.sandbox)
        tutorialStore.setTutorialPresentationActive(false)

        XCTAssertTrue(tutorialStore.session.hasStartedSession)
        XCTAssertFalse(tutorialStore.isTutorialPresentationActive)

        let coordinator = makeCoordinator()
        let generated = try stack.engine.generateKey(
            name: "Dismissed Tutorial",
            email: "dismissed@example.com",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        let url = try makeImportURL(publicKeyData: generated.publicKeyData)

        coordinator.handleIncomingURL(
            url,
            isTutorialPresentationActive: tutorialStore.isTutorialPresentationActive
        )

        XCTAssertFalse(coordinator.isTutorialImportBlocked)
        XCTAssertNotNil(coordinator.importConfirmationCoordinator.request)
    }

    @MainActor
    private func makeCoordinator() -> IncomingURLImportCoordinator {
        IncomingURLImportCoordinator(
            importLoader: PublicKeyImportLoader(
                qrService: QRService(
                    contactImportAdapter: PGPContactImportAdapter(engine: stack.engine)
                )
            ),
            importWorkflow: ContactImportWorkflow(contactService: stack.contactService)
        )
    }

    private func makeImportURL(publicKeyData: Data) throws -> URL {
        let urlString = try stack.engine.encodeQrUrl(publicKeyData: publicKeyData)
        return try XCTUnwrap(URL(string: urlString))
    }

    @MainActor
    private func makeRequest(fingerprintSeed: Character) -> ImportConfirmationRequest {
        ImportConfirmationRequest(
            metadata: PGPKeyMetadata(
                fingerprint: String(repeating: String(fingerprintSeed), count: 40),
                keyVersion: 4,
                userId: "Pending <pending@example.invalid>",
                hasEncryptionSubkey: true,
                isRevoked: false,
                isExpired: false,
                suite: .ed25519LegacyCurve25519Legacy,
                primaryAlgo: "Ed25519",
                subkeyAlgo: "X25519",
                expiryTimestamp: nil
            ),
            allowsUnverifiedImport: true,
            onImportVerified: {},
            onImportUnverified: {},
            onCancel: {}
        )
    }

    private func isInvalidQRCode(_ error: CypherAirError?) -> Bool {
        guard case .invalidQRCode? = error else {
            return false
        }
        return true
    }
}
