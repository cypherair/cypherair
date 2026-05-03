import Foundation
import XCTest
@testable import CypherAir

final class IncomingURLImportCoordinatorTests: XCTestCase {
    private var stack: TestHelpers.ServiceStack!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
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
        XCTAssertNil(coordinator.pendingKeyUpdateRequest)
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
            profile: .universal
        )
        let url = try makeImportURL(publicKeyData: generated.publicKeyData)

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        let request = try XCTUnwrap(coordinator.importConfirmationCoordinator.request)
        request.onImportVerified()

        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertNil(coordinator.importError)
        XCTAssertEqual(stack.contactService.availableContacts.count, 1)
        XCTAssertNotNil(stack.contactService.availableContact(forFingerprint: generated.fingerprint))
    }

    @MainActor
    func test_handleIncomingURL_replacementFlow_confirmStoresReplacementAndClearsPendingRequest() throws {
        let coordinator = makeCoordinator()
        let firstKey = try stack.engine.generateKey(
            name: "Carol",
            email: "carol@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let secondKey = try stack.engine.generateKey(
            name: "Carol",
            email: "carol@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try stack.contactService.addContact(publicKeyData: firstKey.publicKeyData)
        let url = try makeImportURL(publicKeyData: secondKey.publicKeyData)

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)
        let request = try XCTUnwrap(coordinator.importConfirmationCoordinator.request)
        request.onImportVerified()

        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertNotNil(coordinator.pendingKeyUpdateRequest)

        coordinator.confirmPendingKeyUpdate()

        XCTAssertNil(coordinator.pendingKeyUpdateRequest)
        XCTAssertEqual(stack.contactService.availableContacts.count, 1)
        XCTAssertNil(stack.contactService.availableContact(forFingerprint: firstKey.fingerprint))
        XCTAssertNotNil(stack.contactService.availableContact(forFingerprint: secondKey.fingerprint))
    }

    @MainActor
    func test_handleIncomingURL_replacementFlow_cancelClearsPendingRequestWithoutReplacing() throws {
        let coordinator = makeCoordinator()
        let firstKey = try stack.engine.generateKey(
            name: "Dana",
            email: "dana@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let secondKey = try stack.engine.generateKey(
            name: "Dana",
            email: "dana@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        _ = try stack.contactService.addContact(publicKeyData: firstKey.publicKeyData)
        let url = try makeImportURL(publicKeyData: secondKey.publicKeyData)

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)
        let request = try XCTUnwrap(coordinator.importConfirmationCoordinator.request)
        request.onImportVerified()

        XCTAssertNotNil(coordinator.pendingKeyUpdateRequest)

        coordinator.cancelPendingKeyUpdate()

        XCTAssertNil(coordinator.pendingKeyUpdateRequest)
        XCTAssertEqual(stack.contactService.availableContacts.count, 1)
        XCTAssertNotNil(stack.contactService.availableContact(forFingerprint: firstKey.fingerprint))
        XCTAssertNil(stack.contactService.availableContact(forFingerprint: secondKey.fingerprint))
    }

    @MainActor
    func test_handleIncomingURL_whileTutorialPresentationIsActive_showsBlockedAlertAndDoesNotImport() throws {
        let coordinator = makeCoordinator()
        let generated = try stack.engine.generateKey(
            name: "Tutorial Blocked",
            email: "blocked@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let url = try makeImportURL(publicKeyData: generated.publicKeyData)

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: true)

        XCTAssertTrue(coordinator.isTutorialImportBlocked)
        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertNil(coordinator.importError)
        XCTAssertTrue(stack.contactService.availableContacts.isEmpty)
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
            profile: .universal
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
            importLoader: PublicKeyImportLoader(qrService: QRService(engine: stack.engine)),
            importWorkflow: ContactImportWorkflow(contactService: stack.contactService)
        )
    }

    private func makeImportURL(publicKeyData: Data) throws -> URL {
        let urlString = try stack.engine.encodeQrUrl(publicKeyData: publicKeyData)
        return try XCTUnwrap(URL(string: urlString))
    }

    private func isInvalidQRCode(_ error: CypherAirError?) -> Bool {
        guard case .invalidQRCode? = error else {
            return false
        }
        return true
    }
}
