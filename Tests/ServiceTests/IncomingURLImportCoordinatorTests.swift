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
    func test_handleIncomingURL_nonCypherAirURL_ignoresWithoutAlert() throws {
        let coordinator = try makeCoordinator()
        let url = URL(string: "https://example.com/import/v1/AAAA")!

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: true)

        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertNil(coordinator.importError)
        XCTAssertFalse(coordinator.isTutorialImportBlocked)
    }

    @MainActor
    func test_handleIncomingURL_invalidCypherAirURL_setsImportError() throws {
        let coordinator = try makeCoordinator()
        let url = URL(string: "cypherairx://import/v1/not-a-valid-key")!

        coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        XCTAssertNil(coordinator.importConfirmationCoordinator.request)
        XCTAssertTrue(isInvalidQRCode(coordinator.importError))
        XCTAssertFalse(coordinator.isTutorialImportBlocked)
    }

    @MainActor
    func test_handleIncomingURL_validURL_presentsConfirmationAndConfirmedImportStoresContact() throws {
        let coordinator = try makeCoordinator()
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
        let coordinator = try makeCoordinator()
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
        let coordinator = try makeCoordinator()
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
        let coordinator = try makeCoordinator()
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
            URL(string: "cypherairx://import/v1/not-a-valid-key")!,
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
        let coordinator = try makeCoordinator()
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
        let coordinator = try makeCoordinator()
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

        let coordinator = try makeCoordinator()
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

    // MARK: - Opened documents

    /// The certificate route is the one an opened file shares with a scanned QR
    /// code: same confirmation, same explicit approval before anything is
    /// stored.
    @MainActor
    func test_openedPublicCertificate_presentsContactImportConfirmationAndErasesInboxCopy() throws {
        let fixture = try makeOpenedFileFixture()
        let generated = try generateKey(named: "Opened Certificate")
        let url = try fixture.writeToInbox(
            "friend.asc",
            try stack.engine.armor(data: generated.publicKeyData, kind: .publicKey)
        )

        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        let request = try XCTUnwrap(fixture.coordinator.importConfirmationCoordinator.request)
        XCTAssertEqual(request.metadata.fingerprint, generated.fingerprint)
        XCTAssertNil(fixture.coordinator.importError)
        XCTAssertEqual(fixture.inboxContents, [])

        request.onImportVerified()
        XCTAssertNotNil(stack.contactService.availableContactKeyRecord(fingerprint: generated.fingerprint))
    }

    @MainActor
    func test_openedSecretKey_routesToImportKeyCarryingTheFile() throws {
        let fixture = try makeOpenedFileFixture()
        let generated = try generateKey(named: "Opened Secret Key")
        let armoredSecretKey = try stack.engine.armor(data: generated.certData, kind: .secretKey)
        let url = try fixture.writeToInbox("mine.asc", armoredSecretKey)

        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        XCTAssertNil(fixture.coordinator.importError)
        XCTAssertEqual(fixture.navigationState.selectedTab, .keys)
        XCTAssertEqual(fixture.navigationState.path(for: .keys), [.importKey])

        let document = try XCTUnwrap(fixture.handoff.take(for: .keyImport))
        XCTAssertEqual(document.fileName, "mine.asc")
        XCTAssertEqual(document.content, armoredSecretKey)
        XCTAssertEqual(fixture.inboxContents, [])
    }

    /// The one route that keeps the file rather than its bytes, because an
    /// encrypted message has no size worth holding. The inbox copy still must
    /// not survive there, so it moves under the artifact store instead.
    @MainActor
    func test_openedCiphertext_routesToDecryptAndMovesTheInboxCopyUnderTheArtifactStore() throws {
        let fixture = try makeOpenedFileFixture()
        let url = try fixture.writeToInbox("secret.gpg", try makeBinaryCiphertext())

        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        XCTAssertNil(fixture.coordinator.importError)
        XCTAssertEqual(fixture.navigationState.selectedTab, .home)
        XCTAssertEqual(fixture.navigationState.path(for: .home), [.decrypt])

        let document = try XCTUnwrap(fixture.handoff.take(for: .decryption))
        let retainedURL = try XCTUnwrap(document.fileURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: retainedURL.path))
        XCTAssertTrue(retainedURL.path.hasPrefix(fixture.artifactRoot.path))
        XCTAssertEqual(fixture.inboxContents, [])
    }

    @MainActor
    func test_openedSignedMessage_routesToVerifyCarryingTheMessage() throws {
        let fixture = try makeOpenedFileFixture()
        let generated = try generateKey(named: "Opened Signer")
        let signedMessage = try stack.engine.signCleartext(
            text: Data("a message worth checking".utf8),
            signerCert: generated.certData
        )
        let url = try fixture.writeToInbox("signed.asc", signedMessage)

        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        XCTAssertNil(fixture.coordinator.importError)
        XCTAssertEqual(fixture.navigationState.selectedTab, .home)
        XCTAssertEqual(fixture.navigationState.path(for: .home), [.verify])

        let document = try XCTUnwrap(fixture.handoff.take(for: .verification))
        XCTAssertEqual(document.content, signedMessage)
        XCTAssertEqual(fixture.inboxContents, [])
    }

    @MainActor
    func test_openedDetachedSignature_saysVerifyingNeedsTheOriginalFile() throws {
        let fixture = try makeOpenedFileFixture()
        let url = try fixture.writeToInbox("report.pdf.sig", try makeDetachedSignature())

        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        assertImportError(.openedDetachedSignatureNeedsOriginal, fixture)
    }

    /// Content decides where a file goes, and the name decides where it is
    /// allowed to go. A certificate arriving as `.gpg` is refused rather than
    /// imported: acting on it would let whoever named the file pick the
    /// destination.
    @MainActor
    func test_openedFileWhoseContentContradictsItsExtension_isRefused() throws {
        let fixture = try makeOpenedFileFixture()
        let generated = try generateKey(named: "Misnamed Certificate")
        let url = try fixture.writeToInbox("friend.gpg", generated.publicKeyData)

        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        assertImportError(.openedFileUnsupportedContent, fixture)
        XCTAssertTrue(stack.contactService.testContactKeyRecords.isEmpty)
    }

    /// GnuPG armors a revocation certificate as a public key block, so only the
    /// packets tell it apart from the certificate it retires.
    @MainActor
    func test_openedRevocationCertificate_isRefused() throws {
        let fixture = try makeOpenedFileFixture()
        let generated = try generateKey(named: "Revoked Identity")
        let url = try fixture.writeToInbox(
            "revocation.asc",
            try stack.engine.armor(data: generated.revocationCert, kind: .publicKey)
        )

        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        assertImportError(.openedFileUnsupportedContent, fixture)
        XCTAssertTrue(stack.contactService.testContactKeyRecords.isEmpty)
    }

    @MainActor
    func test_openedFileThatIsNotOpenPGP_isRefused() throws {
        let fixture = try makeOpenedFileFixture()
        let url = try fixture.writeToInbox("notes.asc", Data("just some notes".utf8))

        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        assertImportError(.openedFileUnsupportedContent, fixture)
    }

    @MainActor
    func test_openedFileWhileAConfirmationIsPending_isRefusedAndItsCopyErased() throws {
        let fixture = try makeOpenedFileFixture()
        let pendingKey = try generateKey(named: "Already Pending")
        fixture.coordinator.handleIncomingURL(
            try makeImportURL(publicKeyData: pendingKey.publicKeyData),
            isTutorialPresentationActive: false
        )
        let pendingRequest = try XCTUnwrap(fixture.coordinator.importConfirmationCoordinator.request)

        let url = try fixture.writeToInbox("secret.gpg", try makeBinaryCiphertext())
        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: false)

        XCTAssertEqual(fixture.coordinator.importConfirmationCoordinator.request?.id, pendingRequest.id)
        assertImportError(.contactImportConfirmationAlreadyPending, fixture)
    }

    @MainActor
    func test_openedFileWhileTheTutorialIsOnScreen_isBlockedAndItsCopyErased() throws {
        let fixture = try makeOpenedFileFixture()
        let url = try fixture.writeToInbox("secret.gpg", try makeBinaryCiphertext())

        fixture.coordinator.handleIncomingURL(url, isTutorialPresentationActive: true)

        XCTAssertTrue(fixture.coordinator.isTutorialImportBlocked)
        XCTAssertNil(fixture.coordinator.importError)
        XCTAssertNil(fixture.handoff.pending)
        XCTAssertEqual(fixture.navigationState.selectedTab, .home)
        XCTAssertEqual(fixture.navigationState.path(for: .home), [])
        XCTAssertEqual(fixture.inboxContents, [])
    }

    /// A document opened in place is the reader's own file. Erasing it would
    /// destroy what they asked the app to look at, so only the inbox copy is
    /// ever deleted — including when the file is refused.
    @MainActor
    func test_openedDocumentOutsideTheContainer_isNeverDeleted() throws {
        let fixture = try makeOpenedFileFixture()
        let refused = try fixture.writeOutsideTheContainer("notes.asc", Data("just some notes".utf8))
        let accepted = try fixture.writeOutsideTheContainer("secret.gpg", try makeBinaryCiphertext())

        fixture.coordinator.handleIncomingURL(refused, isTutorialPresentationActive: false)
        assertImportError(.openedFileUnsupportedContent, fixture)
        fixture.coordinator.dismissImportError()

        fixture.coordinator.handleIncomingURL(accepted, isTutorialPresentationActive: false)
        let document = try XCTUnwrap(fixture.handoff.take(for: .decryption))

        XCTAssertEqual(document.fileURL, accepted)
        XCTAssertTrue(FileManager.default.fileExists(atPath: refused.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: accepted.path))
    }

    // MARK: - Helpers

    @MainActor
    private func makeCoordinator() throws -> IncomingURLImportCoordinator {
        try makeOpenedFileFixture().coordinator
    }

    @MainActor
    private func assertImportError(
        _ expected: CypherAirError,
        _ fixture: OpenedFileFixture,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(
            fixture.coordinator.importError?.localizedDescription,
            expected.localizedDescription,
            file: file,
            line: line
        )
        XCTAssertNil(fixture.handoff.pending, file: file, line: line)
        XCTAssertEqual(fixture.navigationState.path(for: .home), [], file: file, line: line)
        XCTAssertEqual(fixture.navigationState.path(for: .keys), [], file: file, line: line)
        XCTAssertEqual(fixture.inboxContents, [], file: file, line: line)
    }

    private func generateKey(named name: String) throws -> GeneratedKey {
        try stack.engine.generateKey(
            name: name,
            email: nil,
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
    }

    private func makeBinaryCiphertext() throws -> Data {
        let recipient = try generateKey(named: "Ciphertext Recipient")
        let armored = try stack.engine.encrypt(
            plaintext: Data("classified".utf8),
            recipients: [recipient.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        return try stack.engine.dearmor(armored: armored)
    }

    private func makeDetachedSignature() throws -> Data {
        let signer = try generateKey(named: "Detached Signer")
        let signedFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("detached-\(UUID().uuidString).txt")
        try Data("the original".utf8).write(to: signedFile)
        defer { try? FileManager.default.removeItem(at: signedFile) }

        return try stack.engine.signDetachedFile(
            inputPath: signedFile.path,
            signerCert: signer.certData,
            progress: nil
        )
    }

    @MainActor
    private func makeOpenedFileFixture() throws -> OpenedFileFixture {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("opened-documents-\(UUID().uuidString)", isDirectory: true)
        let artifactRoot = root.appendingPathComponent("tmp", isDirectory: true)
        let inbox = root.appendingPathComponent("Documents/Inbox", isDirectory: true)
        let elsewhere = root.appendingPathComponent("elsewhere", isDirectory: true)
        for directory in [artifactRoot, inbox, elsewhere] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }

        let navigationState = AppShellNavigationState()
        let handoff = OpenedDocumentHandoff()
        let coordinator = IncomingURLImportCoordinator(
            importLoader: PublicKeyImportLoader(
                qrService: QRService(
                    contactImportAdapter: PGPContactImportAdapter(engine: stack.engine)
                )
            ),
            importWorkflow: ContactImportWorkflow(contactService: stack.contactService),
            openedDocumentReader: OpenedDocumentReader(
                temporaryArtifactStore: AppTemporaryArtifactStore(
                    temporaryDirectory: artifactRoot,
                    documentInboxDirectory: inbox
                )
            ),
            openedDocumentHandoff: handoff,
            navigationState: navigationState
        )

        return OpenedFileFixture(
            coordinator: coordinator,
            navigationState: navigationState,
            handoff: handoff,
            artifactRoot: artifactRoot,
            inbox: inbox,
            elsewhere: elsewhere
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

/// A coordinator wired to a container the test owns, so that "the inbox is
/// empty afterwards" is something a test can actually observe.
@MainActor
private struct OpenedFileFixture {
    let coordinator: IncomingURLImportCoordinator
    let navigationState: AppShellNavigationState
    let handoff: OpenedDocumentHandoff
    let artifactRoot: URL
    let inbox: URL
    let elsewhere: URL

    /// A document the system copied into the container, as it does when another
    /// app hands one over. The app owns this copy.
    func writeToInbox(_ fileName: String, _ contents: Data) throws -> URL {
        try write(contents, to: inbox.appendingPathComponent(fileName))
    }

    /// A document opened where it lives, as Finder and the Files app do. The
    /// app must read it and leave it alone.
    func writeOutsideTheContainer(_ fileName: String, _ contents: Data) throws -> URL {
        try write(contents, to: elsewhere.appendingPathComponent(fileName))
    }

    var inboxContents: [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: inbox.path)) ?? []).sorted()
    }

    private func write(_ contents: Data, to url: URL) throws -> URL {
        try contents.write(to: url)
        return url
    }
}
