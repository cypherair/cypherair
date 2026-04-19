import XCTest
@testable import CypherAir

final class ContactCertificateSignaturesScreenModelTests: XCTestCase {
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
    func test_loadIfNeeded_onlyLoadsOnce() async throws {
        let contact = try makeContact(name: "Load Once Contact", email: "load-once@example.com")
        let catalog = try stack.certificateSignatureService.selectionCatalog(
            targetCert: contact.publicKeyData
        )
        var loadCount = 0

        let model = makeModel(
            fingerprint: contact.fingerprint,
            selectionCatalogAction: { _ in
                loadCount += 1
                return catalog
            }
        )

        model.loadIfNeeded()
        model.loadIfNeeded()

        await waitUntil("catalog to load") {
            model.loadState == .loaded
        }

        XCTAssertEqual(loadCount, 1)
        XCTAssertEqual(model.userIds, catalog.userIds)
    }

    @MainActor
    func test_retry_afterFailure_reloadsCatalog() async throws {
        let contact = try makeContact(name: "Retry Contact", email: "retry@example.com")
        let catalog = try stack.certificateSignatureService.selectionCatalog(
            targetCert: contact.publicKeyData
        )
        enum RetryError: Error { case failed }
        var callCount = 0

        let model = makeModel(
            fingerprint: contact.fingerprint,
            selectionCatalogAction: { _ in
                callCount += 1
                if callCount == 1 {
                    throw RetryError.failed
                }
                return catalog
            }
        )

        model.loadIfNeeded()

        await waitUntil("initial load failure") {
            model.loadState == .failed
        }

        model.retry()

        await waitUntil("retry load success") {
            model.loadState == .loaded
        }

        XCTAssertEqual(callCount, 2)
        XCTAssertEqual(model.userIds, catalog.userIds)
    }

    @MainActor
    func test_handleDisappear_cancelsInFlightLoad() async throws {
        let contact = try makeContact(name: "Disappear Contact", email: "disappear@example.com")
        let model = makeModel(
            fingerprint: contact.fingerprint,
            selectionCatalogAction: { _ in
                try await Task.sleep(nanoseconds: 300_000_000)
                return try self.stack.certificateSignatureService.selectionCatalog(
                    targetCert: contact.publicKeyData
                )
            }
        )

        model.loadIfNeeded()
        model.handleDisappear()

        await Task.yield()

        XCTAssertEqual(model.loadState, .idle)
        XCTAssertNil(model.catalog)
    }

    @MainActor
    func test_buttonGating_matchesModeRequirements() async throws {
        let contact = try makeContact(name: "Gating Contact", email: "gating@example.com")
        let catalog = try stack.certificateSignatureService.selectionCatalog(
            targetCert: contact.publicKeyData
        )
        _ = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Signer"
        )

        let model = makeModel(
            fingerprint: contact.fingerprint,
            selectionCatalogAction: { _ in catalog }
        )
        model.loadIfNeeded()

        await waitUntil("catalog to load for gating") {
            model.loadState == .loaded
        }

        XCTAssertFalse(model.canVerifyDirectKey)
        model.setSignatureInput("signature")
        XCTAssertTrue(model.canVerifyDirectKey)

        model.setMode(.userIdBindingVerify)
        XCTAssertFalse(model.canVerifyUserIdBinding)
        model.selectUserId(catalog.userIds[0])
        XCTAssertTrue(model.canVerifyUserIdBinding)

        model.setMode(.certifyUserId)
        XCTAssertTrue(model.selectedSigner != nil)
        XCTAssertTrue(model.canCertifyUserId)
    }

    @MainActor
    func test_verifyAndCertify_results_areStored() async throws {
        let contact = try makeContact(name: "Result Contact", email: "result@example.com")
        let catalog = try stack.certificateSignatureService.selectionCatalog(
            targetCert: contact.publicKeyData
        )
        let verification = CertificateSignatureVerification(
            status: .valid,
            certificationKind: .positive,
            signerPrimaryFingerprint: contact.fingerprint,
            signingKeyFingerprint: "1234567890abcdef1234567890abcdef12345678",
            signerIdentity: nil
        )
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")

        let model = makeModel(
            fingerprint: contact.fingerprint,
            selectionCatalogAction: { _ in catalog },
            verifyDirectKeyAction: { _, _ in verification },
            verifyUserIdBindingAction: { _, _, _ in verification },
            generateArmoredCertificationAction: { _, _, _, _ in Data("armored".utf8) }
        )
        model.loadIfNeeded()
        await waitUntil("catalog to load for results") {
            model.loadState == .loaded
        }

        model.setSignatureInput("direct")
        model.verifyDirectKey()
        await waitUntil("direct verification result") {
            model.verification?.status == .valid
        }
        XCTAssertEqual(model.verification?.signingKeyFingerprint, verification.signingKeyFingerprint)

        model.setMode(.certifyUserId)
        model.selectUserId(catalog.userIds[0])
        model.certifyUserId()
        await waitUntil("certify result and export") {
            model.verification?.status == .valid && model.exportController.payload != nil
        }
        XCTAssertEqual(model.verification?.certificationKind, .positive)
    }

    @MainActor
    func test_certifyUserId_routesExportThroughInterceptionPolicy() async throws {
        let contact = try makeContact(name: "Intercept Contact", email: "intercept@example.com")
        let catalog = try stack.certificateSignatureService.selectionCatalog(
            targetCert: contact.publicKeyData
        )
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")
        var interceptedKind: OutputArtifactKind?
        var interceptedFilename: String?
        let configuration = ContactCertificateSignaturesView.Configuration(
            outputInterceptionPolicy: OutputInterceptionPolicy(
                interceptDataExport: { _, filename, kind in
                    interceptedFilename = filename
                    interceptedKind = kind
                    return true
                }
            )
        )

        let model = makeModel(
            fingerprint: contact.fingerprint,
            configuration: configuration,
            selectionCatalogAction: { _ in catalog },
            verifyUserIdBindingAction: { _, _, _ in
                CertificateSignatureVerification(
                    status: .valid,
                    certificationKind: .generic,
                    signerPrimaryFingerprint: nil,
                    signingKeyFingerprint: nil,
                    signerIdentity: nil
                )
            },
            generateArmoredCertificationAction: { _, _, _, _ in Data("armored".utf8) }
        )
        model.loadIfNeeded()
        await waitUntil("catalog to load for interception") {
            model.loadState == .loaded
        }

        model.setMode(.certifyUserId)
        model.selectUserId(catalog.userIds[0])
        model.certifyUserId()

        await waitUntil("intercepted export") {
            interceptedFilename != nil
        }

        XCTAssertEqual(interceptedKind, .generic)
        XCTAssertTrue(interceptedFilename?.contains("userid-certification-") == true)
        XCTAssertNil(model.exportController.payload)
    }

    @MainActor
    func test_errorPresentation_coversGenerationAndExportFailures() async throws {
        let contact = try makeContact(name: "Error Contact", email: "error@example.com")
        let catalog = try stack.certificateSignatureService.selectionCatalog(
            targetCert: contact.publicKeyData
        )
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Signer")

        let model = makeModel(
            fingerprint: contact.fingerprint,
            selectionCatalogAction: { _ in catalog },
            generateArmoredCertificationAction: { _, _, _, _ in
                throw CypherAirError.authenticationFailed
            }
        )
        model.loadIfNeeded()
        await waitUntil("catalog to load for error") {
            model.loadState == .loaded
        }

        model.setMode(.certifyUserId)
        model.selectUserId(catalog.userIds[0])
        model.certifyUserId()

        await waitUntil("generation failure") {
            model.showError
        }

        guard case .authenticationFailed? = model.error else {
            return XCTFail("Expected authenticationFailed, got \(String(describing: model.error))")
        }

        model.dismissError()
        model.handleExportError(ContactCertificateSignaturesScreenModelTestError(message: "export"))

        XCTAssertTrue(model.showError)
        guard case .fileIoError(let reason)? = model.error else {
            return XCTFail("Expected fileIoError, got \(String(describing: model.error))")
        }
        XCTAssertEqual(reason, "export")
    }

    @MainActor
    func test_loadIfNeeded_withMissingContact_entersLoadedStateWithoutCatalog() {
        let model = makeModel(
            fingerprint: "missing-fingerprint",
            selectionCatalogAction: { _ in
                XCTFail("Selection catalog should not load without a contact")
                return CertificateSelectionCatalog(
                    certificateFingerprint: "unused",
                    subkeys: [],
                    userIds: []
                )
            }
        )

        model.loadIfNeeded()

        XCTAssertEqual(model.loadState, .loaded)
        XCTAssertNil(model.contact)
        XCTAssertTrue(model.userIds.isEmpty)
    }

    @MainActor
    private func makeContact(name: String, email: String) throws -> Contact {
        let generated = try stack.engine.generateKey(
            name: name,
            email: email,
            expirySeconds: nil,
            profile: .universal
        )
        let result = try stack.contactService.addContact(publicKeyData: generated.publicKeyData)
        guard case .added(let contact) = result else {
            XCTFail("Expected contact to be added")
            throw ContactCertificateSignaturesScreenModelTestError(message: "contact add failed")
        }
        return contact
    }

    @MainActor
    private func makeModel(
        fingerprint: String,
        configuration: ContactCertificateSignaturesView.Configuration = .default,
        selectionCatalogAction: ContactCertificateSignaturesScreenModel.SelectionCatalogAction? = nil,
        verifyDirectKeyAction: ContactCertificateSignaturesScreenModel.VerifyDirectKeyAction? = nil,
        verifyUserIdBindingAction: ContactCertificateSignaturesScreenModel.VerifyUserIdBindingAction? = nil,
        generateArmoredCertificationAction: ContactCertificateSignaturesScreenModel.GenerateArmoredCertificationAction? = nil
    ) -> ContactCertificateSignaturesScreenModel {
        ContactCertificateSignaturesScreenModel(
            fingerprint: fingerprint,
            contactService: stack.contactService,
            keyManagement: stack.keyManagement,
            certificateSignatureService: stack.certificateSignatureService,
            configuration: configuration,
            selectionCatalogAction: selectionCatalogAction,
            verifyDirectKeyAction: verifyDirectKeyAction,
            verifyUserIdBindingAction: verifyUserIdBindingAction,
            generateArmoredCertificationAction: generateArmoredCertificationAction
        )
    }

    @MainActor
    private func waitUntil(
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
}

private struct ContactCertificateSignaturesScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}
