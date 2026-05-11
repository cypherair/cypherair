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
    func test_handleImportedFile_binaryImport_clearsVisibleText_andPreservesRawData() throws {
        let contact = try makeContact(name: "Binary Import Contact", email: "binary-import@example.com")
        let importedBinary = Data([0x89, 0x50, 0x47, 0x50])
        let model = makeModel(
            fingerprint: contact.fingerprint,
            signatureFileImportAction: { _ in
                (data: importedBinary, text: nil)
            }
        )

        model.setSignatureInput("old text")
        model.handleImportedFile(URL(fileURLWithPath: "/tmp/signature.sig"))

        XCTAssertEqual(model.signatureInput, "")
        XCTAssertTrue(model.importedSignature.hasImportedFile)
        XCTAssertEqual(model.importedSignature.rawData, importedBinary)
        XCTAssertEqual(model.importedSignature.fileName, "signature.sig")
        XCTAssertEqual(model.importedSignature.textSnapshot, "")
    }

    @MainActor
    func test_handleImportedFile_binaryImport_verifyUsesImportedRawData_notPreviousText() async throws {
        let contact = try makeContact(name: "Binary Verify Contact", email: "binary-verify@example.com")
        let importedBinary = Data([0xde, 0xad, 0xbe, 0xef])
        var capturedSignature: Data?
        let verification = CertificateSignatureVerification(
            status: .valid,
            certificationKind: nil,
            signerPrimaryFingerprint: nil,
            signingKeyFingerprint: nil,
            signerIdentity: nil
        )
        let model = makeModel(
            fingerprint: contact.fingerprint,
            verifyDirectKeyAction: { signature, _ in
                capturedSignature = signature
                return verification
            },
            signatureFileImportAction: { _ in
                (data: importedBinary, text: nil)
            }
        )

        model.setSignatureInput("old text")
        model.handleImportedFile(URL(fileURLWithPath: "/tmp/imported.sig"))
        model.verifyDirectKey()

        await waitUntil("binary direct-key verification capture") {
            capturedSignature == importedBinary
        }

        XCTAssertEqual(model.signatureInput, "")
        XCTAssertEqual(capturedSignature, importedBinary)
    }

    @MainActor
    func test_setSignatureInput_afterBinaryImport_invalidatesImportedAuthority() async throws {
        let contact = try makeContact(name: "Binary Edit Contact", email: "binary-edit@example.com")
        let importedBinary = Data([0xaa, 0xbb, 0xcc])
        var capturedSignature: Data?
        let verification = CertificateSignatureVerification(
            status: .valid,
            certificationKind: nil,
            signerPrimaryFingerprint: nil,
            signingKeyFingerprint: nil,
            signerIdentity: nil
        )
        let model = makeModel(
            fingerprint: contact.fingerprint,
            verifyDirectKeyAction: { signature, _ in
                capturedSignature = signature
                return verification
            },
            signatureFileImportAction: { _ in
                (data: importedBinary, text: nil)
            }
        )

        model.handleImportedFile(URL(fileURLWithPath: "/tmp/imported.sig"))
        XCTAssertTrue(model.importedSignature.hasImportedFile)

        model.setSignatureInput("replacement text")

        XCTAssertFalse(model.importedSignature.hasImportedFile)
        XCTAssertNil(model.importedSignature.rawData)
        XCTAssertNil(model.importedSignature.fileName)
        XCTAssertNil(model.importedSignature.textSnapshot)

        model.verifyDirectKey()

        await waitUntil("edited direct-key verification capture") {
            capturedSignature == Data("replacement text".utf8)
        }

        XCTAssertEqual(capturedSignature, Data("replacement text".utf8))
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
    func test_clearTransientInput_clearsSignatureInputImportAndVerification() throws {
        let contact = try makeContact(name: "Clear Contact", email: "clear@example.com")
        let model = makeModel(fingerprint: contact.fingerprint)
        model.signatureInput = "signature"
        model.importedSignature.setImportedFile(
            data: Data("signature".utf8),
            fileName: "signature.sig",
            text: "signature"
        )
        model.verification = CertificateSignatureVerification(
            status: .valid,
            certificationKind: nil,
            signerPrimaryFingerprint: nil,
            signingKeyFingerprint: nil,
            signerIdentity: nil
        )
        model.showFileImporter = true

        model.clearTransientInput()

        XCTAssertEqual(model.signatureInput, "")
        XCTAssertFalse(model.importedSignature.hasImportedFile)
        XCTAssertNil(model.verification)
        XCTAssertFalse(model.showFileImporter)
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
        generateArmoredCertificationAction: ContactCertificateSignaturesScreenModel.GenerateArmoredCertificationAction? = nil,
        signatureFileImportAction: ContactCertificateSignaturesScreenModel.SignatureFileImportAction? = nil
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
            generateArmoredCertificationAction: generateArmoredCertificationAction,
            signatureFileImportAction: signatureFileImportAction
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

final class ContactCertificationDetailsScreenModelTests: XCTestCase {
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
    func test_generateCertification_savesWithoutAutomaticExport_thenExplicitExportUsesPolicy() async throws {
        let protectedContacts = try await makeProtectedContactService(prefix: "DetailsGenerate")
        defer {
            try? FileManager.default.removeItem(
                at: protectedContacts.storageRoot.rootURL.deletingLastPathComponent()
            )
        }
        let certificateSignatureService = CertificateSignatureService(
            engine: stack.engine,
            keyManagement: stack.keyManagement,
            contactService: protectedContacts.service
        )
        let (contactId, key, catalog) = try makeContactContext(
            name: "Details Generate",
            email: "details-generate@example.com",
            contactService: protectedContacts.service,
            certificateSignatureService: certificateSignatureService
        )
        _ = try await TestHelpers.generateProfileAKey(service: stack.keyManagement, name: "Details Signer")
        var interceptedFilename: String?
        let configuration = ContactCertificationDetailsConfiguration(
            outputInterceptionPolicy: OutputInterceptionPolicy(
                interceptDataExport: { _, filename, _ in
                    interceptedFilename = filename
                    return true
                }
            )
        )
        let model = makeModel(
            contactId: contactId,
            keyId: key.keyId,
            contactService: protectedContacts.service,
            certificateSignatureService: certificateSignatureService,
            configuration: configuration,
            selectionCatalogAction: { _ in catalog }
        )

        model.loadIfNeeded()
        await waitUntil("details catalog load") {
            model.loadState == .loaded
        }
        model.generateAndSaveCertification()
        await waitUntil("generated certification save") {
            model.lastSavedArtifact != nil
        }

        XCTAssertNil(model.exportController.payload)

        let savedArtifact = try XCTUnwrap(model.lastSavedArtifact)
        model.exportArtifact(savedArtifact)
        await waitUntil("explicit export interception") {
            interceptedFilename == savedArtifact.resolvedExportFilename
        }
    }

    @MainActor
    func test_importPreviewOnlyEnablesSaveForValidArtifact() async throws {
        let protectedContacts = try await makeProtectedContactService(prefix: "DetailsImport")
        defer {
            try? FileManager.default.removeItem(
                at: protectedContacts.storageRoot.rootURL.deletingLastPathComponent()
            )
        }
        let certificateSignatureService = CertificateSignatureService(
            engine: stack.engine,
            keyManagement: stack.keyManagement,
            contactService: protectedContacts.service
        )
        let (contactId, key, catalog) = try makeContactContext(
            name: "Details Import",
            email: "details-import@example.com",
            contactService: protectedContacts.service,
            certificateSignatureService: certificateSignatureService
        )
        let signer = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Details Import Signer"
        )
        let keyRecord = try XCTUnwrap(
            protectedContacts.service.availableContactKeyRecord(keyId: key.keyId)
        )
        let validSignature = try await certificateSignatureService.generateArmoredUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: keyRecord.publicKeyData,
            selectedUserId: catalog.userIds[0],
            certificationKind: .generic
        )
        var validationCalls = 0
        let model = makeModel(
            contactId: contactId,
            keyId: key.keyId,
            contactService: protectedContacts.service,
            certificateSignatureService: certificateSignatureService,
            selectionCatalogAction: { _ in catalog },
            validateUserIdArtifactAction: { signature, targetKey, targetCert, selectedUserId, source, filename in
                validationCalls += 1
                if validationCalls == 1 {
                    return ContactCertificationArtifactValidation(
                        verification: CertificateSignatureVerification(
                            status: .invalid,
                            certificationKind: nil,
                            signerPrimaryFingerprint: nil,
                            signingKeyFingerprint: nil,
                            signerIdentity: nil
                        ),
                        artifact: nil
                    )
                }
                return try await certificateSignatureService.validateUserIdCertificationArtifact(
                    signature: signature,
                    targetKey: targetKey,
                    targetCert: targetCert,
                    selectedUserId: selectedUserId,
                    source: source,
                    exportFilename: filename
                )
            }
        )

        model.loadIfNeeded()
        await waitUntil("details import catalog load") {
            model.loadState == .loaded
        }
        model.setSignatureInput("invalid signature")
        model.verifyImportedSignature()
        await waitUntil("invalid import preview") {
            model.verification?.status == .invalid
        }
        XCTAssertFalse(model.canSavePendingArtifact)

        model.setSignatureInput(String(decoding: validSignature, as: UTF8.self))
        model.verifyImportedSignature()
        await waitUntil("valid import preview") {
            model.pendingArtifact != nil
        }
        XCTAssertTrue(model.canSavePendingArtifact)

        model.savePendingSignature()
        await waitUntil("pending signature save") {
            model.lastSavedArtifact != nil
        }
    }

    @MainActor
    func test_legacyCompatibilityDisablesCertificationPersistenceActions() async throws {
        let (contactId, key, catalog) = try makeContactContext(
            name: "Details Legacy",
            email: "details-legacy@example.com"
        )
        let signer = try await TestHelpers.generateProfileAKey(
            service: stack.keyManagement,
            name: "Details Legacy Signer"
        )
        let keyRecord = try XCTUnwrap(
            stack.contactService.availableContactKeyRecord(keyId: key.keyId)
        )
        let validSignature = try await stack.certificateSignatureService.generateArmoredUserIdCertification(
            signerFingerprint: signer.fingerprint,
            targetCert: keyRecord.publicKeyData,
            selectedUserId: catalog.userIds[0],
            certificationKind: .generic
        )
        let model = makeModel(
            contactId: contactId,
            keyId: key.keyId,
            selectionCatalogAction: { _ in catalog }
        )

        model.loadIfNeeded()
        await waitUntil("legacy details catalog load") {
            model.loadState == .loaded
        }

        XCTAssertEqual(model.contactsAvailability, .availableLegacyCompatibility)
        XCTAssertFalse(model.canGenerateAndSave)

        model.setSignatureInput(String(decoding: validSignature, as: UTF8.self))
        model.verifyImportedSignature()
        await waitUntil("legacy valid import preview") {
            model.pendingArtifact != nil
        }

        XCTAssertFalse(model.canSavePendingArtifact)
        model.savePendingSignature()
        await Task.yield()
        XCTAssertNil(model.lastSavedArtifact)
    }

    @MainActor
    func test_clearTransientInput_clearsImportedSignatureInputAndPicker() throws {
        let (contactId, key, _) = try makeContactContext(
            name: "Details Clear",
            email: "details-clear@example.com"
        )
        let model = makeModel(contactId: contactId, keyId: key.keyId)
        model.signatureInput = "signature"
        model.importedSignature.setImportedFile(
            data: Data("signature".utf8),
            fileName: "signature.sig",
            text: "signature"
        )
        model.showFileImporter = true

        model.clearTransientInput()

        XCTAssertEqual(model.signatureInput, "")
        XCTAssertFalse(model.importedSignature.hasImportedFile)
        XCTAssertNil(model.pendingArtifact)
        XCTAssertNil(model.verification)
        XCTAssertFalse(model.showFileImporter)
    }

    @MainActor
    private func makeContactContext(
        name: String,
        email: String,
        contactService: ContactService? = nil,
        certificateSignatureService: CertificateSignatureService? = nil
    ) throws -> (contactId: String, key: ContactKeySummary, catalog: CertificateSelectionCatalog) {
        let contactService = contactService ?? stack.contactService
        let certificateSignatureService = certificateSignatureService ?? stack.certificateSignatureService
        let generated = try stack.engine.generateKey(
            name: name,
            email: email,
            expirySeconds: nil,
            profile: .universal
        )
        _ = try contactService.addContact(publicKeyData: generated.publicKeyData)
        let contactId = try XCTUnwrap(contactService.contactId(forFingerprint: generated.fingerprint))
        let key = try XCTUnwrap(contactService.availableKey(fingerprint: generated.fingerprint))
        let catalog = try certificateSignatureService.selectionCatalog(
            targetCert: generated.publicKeyData
        )
        return (contactId, key, catalog)
    }

    @MainActor
    private func makeModel(
        contactId: String,
        keyId: String,
        contactService: ContactService? = nil,
        keyManagement: KeyManagementService? = nil,
        certificateSignatureService: CertificateSignatureService? = nil,
        configuration: ContactCertificationDetailsConfiguration = .default,
        selectionCatalogAction: ContactCertificationDetailsScreenModel.SelectionCatalogAction? = nil,
        generateArmoredCertificationAction: ContactCertificationDetailsScreenModel.GenerateArmoredCertificationAction? = nil,
        validateUserIdArtifactAction: ContactCertificationDetailsScreenModel.ValidateUserIdArtifactAction? = nil,
        validateDirectKeyArtifactAction: ContactCertificationDetailsScreenModel.ValidateDirectKeyArtifactAction? = nil,
        saveArtifactAction: ContactCertificationDetailsScreenModel.SaveArtifactAction? = nil,
        exportArtifactAction: ContactCertificationDetailsScreenModel.ExportArtifactAction? = nil
    ) -> ContactCertificationDetailsScreenModel {
        ContactCertificationDetailsScreenModel(
            contactId: contactId,
            initialKeyId: keyId,
            intent: .details,
            contactService: contactService ?? stack.contactService,
            keyManagement: keyManagement ?? stack.keyManagement,
            certificateSignatureService: certificateSignatureService ?? stack.certificateSignatureService,
            configuration: configuration,
            selectionCatalogAction: selectionCatalogAction,
            generateArmoredCertificationAction: generateArmoredCertificationAction,
            validateUserIdArtifactAction: validateUserIdArtifactAction,
            validateDirectKeyArtifactAction: validateDirectKeyArtifactAction,
            saveArtifactAction: saveArtifactAction,
            exportArtifactAction: exportArtifactAction
        )
    }

    private func makeProtectedContactService(
        prefix: String
    ) async throws -> (
        service: ContactService,
        storageRoot: ProtectedDataStorageRoot,
        contactsDirectory: URL
    ) {
        let contactsDirectory = stack.tempDir
            .appendingPathComponent("\(prefix)-contacts-\(UUID().uuidString)", isDirectory: true)
        let storageRoot = ProtectedDataStorageRoot(
            baseDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        )
        let registryStore = ProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.details.\(UUID().uuidString)"
        )
        _ = try registryStore.performSynchronousBootstrap()
        var registry = try registryStore.loadRegistry()
        registry.sharedResourceLifecycleState = .ready
        registry.committedMembership = [ProtectedSettingsStore.domainID: .active]
        try registryStore.saveRegistry(registry)

        let domainKeyManager = ProtectedDomainKeyManager(storageRoot: storageRoot)
        let wrappingRootKey = Data(repeating: 0xD6, count: 32)
        let migrationSource = ContactsLegacyMigrationSource(
            engine: stack.engine,
            repository: ContactRepository(contactsDirectory: contactsDirectory)
        )
        let store = ContactsDomainStore(
            storageRoot: storageRoot,
            registryStore: registryStore,
            domainKeyManager: domainKeyManager,
            currentWrappingRootKey: { wrappingRootKey },
            initialSnapshotProvider: {
                try migrationSource.makeInitialSnapshot()
            }
        )
        let service = ContactService(
            engine: stack.engine,
            contactsDirectory: contactsDirectory,
            contactsDomainStore: store
        )
        let availability = await service.openContactsAfterPostUnlock(
            gateResult: ContactsPostAuthGateResult(
                postUnlockOutcome: .opened([ProtectedSettingsStore.domainID]),
                frameworkState: .sessionAuthorized
            ),
            wrappingRootKey: { wrappingRootKey }
        )
        XCTAssertEqual(availability, .availableProtectedDomain)

        return (service, storageRoot, contactsDirectory)
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
