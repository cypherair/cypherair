import Foundation
import XCTest

final class ArchitectureSourceAuditTests: XCTestCase {
    func test_repositoryAuditLoader_returnsRepositoryRelativeSwiftSourcePaths() throws {
        let paths = try RepositoryAuditLoader.swiftSourceRelativePaths()

        XCTAssertFalse(paths.isEmpty)
        XCTAssertTrue(paths.allSatisfy { $0.hasPrefix("Sources/") })
        XCTAssertFalse(paths.contains { $0.hasPrefix("Sources/Sources/") })

        let knownPath = "Sources/App/AppContainer.swift"
        XCTAssertTrue(paths.contains(knownPath))
        XCTAssertFalse(try RepositoryAuditLoader.loadString(relativePath: knownPath).isEmpty)
    }

    func test_generatedUniFFITypes_doNotLeakIntoNewUpperLayerFiles() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.generatedFFITypes)
    }

    func test_generatedErrorMapping_isLimitedToFFIAdapters() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.generatedErrorMappingContainment)
    }

    func test_appLayerPgpErrorHandling_isLimitedToKnownTemporaryExceptions() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.appLayerPgpErrorHandling)
    }

    func test_appLayerFFIAdapterUsage_isBlocked() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.appLayerFFIAdapterUsage)
    }

    func test_modelsSwiftUIPresentationPolicy_isLimitedToKnownTemporaryExceptions() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.modelsSwiftUIPresentationPolicy)
    }

    func test_modelsLocalizedPresentationText_isBlocked() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.modelsLocalizedPresentationText)
    }

    func test_modelsSecurityImplementationVocabulary_isBlocked() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.modelsSecurityImplementationVocabulary)
    }

    func test_contactArrayRuntimeDependencies_areLimitedToKnownTemporaryExceptions() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.contactArrayRuntimeDependencies)
    }

    func test_contactsLegacyRuntimeVocabulary_isRemovedFromProductionSources() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.contactsLegacyRuntimeVocabulary)
    }

    func test_privateOperationCustodySwitchesStayInsideRouterBoundaries() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.privateOperationCustodySwitchContainment)
    }

    func test_phase5KeyManagementCustodySwitchesStayInExplicitBoundaries() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.phase5KeyManagementCustodySwitchContainment)
    }

    func test_phase5WorkflowServicesDoNotCallExternalSignerRuntimeDirectly() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.phase5WorkflowExternalSignerContainment)
    }

    func test_phase5ExternalSignerRuntimeStaysInsideFFIAndRouterOwnedHelpers() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.phase5ExternalSignerRuntimeContainment)
    }

    func test_phase6ExternalKeyAgreementRuntimeStaysInsideFFISecurityAndRouterBoundary() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.phase6ExternalKeyAgreementRuntimeContainment)
    }

    func test_phase6WorkflowServicesDoNotCallExternalKeyAgreementRuntimeDirectly() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.phase6WorkflowExternalKeyAgreementContainment)
    }

    func test_phase6KeyAgreementSharedSecretHandoffZeroizesSwiftTemporaryBuffers() throws {
        let securityBridge = try RepositoryAuditLoader.loadString(
            relativePath: "Sources/Security/SecureEnclaveCustodyKeyAgreement.swift"
        )
        XCTAssertTrue(securityBridge.contains("mutating func zeroize()"))
        XCTAssertTrue(securityBridge.contains("defer { sharedSecret.resetBytes(in: 0..<sharedSecret.count) }"))

        let ffiBridge = try RepositoryAuditLoader.loadString(
            relativePath: "Sources/Services/FFI/PGPExternalP256KeyAgreementProviderBridge.swift"
        )
        XCTAssertTrue(ffiBridge.contains("defer { sharedSecret.zeroize() }"))
        XCTAssertTrue(ffiBridge.contains("defer { raw.resetBytes(in: 0..<raw.count) }"))
        XCTAssertTrue(ffiBridge.contains("UniFFI must copy this record across the callback boundary"))
    }

    func test_phase5PrivateKeyHelpersRouteThroughExpectedOperationKinds() throws {
        let expectations: [(path: String, operation: String)] = [
            ("Sources/Services/KeyManagement/PrivateKeyCleartextSigningService.swift", ".sign"),
            ("Sources/Services/KeyManagement/PrivateKeyTextEncryptionService.swift", ".sign"),
            ("Sources/Services/KeyManagement/PrivateKeyPasswordMessageEncryptionService.swift", ".sign"),
            ("Sources/Services/KeyManagement/PrivateKeyDetachedFileSigningService.swift", ".sign"),
            ("Sources/Services/KeyManagement/PrivateKeyStreamingFileEncryptionService.swift", ".sign"),
            ("Sources/Services/KeyManagement/PrivateKeyExpiryMutationService.swift", ".modifyExpiry"),
            ("Sources/Services/KeyManagement/PrivateKeySelectiveRevocationService.swift", ".revoke"),
            ("Sources/Services/KeyManagement/PrivateKeyContactCertificationService.swift", ".certify"),
        ]

        for expectation in expectations {
            let contents = try RepositoryAuditLoader.loadString(relativePath: expectation.path)
            XCTAssertTrue(
                contents.contains("router.route("),
                "\(expectation.path) must dispatch through PrivateKeyOperationRouter."
            )
            XCTAssertTrue(
                contents.contains("PrivateKeyOperationRequest("),
                "\(expectation.path) must build an app-owned private-operation request."
            )
            XCTAssertTrue(
                contents.contains("operation: \(expectation.operation)"),
                "\(expectation.path) must route through \(expectation.operation)."
            )
            XCTAssertTrue(
                contents.contains("PGPExternalP256SigningProviderBridge("),
                "\(expectation.path) must keep external P-256 signing behind the shared bridge."
            )
        }
    }

    func test_phase6MessageDecryptionHelperRoutesThroughKeyAgreementOperation() throws {
        let path = "Sources/Services/KeyManagement/PrivateKeyMessageDecryptionService.swift"
        let contents = try RepositoryAuditLoader.loadString(relativePath: path)
        XCTAssertTrue(
            contents.contains("router.route("),
            "\(path) must dispatch through PrivateKeyOperationRouter."
        )
        XCTAssertTrue(
            contents.contains("PrivateKeyOperationRequest("),
            "\(path) must build an app-owned private-operation request."
        )
        XCTAssertTrue(
            contents.contains("operation: .decrypt"),
            "\(path) must route through .decrypt."
        )
        XCTAssertTrue(
            contents.contains("PGPExternalP256KeyAgreementProviderBridge("),
            "\(path) must keep external P-256 key agreement behind the shared bridge."
        )
        XCTAssertFalse(
            contents.contains("WithExternalP256Signer"),
            "\(path) must not invoke the external P-256 signer runtime."
        )
    }

    func test_phase6FileDecryptionHelperRoutesThroughKeyAgreementOperation() throws {
        let path = "Sources/Services/KeyManagement/PrivateKeyStreamingFileDecryptionService.swift"
        let contents = try RepositoryAuditLoader.loadString(relativePath: path)
        XCTAssertTrue(
            contents.contains("router.route("),
            "\(path) must dispatch through PrivateKeyOperationRouter."
        )
        XCTAssertTrue(
            contents.contains("PrivateKeyOperationRequest("),
            "\(path) must build an app-owned private-operation request."
        )
        XCTAssertTrue(
            contents.contains("operation: .decrypt"),
            "\(path) must route through .decrypt."
        )
        XCTAssertTrue(
            contents.contains("PGPExternalP256KeyAgreementProviderBridge("),
            "\(path) must keep external P-256 key agreement behind the shared bridge."
        )
        XCTAssertFalse(
            contents.contains("WithExternalP256Signer"),
            "\(path) must not invoke the external P-256 signer runtime."
        )
    }

    func test_secureEnclaveUnsupportedAndGatedOperationsRemainExplicit() throws {
        let resolver = try RepositoryAuditLoader.loadString(
            relativePath: "Sources/Services/KeyManagement/PGPKeyCapabilityResolver.swift"
        )
        XCTAssertTrue(resolver.contains("secureEnclaveRefreshBindingOperationSupport"))
        XCTAssertTrue(resolver.contains("secureEnclaveKeyAgreementOperationSupport"))
        XCTAssertTrue(resolver.contains("case .refreshBinding:"))
        XCTAssertTrue(resolver.contains("case .decrypt:"))

        let operationKind = try RepositoryAuditLoader.loadString(
            relativePath: "Sources/Models/PGPPrivateOperationKind.swift"
        )
        XCTAssertTrue(operationKind.contains("case refreshBinding"))
        XCTAssertTrue(operationKind.contains("case decrypt"))
    }

    func test_keyRouteViews_doNotOrchestrateKeyManagementWorkflows() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.keyRouteViewWorkflowContainment)
    }

    func test_contactsRouteViews_doNotOrchestrateContactOrQRWorkflows() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.contactsRouteViewWorkflowContainment)
    }

    func test_screenModelsDoNotExposePhotosUIPickerTypes() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.screenModelPhotosUIContainment)
    }

    func test_screenModelPublicAPIsDoNotExposeServiceFileInternals() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.screenModelPublicAPIContainment)
    }

    func test_screenModelStreamingServicesUsePerOperationProgressReporter() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.screenModelStreamingProgressOwnership)
    }

    func test_appContainerUITestContactsBootstrapDoesNotBlockSynchronously() throws {
        let contents = try RepositoryAuditLoader.loadString(relativePath: "Sources/App/AppContainer.swift")

        XCTAssertFalse(contents.contains("DispatchSemaphore"))
        XCTAssertFalse(contents.contains("openSandboxContactsSynchronously"))
    }

    func test_securityMockImplementations_areConfinedToTemporaryMocksDirectory() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.securityMockImplementationContainment)
    }

    func test_protectedDataProductionFiles_doNotEmbedMockImplementations() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.protectedDataMockImplementationContainment)
    }

    func test_productionCodeDoesNotReferenceMockKeychainErrorOutsideMocks() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.productionMockKeychainErrorReferences)
    }

    func test_protectedDataAuthorizationClassificationUsesKeychainFailureClassifier() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.protectedDataAuthorizationConcreteKeychainErrorClassification)
    }

    func test_legacyCleanup_item2_keyMetadataMigration_isTrackedForStrictRetirement() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.legacyCleanupKeyMetadataMigrationSymbols)
    }

    func test_legacyCleanup_item3_privateKeyControlDefaults_isTrackedForStrictRetirement() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.legacyCleanupPrivateKeyControlDefaultsSymbols)
    }

    func test_legacyCleanup_item4_protectedSettingsMigration_isTrackedForStrictRetirement() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.legacyCleanupProtectedSettingsMigrationSymbols)
    }

    func test_legacyCleanup_item5_contactsSnapshotMigration_isTrackedForStrictRetirement() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.legacyCleanupContactsSnapshotMigrationSymbols)
    }

    func test_legacyCleanup_phase1_contactsArtifactSentinel_isTrackedForStrictRetirement() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.legacyCleanupContactsArtifactSentinelSymbols)
    }

    func test_legacyCleanup_item1A_rootSecretRightStore_isTrackedForStrictRetirement() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.legacyCleanupRootSecretRightStoreSymbols)
    }

    func test_legacyCleanup_item1B_rawRootSecret_isTrackedForStrictRetirement() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.legacyCleanupRawRootSecretSymbols)
    }

    func test_legacyCleanup_item7_revocationBackfill_isTrackedForStrictRetirement() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.legacyCleanupRevocationBackfillSymbols)
    }

    func test_sourceAuditRules_detectViolationsAndAllowFileExceptions() throws {
        try assertRuleBehavior(
            ArchitectureSourceAuditRules.generatedFFITypes.withTemporaryExceptions([
                "Sources/App/AppContainer.swift": "fixture exception"
            ]),
            violatingPath: "Sources/App/NewScreenModel.swift",
            violatingContents: "struct NewScreenModel { let engine: PgpEngine }",
            allowedPath: "Sources/App/AppContainer.swift",
            allowedContents: "struct AppContainer { let engine: PgpEngine }",
            cleanContents: "struct CleanContainer {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.appLayerPgpErrorHandling.withTemporaryExceptions([
                "Sources/App/Common/OperationController.swift": "fixture exception"
            ]),
            violatingPath: "Sources/App/NewView.swift",
            violatingContents: "func handle(_ error: Error) { _ = error as? PgpError }",
            allowedPath: "Sources/App/Common/OperationController.swift",
            allowedContents: "func shouldIgnore(_ error: Error) -> Bool { error is PgpError }",
            cleanContents: "func shouldIgnore(_ error: Error) -> Bool { false }"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.generatedErrorMappingContainment.withTemporaryExceptions([
                "Sources/Services/FFI/PGPErrorMapper.swift": "fixture exception"
            ]),
            violatingPath: "Sources/Services/NewService.swift",
            violatingContents: "struct NewService { func map(_ error: Error) { _ = PGPErrorMapper.map(error) { .internalError(reason: $0) } } }",
            allowedPath: "Sources/Services/FFI/PGPErrorMapper.swift",
            allowedContents: "enum PGPErrorMapper { static func map(_ error: PgpError) {} }",
            cleanContents: "struct NewService {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.appLayerFFIAdapterUsage.withTemporaryExceptions([
                "Sources/App/Contacts/Import/LegacyImportLoader.swift": "fixture exception"
            ]),
            violatingPath: "Sources/App/Contacts/Import/NewImportLoader.swift",
            violatingContents: "struct NewImportLoader { let adapter = PGPKeyMetadataAdapter.self }",
            allowedPath: "Sources/App/Contacts/Import/LegacyImportLoader.swift",
            allowedContents: "struct LegacyImportLoader { let adapter = PGPCertificateSelectionAdapter.self }",
            cleanContents: "struct ImportLoader {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.phase5ExternalSignerRuntimeContainment.withTemporaryExceptions([
                "Sources/Services/KeyManagement/PrivateKeyCleartextSigningService.swift": "fixture exception"
            ]),
            violatingPath: "Sources/Services/NewSigningWorkflow.swift",
            violatingContents: "struct NewSigningWorkflow { func run() { _ = PGPExternalP256SigningProviderBridge.self } }",
            allowedPath: "Sources/Services/KeyManagement/PrivateKeyCleartextSigningService.swift",
            allowedContents: "struct PrivateKeyCleartextSigningService { func run() { _ = PGPExternalP256SigningProviderBridge.self } }",
            cleanContents: "struct PrivateKeyCleartextSigningService {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.phase5KeyManagementCustodySwitchContainment.withTemporaryExceptions([
                "Sources/Services/KeyManagement/PrivateKeyOperationRouter.swift": "fixture exception"
            ]),
            violatingPath: "Sources/Services/KeyManagement/NewWorkflowHelper.swift",
            violatingContents: "struct NewWorkflowHelper { func run(identity: PGPKeyIdentity) { _ = identity.privateKeyCustodyKind } }",
            allowedPath: "Sources/Services/KeyManagement/PrivateKeyOperationRouter.swift",
            allowedContents: "struct PrivateKeyOperationRouter { func run(identity: PGPKeyIdentity) { _ = identity.privateKeyCustodyKind } }",
            cleanContents: "struct PrivateKeyOperationRouter {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.modelsSwiftUIPresentationPolicy.withTemporaryExceptions([
                "Sources/Models/LegacyPresentationModel.swift": "fixture exception"
            ]),
            violatingPath: "Sources/Models/NewDomainModel.swift",
            violatingContents: "import SwiftUI\nstruct NewDomainModel {}",
            allowedPath: "Sources/Models/LegacyPresentationModel.swift",
            allowedContents: "import SwiftUI\nstruct LegacyPresentationModel {}",
            cleanContents: "import Foundation\nstruct LegacyPresentationModel {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.modelsLocalizedPresentationText.withTemporaryExceptions([
                "Sources/Models/LegacyLocalizedModel.swift": "fixture exception"
            ]),
            violatingPath: "Sources/Models/NewDomainModel.swift",
            violatingContents: #"struct NewDomainModel { let label = String(localized: "model.label") }"#,
            allowedPath: "Sources/Models/LegacyLocalizedModel.swift",
            allowedContents: #"struct LegacyLocalizedModel { let label = String.localizedStringWithFormat("%d keys", 2) }"#,
            cleanContents: "struct LegacyLocalizedModel { let label = \"\" }"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.modelsSecurityImplementationVocabulary.withTemporaryExceptions([
                "Sources/Models/LegacySecurityModel.swift": "fixture exception"
            ]),
            violatingPath: "Sources/Models/NewDomainModel.swift",
            violatingContents: "import LocalAuthentication\nstruct NewDomainModel { let state: ProtectedDataFrameworkState }",
            allowedPath: "Sources/Models/LegacySecurityModel.swift",
            allowedContents: "struct LegacySecurityModel { let error: ProtectedDataError }",
            cleanContents: "struct LegacySecurityModel { let availability: ProtectedOrdinarySettingsAvailability }"
        )

        let contactArraySource = AuditedSource(
            path: "Sources/Services/NewRecipientService.swift",
            contents: "struct NewRecipientService { let contacts: [Contact] }"
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.contactArrayRuntimeDependencies
                .violations(in: [contactArraySource])
                .map(\.path),
            [contactArraySource.path]
        )

        let contactGenericArraySource = AuditedSource(
            path: "Sources/Services/NewRecipientService.swift",
            contents: "struct NewRecipientService { let contacts: Array<Contact> }"
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.contactArrayRuntimeDependencies
                .violations(in: [contactGenericArraySource])
                .map(\.path),
            [contactGenericArraySource.path]
        )

        let contactsLegacySource = AuditedSource(
            path: "Sources/Services/NewContactsLegacyRuntime.swift",
            contents: """
            struct Contact {}
            struct NewContactsLegacyRuntime {
                let repository = ContactRepository.self
                let source = ContactsLegacyMigrationSource.self
                let mapper = ContactsCompatibilityMapper.self
                let availability = "not in stripped source"
            }
            """
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.contactsLegacyRuntimeVocabulary
                .violations(in: [contactsLegacySource])
                .map(\.path),
            [contactsLegacySource.path]
        )

        let keyRouteViewSource = AuditedSource(
            path: "Sources/App/Keys/KeyGenerationView.swift",
            contents: "struct NewKeyView { func run() async throws { try await service.generateKey(name: \"\", email: nil, expirySeconds: nil, profile: .advanced) } }"
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.keyRouteViewWorkflowContainment
                .violations(in: [keyRouteViewSource])
                .map(\.path),
            [keyRouteViewSource.path]
        )

        let keyRouteScreenModelSource = AuditedSource(
            path: "Sources/App/Keys/NewKeyScreenModel.swift",
            contents: "final class NewKeyScreenModel { func run() async throws { try await keyManagement.generateKey(name: \"\", email: nil, expirySeconds: nil, profile: .advanced) } }"
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.keyRouteViewWorkflowContainment
                .violations(in: [keyRouteScreenModelSource])
                .isEmpty
        )

        let contactsRouteViewSource = AuditedSource(
            path: "Sources/App/Contacts/QRDisplayView.swift",
            contents: "struct NewQRView { func run() throws { _ = try qrService.generateQRCode(for: Data()) } }"
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.contactsRouteViewWorkflowContainment
                .violations(in: [contactsRouteViewSource])
                .map(\.path),
            [contactsRouteViewSource.path]
        )

        let contactsRouteScreenModelSource = AuditedSource(
            path: "Sources/App/Contacts/QRDisplayScreenModel.swift",
            contents: "final class QRDisplayScreenModel { func run() throws { _ = try qrService.generateQRCode(for: Data()) } }"
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.contactsRouteViewWorkflowContainment
                .violations(in: [contactsRouteScreenModelSource])
                .isEmpty
        )

        let contactsListScreenModelSource = AuditedSource(
            path: "Sources/App/Contacts/ContactsScreenModel.swift",
            contents: "final class ContactsScreenModel { func run() { _ = contactService.contactIdentities() } }"
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.contactsRouteViewWorkflowContainment
                .violations(in: [contactsListScreenModelSource])
                .isEmpty
        )

        let contactsImportCoordinatorSource = AuditedSource(
            path: "Sources/App/Contacts/Import/ContactImportWorkflow.swift",
            contents: "struct ContactImportWorkflow { func run() throws { try contactService.importContact() } }"
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.contactsRouteViewWorkflowContainment
                .violations(in: [contactsImportCoordinatorSource])
                .isEmpty
        )

        let screenModelPhotosUISource = AuditedSource(
            path: "Sources/App/Contacts/NewScreenModel.swift",
            contents: """
            import PhotosUI
            final class NewScreenModel {
                func run(_ item: PhotosPickerItem) {}
            }
            """
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.screenModelPhotosUIContainment
                .violations(in: [screenModelPhotosUISource])
                .map(\.path),
            [screenModelPhotosUISource.path]
        )

        let loaderPhotosUISource = AuditedSource(
            path: "Sources/App/Contacts/Import/PublicKeyImportLoader.swift",
            contents: """
            import PhotosUI
            struct PublicKeyImportLoader {
                func load(_ item: PhotosPickerItem) {}
            }
            """
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.screenModelPhotosUIContainment
                .violations(in: [loaderPhotosUISource])
                .isEmpty
        )

        let viewPhotosUISource = AuditedSource(
            path: "Sources/App/Contacts/AddContactView.swift",
            contents: """
            import PhotosUI
            struct AddContactView {
                let selectedPhotoItem: PhotosPickerItem?
            }
            """
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.screenModelPhotosUIContainment
                .violations(in: [viewPhotosUISource])
                .isEmpty
        )

        let screenModelPhase1Source = AuditedSource(
            path: "Sources/App/Decrypt/NewDecryptScreenModel.swift",
            contents: "final class NewDecryptScreenModel { var result: DecryptionService.Phase1Result? }"
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.screenModelPublicAPIContainment
                .violations(in: [screenModelPhase1Source])
                .map(\.path),
            [screenModelPhase1Source.path]
        )

        let screenModelProgressSource = AuditedSource(
            path: "Sources/App/Sign/NewSignScreenModel.swift",
            contents: "final class NewSignScreenModel { typealias Action = (FileProgressReporter) -> AppTemporaryArtifact }"
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.screenModelPublicAPIContainment
                .violations(in: [screenModelProgressSource])
                .map(\.path),
            [screenModelProgressSource.path]
        )

        let appCommonFileOutputSource = AuditedSource(
            path: "Sources/App/Common/TemporaryFileOutput.swift",
            contents: "extension AppTemporaryArtifact { var output: TemporaryFileOutput { fatalError() } }"
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.screenModelPublicAPIContainment
                .violations(in: [appCommonFileOutputSource])
                .isEmpty
        )

        let staleOperationProgressSource = AuditedSource(
            path: "Sources/App/Encrypt/NewEncryptScreenModel.swift",
            contents: """
            final class NewEncryptScreenModel {
                func encrypt(service: EncryptionService, operation: OperationController) async throws {
                    _ = try await service.encryptFileStreaming(
                        inputURL: URL(fileURLWithPath: "/tmp/input"),
                        recipientContactIds: [],
                        signWithFingerprint: nil,
                        encryptToSelf: false,
                        encryptToSelfFingerprint: nil,
                        progress: operation.progress
                    )
                }
            }
            """
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.screenModelStreamingProgressOwnership
                .violations(in: [staleOperationProgressSource])
                .map(\.path),
            [staleOperationProgressSource.path]
        )

        let staleOperationControllerProgressSource = AuditedSource(
            path: "Sources/App/Sign/NewSignScreenModel.swift",
            contents: """
            final class NewSignScreenModel {
                func sign(service: SigningService, operationController: OperationController) async throws {
                    _ = try await service.signDetachedStreaming(
                        fileURL: URL(fileURLWithPath: "/tmp/input"),
                        signerFingerprint: "ABCD",
                        progress: operationController.progress
                    )
                }
            }
            """
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.screenModelStreamingProgressOwnership
                .violations(in: [staleOperationControllerProgressSource])
                .map(\.path),
            [staleOperationControllerProgressSource.path]
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.generatedFFITypes.withTemporaryExceptions([
                "Sources/Services/FileProgressReporter.swift": "fixture exception"
            ]),
            violatingPath: "Sources/App/NewReporterFactory.swift",
            violatingContents: "struct NewReporterFactory { let reporter: ProgressReporterImpl }",
            allowedPath: "Sources/Services/FileProgressReporter.swift",
            allowedContents: "struct FileProgressReporterBox { let reporter: ProgressReporterImpl }",
            cleanContents: "struct FileProgressReporterBox {}"
        )

        let embeddedProtectedDataMockSource = AuditedSource(
            path: "Sources/Security/ProtectedData/NewStore.swift",
            contents: "final class MockProtectedDataThing {}"
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.securityMockImplementationContainment
                .violations(in: [embeddedProtectedDataMockSource])
                .map(\.path),
            [embeddedProtectedDataMockSource.path]
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.protectedDataMockImplementationContainment
                .violations(in: [embeddedProtectedDataMockSource])
                .map(\.path),
            [embeddedProtectedDataMockSource.path]
        )

        let temporaryMockDirectorySource = AuditedSource(
            path: "Sources/Security/Mocks/MockNewStore.swift",
            contents: "final class MockNewStore {}"
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.securityMockImplementationContainment
                .violations(in: [temporaryMockDirectorySource])
                .isEmpty
        )

        let mockKeychainErrorSource = AuditedSource(
            path: "Sources/Security/NewStore.swift",
            contents: "func check(_ error: Error) -> Bool { error is MockKeychainError }"
        )
        XCTAssertEqual(
            ArchitectureSourceAuditRules.productionMockKeychainErrorReferences
                .violations(in: [mockKeychainErrorSource])
                .map(\.path),
            [mockKeychainErrorSource.path]
        )

        let mockKeychainErrorInTemporaryMockSource = AuditedSource(
            path: "Sources/Security/Mocks/MockKeychain.swift",
            contents: "enum MockKeychainError: Error {}"
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.productionMockKeychainErrorReferences
                .violations(in: [mockKeychainErrorInTemporaryMockSource])
                .isEmpty
        )
    }

    func test_sourceAuditRules_ignoreCommentsAndStringLiterals() throws {
        let source = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: """
            // PgpEngine, PgpError, PGPErrorMapper, and PGPKeyMetadataAdapter should be ignored in comments.
            let message = "KeyInfo [Contact] import SwiftUI"
            let raw = #"ProgressReporterImpl KeyProfile Array<Contact> PGPCertificateSelectionAdapter PGPErrorMapper"#
            struct NewView {}
            """
        )

        XCTAssertTrue(
            ArchitectureSourceAuditRules.generatedFFITypes.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.generatedErrorMappingContainment.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.appLayerPgpErrorHandling.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.appLayerFFIAdapterUsage.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.phase5WorkflowExternalSignerContainment.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.phase6WorkflowExternalKeyAgreementContainment.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.phase5ExternalSignerRuntimeContainment.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.phase5KeyManagementCustodySwitchContainment.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.contactsRouteViewWorkflowContainment.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.contactArrayRuntimeDependencies.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.contactsLegacyRuntimeVocabulary.violations(in: [source]).isEmpty
        )

        let modelsSource = AuditedSource(
            path: "Sources/Models/NewDomainModel.swift",
            contents: """
            // import SwiftUI should be ignored in comments.
            // String(localized:) should be ignored in comments.
            // ProtectedDataError and ProtectedSettingsStore should be ignored in comments.
            let note = "import SwiftUI String(localized:) ProtectedDataError ProtectedSettingsStore"
            struct NewDomainModel {}
            """
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.modelsSwiftUIPresentationPolicy.violations(in: [modelsSource]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.modelsLocalizedPresentationText.violations(in: [modelsSource]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.modelsSecurityImplementationVocabulary.violations(in: [modelsSource]).isEmpty
        )

        let screenModelSource = AuditedSource(
            path: "Sources/App/Contacts/NewScreenModel.swift",
            contents: """
            // PhotosPickerItem and import PhotosUI should be ignored in comments.
            let message = "PhotosPickerItem import PhotosUI"
            final class NewScreenModel {}
            """
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.screenModelPhotosUIContainment.violations(in: [screenModelSource]).isEmpty
        )

        let screenModelAPISource = AuditedSource(
            path: "Sources/App/Sign/NewScreenModel.swift",
            contents: """
            // FileProgressReporter, AppTemporaryArtifact, and DecryptionService.Phase1Result should be ignored in comments.
            let message = "FileProgressReporter AppTemporaryArtifact DecryptionService.Phase1Result"
            final class NewScreenModel {}
            """
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.screenModelPublicAPIContainment.violations(in: [screenModelAPISource]).isEmpty
        )

        let progressStateReadSource = AuditedSource(
            path: "Sources/App/Encrypt/NewScreenModel.swift",
            contents: """
            final class NewScreenModel {
                var showsProgress: Bool {
                    operation.isRunning && operation.progress != nil
                }
            }
            """
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.screenModelStreamingProgressOwnership
                .violations(in: [progressStateReadSource])
                .isEmpty
        )

        let mockSource = AuditedSource(
            path: "Sources/Security/ProtectedData/NewStore.swift",
            contents: """
            // final class MockProtectedDataThing {}
            let message = "MockKeychainError final class MockProtectedDataThing"
            struct NewStore {}
            """
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.securityMockImplementationContainment
                .violations(in: [mockSource])
                .isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.protectedDataMockImplementationContainment
                .violations(in: [mockSource])
                .isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.productionMockKeychainErrorReferences
                .violations(in: [mockSource])
                .isEmpty
        )
    }

    func test_sourceAuditRules_preserveStringInterpolationCode() throws {
        let generatedInterpolationSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: #"""
            struct NewView {
                let profile = "\(KeyProfile.advanced)"
            }
            """#
        )
        let generatedViolations = ArchitectureSourceAuditRules.generatedFFITypes
            .violations(in: [generatedInterpolationSource])
        XCTAssertEqual(generatedViolations.map(\.path), ["Sources/App/NewView.swift"])
        XCTAssertEqual(generatedViolations.first?.matches, ["KeyProfile"])

        let pgpErrorInterpolationSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: #"""
            struct NewView {
                let message = "\(PgpError.cancelled)"
            }
            """#
        )
        let pgpErrorViolations = ArchitectureSourceAuditRules.appLayerPgpErrorHandling
            .violations(in: [pgpErrorInterpolationSource])
        XCTAssertEqual(pgpErrorViolations.map(\.path), ["Sources/App/NewView.swift"])
        XCTAssertEqual(pgpErrorViolations.first?.matches, ["PgpError"])

        let adapterInterpolationSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: #"""
            struct NewView {
                let adapterName = "\(PGPKeyMetadataAdapter.self)"
            }
            """#
        )
        let adapterViolations = ArchitectureSourceAuditRules.appLayerFFIAdapterUsage
            .violations(in: [adapterInterpolationSource])
        XCTAssertEqual(adapterViolations.map(\.path), ["Sources/App/NewView.swift"])
        XCTAssertEqual(adapterViolations.first?.matches, ["PGPKeyMetadataAdapter"])

        let rawInterpolationSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: ##"""
            struct NewView {
                let profile = #"\#(KeyProfile.advanced)"#
            }
            """##
        )
        let rawViolations = ArchitectureSourceAuditRules.generatedFFITypes
            .violations(in: [rawInterpolationSource])
        XCTAssertEqual(rawViolations.map(\.path), ["Sources/App/NewView.swift"])
        XCTAssertEqual(rawViolations.first?.matches, ["KeyProfile"])

        let nestedStringAndCommentSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: #"""
            struct NewView {
                let message = "\(String(describing: "PgpError KeyProfile Array<Contact>") /* PgpError */)"
            }
            """#
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.generatedFFITypes
                .violations(in: [nestedStringAndCommentSource])
                .isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.generatedErrorMappingContainment
                .violations(in: [nestedStringAndCommentSource])
                .isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.appLayerPgpErrorHandling
                .violations(in: [nestedStringAndCommentSource])
                .isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.appLayerFFIAdapterUsage
                .violations(in: [nestedStringAndCommentSource])
                .isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.contactArrayRuntimeDependencies
                .violations(in: [nestedStringAndCommentSource])
                .isEmpty
        )

        let modelSecurityInterpolationSource = AuditedSource(
            path: "Sources/Models/NewDomainModel.swift",
            contents: #"""
            struct NewDomainModel {
                let message = "\(ProtectedDataError.authorizingUnavailable)"
            }
            """#
        )
        let modelSecurityViolations = ArchitectureSourceAuditRules.modelsSecurityImplementationVocabulary
            .violations(in: [modelSecurityInterpolationSource])
        XCTAssertEqual(modelSecurityViolations.map(\.path), ["Sources/Models/NewDomainModel.swift"])
        XCTAssertEqual(modelSecurityViolations.first?.matches, ["ProtectedDataError"])
    }

    private func assertRulePasses(
        _ rule: ArchitectureSourceAuditRule,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let sources = try productionSwiftSources()
        let violations = rule.violations(in: sources)
        XCTAssertTrue(
            violations.isEmpty,
            rule.violationMessage(for: violations),
            file: file,
            line: line
        )

        let staleExceptions = rule.staleTemporaryExceptions(in: sources)
        XCTAssertTrue(
            staleExceptions.isEmpty,
            rule.staleExceptionMessage(for: staleExceptions),
            file: file,
            line: line
        )
    }

    private func assertRuleBehavior(
        _ rule: ArchitectureSourceAuditRule,
        violatingPath: String,
        violatingContents: String,
        allowedPath: String,
        allowedContents: String,
        cleanContents: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let violatingSource = AuditedSource(path: violatingPath, contents: violatingContents)
        let allowedSource = AuditedSource(path: allowedPath, contents: allowedContents)
        let staleSource = AuditedSource(path: allowedPath, contents: cleanContents)
        let cleanSource = AuditedSource(path: violatingPath, contents: cleanContents)

        XCTAssertEqual(
            rule.violations(in: [violatingSource]).map(\.path),
            [violatingPath],
            file: file,
            line: line
        )
        XCTAssertTrue(
            rule.violations(in: [allowedSource]).isEmpty,
            file: file,
            line: line
        )
        XCTAssertEqual(
            rule.staleTemporaryExceptions(in: [staleSource]).map(\.path),
            [allowedPath],
            file: file,
            line: line
        )
        XCTAssertTrue(
            rule.violations(in: [cleanSource]).isEmpty,
            file: file,
            line: line
        )
    }

    private func productionSwiftSources() throws -> [AuditedSource] {
        try RepositoryAuditLoader.swiftSourceRelativePaths()
            .filter { !$0.hasPrefix("Sources/PgpMobile/") }
            .map { path in
                AuditedSource(
                    path: path,
                    contents: try RepositoryAuditLoader.loadString(relativePath: path)
                )
            }
    }
}

private enum ArchitectureSourceAuditRules {
    static let generatedFFITypes = ArchitectureSourceAuditRule(
        name: "Generated UniFFI type containment",
        failureSummary: "Generated UniFFI types should not leak into new upper-layer source files.",
        pattern: wordPattern(for: [
            "ArmorKind",
            "CertificateMergeOutcome",
            "CertificateMergeResult",
            "CertificateSignatureResult",
            "CertificateSignatureStatus",
            "CertificationKind",
            "DecryptDetailedResult",
            "DetailedSignatureEntry",
            "DetailedSignatureStatus",
            "DiscoveredCertificateSelectors",
            "DiscoveredSubkey",
            "DiscoveredUserId",
            "FileDecryptDetailedResult",
            "FileVerifyDetailedResult",
            "ExternalP256KeyAgreementError",
            "ExternalP256KeyAgreementFailureCategory",
            "ExternalP256KeyAgreementProvider",
            "ExternalP256KeyAgreementRequest",
            "ExternalP256SigningError",
            "ExternalP256SigningFailureCategory",
            "ExternalP256SigningProvider",
            "GeneratedKey",
            "KeyInfo",
            "KeyProfile",
            "ModifyExpiryPublicResult",
            "ModifyExpiryResult",
            "P256EcdsaSignature",
            "P256RawSharedSecret",
            "PasswordDecryptResult",
            "PasswordDecryptStatus",
            "PasswordMessageFormat",
            "PgpEngine",
            "PgpEngineProtocol",
            "PgpError",
            "ProgressReporter",
            "ProgressReporterImpl",
            "PublicCertificateValidationResult",
            "S2kInfo",
            "SignatureStatus",
            "SignatureVerificationState",
            "UserIdSelectorInput",
            "VerifyDetailedResult",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "Composition roots may construct PgpEngine and FFI adapters while wiring the dependency graph.",
                [
                    "Sources/App/AppContainer.swift",
                    "Sources/App/Onboarding/TutorialSandboxContainer.swift",
                ]
            ),
            (
                "FFI adapter files intentionally contain generated UniFFI types while exposing app-owned contracts upward.",
                [
                    "Sources/Services/FFI/PGPErrorMapper.swift",
                    "Sources/Services/FFI/PGPCertificateOperationAdapter.swift",
                    "Sources/Services/FFI/PGPCertificateSelectionAdapter.swift",
                    "Sources/Services/FFI/PGPContactImportAdapter.swift",
                    "Sources/Services/FFI/PGPExternalP256KeyAgreementProviderBridge.swift",
                    "Sources/Services/FFI/PGPExternalP256SigningProviderBridge.swift",
                    "Sources/Services/FFI/PGPKeyMetadataAdapter.swift",
                    "Sources/Services/FFI/PGPKeyOperationAdapter.swift",
                    "Sources/Services/FFI/PGPMessageOperationAdapter.swift",
                    "Sources/Services/FFI/PGPMessageResultMapper.swift",
                    "Sources/Services/FFI/PGPSecureEnclaveCustodyGenerationAdapter.swift",
                    "Sources/Services/FFI/PGPSecureEnclaveCustodyPublicBindingInspector.swift",
                    "Sources/Services/FFI/PGPSelfTestOperationAdapter.swift",
                ]
            ),
            (
                "Security key-agreement bridge owns the Apple ECDH callback request boundary.",
                [
                    "Sources/Security/SecureEnclaveCustodyKeyAgreement.swift",
                ]
            ),
        ])
    )

    static let appLayerPgpErrorHandling = ArchitectureSourceAuditRule(
        name: "App-layer PgpError handling",
        failureSummary: "New App-layer files should not inspect generated PgpError directly.",
        pattern: #"\bPgpError\b"#,
        scope: { path in
            path.hasPrefix("Sources/App/") && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let generatedErrorMappingContainment = ArchitectureSourceAuditRule(
        name: "Generated error mapping containment",
        failureSummary: "Generated PgpError mapping should stay inside the FFI adapter boundary.",
        pattern: wordPattern(for: [
            "PGPErrorMapper",
            "PgpError",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "FFI adapter files intentionally normalize generated PgpError values into CypherAirError.",
                [
                    "Sources/Services/FFI/PGPErrorMapper.swift",
                    "Sources/Services/FFI/PGPCertificateOperationAdapter.swift",
                    "Sources/Services/FFI/PGPCertificateSelectionAdapter.swift",
                    "Sources/Services/FFI/PGPContactImportAdapter.swift",
                    "Sources/Services/FFI/PGPKeyOperationAdapter.swift",
                    "Sources/Services/FFI/PGPMessageOperationAdapter.swift",
                    "Sources/Services/FFI/PGPSecureEnclaveCustodyGenerationAdapter.swift",
                    "Sources/Services/FFI/PGPSecureEnclaveCustodyPublicBindingInspector.swift",
                    "Sources/Services/FFI/PGPSelfTestOperationAdapter.swift",
                ]
            ),
        ])
    )

    static let appLayerFFIAdapterUsage = ArchitectureSourceAuditRule(
        name: "App-layer FFI adapter usage",
        failureSummary: "App-layer files should not call FFI adapters directly.",
        pattern: wordPattern(for: [
            "PGPCertificateSelectionAdapter",
            "PGPCertificateOperationAdapter",
            "PGPContactImportAdapter",
            "PGPExternalP256KeyAgreementProviderBridge",
            "PGPExternalP256SigningProviderBridge",
            "PGPKeyMetadataAdapter",
            "PGPKeyOperationAdapter",
            "PGPMessageOperationAdapter",
            "PGPMessageResultMapper",
            "PGPErrorMapper",
            "PGPSecureEnclaveCustodyGenerationAdapter",
            "PGPSecureEnclaveCustodyPublicBindingInspector",
            "PGPSecureEnclaveExternalSigningProviderBridge",
            "PGPSelfTestOperationAdapter",
        ]),
        scope: { path in
            path.hasPrefix("Sources/App/") && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "Composition roots may construct FFI adapters while wiring the dependency graph.",
                [
                    "Sources/App/AppContainer.swift",
                    "Sources/App/Onboarding/TutorialSandboxContainer.swift",
                ]
            ),
        ])
    )

    static let modelsSwiftUIPresentationPolicy = ArchitectureSourceAuditRule(
        name: "Models SwiftUI presentation policy",
        failureSummary: "Core Models should not import SwiftUI.",
        pattern: #"^\s*import\s+SwiftUI\b"#,
        scope: { path in
            path.hasPrefix("Sources/Models/") && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        expressionOptions: [.anchorsMatchLines],
        temporaryExceptions: temporaryExceptions([])
    )

    static let modelsLocalizedPresentationText = ArchitectureSourceAuditRule(
        name: "Models localized presentation text",
        failureSummary: "Core Models should not own localized presentation text.",
        pattern: #"\bString\s*(?:\(\s*localized\s*:|\.localizedStringWithFormat\s*\()"#,
        scope: { path in
            path.hasPrefix("Sources/Models/") && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let modelsSecurityImplementationVocabulary = ArchitectureSourceAuditRule(
        name: "Models Security implementation vocabulary",
        failureSummary: "Core Models should not depend on Security or ProtectedData implementation vocabulary.",
        pattern: #"^\s*import\s+(?:LocalAuthentication|Security)\b|"# + wordPattern(for: [
            "AuthenticationManager",
            "KeychainConstants",
            "KeychainManager",
            "KeychainManageable",
            "LAContext",
            "ProtectedData",
            "ProtectedDataError",
            "ProtectedDataFrameworkState",
            "ProtectedDataPostUnlockOutcome",
            "ProtectedDataRegistry",
            "ProtectedDataSessionCoordinator",
            "ProtectedDataStorageRoot",
            "ProtectedDomainBootstrapStore",
            "ProtectedDomainKeyManager",
            "ProtectedSettingsDomainState",
            "ProtectedSettingsOrdinarySettingsPersistence",
            "ProtectedSettingsStore",
            "SecureEnclaveManageable",
            "SecureEnclaveManager",
        ]),
        scope: { path in
            path.hasPrefix("Sources/Models/") && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        expressionOptions: [.anchorsMatchLines],
        temporaryExceptions: temporaryExceptions([])
    )

    static let contactArrayRuntimeDependencies = ArchitectureSourceAuditRule(
        name: "Legacy Contact array runtime dependencies",
        failureSummary: "New production code should not introduce ordinary runtime Contact collection dependencies.",
        pattern: #"(?:\[\s*Contact\s*\]|\bArray\s*<\s*Contact\s*>)"#,
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let contactsLegacyRuntimeVocabulary = ArchitectureSourceAuditRule(
        name: "Contacts legacy runtime vocabulary",
        failureSummary: "Production sources must not reintroduce flat Contacts projection, migration, or repository code.",
        pattern: #"(?:availableLegacyCompatibility|openLegacyCompatibility|legacyKeyReplacementDetected|\bContactRepository\b|\bContactsLegacyMigrationSource\b|\bContactsCompatibilityMapper\b|\bstruct\s+Contact\b)"#,
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let privateOperationCustodySwitchContainment = ArchitectureSourceAuditRule(
        name: "Private operation custody switch containment",
        failureSummary: "Workflow services should route custody-specific private operations through the key-management router.",
        pattern: wordPattern(for: [
            "PGPPrivateKeyCustodyKind",
            "appleSecureEnclavePrivateOperations",
            "privateKeyCustodyKind",
            "softwareSecretCertificate",
        ]),
        scope: { path in
            path.hasPrefix("Sources/Services/")
                && !path.hasPrefix("Sources/Services/FFI/")
                && !path.hasPrefix("Sources/Services/KeyManagement/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let phase5KeyManagementCustodySwitchContainment = ArchitectureSourceAuditRule(
        name: "Phase 5 key-management custody switch containment",
        failureSummary: "Key-management custody switches should stay in resolver/router/storage/export boundaries or documented legacy fallbacks.",
        pattern: #"\b(?:PGPPrivateKeyCustodyKind|privateKeyCustodyKind)\b|\.\s*appleSecureEnclavePrivateOperations\b"#,
        scope: { path in
            path.hasPrefix("Sources/Services/KeyManagement/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "The resolver owns operation/custody policy decisions.",
                [
                    "Sources/Services/KeyManagement/PGPKeyCapabilityResolver.swift",
                ]
            ),
            (
                "The router owns Secure Enclave signer-route selection after resolver approval.",
                [
                    "Sources/Services/KeyManagement/PrivateKeyOperationRouter.swift",
                ]
            ),
            (
                "Hidden/test generation and recovery classify Secure Enclave custody metadata and handle state.",
                [
                    "Sources/Services/KeyManagement/SecureEnclaveCustodyGenerationRecoveryService.swift",
                    "Sources/Services/KeyManagement/SecureEnclaveCustodyGenerationService.swift",
                ]
            ),
            (
                "Catalog/export boundaries preserve custody metadata and enforce Secure Enclave private-export unsupported outcomes.",
                [
                    "Sources/Services/KeyManagement/KeyCatalogStore.swift",
                    "Sources/Services/KeyManagement/KeyExportService.swift",
                ]
            ),
            (
                "Provisioning persists explicit configuration identity and custody kind on every new software-custody record.",
                [
                    "Sources/Services/KeyManagement/KeyProvisioningService.swift",
                ]
            ),
            (
                "Phase 5G/5H keep narrow compatibility fallbacks for unconfigured tests; app and tutorial composition roots inject router-backed helpers.",
                [
                    "Sources/Services/KeyManagement/KeyMutationService.swift",
                    "Sources/Services/KeyManagement/SelectiveRevocationService.swift",
                ]
            ),
        ])
    )

    static let phase5WorkflowExternalSignerContainment = ArchitectureSourceAuditRule(
        name: "Phase 5 workflow external signer containment",
        failureSummary: "Workflow services should delegate external P-256 signer runtime calls to private-key helpers.",
        pattern: phase5ExternalSignerRuntimePattern,
        scope: { path in
            phase5WorkflowServicePaths.contains(path)
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let phase5ExternalSignerRuntimeContainment = ArchitectureSourceAuditRule(
        name: "Phase 5 external signer runtime containment",
        failureSummary: "External P-256 signer runtime calls should stay inside FFI adapters, hidden generation, and router-owned private-key helpers.",
        pattern: phase5ExternalSignerRuntimePattern,
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "FFI adapters and the shared provider bridge intentionally touch generated external signer APIs.",
                [
                    "Sources/Services/FFI/PGPCertificateOperationAdapter.swift",
                    "Sources/Services/FFI/PGPExternalP256SigningProviderBridge.swift",
                    "Sources/Services/FFI/PGPKeyOperationAdapter.swift",
                    "Sources/Services/FFI/PGPMessageOperationAdapter.swift",
                    "Sources/Services/FFI/PGPSecureEnclaveCustodyGenerationAdapter.swift",
                ]
            ),
            (
                "Router-owned Phase 5 helpers are the only service boundary allowed to invoke external signer runtime adapters.",
                [
                    "Sources/Services/KeyManagement/PrivateKeyCleartextSigningService.swift",
                    "Sources/Services/KeyManagement/PrivateKeyContactCertificationService.swift",
                    "Sources/Services/KeyManagement/PrivateKeyDetachedFileSigningService.swift",
                    "Sources/Services/KeyManagement/PrivateKeyExpiryMutationService.swift",
                    "Sources/Services/KeyManagement/PrivateKeyPasswordMessageEncryptionService.swift",
                    "Sources/Services/KeyManagement/PrivateKeySelectiveRevocationService.swift",
                    "Sources/Services/KeyManagement/PrivateKeyStreamingFileEncryptionService.swift",
                    "Sources/Services/KeyManagement/PrivateKeyTextEncryptionService.swift",
                ]
            ),
        ])
    )

    static let phase6ExternalKeyAgreementRuntimeContainment = ArchitectureSourceAuditRule(
        name: "Phase 6 external key-agreement runtime containment",
        failureSummary: "External P-256 key-agreement runtime calls should stay inside FFI, Security, and router-owned helper boundaries.",
        pattern: phase6ExternalKeyAgreementRuntimePattern,
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "FFI adapter and provider bridge intentionally expose the external P-256 key-agreement callback API.",
                [
                    "Sources/Services/FFI/PGPErrorMapper.swift",
                    "Sources/Services/FFI/PGPExternalP256KeyAgreementProviderBridge.swift",
                    "Sources/Services/FFI/PGPMessageOperationAdapter.swift",
                ]
            ),
            (
                "Security bridge owns Apple P-256 ECDH callback request handling.",
                [
                    "Sources/Security/SecureEnclaveCustodyKeyAgreement.swift",
                ]
            ),
            (
                "Router-owned Phase 6 decrypt helpers are the only service boundary allowed to consume the external P-256 key-agreement route.",
                [
                    "Sources/Services/KeyManagement/PrivateKeyMessageDecryptionService.swift",
                    "Sources/Services/KeyManagement/PrivateKeyStreamingFileDecryptionService.swift",
                ]
            ),
        ])
    )

    static let phase6WorkflowExternalKeyAgreementContainment = ArchitectureSourceAuditRule(
        name: "Phase 6 workflow external key-agreement containment",
        failureSummary: "Decrypt-class workflow services should delegate external P-256 key-agreement runtime calls to router-owned private-key decrypt helpers.",
        pattern: phase6ExternalKeyAgreementRuntimePattern,
        scope: { path in
            phase6WorkflowServicePaths.contains(path)
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let keyRouteViewWorkflowContainment = ArchitectureSourceAuditRule(
        name: "Key route view workflow containment",
        failureSummary: "Key-management route Views should send intent to ScreenModels instead of calling key workflow services directly.",
        pattern: #"\b(?:keyManagement|service)\s*\.\s*(?:generateKey|importKey|exportKeyBackupData|exportKey|modifyExpiry|exportRevocationCertificate|exportSubkeyRevocationCertificate|exportUserIdRevocationCertificate|loadSelectionCatalog|setDefaultKey|deleteKey|confirmKeyBackupExported)\s*\("#,
        scope: { path in
            keyRouteViewPaths.contains(path)
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let contactsRouteViewWorkflowContainment = ArchitectureSourceAuditRule(
        name: "Contacts route view workflow containment",
        failureSummary: "Contacts route Views should send intent to ScreenModels or coordinators instead of calling contact or QR workflow services directly.",
        pattern: #"\b(?:contactService|qrService|importLoader|importWorkflow|service)\s*\.\s*(?:generateQRCode|parseImportURL|inspectImportablePublicCertificate|inspectKeyMetadata|detectKeyProfile|decodeQRCodes|loadKeyDataFromQRPhoto|loadFromQRPhoto|loadFromURL|inspect|loadFromFile|makeImportConfirmationRequest|importContact|removeContactIdentity|mergeContact|addTag|assignTag|removeTag|setVerificationState|setPreferredKey|setKeyUsageState|contactIdentities|availableContactIdentity|availableContactKeyRecord|contactTagSummaries|tagSuggestions|createTag|replaceTagMembership|renameTag|deleteTag|requireContactPublicKeyData)\s*\("#,
        scope: { path in
            isContactsViewPath(path)
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let screenModelPhotosUIContainment = ArchitectureSourceAuditRule(
        name: "ScreenModel PhotosUI containment",
        failureSummary: "ScreenModels should expose app-owned selection values instead of PhotosUI picker types.",
        pattern: #"^\s*import\s+PhotosUI\b|\bPhotosPickerItem\b"#,
        scope: { path in
            path.hasPrefix("Sources/App/") && path.hasSuffix("ScreenModel.swift")
        },
        stripsCommentsAndStrings: true,
        expressionOptions: [.anchorsMatchLines],
        temporaryExceptions: temporaryExceptions([])
    )

    static let screenModelPublicAPIContainment = ArchitectureSourceAuditRule(
        name: "ScreenModel public API containment",
        failureSummary: "ScreenModels should expose app-owned request/result values instead of service phase, progress, or temporary-artifact internals.",
        pattern: #"\bDecryptionService\s*\.\s*(?:Phase1Result|FilePhase1Result)\b|\b(?:FileProgressReporter|AppTemporaryArtifact)\b"#,
        scope: { path in
            path.hasPrefix("Sources/App/") && path.hasSuffix("ScreenModel.swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let screenModelStreamingProgressOwnership = ArchitectureSourceAuditRule(
        name: "ScreenModel streaming progress ownership",
        failureSummary: "ScreenModel streaming service calls must use the per-operation progress reporter passed by runFileOperation.",
        pattern: #"\bprogress\s*:\s*(?:operation|operationController)\s*\.\s*progress\b"#,
        scope: { path in
            path.hasPrefix("Sources/App/") && path.hasSuffix("ScreenModel.swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let securityMockImplementationContainment = ArchitectureSourceAuditRule(
        name: "Security mock implementation containment",
        failureSummary: "Mock implementations in production sources must stay in the temporary Sources/Security/Mocks debt area.",
        pattern: mockTypeDeclarationPattern,
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && !path.hasPrefix("Sources/Security/Mocks/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let protectedDataMockImplementationContainment = ArchitectureSourceAuditRule(
        name: "ProtectedData mock implementation containment",
        failureSummary: "ProtectedData production files must not embed mock implementations.",
        pattern: mockTypeDeclarationPattern,
        scope: { path in
            path.hasPrefix("Sources/Security/ProtectedData/") && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let productionMockKeychainErrorReferences = ArchitectureSourceAuditRule(
        name: "Production MockKeychainError references",
        failureSummary: "Production code outside the temporary mock directory must not reference MockKeychainError directly.",
        pattern: #"\bMockKeychainError\b"#,
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && !path.hasPrefix("Sources/Security/Mocks/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let protectedDataAuthorizationConcreteKeychainErrorClassification = ArchitectureSourceAuditRule(
        name: "ProtectedData authorization keychain failure classification",
        failureSummary: "ProtectedData authorization must classify keychain failures through KeychainFailureClassifier, not concrete KeychainError casts.",
        pattern: #"\bas\s*\?\s*KeychainError\b"#,
        scope: { path in
            path == "Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift"
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    // MARK: - Legacy-cleanup reintroduction guardrails (2026-06-08 support cutoff)
    //
    // Each rule forbids Swift symbols that strict legacy-retirement cleanup removes
    // (docs/LEGACY_CLEANUP.md, 2026-06-08 cutoff). Until that PR lands, the production file
    // that still holds the symbol is listed as a temporary allowance. The removal PR must delete the
    // symbol AND its matching allowance in lockstep: `assertRulePasses` fails if a symbol is gone but
    // its allowance remains, or if an allowance is dropped while the symbol still exists. See
    // docs/LEGACY_CLEANUP.md Guardrails.
    //
    // Item #9 (Swift) symbols — legacyStatus, legacySignerFingerprint, legacySignerIdentity,
    // legacyVerification — are added when Phase 6 retires the remaining Rust/UniFFI legacy signature
    // surface and generated Swift fields.

    static let legacyCleanupKeyMetadataMigrationSymbols = ArchitectureSourceAuditRule(
        name: "Legacy cleanup #2 key-metadata migration symbols",
        failureSummary: "Legacy key-metadata migration symbols are removed under the 2026-06-08 cutoff and must not be reintroduced.",
        pattern: wordPattern(for: [
            "migrateLegacyMetadataIfNeeded",
            "loadMigrationSourceSnapshot",
            "cleanupMigrationSourceItems",
            "KeyMetadataLegacyMigrationOutcome",
            "KeyMetadataMigrationSourceItem",
            "KeyMetadataMigrationSourceSnapshot",
            "cleanupLegacyMetadataRows",
            "cleanupLegacyRowsMatchingOpenedPayload",
            "borrowAuthenticatedContextForMetadataMigration",
            "sourceSchemaVersion",
            "metadataAccount",
            "metadataPrefix",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let legacyCleanupPrivateKeyControlDefaultsSymbols = ArchitectureSourceAuditRule(
        name: "Legacy cleanup #3 private-key-control defaults symbols",
        failureSummary: "Legacy private-key-control defaults symbols are removed under the 2026-06-08 cutoff and must not be reintroduced.",
        pattern: wordPattern(for: [
            "legacyInitialPayload",
            "cleanupLegacyDefaults",
            "invalidLegacyAuthMode",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "Item #3 private-key-control legacy UserDefaults import/cleanup; removed by LEGACY_CLEANUP Phase 4 under the 2026-06-08 cutoff.",
                [
                    "Sources/Security/ProtectedData/PrivateKeyControlStore.swift",
                    "Sources/Security/AuthenticationEvaluable.swift",
                ]
            ),
        ])
    )

    static let legacyCleanupProtectedSettingsMigrationSymbols = ArchitectureSourceAuditRule(
        name: "Legacy cleanup #4 protected-settings migration symbols",
        failureSummary: "Legacy protected-settings v1→v2 / ordinary-settings migration symbols are removed under the 2026-06-08 cutoff and must not be reintroduced.",
        pattern: wordPattern(for: [
            "requiresOrdinarySettingsMigration",
            "migrateOpenedSettingsSnapshotIfNeeded",
            "legacyOrdinarySettingsSnapshot",
            "removeLegacySettingsSources",
            "ensureCommittedAndMigrateSettingsIfNeeded",
            "migrationAuthorizationRequirement",
            "LegacyOrdinarySettingsStore",
            "ProtectedOrdinarySettingsLegacyKeys",
            "clipboardNoticeLegacyKey",
            "PayloadV1",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let legacyCleanupContactsSnapshotMigrationSymbols = ArchitectureSourceAuditRule(
        name: "Legacy cleanup #5 contacts snapshot migration symbols",
        failureSummary: "Legacy contacts snapshot v1→v2 migration symbols are removed under the 2026-06-08 cutoff and must not be reintroduced.",
        pattern: wordPattern(for: [
            "LegacySnapshotV1",
            "migrateLegacyV1Snapshot",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let legacyCleanupContactsArtifactSentinelSymbols = ArchitectureSourceAuditRule(
        name: "Legacy cleanup Phase 1 contacts certification-artifact and sentinel symbols",
        failureSummary: "Phase 1 contacts certification-artifact defaulting and \"Unknown\" sentinel symbols are removed under the 2026-06-08 cutoff and must not be reintroduced.",
        pattern: wordPattern(for: [
            "legacyTargetSelector",
            "legacyUserIdDisplayText",
            "legacyUnknownDisplayName",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    static let legacyCleanupRootSecretRightStoreSymbols = ArchitectureSourceAuditRule(
        name: "Legacy cleanup #1A root-secret right-store symbols",
        failureSummary: "Legacy root-secret right-store migration symbols are removed under the 2026-06-08 cutoff and must not be reintroduced.",
        pattern: wordPattern(for: [
            "legacyRightStoreClient",
            "migrateLegacySharedRightIfNeeded",
            "legacyMigrationDeferred",
            "allowLegacyMigration",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "Item #1A legacy LARight right-store migration; removed under the strict retirement roadmap. Current root-secret envelope and device-binding coverage use current-model data.",
                [
                    "Sources/App/AppContainer.swift",
                    "Sources/App/Settings/LocalDataResetService.swift",
                    "Sources/Security/ProtectedData/ProtectedDataRootSecretCoordinator.swift",
                    "Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift",
                    "Sources/Security/ProtectedData/ProtectedDataPostUnlockCoordinator.swift",
                ]
            ),
        ])
    )

    static let legacyCleanupRawRootSecretSymbols = ArchitectureSourceAuditRule(
        name: "Legacy cleanup #1B raw-v1 root-secret symbols",
        failureSummary: "Legacy raw-v1 root-secret migration symbols are removed under the 2026-06-08 cutoff and must not be reintroduced.",
        pattern: wordPattern(for: [
            "migrateLegacyRawRootSecret",
            "legacyV1Raw",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "Item #1B raw-v1 root-secret migration; removed under the strict retirement roadmap. Current root-secret format-floor coverage must not seed or name raw-v1 data.",
                [
                    "Sources/Security/ProtectedData/ProtectedDataRightStoreClient.swift",
                ]
            ),
        ])
    )

    static let legacyCleanupRevocationBackfillSymbols = ArchitectureSourceAuditRule(
        name: "Legacy cleanup #7 revocation backfill symbols",
        failureSummary: "Legacy imported-key revocation backfill symbol is removed under the 2026-06-08 cutoff and must not be reintroduced.",
        pattern: wordPattern(for: [
            "updateRevocation",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([])
    )

    private static let keyRouteViewPaths: Set<String> = [
        "Sources/App/Keys/BackupKeyView.swift",
        "Sources/App/Keys/ImportKeyView.swift",
        "Sources/App/Keys/KeyDetailView.swift",
        "Sources/App/Keys/KeyGenerationView.swift",
        "Sources/App/Keys/ModifyExpiry/ModifyExpirySheetView.swift",
        "Sources/App/Keys/SelectiveRevocationView.swift",
    ]

    private static let phase5WorkflowServicePaths: Set<String> = [
        "Sources/Services/CertificateSignatureService.swift",
        "Sources/Services/EncryptionService.swift",
        "Sources/Services/KeyManagementService.swift",
        "Sources/Services/PasswordMessageService.swift",
        "Sources/Services/SigningService.swift",
    ]

    private static let phase6WorkflowServicePaths: Set<String> = [
        "Sources/Services/DecryptionService.swift",
    ]

    private static let phase5ExternalSignerRuntimePattern =
        #"\b(?:PGPExternalP256SigningProviderBridge|PGPSecureEnclaveExternalSigningProviderBridge|[A-Za-z0-9_]*WithExternalP256Signer)\b"#

    private static let phase6ExternalKeyAgreementRuntimePattern =
        #"\b(?:PGPExternalP256KeyAgreementProviderBridge|ExternalP256KeyAgreementProvider|ExternalP256KeyAgreementRequest|ExternalP256KeyAgreementError|ExternalP256KeyAgreementFailureCategory|P256RawSharedSecret|[A-Za-z0-9_]*WithExternalP256KeyAgreement)\b"#

    private static func isContactsViewPath(_ path: String) -> Bool {
        path.hasPrefix("Sources/App/Contacts/")
            && path.hasSuffix("View.swift")
    }

    private static let mockTypeDeclarationPattern =
        #"\b(?:(?:private|fileprivate|internal|public|package)\s+)*(?:final\s+)?(?:class|struct|enum|actor)\s+Mock[A-Za-z0-9_]*\b"#

    private static func wordPattern(for symbols: [String]) -> String {
        let alternation = symbols
            .sorted { lhs, rhs in
                if lhs.count != rhs.count {
                    return lhs.count > rhs.count
                }
                return lhs < rhs
            }
            .map(NSRegularExpression.escapedPattern(for:))
            .joined(separator: "|")
        return "\\b(?:\(alternation))\\b"
    }

    private static func temporaryExceptions(
        _ groups: [(reason: String, paths: [String])]
    ) -> [String: String] {
        var exceptions: [String: String] = [:]
        for group in groups {
            for path in group.paths {
                precondition(exceptions[path] == nil, "Duplicate source-audit exception: \(path)")
                exceptions[path] = group.reason
            }
        }
        return exceptions
    }
}

private struct AuditedSource {
    let path: String
    let contents: String
}

private struct ArchitectureSourceAuditRule: @unchecked Sendable {
    let name: String
    let failureSummary: String
    let expression: NSRegularExpression
    let scope: (String) -> Bool
    let stripsCommentsAndStrings: Bool
    let temporaryExceptions: [String: String]

    init(
        name: String,
        failureSummary: String,
        pattern: String,
        scope: @escaping (String) -> Bool,
        stripsCommentsAndStrings: Bool,
        expressionOptions: NSRegularExpression.Options = [],
        temporaryExceptions: [String: String]
    ) {
        self.name = name
        self.failureSummary = failureSummary
        self.expression = try! NSRegularExpression(pattern: pattern, options: expressionOptions)
        self.scope = scope
        self.stripsCommentsAndStrings = stripsCommentsAndStrings
        self.temporaryExceptions = temporaryExceptions
    }

    private init(
        name: String,
        failureSummary: String,
        expression: NSRegularExpression,
        scope: @escaping (String) -> Bool,
        stripsCommentsAndStrings: Bool,
        temporaryExceptions: [String: String]
    ) {
        self.name = name
        self.failureSummary = failureSummary
        self.expression = expression
        self.scope = scope
        self.stripsCommentsAndStrings = stripsCommentsAndStrings
        self.temporaryExceptions = temporaryExceptions
    }

    func withTemporaryExceptions(_ exceptions: [String: String]) -> Self {
        Self(
            name: name,
            failureSummary: failureSummary,
            expression: expression,
            scope: scope,
            stripsCommentsAndStrings: stripsCommentsAndStrings,
            temporaryExceptions: exceptions
        )
    }

    func violations(in sources: [AuditedSource]) -> [ArchitectureSourceAuditViolation] {
        sources
            .filter { scope($0.path) }
            .compactMap { source in
                let matches = matches(in: source)
                guard !matches.isEmpty, temporaryExceptions[source.path] == nil else {
                    return nil
                }
                return ArchitectureSourceAuditViolation(path: source.path, matches: matches)
            }
            .sorted { $0.path < $1.path }
    }

    func staleTemporaryExceptions(in sources: [AuditedSource]) -> [ArchitectureSourceAuditStaleException] {
        let sourcesByPath = Dictionary(uniqueKeysWithValues: sources.map { ($0.path, $0) })
        return temporaryExceptions
            .map { path, reason in
                guard let source = sourcesByPath[path] else {
                    return ArchitectureSourceAuditStaleException(
                        path: path,
                        reason: reason,
                        problem: "file is no longer present in the RepositoryAudit snapshot"
                    )
                }
                guard scope(path) else {
                    return ArchitectureSourceAuditStaleException(
                        path: path,
                        reason: reason,
                        problem: "file is outside this rule's audited scope"
                    )
                }
                guard matches(in: source).isEmpty else {
                    return nil
                }
                return ArchitectureSourceAuditStaleException(
                    path: path,
                    reason: reason,
                    problem: "exception no longer matches this rule and should be removed"
                )
            }
            .compactMap { $0 }
            .sorted { $0.path < $1.path }
    }

    func violationMessage(for violations: [ArchitectureSourceAuditViolation]) -> String {
        let details = violations.map { violation in
            "- \(violation.path): \(violation.matches.joined(separator: ", "))"
        }
        return ([failureSummary, "Unexpected matches:"] + details).joined(separator: "\n")
    }

    func staleExceptionMessage(for exceptions: [ArchitectureSourceAuditStaleException]) -> String {
        let details = exceptions.map { stale in
            "- \(stale.path): \(stale.problem). Reason was: \(stale.reason)"
        }
        return (["\(name) has stale temporary exceptions:"] + details).joined(separator: "\n")
    }

    private func matches(in source: AuditedSource) -> [String] {
        let text = stripsCommentsAndStrings
            ? SwiftSourceSanitizer.codeOnly(source.contents)
            : source.contents
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        let matches = expression.matches(in: text, range: range).compactMap { match -> String? in
            guard let matchRange = Range(match.range, in: text) else {
                return nil
            }
            return String(text[matchRange]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return Array(Set(matches)).sorted()
    }
}

private struct ArchitectureSourceAuditViolation {
    let path: String
    let matches: [String]
}

private struct ArchitectureSourceAuditStaleException {
    let path: String
    let reason: String
    let problem: String
}

private enum SwiftSourceSanitizer {
    static func codeOnly(_ text: String) -> String {
        var result = ""
        var index = text.startIndex

        while index < text.endIndex {
            if text[index...].hasPrefix("//") {
                replaceLineComment(in: text, index: &index, result: &result)
            } else if text[index...].hasPrefix("/*") {
                replaceBlockComment(in: text, index: &index, result: &result)
            } else if let literal = stringLiteralStart(in: text, at: index) {
                replaceStringLiteral(
                    in: text,
                    index: &index,
                    result: &result,
                    literal: literal
                )
            } else {
                result.append(text[index])
                index = text.index(after: index)
            }
        }

        return result
    }

    private static func replaceLineComment(
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        while index < text.endIndex {
            let character = text[index]
            appendPlaceholder(for: character, result: &result)
            index = text.index(after: index)
            if character == "\n" {
                break
            }
        }
    }

    private static func replaceBlockComment(
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        var depth = 0
        while index < text.endIndex {
            if text[index...].hasPrefix("/*") {
                depth += 1
                replaceCharacters(2, in: text, index: &index, result: &result)
            } else if text[index...].hasPrefix("*/") {
                depth -= 1
                replaceCharacters(2, in: text, index: &index, result: &result)
                if depth == 0 {
                    break
                }
            } else {
                replaceCharacters(1, in: text, index: &index, result: &result)
            }
        }
    }

    private static func replaceStringLiteral(
        in text: String,
        index: inout String.Index,
        result: inout String,
        literal: StringLiteralStart
    ) {
        replaceCharacters(literal.openingLength, in: text, index: &index, result: &result)

        if literal.isMultiline {
            replaceMultilineStringBody(
                in: text,
                index: &index,
                result: &result,
                hashCount: literal.hashCount
            )
        } else {
            replaceSingleLineStringBody(
                in: text,
                index: &index,
                result: &result,
                hashCount: literal.hashCount
            )
        }
    }

    private static func replaceSingleLineStringBody(
        in text: String,
        index: inout String.Index,
        result: inout String,
        hashCount: Int
    ) {
        var escaped = false
        while index < text.endIndex {
            if hashCount == 0, escaped {
                let character = text[index]
                replaceCharacters(1, in: text, index: &index, result: &result)
                escaped = false
                if character == "\n" {
                    break
                }
                continue
            }

            if isInterpolationStart(hashCount: hashCount, in: text, at: index) {
                replaceInterpolationOpening(hashCount: hashCount, in: text, index: &index, result: &result)
                preserveInterpolationBody(in: text, index: &index, result: &result)
                continue
            }

            let character = text[index]
            replaceCharacters(1, in: text, index: &index, result: &result)

            if character == "\n" {
                break
            }
            if hashCount == 0, character == "\\" {
                escaped = true
                continue
            }
            if character == "\"", consumeClosingHashes(hashCount, in: text, index: &index, result: &result) {
                break
            }
        }
    }

    private static func replaceMultilineStringBody(
        in text: String,
        index: inout String.Index,
        result: inout String,
        hashCount: Int
    ) {
        while index < text.endIndex {
            if text[index...].hasPrefix("\"\"\"") {
                let cursor = text.index(index, offsetBy: 3)
                if hasHashes(hashCount, in: text, at: cursor) {
                    replaceCharacters(3, in: text, index: &index, result: &result)
                    _ = consumeClosingHashes(hashCount, in: text, index: &index, result: &result)
                    break
                }
            }
            if isInterpolationStart(hashCount: hashCount, in: text, at: index) {
                replaceInterpolationOpening(hashCount: hashCount, in: text, index: &index, result: &result)
                preserveInterpolationBody(in: text, index: &index, result: &result)
                continue
            }
            replaceCharacters(1, in: text, index: &index, result: &result)
        }
    }

    private static func preserveInterpolationBody(
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        var parenDepth = 0
        while index < text.endIndex {
            if text[index...].hasPrefix("//") {
                replaceLineComment(in: text, index: &index, result: &result)
            } else if text[index...].hasPrefix("/*") {
                replaceBlockComment(in: text, index: &index, result: &result)
            } else if let literal = stringLiteralStart(in: text, at: index) {
                replaceStringLiteral(
                    in: text,
                    index: &index,
                    result: &result,
                    literal: literal
                )
            } else {
                let character = text[index]
                if character == "(" {
                    result.append(character)
                    parenDepth += 1
                    index = text.index(after: index)
                } else if character == ")" {
                    if parenDepth == 0 {
                        appendPlaceholder(for: character, result: &result)
                        index = text.index(after: index)
                        break
                    }
                    result.append(character)
                    parenDepth -= 1
                    index = text.index(after: index)
                } else {
                    result.append(character)
                    index = text.index(after: index)
                }
            }
        }
    }

    private static func isInterpolationStart(
        hashCount: Int,
        in text: String,
        at index: String.Index
    ) -> Bool {
        guard text[index] == "\\" else {
            return false
        }

        var cursor = text.index(after: index)
        for _ in 0..<hashCount {
            guard cursor < text.endIndex, text[cursor] == "#" else {
                return false
            }
            cursor = text.index(after: cursor)
        }

        return cursor < text.endIndex && text[cursor] == "("
    }

    private static func replaceInterpolationOpening(
        hashCount: Int,
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        replaceCharacters(hashCount + 2, in: text, index: &index, result: &result)
    }

    private static func stringLiteralStart(in text: String, at index: String.Index) -> StringLiteralStart? {
        var cursor = index
        var hashCount = 0
        while cursor < text.endIndex, text[cursor] == "#" {
            hashCount += 1
            cursor = text.index(after: cursor)
        }

        guard cursor < text.endIndex, text[cursor] == "\"" else {
            return nil
        }

        let isMultiline = text[cursor...].hasPrefix("\"\"\"")
        return StringLiteralStart(
            hashCount: hashCount,
            isMultiline: isMultiline,
            openingLength: hashCount + (isMultiline ? 3 : 1)
        )
    }

    private static func consumeClosingHashes(
        _ count: Int,
        in text: String,
        index: inout String.Index,
        result: inout String
    ) -> Bool {
        guard hasHashes(count, in: text, at: index) else {
            return false
        }
        replaceCharacters(count, in: text, index: &index, result: &result)
        return true
    }

    private static func hasHashes(_ count: Int, in text: String, at index: String.Index) -> Bool {
        var cursor = index
        for _ in 0..<count {
            guard cursor < text.endIndex, text[cursor] == "#" else {
                return false
            }
            cursor = text.index(after: cursor)
        }
        return true
    }

    private static func replaceCharacters(
        _ count: Int,
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        for _ in 0..<count where index < text.endIndex {
            appendPlaceholder(for: text[index], result: &result)
            index = text.index(after: index)
        }
    }

    private static func appendPlaceholder(for character: Character, result: inout String) {
        result.append(character == "\n" ? "\n" : " ")
    }
}

private struct StringLiteralStart {
    let hashCount: Int
    let isMultiline: Bool
    let openingLength: Int
}
