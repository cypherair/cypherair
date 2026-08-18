import Foundation

enum TutorialSandboxContainerError: LocalizedError {
    case contactsProtectedDomainOpenFailed

    var errorDescription: String? {
        switch self {
        case .contactsProtectedDomainOpenFailed:
            String(localized: "guidedTutorial.error.contactsProtectedDomain", defaultValue: "Could not open isolated tutorial contacts storage.")
        }
    }
}

/// Isolated dependency graph for the guided tutorial.
///
/// Uses real app services backed by RAM-only stores and real, ephemeral
/// security primitives: software-key wrapping runs on the actual Secure
/// Enclave through `EphemeralKeyWrappingCustody` (promptless nil-ACL wrapping
/// keys whose representations live only inside envelope rows), and those
/// envelope rows live in an in-memory `EphemeralKeychainStore` that is wiped
/// on cleanup. The container names no storage root, no registry, no database,
/// and no preferences suite — the sandbox writes zero bytes to disk by
/// construction. Device-bound custody seams are wired to the inert
/// fail-closed conformances in `InertCustodyStores.swift`, so the sandbox
/// cannot reach real custody state by construction. The product flow owns a
/// single active tutorial sandbox at a time.
final class TutorialSandboxContainer {
    let engine: PgpEngine
    let keychain: EphemeralKeychainStore
    let authManager: AuthenticationManager
    let privateKeyControlStore: InMemoryPrivateKeyControlStore
    let config: AppConfiguration
    let protectedOrdinarySettingsCoordinator: ProtectedOrdinarySettingsCoordinator
    let contentClear = ContentClearSignal()
    let keyManagement: KeyManagementService
    let contactService: ContactService
    let encryptionService: EncryptionService
    let decryptionService: DecryptionService
    let signingService: SigningService
    let certificateSignatureService: CertificateSignatureService
    let qrService: QRService
    let selfTestService: SelfTestService

    private let keyWrappingCustody: EphemeralKeyWrappingCustody
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator

    init(temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()) {
        self.engine = PgpEngine()
        self.keyWrappingCustody = EphemeralKeyWrappingCustody()
        self.keychain = EphemeralKeychainStore()
        self.authenticationPromptCoordinator = AuthenticationPromptCoordinator()

        self.authManager = AuthenticationManager(
            secureEnclave: keyWrappingCustody,
            keychain: keychain,
            authenticationPromptCoordinator: authenticationPromptCoordinator
        )
        self.privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        self.authManager.configurePrivateKeyControlStore(privateKeyControlStore)
        self.config = AppConfiguration(preferences: InMemoryAppPreferenceStorage())
        self.config.privateKeyControlState = .unlocked(.standard)
        let protectedOrdinarySettingsCoordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: InMemoryOrdinarySettingsStore()
        )
        protectedOrdinarySettingsCoordinator.loadFromUngatedEphemeralPersistence()
        self.protectedOrdinarySettingsCoordinator = protectedOrdinarySettingsCoordinator
        let keyAdapter = PGPKeyOperationAdapter(engine: engine)
        let certificateAdapter = PGPCertificateOperationAdapter(engine: engine)
        let contactImportAdapter = PGPContactImportAdapter(engine: engine)
        let selfTestAdapter = PGPSelfTestOperationAdapter(engine: engine)
        self.keyManagement = KeyManagementService(
            keyAdapter: keyAdapter,
            certificateAdapter: certificateAdapter,
            secureEnclave: keyWrappingCustody,
            keychain: keychain,
            authenticationPromptCoordinator: authenticationPromptCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            metadataPersistence: InMemoryKeyMetadataStore()
        )
        try? self.keyManagement.loadKeys()
        self.contactService = ContactService(
            contactImportAdapter: contactImportAdapter,
            certificateAdapter: certificateAdapter,
            contactsDomainStore: InMemoryContactsDomainStore()
        )
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        // Inert fail-closed custody seams: the sandbox offers no device-bound
        // families, and must not be able to reach real custody state.
        let secureEnclaveCustodyHandleStore = SecureEnclaveCustodyHandleStore(
            keyStore: InertCustodyKeyStore(),
            tier: .classicalP256
        )
        let secureEnclaveDigestSigner = InertCustodyDigestSigner()
        let secureEnclaveCompositeOperations = InertCustodyCompositeOperations()
        keyManagement.configurePrivateKeyExpiryMutationService(
            PrivateKeyExpiryMutationService(
                router: keyManagement.makePrivateKeyOperationRouter(
                    publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                    handleStore: secureEnclaveCustodyHandleStore
                ),
                keyAdapter: keyAdapter,
                digestSigner: secureEnclaveDigestSigner,
                compositeSigner: secureEnclaveCompositeOperations
            )
        )
        keyManagement.configurePrivateKeySelectiveRevocationService(
            PrivateKeySelectiveRevocationService(
                router: keyManagement.makePrivateKeyOperationRouter(
                    publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                    handleStore: secureEnclaveCustodyHandleStore
                ),
                certificateAdapter: certificateAdapter,
                digestSigner: secureEnclaveDigestSigner,
                compositeSigner: secureEnclaveCompositeOperations
            )
        )
        let textEncryptor = PrivateKeyTextEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        let fileEncryptor = PrivateKeyStreamingFileEncryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        self.encryptionService = EncryptionService(
            keyManagement: keyManagement,
            contactService: contactService,
            textEncryptor: textEncryptor,
            fileEncryptor: fileEncryptor,
            temporaryArtifactStore: temporaryArtifactStore
        )
        let messageDecryptor = PrivateKeyMessageDecryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            keyAgreement: InertCustodyKeyAgreement(),
            compositeDecapsulator: secureEnclaveCompositeOperations
        )
        let fileDecryptor = PrivateKeyStreamingFileDecryptionService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            keyAgreement: InertCustodyKeyAgreement(),
            compositeDecapsulator: secureEnclaveCompositeOperations
        )
        self.decryptionService = DecryptionService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            messageDecryptor: messageDecryptor,
            fileDecryptor: fileDecryptor,
            temporaryArtifactStore: temporaryArtifactStore
        )
        let cleartextSigner = PrivateKeyCleartextSigningService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        let detachedFileSigner = PrivateKeyDetachedFileSigningService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            messageAdapter: messageAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        self.signingService = SigningService(
            messageAdapter: messageAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            cleartextSigner: cleartextSigner,
            detachedFileSigner: detachedFileSigner
        )
        let contactCertificationSigner = PrivateKeyContactCertificationService(
            router: keyManagement.makePrivateKeyOperationRouter(
                publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine),
                handleStore: secureEnclaveCustodyHandleStore
            ),
            softwarePrivateKeyAccess: keyManagement,
            certificateAdapter: certificateAdapter,
            digestSigner: secureEnclaveDigestSigner,
            compositeSigner: secureEnclaveCompositeOperations
        )
        self.certificateSignatureService = CertificateSignatureService(
            certificateAdapter: certificateAdapter,
            keyManagement: keyManagement,
            contactService: contactService,
            certificationSigner: contactCertificationSigner
        )
        self.qrService = QRService(contactImportAdapter: contactImportAdapter)
        self.selfTestService = SelfTestService(
            selfTestAdapter: selfTestAdapter,
            messageAdapter: messageAdapter
        )
    }

    func openContactsIfNeeded() async throws {
        guard contactService.contactsAvailability != .availableProtectedDomain else {
            return
        }

        try Task.checkCancellation()
        let availability = await contactService.openContactsAfterPostUnlock(
            gateDecision: ContactsPostAuthGateDecision(
                postUnlockOutcome: .opened([ContactsDomainStore.domainID]),
                frameworkState: .sessionAuthorized
            ),
            wrappingRootKey: { Data() },
            ownSignerKeys: keyManagement.keys
        )
        try Task.checkCancellation()
        guard availability == .availableProtectedDomain else {
            throw TutorialSandboxContainerError.contactsProtectedDomainOpenFailed
        }
    }

    func cleanup() {
        keychain.wipe()
    }

    deinit {
        cleanup()
    }
}
