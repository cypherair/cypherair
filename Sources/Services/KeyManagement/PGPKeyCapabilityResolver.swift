import Foundation

/// Pure policy resolver for OpenPGP configuration, custody, and operation support.
struct PGPKeyCapabilityResolver: Sendable {
    struct Policy: Equatable, Sendable {
        var secureEnclaveGenerationSupport: PGPKeyOperationSupport
        var secureEnclaveSigningOperationSupport: PGPKeyOperationSupport
        var secureEnclaveKeyAgreementOperationSupport: PGPKeyOperationSupport
        var secureEnclaveRefreshBindingOperationSupport: PGPKeyOperationSupport

        /// Production exposure (issue #501 decision 3, P7D): generation and the
        /// implemented private-operation classes are supported; refreshBinding
        /// stays `.notImplemented` because no service implements that route.
        static let production = Policy(
            secureEnclaveGenerationSupport: .supported,
            secureEnclaveSigningOperationSupport: .supported,
            secureEnclaveKeyAgreementOperationSupport: .supported,
            secureEnclaveRefreshBindingOperationSupport: .notImplemented
        )

        /// All Secure Enclave supports blocked. Pins the resolver-before-
        /// handle-store ordering in route tests now that the production policy
        /// is exposed (P7D); this is the pre-exposure production shape.
        static let testSecureEnclaveOperationsBlocked = Policy(
            secureEnclaveGenerationSupport: .unavailable,
            secureEnclaveSigningOperationSupport: .unavailable,
            secureEnclaveKeyAgreementOperationSupport: .unavailable,
            secureEnclaveRefreshBindingOperationSupport: .unavailable
        )

        static let testSecureEnclavePrivateOperations = Policy(
            secureEnclaveGenerationSupport: .unavailable,
            secureEnclaveSigningOperationSupport: .notImplemented,
            secureEnclaveKeyAgreementOperationSupport: .notImplemented,
            secureEnclaveRefreshBindingOperationSupport: .notImplemented
        )

        static let testSecureEnclaveGeneration = Policy(
            secureEnclaveGenerationSupport: .supported,
            secureEnclaveSigningOperationSupport: .notImplemented,
            secureEnclaveKeyAgreementOperationSupport: .notImplemented,
            secureEnclaveRefreshBindingOperationSupport: .notImplemented
        )

        static let testSecureEnclaveSigningRoutes = Policy(
            secureEnclaveGenerationSupport: .unavailable,
            secureEnclaveSigningOperationSupport: .supported,
            secureEnclaveKeyAgreementOperationSupport: .notImplemented,
            secureEnclaveRefreshBindingOperationSupport: .notImplemented
        )

        static let testSecureEnclaveKeyAgreementRoutes = Policy(
            secureEnclaveGenerationSupport: .unavailable,
            secureEnclaveSigningOperationSupport: .notImplemented,
            secureEnclaveKeyAgreementOperationSupport: .supported,
            secureEnclaveRefreshBindingOperationSupport: .notImplemented
        )
    }

    struct MetadataAvailability: Equatable, Sendable {
        var hasPublicMaterial: Bool
        var hasRevocationArtifact: Bool

        static let present = MetadataAvailability(
            hasPublicMaterial: true,
            hasRevocationArtifact: true
        )
    }

    private let policy: Policy

    init(policy: Policy = .production) {
        self.policy = policy
    }

    func support(
        for operation: PGPKeyOperationKind,
        identity: PGPKeyIdentity
    ) -> PGPKeyOperationSupport {
        resolution(
            for: operation,
            identity: identity
        ).support
    }

    func support(
        for operation: PGPKeyOperationKind,
        configuration: PGPKeyConfiguration,
        custody: PGPPrivateKeyCustodyKind,
        metadataAvailability: MetadataAvailability = .present
    ) -> PGPKeyOperationSupport {
        resolution(
            for: operation,
            configuration: configuration,
            custody: custody,
            metadataAvailability: metadataAvailability
        ).support
    }

    func resolution(
        for operation: PGPKeyOperationKind,
        identity: PGPKeyIdentity
    ) -> PGPKeyOperationResolution {
        resolution(
            for: operation,
            configuration: identity.openPGPConfiguration,
            custody: identity.privateKeyCustodyKind,
            metadataAvailability: MetadataAvailability(
                hasPublicMaterial: !identity.publicKeyData.isEmpty,
                hasRevocationArtifact: !identity.revocationCert.isEmpty
            )
        )
    }

    func resolution(
        for operation: PGPKeyOperationKind,
        configuration: PGPKeyConfiguration,
        custody: PGPPrivateKeyCustodyKind,
        metadataAvailability: MetadataAvailability = .present
    ) -> PGPKeyOperationResolution {
        guard isValidConfigurationCustodyPair(
            configuration: configuration,
            custody: custody
        ) else {
            return .unsupported(.invalidConfigurationCustody)
        }

        switch custody {
        case .softwareSecretCertificate:
            return .supported
        case .appleSecureEnclavePrivateOperations:
            return resolutionForSecureEnclaveCustody(
                operation: operation,
                metadataAvailability: metadataAvailability
            )
        }
    }

    func isValidConfigurationCustodyPair(
        configuration: PGPKeyConfiguration,
        custody: PGPPrivateKeyCustodyKind
    ) -> Bool {
        switch (configuration.algorithmSuite, custody) {
        case (.p256, .appleSecureEnclavePrivateOperations),
             (.ed25519X25519, .softwareSecretCertificate),
             (.ed448X448, .softwareSecretCertificate):
            return true
        case (.p256, .softwareSecretCertificate),
             (.ed25519X25519, .appleSecureEnclavePrivateOperations),
             (.ed448X448, .appleSecureEnclavePrivateOperations):
            return false
        }
    }

    private func resolutionForSecureEnclaveCustody(
        operation: PGPKeyOperationKind,
        metadataAvailability: MetadataAvailability
    ) -> PGPKeyOperationResolution {
        switch operation {
        case .generate:
            return resolutionForPolicySupport(policy.secureEnclaveGenerationSupport)
        case .sign,
             .certify,
             .revoke,
             .modifyExpiry:
            return resolutionForPolicySupport(policy.secureEnclaveSigningOperationSupport)
        case .refreshBinding:
            return resolutionForPolicySupport(policy.secureEnclaveRefreshBindingOperationSupport)
        case .decrypt:
            return resolutionForPolicySupport(policy.secureEnclaveKeyAgreementOperationSupport)
        case .exportPrivateMaterial:
            return .unsupported(.operationUnsupportedForCustody)
        case .exportPublicMaterial:
            return metadataAvailability.hasPublicMaterial
                ? .supported
                : .unavailable(.publicMaterialUnavailable)
        case .exportRevocationArtifact:
            return metadataAvailability.hasRevocationArtifact
                ? .supported
                : .unavailable(.revocationArtifactUnavailable)
        }
    }

    private func resolutionForPolicySupport(
        _ support: PGPKeyOperationSupport
    ) -> PGPKeyOperationResolution {
        switch support {
        case .supported:
            return .supported
        case .unsupported:
            return .unsupported(.operationUnsupportedForCustody)
        case .notImplemented:
            return .notImplemented(.operationNotImplementedForCustody)
        case .unavailable:
            return .unavailable(.operationUnavailableByPolicy)
        }
    }
}
