import Foundation

/// Pure policy resolver for OpenPGP configuration, custody, and operation support.
struct PGPKeyCapabilityResolver: Sendable {
    struct Policy: Equatable, Sendable {
        var secureEnclaveGenerationSupport: PGPKeyOperationSupport
        var secureEnclaveSigningOperationSupport: PGPKeyOperationSupport
        var secureEnclaveKeyAgreementOperationSupport: PGPKeyOperationSupport

        /// Generation and the implemented private-operation classes are supported.
        static let production = Policy(
            secureEnclaveGenerationSupport: .supported,
            secureEnclaveSigningOperationSupport: .supported,
            secureEnclaveKeyAgreementOperationSupport: .supported
        )

        /// All Secure Enclave supports blocked — a test-only fixture that pins
        /// the resolver-before-handle-store ordering in route tests. It is not a
        /// production shape.
        static let testSecureEnclaveOperationsBlocked = Policy(
            secureEnclaveGenerationSupport: .unavailable,
            secureEnclaveSigningOperationSupport: .unavailable,
            secureEnclaveKeyAgreementOperationSupport: .unavailable
        )

        static let testSecureEnclavePrivateOperations = Policy(
            secureEnclaveGenerationSupport: .unavailable,
            secureEnclaveSigningOperationSupport: .notImplemented,
            secureEnclaveKeyAgreementOperationSupport: .notImplemented
        )

        static let testSecureEnclaveGeneration = Policy(
            secureEnclaveGenerationSupport: .supported,
            secureEnclaveSigningOperationSupport: .notImplemented,
            secureEnclaveKeyAgreementOperationSupport: .notImplemented
        )

        static let testSecureEnclaveSigningRoutes = Policy(
            secureEnclaveGenerationSupport: .unavailable,
            secureEnclaveSigningOperationSupport: .supported,
            secureEnclaveKeyAgreementOperationSupport: .notImplemented
        )

        static let testSecureEnclaveKeyAgreementRoutes = Policy(
            secureEnclaveGenerationSupport: .unavailable,
            secureEnclaveSigningOperationSupport: .notImplemented,
            secureEnclaveKeyAgreementOperationSupport: .supported
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

    /// The composite suite is the only one legal under BOTH custody kinds
    /// (Portable Post-Quantum software keys and Device-Bound Post-Quantum
    /// split custody), so validity is decided per configuration identity,
    /// not per algorithm suite.
    func isValidConfigurationCustodyPair(
        configuration: PGPKeyConfiguration,
        custody: PGPPrivateKeyCustodyKind
    ) -> Bool {
        switch (configuration.identity, custody) {
        case (.compatibleSoftwareV4, .softwareSecretCertificate),
             (.modernSoftwareV6, .softwareSecretCertificate),
             (.modernHighSoftwareV6, .softwareSecretCertificate),
             (.postQuantumSoftwareV6, .softwareSecretCertificate),
             (.postQuantumHighSoftwareV6, .softwareSecretCertificate),
             (.compatibleP256V4, .appleSecureEnclavePrivateOperations),
             (.modernP256V6, .appleSecureEnclavePrivateOperations),
             (.deviceBoundPostQuantumV6, .appleSecureEnclavePrivateOperations),
             (.deviceBoundPostQuantumHighV6, .appleSecureEnclavePrivateOperations):
            return true
        case (.compatibleSoftwareV4, .appleSecureEnclavePrivateOperations),
             (.modernSoftwareV6, .appleSecureEnclavePrivateOperations),
             (.modernHighSoftwareV6, .appleSecureEnclavePrivateOperations),
             (.postQuantumSoftwareV6, .appleSecureEnclavePrivateOperations),
             (.postQuantumHighSoftwareV6, .appleSecureEnclavePrivateOperations),
             (.compatibleP256V4, .softwareSecretCertificate),
             (.modernP256V6, .softwareSecretCertificate),
             (.deviceBoundPostQuantumV6, .softwareSecretCertificate),
             (.deviceBoundPostQuantumHighV6, .softwareSecretCertificate):
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
