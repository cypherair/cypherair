import Foundation

/// Pure policy resolver for key-family, custody, and operation support.
struct PGPKeyCapabilityResolver: Sendable {
    struct Policy: Equatable, Sendable {
        var secureEnclaveGenerationSupport: PGPKeyOperationSupport
        var secureEnclaveSigningOperationSupport: PGPKeyOperationSupport
        var secureEnclaveKeyAgreementOperationSupport: PGPKeyOperationSupport

        /// Generation and the implemented private-operation classes are
        /// supported — the only production shape.
        static let production = Policy(
            secureEnclaveGenerationSupport: .supported,
            secureEnclaveSigningOperationSupport: .supported,
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
        family: PGPKeyFamily,
        custody: PGPPrivateKeyCustodyKind,
        metadataAvailability: MetadataAvailability = .present
    ) -> PGPKeyOperationSupport {
        resolution(
            for: operation,
            family: family,
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
            family: identity.keyFamily,
            custody: identity.privateKeyCustodyKind,
            metadataAvailability: MetadataAvailability(
                hasPublicMaterial: !identity.publicKeyData.isEmpty,
                hasRevocationArtifact: !identity.revocationCert.isEmpty
            )
        )
    }

    func resolution(
        for operation: PGPKeyOperationKind,
        family: PGPKeyFamily,
        custody: PGPPrivateKeyCustodyKind,
        metadataAvailability: MetadataAvailability = .present
    ) -> PGPKeyOperationResolution {
        guard isValidFamilyCustodyPair(
            family: family,
            custody: custody
        ) else {
            return .unsupported(.invalidFamilyCustody)
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

    /// A family and a custody kind pair validly exactly when they agree on the
    /// family's custody axis. The composite algorithm suite is the only one
    /// legal under BOTH custody kinds (portable Post-Quantum software keys and
    /// device-bound split custody), which is why validity is decided by the
    /// family — never by the algorithm suite.
    func isValidFamilyCustodyPair(
        family: PGPKeyFamily,
        custody: PGPPrivateKeyCustodyKind
    ) -> Bool {
        switch (family.custody, custody) {
        case (.portable, .softwareSecretCertificate),
             (.deviceBound, .appleSecureEnclavePrivateOperations):
            return true
        case (.portable, .appleSecureEnclavePrivateOperations),
             (.deviceBound, .softwareSecretCertificate):
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
