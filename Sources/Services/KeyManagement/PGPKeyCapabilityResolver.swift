import Foundation

/// Pure policy resolver for OpenPGP configuration, custody, and operation support.
struct PGPKeyCapabilityResolver: Sendable {
    struct Policy: Equatable, Sendable {
        var secureEnclavePrivateOperationSupport: PGPKeyOperationSupport

        static let production = Policy(
            secureEnclavePrivateOperationSupport: .unavailable
        )

        static let testSecureEnclavePrivateOperations = Policy(
            secureEnclavePrivateOperationSupport: .notImplemented
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
        support(
            for: operation,
            configuration: identity.openPGPConfiguration,
            custody: identity.privateKeyCustodyKind,
            metadataAvailability: MetadataAvailability(
                hasPublicMaterial: !identity.publicKeyData.isEmpty,
                hasRevocationArtifact: !identity.revocationCert.isEmpty
            )
        )
    }

    func support(
        for operation: PGPKeyOperationKind,
        configuration: PGPKeyConfiguration,
        custody: PGPPrivateKeyCustodyKind,
        metadataAvailability: MetadataAvailability = .present
    ) -> PGPKeyOperationSupport {
        guard isValidConfigurationCustodyPair(
            configuration: configuration,
            custody: custody
        ) else {
            return .unsupported
        }

        switch custody {
        case .softwareSecretCertificate:
            return .supported
        case .appleSecureEnclavePrivateOperations:
            return supportForSecureEnclaveCustody(
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

    private func supportForSecureEnclaveCustody(
        operation: PGPKeyOperationKind,
        metadataAvailability: MetadataAvailability
    ) -> PGPKeyOperationSupport {
        switch operation {
        case .generate:
            return .unavailable
        case .sign,
             .decrypt,
             .certify,
             .revoke,
             .modifyExpiry,
             .refreshBinding:
            return policy.secureEnclavePrivateOperationSupport
        case .exportPrivateMaterial:
            return .unsupported
        case .exportPublicMaterial:
            return metadataAvailability.hasPublicMaterial ? .supported : .unavailable
        case .exportRevocationArtifact:
            return metadataAvailability.hasRevocationArtifact ? .supported : .unavailable
        }
    }
}
