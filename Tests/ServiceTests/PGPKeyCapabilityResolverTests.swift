import Foundation
import XCTest
@testable import CypherAir

final class PGPKeyCapabilityResolverTests: XCTestCase {
    func test_currentSoftwareProfileCombinationsAreSupported() {
        let resolver = PGPKeyCapabilityResolver()
        let identities = [
            makeIdentity(
                fingerprint: "1111111111111111111111111111111111111111",
                keyVersion: 4,
                profile: .universal
            ),
            makeIdentity(
                fingerprint: "2222222222222222222222222222222222222222",
                keyVersion: 6,
                profile: .advanced
            )
        ]

        for identity in identities {
            XCTAssertEqual(identity.privateKeyCustodyKind, .softwareSecretCertificate)
            for operation in PGPKeyOperationKind.allCases {
                let resolution = resolver.resolution(for: operation, identity: identity)
                XCTAssertEqual(resolution, .supported)
                XCTAssertNil(resolution.failureCategory)
                XCTAssertEqual(
                    resolver.support(for: operation, identity: identity),
                    .supported,
                    "Expected \(operation) to be supported for \(identity.profile)."
                )
            }
        }
    }

    func test_invalidCustodyConfigurationCombinationsAreUnsupported() {
        let resolver = PGPKeyCapabilityResolver()
        let invalidPairs: [(PGPKeyConfiguration, PGPPrivateKeyCustodyKind)] = [
            (.compatibleSoftwareV4, .appleSecureEnclavePrivateOperations),
            (.modernSoftwareV6, .appleSecureEnclavePrivateOperations),
            (.modernHighSoftwareV6, .appleSecureEnclavePrivateOperations),
            (.postQuantumHighSoftwareV6, .appleSecureEnclavePrivateOperations),
            // The composite suite is legal under both custody kinds, but only
            // through its matching identity: the portable identity stays
            // software-only and the device-bound identity stays enclave-only.
            (.postQuantumSoftwareV6, .appleSecureEnclavePrivateOperations),
            (.deviceBoundPostQuantumV6, .softwareSecretCertificate),
            (.compatibleP256V4, .softwareSecretCertificate),
            (.modernP256V6, .softwareSecretCertificate)
        ]

        for (configuration, custody) in invalidPairs {
            XCTAssertFalse(resolver.isValidConfigurationCustodyPair(
                configuration: configuration,
                custody: custody
            ))
            for operation in PGPKeyOperationKind.allCases {
                let resolution = resolver.resolution(
                    for: operation,
                    configuration: configuration,
                    custody: custody
                )
                XCTAssertEqual(resolution.support, .unsupported)
                XCTAssertEqual(resolution.failureCategory, .invalidConfigurationCustody)
                XCTAssertEqual(
                    resolver.support(
                        for: operation,
                        configuration: configuration,
                        custody: custody
                    ),
                    .unsupported,
                    "Expected \(operation) to be unsupported for \(configuration.identity) + \(custody)."
                )
            }
        }
    }

    func test_productionPolicySupportsImplementedSecureEnclaveOperations() {
        let resolver = PGPKeyCapabilityResolver()

        for configuration in [PGPKeyConfiguration.compatibleP256V4, .modernP256V6, .deviceBoundPostQuantumV6] {
            XCTAssertTrue(resolver.isValidConfigurationCustodyPair(
                configuration: configuration,
                custody: .appleSecureEnclavePrivateOperations
            ))

            // Positive: generation and every implemented private-operation
            // class are exposed by the production policy (P7D).
            for operation: PGPKeyOperationKind in [.generate, .sign, .certify, .revoke, .modifyExpiry, .decrypt] {
                XCTAssertEqual(
                    resolver.resolution(
                        for: operation,
                        configuration: configuration,
                        custody: .appleSecureEnclavePrivateOperations
                    ),
                    .supported,
                    "Expected \(operation) supported for \(configuration.identity) under production policy."
                )
            }

            // Negative: private-material export stays hard-unsupported for
            // Secure Enclave custody regardless of policy.
            XCTAssertEqual(
                resolver.resolution(
                    for: .exportPrivateMaterial,
                    configuration: configuration,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .unsupported(.operationUnsupportedForCustody)
            )
        }

        // Negative: invalid configuration/custody pairs stay unsupported under
        // the exposed policy.
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                configuration: .compatibleSoftwareV4,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unsupported(.invalidConfigurationCustody)
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                configuration: .compatibleP256V4,
                custody: .softwareSecretCertificate
            ),
            .unsupported(.invalidConfigurationCustody)
        )
    }

    func test_testOnlyP256SecureEnclavePrivateOperationsAreNotImplemented() {
        let resolver = PGPKeyCapabilityResolver(policy: .testSecureEnclavePrivateOperations)
        let privateOperations: [PGPKeyOperationKind] = [
            .sign,
            .decrypt,
            .certify,
            .revoke,
            .modifyExpiry
        ]

        for operation in privateOperations {
            XCTAssertEqual(
                resolver.resolution(
                    for: operation,
                    configuration: .modernP256V6,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .notImplemented(.operationNotImplementedForCustody),
                "Expected \(operation) to remain a test-only not-implemented future path."
            )
            XCTAssertEqual(
                resolver.support(
                    for: operation,
                    configuration: .modernP256V6,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .notImplemented,
                "Expected \(operation) to remain a test-only not-implemented future path."
            )
        }
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                configuration: .modernP256V6,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unavailable(.operationUnavailableByPolicy)
        )
        XCTAssertEqual(
            resolver.support(
                for: .generate,
                configuration: .modernP256V6,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unavailable
        )
    }

    func test_hiddenSecureEnclaveGenerationPolicySupportsOnlyP256Generation() {
        let resolver = PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration)

        for configuration in [PGPKeyConfiguration.compatibleP256V4, .modernP256V6] {
            XCTAssertEqual(
                resolver.resolution(
                    for: .generate,
                    configuration: configuration,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .supported
            )
            XCTAssertEqual(
                resolver.support(
                    for: .generate,
                    configuration: configuration,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .supported
            )
        }

        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                configuration: .compatibleSoftwareV4,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unsupported(.invalidConfigurationCustody)
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .sign,
                configuration: .modernP256V6,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .notImplemented(.operationNotImplementedForCustody)
        )
    }

    func test_secureEnclaveSigningRoutePolicySupportsSigningClassOnly() {
        let resolver = PGPKeyCapabilityResolver(policy: .testSecureEnclaveSigningRoutes)
        let signingOperations: [PGPKeyOperationKind] = [
            .sign,
            .certify,
            .revoke,
            .modifyExpiry
        ]

        for operation in signingOperations {
            XCTAssertEqual(
                resolver.resolution(
                    for: operation,
                    configuration: .compatibleP256V4,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .supported,
                "Expected \(operation) to be routeable through the Phase 5A signing hook."
            )
        }

        XCTAssertEqual(
            resolver.resolution(
                for: .decrypt,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .notImplemented(.operationNotImplementedForCustody)
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unavailable(.operationUnavailableByPolicy)
        )
    }

    func test_secureEnclaveKeyAgreementRoutePolicySupportsDecryptOnly() {
        let resolver = PGPKeyCapabilityResolver(policy: .testSecureEnclaveKeyAgreementRoutes)

        XCTAssertEqual(
            resolver.resolution(
                for: .decrypt,
                configuration: .modernP256V6,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .supported
        )

        let signingOperations: [PGPKeyOperationKind] = [
            .sign,
            .certify,
            .revoke,
            .modifyExpiry
        ]
        for operation in signingOperations {
            XCTAssertEqual(
                resolver.resolution(
                    for: operation,
                    configuration: .modernP256V6,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .notImplemented(.operationNotImplementedForCustody),
                "Expected \(operation) to remain blocked under key-agreement-only policy."
            )
        }

        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                configuration: .modernP256V6,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unavailable(.operationUnavailableByPolicy)
        )
    }

    func test_secureEnclavePrivateExportUnsupportedAndPublicMaterialUsesMetadataAvailability() {
        let resolver = PGPKeyCapabilityResolver(policy: .testSecureEnclavePrivateOperations)

        XCTAssertEqual(
            resolver.resolution(
                for: .exportPrivateMaterial,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unsupported(.operationUnsupportedForCustody)
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportPrivateMaterial,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unsupported
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportPublicMaterial,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: .present
            ),
            .supported
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportRevocationArtifact,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: .present
            ),
            .supported
        )

        let publicOnly = PGPKeyCapabilityResolver.MetadataAvailability(
            hasPublicMaterial: true,
            hasRevocationArtifact: false
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .exportPublicMaterial,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: publicOnly
            ),
            .supported
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportPublicMaterial,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: publicOnly
            ),
            .supported
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .exportRevocationArtifact,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: publicOnly
            ),
            .unavailable(.revocationArtifactUnavailable)
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportRevocationArtifact,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: publicOnly
            ),
            .unavailable
        )

        let revocationOnly = PGPKeyCapabilityResolver.MetadataAvailability(
            hasPublicMaterial: false,
            hasRevocationArtifact: true
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .exportPublicMaterial,
                configuration: .compatibleP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: revocationOnly
            ),
            .unavailable(.publicMaterialUnavailable)
        )
    }

    private func makeIdentity(
        fingerprint: String,
        keyVersion: UInt8,
        profile: PGPKeyProfile
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: keyVersion,
            profile: profile,
            userId: "Test <test@example.invalid>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data([0x01, 0x02]),
            revocationCert: Data([0x03]),
            primaryAlgo: profile == .universal ? "Ed25519" : "Ed448",
            subkeyAlgo: profile == .universal ? "X25519" : "X448",
            expiryDate: nil,
            openPGPConfigurationIdentity: profile.openPGPConfiguration.identity,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
    }
}
