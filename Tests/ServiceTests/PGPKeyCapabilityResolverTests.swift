import Foundation
import XCTest
@testable import CypherAir

final class PGPKeyCapabilityResolverTests: XCTestCase {
    func test_portableFamilySoftwareCustodyCombinationsAreSupported() {
        let resolver = PGPKeyCapabilityResolver()
        let identities = [
            makeIdentity(
                fingerprint: "1111111111111111111111111111111111111111",
                suite: .ed25519LegacyCurve25519Legacy
            ),
            makeIdentity(
                fingerprint: "2222222222222222222222222222222222222222",
                suite: .ed448X448
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
                    "Expected \(operation) to be supported for \(identity.keyFamily)."
                )
            }
        }
    }

    func test_invalidCustodyConfigurationCombinationsAreUnsupported() {
        let resolver = PGPKeyCapabilityResolver()
        let invalidPairs: [(PGPKeyFamily, PGPPrivateKeyCustodyKind)] = [
            (.portableEd25519LegacyCurve25519Legacy, .appleSecureEnclavePrivateOperations),
            (.portableEd25519X25519, .appleSecureEnclavePrivateOperations),
            (.portableEd448X448, .appleSecureEnclavePrivateOperations),
            (.portableMlDsa87Ed448MlKem1024X448, .appleSecureEnclavePrivateOperations),
            // The composite suite is legal under both custody kinds, but only
            // through its matching identity: the portable identity stays
            // software-only and the device-bound identity stays enclave-only.
            (.portableMlDsa65Ed25519MlKem768X25519, .appleSecureEnclavePrivateOperations),
            (.deviceBoundMlDsa65Ed25519MlKem768X25519, .softwareSecretCertificate),
            (.deviceBoundEcdsaNistP256EcdhNistP256V4, .softwareSecretCertificate),
            (.deviceBoundEcdsaNistP256EcdhNistP256, .softwareSecretCertificate)
        ]

        for (family, custody) in invalidPairs {
            XCTAssertFalse(resolver.isValidFamilyCustodyPair(
                family: family,
                custody: custody
            ))
            for operation in PGPKeyOperationKind.allCases {
                let resolution = resolver.resolution(
                    for: operation,
                    family: family,
                    custody: custody
                )
                XCTAssertEqual(resolution.support, .unsupported)
                XCTAssertEqual(resolution.failureCategory, .invalidFamilyCustody)
                XCTAssertEqual(
                    resolver.support(
                        for: operation,
                        family: family,
                        custody: custody
                    ),
                    .unsupported,
                    "Expected \(operation) to be unsupported for \(family) + \(custody)."
                )
            }
        }
    }

    func test_productionPolicySupportsImplementedSecureEnclaveOperations() {
        let resolver = PGPKeyCapabilityResolver()

        for family in [PGPKeyFamily.deviceBoundEcdsaNistP256EcdhNistP256V4, .deviceBoundEcdsaNistP256EcdhNistP256, .deviceBoundMlDsa65Ed25519MlKem768X25519] {
            XCTAssertTrue(resolver.isValidFamilyCustodyPair(
                family: family,
                custody: .appleSecureEnclavePrivateOperations
            ))

            // Positive: generation and every implemented private-operation
            // class are exposed by the production policy.
            for operation: PGPKeyOperationKind in [.generate, .sign, .certify, .revoke, .modifyExpiry, .decrypt] {
                XCTAssertEqual(
                    resolver.resolution(
                        for: operation,
                        family: family,
                        custody: .appleSecureEnclavePrivateOperations
                    ),
                    .supported,
                    "Expected \(operation) supported for \(family) under production policy."
                )
            }

            // Negative: private-material export stays hard-unsupported for
            // Secure Enclave custody regardless of policy.
            XCTAssertEqual(
                resolver.resolution(
                    for: .exportPrivateMaterial,
                    family: family,
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
                family: .portableEd25519LegacyCurve25519Legacy,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unsupported(.invalidFamilyCustody)
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                custody: .softwareSecretCertificate
            ),
            .unsupported(.invalidFamilyCustody)
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
                    family: .deviceBoundEcdsaNistP256EcdhNistP256,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .notImplemented(.operationNotImplementedForCustody),
                "Expected \(operation) to remain a test-only not-implemented future path."
            )
            XCTAssertEqual(
                resolver.support(
                    for: operation,
                    family: .deviceBoundEcdsaNistP256EcdhNistP256,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .notImplemented,
                "Expected \(operation) to remain a test-only not-implemented future path."
            )
        }
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                family: .deviceBoundEcdsaNistP256EcdhNistP256,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unavailable(.operationUnavailableByPolicy)
        )
        XCTAssertEqual(
            resolver.support(
                for: .generate,
                family: .deviceBoundEcdsaNistP256EcdhNistP256,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unavailable
        )
    }

    func test_hiddenSecureEnclaveGenerationPolicySupportsOnlyP256Generation() {
        let resolver = PGPKeyCapabilityResolver(policy: .testSecureEnclaveGeneration)

        for family in [PGPKeyFamily.deviceBoundEcdsaNistP256EcdhNistP256V4, .deviceBoundEcdsaNistP256EcdhNistP256] {
            XCTAssertEqual(
                resolver.resolution(
                    for: .generate,
                    family: family,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .supported
            )
            XCTAssertEqual(
                resolver.support(
                    for: .generate,
                    family: family,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .supported
            )
        }

        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                family: .portableEd25519LegacyCurve25519Legacy,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unsupported(.invalidFamilyCustody)
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .sign,
                family: .deviceBoundEcdsaNistP256EcdhNistP256,
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
                    family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .supported,
                "Expected \(operation) to be routeable through the signing hook."
            )
        }

        XCTAssertEqual(
            resolver.resolution(
                for: .decrypt,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .notImplemented(.operationNotImplementedForCustody)
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
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
                family: .deviceBoundEcdsaNistP256EcdhNistP256,
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
                    family: .deviceBoundEcdsaNistP256EcdhNistP256,
                    custody: .appleSecureEnclavePrivateOperations
                ),
                .notImplemented(.operationNotImplementedForCustody),
                "Expected \(operation) to remain blocked under key-agreement-only policy."
            )
        }

        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                family: .deviceBoundEcdsaNistP256EcdhNistP256,
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
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unsupported(.operationUnsupportedForCustody)
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportPrivateMaterial,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                custody: .appleSecureEnclavePrivateOperations
            ),
            .unsupported
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportPublicMaterial,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: .present
            ),
            .supported
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportRevocationArtifact,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
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
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: publicOnly
            ),
            .supported
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportPublicMaterial,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: publicOnly
            ),
            .supported
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .exportRevocationArtifact,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: publicOnly
            ),
            .unavailable(.revocationArtifactUnavailable)
        )
        XCTAssertEqual(
            resolver.support(
                for: .exportRevocationArtifact,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
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
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4,
                custody: .appleSecureEnclavePrivateOperations,
                metadataAvailability: revocationOnly
            ),
            .unavailable(.publicMaterialUnavailable)
        )
    }

    private func makeIdentity(
        fingerprint: String,
        suite: PGPKeySuite
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            userId: "Test <test@example.invalid>",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data([0x01, 0x02]),
            revocationCert: Data([0x03]),
            primaryAlgo: suite == .ed25519LegacyCurve25519Legacy ? "Ed25519" : "Ed448",
            subkeyAlgo: suite == .ed25519LegacyCurve25519Legacy ? "X25519" : "X448",
            expiryDate: nil,
            keyFamily: suite.portableFamily,
            privateKeyCustodyKind: .softwareSecretCertificate
        )
    }
}
