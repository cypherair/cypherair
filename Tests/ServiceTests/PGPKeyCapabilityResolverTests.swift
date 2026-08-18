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
            XCTAssertEqual(identity.custody, .portable)
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

    func test_productionPolicySupportsImplementedSecureEnclaveOperations() {
        let resolver = PGPKeyCapabilityResolver()

        for family in [PGPKeyFamily.deviceBoundEcdsaNistP256EcdhNistP256V4, .deviceBoundEcdsaNistP256EcdhNistP256, .deviceBoundMlDsa65Ed25519MlKem768X25519] {
            // Positive: generation and every implemented private-operation
            // class are exposed by the production policy.
            for operation: PGPKeyOperationKind in [.generate, .sign, .certify, .revoke, .modifyExpiry, .decrypt] {
                XCTAssertEqual(
                    resolver.resolution(
                        for: operation,
                        family: family
                    ),
                    .supported,
                    "Expected \(operation) supported for \(family) under production policy."
                )
            }
        }
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
                    family: .deviceBoundEcdsaNistP256EcdhNistP256
                ),
                .notImplemented(.operationNotImplementedForCustody),
                "Expected \(operation) to remain a test-only not-implemented future path."
            )
            XCTAssertEqual(
                resolver.support(
                    for: operation,
                    family: .deviceBoundEcdsaNistP256EcdhNistP256
                ),
                .notImplemented,
                "Expected \(operation) to remain a test-only not-implemented future path."
            )
        }
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                family: .deviceBoundEcdsaNistP256EcdhNistP256
            ),
            .unavailable(.operationUnavailableByPolicy)
        )
        XCTAssertEqual(
            resolver.support(
                for: .generate,
                family: .deviceBoundEcdsaNistP256EcdhNistP256
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
                    family: family
                ),
                .supported
            )
            XCTAssertEqual(
                resolver.support(
                    for: .generate,
                    family: family
                ),
                .supported
            )
        }

        // The software path carries no Secure Enclave policy at all.
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                family: .portableEd25519LegacyCurve25519Legacy
            ),
            .supported
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .sign,
                family: .deviceBoundEcdsaNistP256EcdhNistP256
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
                    family: .deviceBoundEcdsaNistP256EcdhNistP256V4
                ),
                .supported,
                "Expected \(operation) to be routeable through the signing hook."
            )
        }

        XCTAssertEqual(
            resolver.resolution(
                for: .decrypt,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4
            ),
            .notImplemented(.operationNotImplementedForCustody)
        )
        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                family: .deviceBoundEcdsaNistP256EcdhNistP256V4
            ),
            .unavailable(.operationUnavailableByPolicy)
        )
    }

    func test_secureEnclaveKeyAgreementRoutePolicySupportsDecryptOnly() {
        let resolver = PGPKeyCapabilityResolver(policy: .testSecureEnclaveKeyAgreementRoutes)

        XCTAssertEqual(
            resolver.resolution(
                for: .decrypt,
                family: .deviceBoundEcdsaNistP256EcdhNistP256
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
                    family: .deviceBoundEcdsaNistP256EcdhNistP256
                ),
                .notImplemented(.operationNotImplementedForCustody),
                "Expected \(operation) to remain blocked under key-agreement-only policy."
            )
        }

        XCTAssertEqual(
            resolver.resolution(
                for: .generate,
                family: .deviceBoundEcdsaNistP256EcdhNistP256
            ),
            .unavailable(.operationUnavailableByPolicy)
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
            keyFamily: suite.portableFamily!,
            keyVersion: suite.keyVersion
        )
    }
}
