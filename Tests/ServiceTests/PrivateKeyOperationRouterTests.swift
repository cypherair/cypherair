import Foundation
import XCTest
@testable import CypherAir

/// Private operations route by custody kind, and every device-bound route
/// fails closed the moment the vault is locked.
final class PrivateKeyOperationRouterTests: XCTestCase {
    func test_softwareKeyRoutesToTheSecretCertificate_andDeviceBoundKeyToTheEnclave() async throws {
        let engine = PgpEngine()
        let (service, sandbox) = try await TestHelpers.makeKeyManagement(engine: engine)
        defer { sandbox.cleanup() }
        let router = service.makePrivateKeyOperationRouter(
            publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine)
        )

        let software = try await TestHelpers.generateLegacyKey(service: service)
        guard case .softwareSecretCertificate(let softwareRoute) = await router.route(
            for: PrivateKeyOperationRequest(fingerprint: software.fingerprint, operation: .sign)
        ) else {
            return XCTFail("a portable key routes to its secret certificate")
        }
        XCTAssertEqual(softwareRoute.identity.fingerprint, software.fingerprint)

        let deviceBound = try await service.generateKey(
            name: "Device Bound",
            email: nil,
            validity: .never,
            family: .deviceBoundEcdsaNistP256EcdhNistP256V4
        )
        let signing = await router.route(
            for: PrivateKeyOperationRequest(fingerprint: deviceBound.fingerprint, operation: .sign)
        )
        defer { signing.endAuthorizedOperation() }
        guard case .secureEnclaveSigner(let signerRoute) = signing else {
            return XCTFail("a device-bound key routes to its enclave signing handle: \(signing)")
        }
        XCTAssertEqual(signerRoute.signingHandle.role, .signing)

        let decrypt = await router.route(
            for: PrivateKeyOperationRequest(fingerprint: deviceBound.fingerprint, operation: .decrypt)
        )
        defer { decrypt.endAuthorizedOperation() }
        guard case .secureEnclaveKeyAgreement(let agreementRoute) = decrypt else {
            return XCTFail("decryption routes to the key-agreement handle: \(decrypt)")
        }
        XCTAssertEqual(agreementRoute.keyAgreementHandle.role, .keyAgreement)

        try await service.relockVault()
        sandbox.vault.relock()
        let locked = await router.route(
            for: PrivateKeyOperationRequest(fingerprint: deviceBound.fingerprint, operation: .sign)
        )
        guard case .blocked = locked else {
            return XCTFail("a locked vault blocks every device-bound route: \(locked)")
        }
    }
}
