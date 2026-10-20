import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir
import Stores
import Vault

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

        sandbox.vault.relock()
        let locked = await router.route(
            for: PrivateKeyOperationRequest(fingerprint: deviceBound.fingerprint, operation: .sign)
        )
        guard case .blocked(let resolution) = locked, resolution.failureCategory == .privateHandleUnauthorized else {
            return XCTFail("a locked vault blocks every device-bound route at the session, not before it: \(locked)")
        }
    }

    /// The approval must be taken inside the operation-prompt window, on the
    /// context every enclave load of the operation then consumes with
    /// interaction disallowed; a prompt outside the window reads as an away
    /// event on macOS and relocks the app mid-operation.
    func test_deviceBoundRoutes_takeTheApprovalInsideTheOperationPromptWindow() async throws {
        let engine = PgpEngine()
        let coordinator = AuthenticationPromptCoordinator()
        let authenticator = WindowRecordingAuthenticator(coordinator: coordinator)
        let sandbox = try await TestHelpers.makeSandbox(authenticator: authenticator)
        defer { sandbox.cleanup() }
        let (service, _) = try await TestHelpers.makeKeyManagement(
            engine: engine, sandbox: sandbox, authenticationPromptCoordinator: coordinator
        )
        let router = service.makePrivateKeyOperationRouter(
            publicBindingInspector: PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine)
        )

        let deviceBound = try await service.generateKey(
            name: "Device Bound",
            email: nil,
            validity: .never,
            family: .deviceBoundEcdsaNistP256EcdhNistP256V4
        )
        XCTAssertEqual(authenticator.evaluationsInsideTheWindow, [true], "generation takes one approval, inside the window")

        let signing = await router.route(
            for: PrivateKeyOperationRequest(fingerprint: deviceBound.fingerprint, operation: .sign)
        )
        defer { signing.endAuthorizedOperation() }
        guard case .secureEnclaveSigner(let route) = signing else {
            return XCTFail("a device-bound key routes to its enclave signing handle: \(signing)")
        }
        XCTAssertEqual(authenticator.evaluationsInsideTheWindow, [true, true])
        XCTAssertEqual(route.operationAuthorization?.authenticationContext.interactionNotAllowed, true)
    }
}

/// Records, for every biometric evaluation, whether an operation prompt was open.
private final class WindowRecordingAuthenticator: Authenticator, @unchecked Sendable {
    private let coordinator: AuthenticationPromptCoordinator
    private let lock = NSLock()
    private var recorded: [Bool] = []

    init(coordinator: AuthenticationPromptCoordinator) {
        self.coordinator = coordinator
    }

    var evaluationsInsideTheWindow: [Bool] { lock.withLock { recorded } }

    func authenticate(context: LAContext, reason: String) async throws(VaultError) {}

    func authenticateBiometrics(context: LAContext, reason: String) async throws(VaultError) {
        let inside = coordinator.isOperationPromptInProgress
        lock.withLock { recorded.append(inside) }
    }
}
