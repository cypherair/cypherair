import XCTest
@testable import CypherAir

final class PrivateKeyAccessServiceTests: XCTestCase {
    func test_unwrapPrivateKey_rejectsUnwrappedCertificateWithForeignFingerprint() async throws {
        let secureEnclave = MockSecureEnclave()
        let bundleStore = KeyBundleStore(keychain: MockKeychain())
        let requestedFingerprint = String(repeating: "a", count: 40)
        let foreignFingerprint = String(repeating: "b", count: 40)
        // A tampered bundle: sealed and device-bound so the Secure Enclave
        // unwrap succeeds, but its material belongs to a DIFFERENT identity than
        // the keychain row it is filed under.
        let fixture = try saveWrappedPrivateKey(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore,
            fingerprint: requestedFingerprint
        )
        let accessService = PrivateKeyAccessService(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore,
            authenticationPromptCoordinator: AuthenticationPromptCoordinator(),
            certificatePrimaryFingerprint: { _ in foreignFingerprint }
        )

        do {
            _ = try await accessService.unwrapPrivateKey(fingerprint: fixture.fingerprint)
            XCTFail("Expected the identity-mismatch gate to reject a forged envelope")
        } catch let error as CypherAirError {
            guard case .keyOperationUnavailable(.publicCertificateAssociationMismatch) = error else {
                XCTFail("Unexpected CypherAirError: \(error)")
                return
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func test_unwrapPrivateKey_rejectsUnparseableUnwrappedCertificate() async throws {
        let secureEnclave = MockSecureEnclave()
        let bundleStore = KeyBundleStore(keychain: MockKeychain())
        let fixture = try saveWrappedPrivateKey(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore
        )
        let accessService = PrivateKeyAccessService(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore,
            authenticationPromptCoordinator: AuthenticationPromptCoordinator(),
            certificatePrimaryFingerprint: { _ in throw NotACertificate() }
        )

        do {
            _ = try await accessService.unwrapPrivateKey(fingerprint: fixture.fingerprint)
            XCTFail("Expected unparseable unwrapped material to fail closed")
        } catch let error as CypherAirError {
            guard case .keyOperationUnavailable(.publicCertificateAssociationMismatch) = error else {
                XCTFail("Unexpected CypherAirError: \(error)")
                return
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    private struct NotACertificate: Error {}

    private func saveWrappedPrivateKey(
        secureEnclave: MockSecureEnclave,
        bundleStore: KeyBundleStore,
        fingerprint: String = String(repeating: "a", count: 40),
        privateKey: Data = Data([0x11, 0x22, 0x33, 0x44])
    ) throws -> (fingerprint: String, privateKey: Data) {
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: privateKey,
            using: handle,
            fingerprint: fingerprint
        )
        try bundleStore.saveBundle(bundle, fingerprint: fingerprint)
        return (fingerprint, privateKey)
    }
}
