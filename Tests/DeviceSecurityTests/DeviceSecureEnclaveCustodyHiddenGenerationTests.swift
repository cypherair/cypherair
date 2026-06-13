import CryptoKit
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

/// Device-only evidence for hidden Secure Enclave custody generation.
///
/// This test creates and deletes only the handle pair owned by the test. It does
/// not invoke Reset All Local Data cleanup or delete inventory-wide custody rows.
final class DeviceSecureEnclaveCustodyHiddenGenerationTests: SecureEnclaveCustodyDeviceTestCase {
    func test_hiddenGenerationBuildsPublicOnlyCertificateWithRealSigningHandle_onDevice() async throws {
        try requireSecureEnclaveCustodyHardware()

        let keyStore = SystemSecureEnclaveCustodyKeyStore()
        let handleStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let pair = try handleStore.createHandlePair()
        defer {
            try? handleStore.deleteHandlePair(pair)
        }

        let context = try await authenticatedBiometricsContext(
            reason: "Authenticate to validate hidden Secure Enclave custody generation."
        )
        defer {
            context.invalidate()
        }

        let signingKey = try loadPrivateKey(
            reference: pair.signing.reference,
            authenticationContext: context
        )
        let loadedPair = try SecureEnclaveCustodyLoadedHandlePair(
            signing: SecureEnclaveCustodyLoadedHandle(
                binding: pair.signing,
                privateKey: signingKey
            ),
            keyAgreement: SecureEnclaveCustodyLoadedHandle(
                binding: pair.keyAgreement,
                privateKey: nil
            )
        )
        let adapter = PGPSecureEnclaveCustodyGenerationAdapter(engine: PgpEngine())

        let material = try await adapter.generatePublicCertificate(
            name: "CypherAir Device Custody",
            email: "device-custody@example.invalid",
            expirySeconds: nil,
            configuration: PGPKeyConfiguration.Identity.compatibleP256V4.configuration,
            handlePair: loadedPair,
            digestSigner: SystemSecureEnclaveCustodyDigestSigner()
        )

        XCTAssertEqual(material.metadata.keyVersion, 4)
        XCTAssertEqual(material.metadata.profile, .universal)
        XCTAssertFalse(material.publicKeyData.isEmpty)
        XCTAssertFalse(material.revocationCert.isEmpty)
        XCTAssertFalse(material.signingKeyFingerprint.isEmpty)
        XCTAssertFalse(material.keyAgreementSubkeyFingerprint.isEmpty)

        let located = try handleStore.locateHandlePair(
            signingPublicKeyX963: pair.signing.publicKeyX963,
            keyAgreementPublicKeyX963: pair.keyAgreement.publicKeyX963
        )
        XCTAssertEqual(located, pair)
    }
}
