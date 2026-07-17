import CryptoKit
import Security
import XCTest

/// Does *this device's* Secure Enclave actually generate
/// and operate on the ML-DSA-87 / ML-KEM-1024 tier? That is the one platform
/// precondition for a device-bound **Post-Quantum · High** family — the rest of
/// the family is the same shape as the 65/768 tier, but SE support for the 87/1024
/// types on the minimum target hardware (8 GB Apple silicon) is the genuine
/// unknown.
///
/// This is a capability probe, not a custody test: it creates *non-biometric*
/// enclave keys (`.privateKeyUsage` only, so no Touch ID prompt), exercises
/// sign→verify and encapsulate→decapsulate, and persists nothing (the keys live
/// only for the test's lifetime — no keychain row is written). It skips cleanly
/// where the Secure Enclave is unavailable (simulator / no SE hardware), so it
/// is inert on the iOS-simulator unit lane and only does real work on an
/// Apple-silicon host or a physical device.
final class DeviceSecureEnclavePqcHighProbeTests: XCTestCase {
    /// A this-device-only enclave key that requires no user presence, so the
    /// probe never prompts for Touch ID / the system auth sheet.
    private func makeNonBiometricAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else {
            let detail = error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown"
            throw XCTSkip("Could not build a Secure Enclave access control: \(detail)")
        }
        return access
    }

    func test_secureEnclave_generatesAndSigns_mlDsa87() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave unavailable (simulator or no SE hardware)")
        let access = try makeNonBiometricAccessControl()

        let key: SecureEnclave.MLDSA87.PrivateKey
        do {
            key = try SecureEnclave.MLDSA87.PrivateKey(accessControl: access, authenticationContext: nil)
        } catch {
            XCTFail("Secure Enclave rejected ML-DSA-87 key generation on this hardware: \(error)")
            return
        }

        // FIPS 204 raw encoding for the ML-87 parameter set.
        XCTAssertEqual(key.publicKey.rawRepresentation.count, 2592, "ML-DSA-87 public key must be 2592 bytes")

        let message = Data("cypherair SE ML-DSA-87 probe".utf8)
        let signature = try key.signature(for: message)
        XCTAssertEqual(signature.count, 4627, "ML-DSA-87 signature must be 4627 bytes")
        XCTAssertTrue(
            key.publicKey.isValidSignature(signature, for: message),
            "Enclave-produced ML-DSA-87 signature must verify against its own public key"
        )
    }

    func test_secureEnclave_generatesAndDecapsulates_mlKem1024() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave unavailable (simulator or no SE hardware)")
        let access = try makeNonBiometricAccessControl()

        let key: SecureEnclave.MLKEM1024.PrivateKey
        do {
            key = try SecureEnclave.MLKEM1024.PrivateKey(accessControl: access, authenticationContext: nil)
        } catch {
            XCTFail("Secure Enclave rejected ML-KEM-1024 key generation on this hardware: \(error)")
            return
        }

        // FIPS 203 raw encoding for the ML-1024 parameter set.
        XCTAssertEqual(key.publicKey.rawRepresentation.count, 1568, "ML-KEM-1024 public key must be 1568 bytes")

        // Encapsulate to the enclave's public key, then decapsulate inside the
        // enclave — the two shared secrets must match for the key to be usable.
        let encapsulation = try key.publicKey.encapsulate()
        XCTAssertEqual(encapsulation.encapsulated.count, 1568, "ML-KEM-1024 ciphertext must be 1568 bytes")

        let recovered = try key.decapsulate(encapsulation.encapsulated)
        XCTAssertEqual(
            recovered, encapsulation.sharedSecret,
            "Enclave ML-KEM-1024 decapsulation must recover the encapsulated shared secret"
        )
    }
}
