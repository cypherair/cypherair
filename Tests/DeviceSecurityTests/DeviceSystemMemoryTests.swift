import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// Real-device memory guard tests.
final class DeviceSystemMemoryTests: DeviceSecurityTestCase {
    // MARK: - Argon2id Memory Guard (Device)

    /// Verify SystemMemoryInfo returns a sane value on real hardware.
    func test_systemMemoryInfo_returnsNonZero() {
        let memoryInfo = SystemMemoryInfo()
        let available = memoryInfo.availableMemoryBytes()

        // On an 8 GB+ device, available memory should be at least 500 MB.
        XCTAssertGreaterThan(available, 500 * 1024 * 1024,
            "os_proc_available_memory must return > 500 MB on 8 GB+ device")

        // And less than total physical memory (sanity check).
        let totalPhysical = ProcessInfo.processInfo.physicalMemory
        XCTAssertLessThanOrEqual(available, totalPhysical,
            "Available memory must not exceed physical memory")
    }

    /// Real 2 GiB Argon2id import with the guard on device — the one place the
    /// granted memory limit is the real one rather than a mock. Validates the
    /// full pipeline: parseS2kParams → guard → importSecretKey.
    func test_argon2idGuard_realDevice_import_succeeds() throws {
        let engine = PgpEngine()

        // Generate and export a Modern High key.
        let key = try engine.generateKey(
            name: "Device Argon2id", email: nil, validity: .never, suite: .ed448X448
        )
        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "device-test-pass"
        )

        // Parse S2K params and run the guard with real memory info.
        let s2kInfo = try engine.parseS2kParams(armoredData: exported)
        let memoryGuard = Argon2idMemoryGuard() // Uses SystemMemoryInfo (real)

        // On an 8 GB+ device with the memory entitlements granted, 2 GiB fits.
        XCTAssertNoThrow(try memoryGuard.validate(protectionInfo: PGPKeyS2KInfo(s2kInfo)))

        // If the guard passes, proceed with actual import.
        let imported = try engine.importSecretKey(
            armoredData: exported,
            passphrase: "device-test-pass"
        )
        XCTAssertFalse(imported.isEmpty, "Imported key data must not be empty")
    }
}
