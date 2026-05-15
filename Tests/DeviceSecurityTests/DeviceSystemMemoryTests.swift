import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// C4.5: Real-device memory guard tests.
final class DeviceSystemMemoryTests: DeviceSecurityTestCase {
    // MARK: - C4.5: Argon2id Memory Guard (Device)

    /// C4.5: Verify SystemMemoryInfo returns a sane value on real hardware.
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

    /// C4.5: Real 512 MB Argon2id import with guard on device.
    /// Validates the full pipeline: parseS2kParams → guard → importSecretKey.
    func test_argon2idGuard_realDevice_512MB_import_succeeds() throws {
        let engine = PgpEngine()

        // Generate and export a Profile B key.
        let key = try engine.generateKey(
            name: "Device Argon2id", email: nil, expirySeconds: nil, profile: .advanced
        )
        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "device-test-pass",
            profile: .advanced
        )

        // Parse S2K params and run the guard with real memory info.
        let s2kInfo = try engine.parseS2kParams(armoredData: exported)
        let memoryGuard = Argon2idMemoryGuard() // Uses SystemMemoryInfo (real)

        // On an 8 GB+ device, 512 MB should be well within limits.
        XCTAssertNoThrow(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib)))

        // If the guard passes, proceed with actual import.
        let imported = try engine.importSecretKey(
            armoredData: exported,
            passphrase: "device-test-pass"
        )
        XCTAssertFalse(imported.isEmpty, "Imported key data must not be empty")
    }
}
