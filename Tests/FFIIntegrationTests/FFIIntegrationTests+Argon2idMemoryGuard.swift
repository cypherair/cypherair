import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    // MARK: - C4: Argon2id Memory Guard Tests

    /// C4.1: Import Modern High key with 512 MB Argon2id → success on device with enough memory.
    /// Uses real Modern High key export/parseS2kParams, but mocks memory to ensure success.
    func test_argon2idGuard_modernHigh_512MB_8GBDevice_passes() throws {
        let key = try engine.generateKey(
            name: "Argon2id Test", email: nil, expirySeconds: nil, profile: .advanced
        )
        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "test-pass-123",
            profile: .advanced
        )

        let s2kInfo = try engine.parseS2kParams(armoredData: exported)
        XCTAssertEqual(s2kInfo.s2kType, "argon2id")
        XCTAssertEqual(s2kInfo.memoryKib, 524_288, "Modern High export should use 512 MB (2^19 KiB)")

        // Mock: 8 GB device with 6 GB available.
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 6 * 1024 * 1024 * 1024
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // Should pass: 512 MB < 75% of 6 GB (4.5 GB).
        XCTAssertNoThrow(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib)))
    }

    /// C4.2: 1 GB Argon2id params → graceful error with limited memory.
    func test_argon2idGuard_1GB_lowMemory_throwsExceeded() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 1_048_576 // 1 GB = 2^20 KiB
        )

        // Mock: 1 GB available (device under heavy load).
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 1 * 1024 * 1024 * 1024
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // Should fail: 1 GB > 75% of 1 GB (768 MB).
        XCTAssertThrowsError(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib))) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            switch cypherError {
            case .argon2idMemoryExceeded(let requiredMb):
                XCTAssertEqual(requiredMb, 1024, "Should report 1024 MB required")
            default:
                XCTFail("Expected argon2idMemoryExceeded, got \(cypherError)")
            }
        }
    }

    /// C4.2: 1 GB Argon2id params → success with ample memory.
    func test_argon2idGuard_1GB_ampleMemory_passes() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 1_048_576 // 1 GB
        )

        // Mock: 6 GB available.
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 6 * 1024 * 1024 * 1024
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // Should pass: 1 GB < 75% of 6 GB (4.5 GB).
        XCTAssertNoThrow(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib)))
    }

    /// C4.3: 2 GB Argon2id → graceful refusal even on device with moderate available memory.
    func test_argon2idGuard_2GB_moderateMemory_throwsExceeded() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 2_097_152 // 2 GB = 2^21 KiB
        )

        // Mock: 2.5 GB available (8 GB device under moderate load).
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = UInt64(2.5 * 1024 * 1024 * 1024)
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // Should fail: 2 GB > 75% of 2.5 GB (1.875 GB).
        XCTAssertThrowsError(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib))) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            switch cypherError {
            case .argon2idMemoryExceeded(let requiredMb):
                XCTAssertEqual(requiredMb, 2048, "Should report 2048 MB required")
            default:
                XCTFail("Expected argon2idMemoryExceeded, got \(cypherError)")
            }
        }
    }

    /// C4.4: Exact 75% boundary — at boundary should pass.
    /// Guard checks: required * 4 <= available * 3.
    /// Smallest passing available = ceil(required * 4 / 3).
    func test_argon2idGuard_exact75PercentBoundary_passes() throws {
        let requiredKib: UInt64 = 524_288 // 512 MB
        let requiredBytes = requiredKib * 1024

        // Smallest available where required * 4 <= available * 3 (ceiling division).
        let minPassingAvailable = (requiredBytes * 4 + 2) / 3

        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: requiredKib
        )

        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = minPassingAvailable
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)

        // At exact threshold (<=): should pass.
        XCTAssertNoThrow(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib)))
    }

    /// C4.4: One byte below 75% boundary — should fail.
    func test_argon2idGuard_justBelow75PercentBoundary_throwsExceeded() throws {
        let requiredKib: UInt64 = 524_288
        let requiredBytes = requiredKib * 1024
        let minPassingAvailable = (requiredBytes * 4 + 2) / 3

        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: requiredKib
        )

        // 1 byte below the minimum passing available: should fail.
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = minPassingAvailable - 1
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        XCTAssertThrowsError(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib)))
    }

    /// C4.4: Legacy (Iterated+Salted) — guard is a no-op even with minimal memory.
    func test_argon2idGuard_legacy_iteratedSalted_alwaysPasses() throws {
        let key = try engine.generateKey(
            name: "Legacy Test", email: nil, expirySeconds: nil, profile: .universal
        )
        let exported = try engine.exportSecretKey(
            certData: key.certData,
            passphrase: "test-pass-456",
            profile: .universal
        )
        let s2kInfo = try engine.parseS2kParams(armoredData: exported)

        XCTAssertEqual(s2kInfo.s2kType, "iterated-salted")
        XCTAssertEqual(s2kInfo.memoryKib, 0)

        // Even with absurdly low memory, guard should pass for Legacy.
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 1
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        XCTAssertNoThrow(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib)))
    }

    /// Defensive: argon2id type with memoryKib=0 — guard should not throw.
    func test_argon2idGuard_argon2idTypeZeroMemory_passes() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 0
        )
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 1
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        XCTAssertNoThrow(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib)))
    }

    /// Defensive: unknown S2K type — guard should be a no-op.
    func test_argon2idGuard_unknownS2kType_passes() throws {
        let s2kInfo = S2kInfo(
            s2kType: "unknown",
            memoryKib: 999_999_999
        )
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 1
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        XCTAssertNoThrow(try memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib)))
    }

    /// Verify that the guard queries the memory provider exactly once.
    func test_argon2idGuard_queriesMemoryProviderExactlyOnce() throws {
        let s2kInfo = S2kInfo(
            s2kType: "argon2id",
            memoryKib: 524_288
        )
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 8 * 1024 * 1024 * 1024
        let memoryGuard = Argon2idMemoryGuard(memoryInfo: mockMemory)
        _ = try? memoryGuard.validate(protectionInfo: PGPKeyImportS2KInfo(s2kType: s2kInfo.s2kType, memoryKib: s2kInfo.memoryKib))
        XCTAssertEqual(mockMemory.callCount, 1,
                       "Guard should query memory provider exactly once")
    }
}
