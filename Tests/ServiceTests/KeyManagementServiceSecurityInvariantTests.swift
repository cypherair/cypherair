import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceSecurityInvariantTests: KeyManagementServiceTestCase {

    func test_hkdfInfo_validV4Fingerprint_succeeds() async throws {
        let v4 = String(repeating: "a1b2c3d4", count: 5) // 40 hex chars
        let data = try SEConstants.hkdfInfo(fingerprint: v4)
        XCTAssertTrue(data.count > 0)
    }

    func test_hkdfInfo_validV6Fingerprint_succeeds() async throws {
        let v6 = String(repeating: "a1b2c3d4", count: 8) // 64 hex chars
        let data = try SEConstants.hkdfInfo(fingerprint: v6)
        XCTAssertTrue(data.count > 0)
    }

    func test_hkdfInfo_emptyFingerprint_throwsInvalidFingerprint() {
        XCTAssertThrowsError(try SEConstants.hkdfInfo(fingerprint: "")) { error in
            XCTAssertEqual(error as? SecureEnclaveError, .invalidFingerprint)
        }
    }

    func test_hkdfInfo_nonHexFingerprint_throwsInvalidFingerprint() {
        XCTAssertThrowsError(try SEConstants.hkdfInfo(fingerprint: "xyz!@#")) { error in
            XCTAssertEqual(error as? SecureEnclaveError, .invalidFingerprint)
        }
    }

    func test_hkdfInfo_mixedCaseFingerprint_normalizedToLowercase() async throws {
        let upper = "AABBCCDD"
        let lower = "aabbccdd"
        let dataUpper = try SEConstants.hkdfInfo(fingerprint: upper)
        let dataLower = try SEConstants.hkdfInfo(fingerprint: lower)
        XCTAssertEqual(dataUpper, dataLower, "Mixed case should normalize to same info data")
    }

    func test_exportKey_highSecurity_biometricsUnavailable_throwsAuthError() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)

        mockSE.simulatedAuthMode = .highSecurity
        mockSE.biometricsAvailable = false

        do {
            _ = try await service.exportKey(
                fingerprint: identity.fingerprint,
                passphrase: "backup-pass"
            )
            XCTFail("Expected error when biometrics unavailable in High Security mode")
        } catch {
            // Auth error from SE reconstructKey during unwrapPrivateKey
        }
    }

    func test_importKey_profileA_wrongPassphrase_throwsError() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "correct-passphrase"
        )

        // Attempt import with wrong passphrase
        do {
            _ = try await service.importKey(
                armoredData: exported,
                passphrase: "wrong-passphrase"
            )
            XCTFail("Expected error for wrong passphrase")
        } catch let error as CypherAirError {
            // Accept .wrongPassphrase or .s2kError — both indicate passphrase failure
            switch error {
            case .wrongPassphrase, .s2kError:
                break // Expected
            default:
                XCTFail("Expected wrong passphrase error, got \(error)")
            }
        }
    }

    func test_importKey_profileB_wrongPassphrase_throwsError() async throws {
        let identity = try await TestHelpers.generateProfileBKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "correct-passphrase"
        )

        do {
            _ = try await service.importKey(
                armoredData: exported,
                passphrase: "wrong-passphrase"
            )
            XCTFail("Expected error for wrong passphrase")
        } catch let error as CypherAirError {
            switch error {
            case .wrongPassphrase, .s2kError:
                break // Expected
            default:
                XCTFail("Expected wrong passphrase error, got \(error)")
            }
        }
    }

    func test_importKey_profileB_lowMemory_throwsArgon2idExceeded() async throws {
        // Service with full memory for key generation + export
        let identity = try await TestHelpers.generateProfileBKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "test-pass"
        )

        // Create a separate service with low memory (500 MB)
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 500_000_000
        let (lowMemService, _, _, _) = TestHelpers.makeKeyManagement(memoryInfo: mockMemory)

        // Profile B uses Argon2id with 512 MB; 512 MB > 75% of 500 MB (375 MB) → rejected
        do {
            _ = try await lowMemService.importKey(
                armoredData: exported,
                passphrase: "test-pass"
            )
            XCTFail("Expected argon2idMemoryExceeded for low-memory import")
        } catch let error as CypherAirError {
            if case .argon2idMemoryExceeded = error {
                // Expected
            } else {
                XCTFail("Expected .argon2idMemoryExceeded, got \(error)")
            }
        }
    }

    func test_importKey_profileA_lowMemory_succeeds() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "test-pass"
        )

        // Create a service with low memory
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 500_000_000
        let (lowMemService, _, _, _) = TestHelpers.makeKeyManagement(memoryInfo: mockMemory)

        // Profile A uses Iterated+Salted S2K (no Argon2id) — guard is no-op
        let imported = try await lowMemService.importKey(
            armoredData: exported,
            passphrase: "test-pass"
        )
        XCTAssertEqual(imported.profile, .universal)
    }

}
