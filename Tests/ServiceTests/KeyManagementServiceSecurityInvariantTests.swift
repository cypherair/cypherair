import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceSecurityInvariantTests: KeyManagementServiceTestCase {

    func test_validateFingerprint_validV4Fingerprint_succeeds() throws {
        let v4 = String(repeating: "a1b2c3d4", count: 5) // 40 hex chars
        XCTAssertNoThrow(try SEConstants.validateFingerprint(v4))
    }

    func test_validateFingerprint_validV6Fingerprint_succeeds() throws {
        let v6 = String(repeating: "a1b2c3d4", count: 8) // 64 hex chars
        XCTAssertNoThrow(try SEConstants.validateFingerprint(v6))
    }

    func test_validateFingerprint_emptyFingerprint_throwsInvalidFingerprint() {
        XCTAssertThrowsError(try SEConstants.validateFingerprint("")) { error in
            XCTAssertEqual(error as? SecureEnclaveError, .invalidFingerprint)
        }
    }

    func test_validateFingerprint_nonHexFingerprint_throwsInvalidFingerprint() {
        XCTAssertThrowsError(try SEConstants.validateFingerprint("xyz!@#")) { error in
            XCTAssertEqual(error as? SecureEnclaveError, .invalidFingerprint)
        }
    }

    func test_validateFingerprint_mixedCaseFingerprint_isAccepted() {
        // The private-key envelope binds the fingerprint as-is; both hex cases are valid.
        XCTAssertNoThrow(try SEConstants.validateFingerprint("AABBCCDD"))
        XCTAssertNoThrow(try SEConstants.validateFingerprint("aabbccdd"))
    }

    func test_exportKey_highSecurity_biometricsUnavailable_throwsAuthError() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)

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

    func test_importKey_legacy_wrongPassphrase_throwsError() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)
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

    func test_importKey_modernHigh_wrongPassphrase_throwsError() async throws {
        let identity = try await TestHelpers.generateModernHighKey(service: service)
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

    func test_importKey_modernHigh_lowMemory_throwsArgon2idExceeded() async throws {
        // Service with full memory for key generation + export
        let identity = try await TestHelpers.generateModernHighKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "test-pass"
        )

        // Create a separate service with low memory (500 MB)
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 500_000_000
        let (lowMemService, _, _, _, _) = TestHelpers.makeKeyManagement(memoryInfo: mockMemory)

        // Modern High uses Argon2id with 512 MB; 512 MB > 75% of 500 MB (375 MB) → rejected
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

    func test_importKey_legacy_lowMemory_succeeds() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)
        let exported = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "test-pass"
        )

        // Create a service with low memory
        let mockMemory = MockMemoryInfo()
        mockMemory.availableBytes = 500_000_000
        let (lowMemService, _, _, _, _) = TestHelpers.makeKeyManagement(memoryInfo: mockMemory)

        // Legacy uses Iterated+Salted S2K (no Argon2id) — guard is no-op
        let imported = try await lowMemService.importKey(
            armoredData: exported,
            passphrase: "test-pass"
        )
        XCTAssertEqual(imported.softwareSuite, .ed25519LegacyCurve25519Legacy)
    }

}
