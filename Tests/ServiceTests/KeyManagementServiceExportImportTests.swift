import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir


final class KeyManagementServiceExportImportTests: KeyManagementServiceTestCase {

    func test_exportKey_legacy_returnsArmoredData() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)

        let exported = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: "test-pass-123")

        XCTAssertFalse(exported.isEmpty, "Exported data should not be empty")
        // Check it starts with PGP armor header
        let armorHeader = String(data: exported.prefix(27), encoding: .utf8)
        XCTAssertTrue(armorHeader?.hasPrefix("-----BEGIN PGP") == true,
                      "Exported data should be ASCII-armored")
    }

    func test_exportKey_marksKeyAsBackedUp() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)
        XCTAssertFalse(identity.isBackedUp)

        _ = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: "backup-pass")

        XCTAssertTrue(service.keys.first?.isBackedUp == true,
                      "Key should be marked as backed up after export")
    }

    func test_exportKeyBackupData_doesNotMarkBackedUpUntilConfirmed() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)
        XCTAssertFalse(try XCTUnwrap(service.keys.first).isBackedUp)

        var exported = try await service.exportKeyBackupData(
            fingerprint: identity.fingerprint,
            passphrase: "backup-pass"
        )
        defer {
            exported.resetBytes(in: 0..<exported.count)
        }

        XCTAssertFalse(try XCTUnwrap(service.keys.first).isBackedUp)

        service.confirmKeyBackupExported(fingerprint: identity.fingerprint)

        XCTAssertTrue(try XCTUnwrap(service.keys.first).isBackedUp)
    }

    func test_exportKey_metadataUpdateFailure_keepsSessionBackedUp_butFreshServiceSeesOldState() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service)
        metadataPersistence.failNextUpdate = true

        _ = try await service.exportKey(
            fingerprint: identity.fingerprint,
            passphrase: "backup-pass"
        )

        XCTAssertTrue(try XCTUnwrap(service.keys.first).isBackedUp)

        let freshService = makeFreshService()
        try freshService.loadKeys()

        XCTAssertEqual(freshService.keys.count, 1)
        XCTAssertFalse(try XCTUnwrap(freshService.keys.first).isBackedUp)
    }

    func test_exportKey_nonexistentFingerprint_throwsError() async {
        do {
            _ = try await service.exportKey(fingerprint: "nonexistent", passphrase: "pass")
            XCTFail("Expected error for nonexistent fingerprint")
        } catch {
            // Should fail — no key with this fingerprint exists in Keychain
        }
    }

    func test_exportKey_modernHigh_returnsArmoredData() async throws {
        let identity = try await TestHelpers.generateModernHighKey(service: service)

        let exported = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: "test-pass-456")
        XCTAssertFalse(exported.isEmpty)
    }

    func test_importKey_legacy_exportThenImport_fingerprintMatches() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service, name: "Export Test A")
        let passphrase = "test-passphrase-123"

        // Export the key
        let exportedData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        XCTAssertFalse(exportedData.isEmpty)

        // Delete the original key
        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        // Import the exported key
        let imported = try await service.importKey(
            armoredData: exportedData,
            passphrase: passphrase
        )

        // Verify fingerprint and suite match
        XCTAssertEqual(imported.fingerprint, identity.fingerprint,
                       "Imported key fingerprint should match original")
        XCTAssertEqual(imported.softwareSuite, .ed25519LegacyCurve25519Legacy,
                       "Imported key should retain the legacy suite")
        XCTAssertEqual(imported.keyVersion, 4)
    }

    func test_importKey_modernHigh_exportThenImport_fingerprintMatches() async throws {
        let identity = try await TestHelpers.generateModernHighKey(service: service, name: "Export Test B")
        let passphrase = "test-passphrase-456"

        let exportedData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        XCTAssertFalse(exportedData.isEmpty)

        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        let imported = try await service.importKey(
            armoredData: exportedData,
            passphrase: passphrase
        )

        XCTAssertEqual(imported.fingerprint, identity.fingerprint,
                       "Imported key fingerprint should match original")
        XCTAssertEqual(imported.softwareSuite, .ed448X448,
                       "Imported key should retain the Ed448 suite")
        XCTAssertEqual(imported.keyVersion, 6)
    }

    func test_importKey_duplicateFingerprint_throwsDuplicateKeyError() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service, name: "Original A")
        let passphrase = "test-pass-dup-a"

        // Export the key (to get armored data for re-import)
        let exportedData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)

        // Attempt to import without deleting — should throw duplicateKey
        do {
            _ = try await service.importKey(armoredData: exportedData, passphrase: passphrase)
            XCTFail("Expected CypherAirError.duplicateKey")
        } catch {
            guard let cypherError = error as? CypherAirError,
                  case .duplicateKey = cypherError else {
                return XCTFail("Expected CypherAirError.duplicateKey, got \(error)")
            }
        }

        // Verify no extra SE key was generated (guard fired before SE wrapping)
        // 1 generate for original key + 0 for the rejected import = 1 total
        XCTAssertEqual(mockSE.generateCallCount, 1,
                       "SE key should not be generated for duplicate import")
    }

    func test_importKey_duplicateFingerprint_modernHigh_throwsDuplicateKeyError() async throws {
        let identity = try await TestHelpers.generateModernHighKey(service: service, name: "Original B")
        let passphrase = "test-pass-dup-b"

        let exportedData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)

        do {
            _ = try await service.importKey(armoredData: exportedData, passphrase: passphrase)
            XCTFail("Expected CypherAirError.duplicateKey")
        } catch {
            guard let cypherError = error as? CypherAirError,
                  case .duplicateKey = cypherError else {
                return XCTFail("Expected CypherAirError.duplicateKey, got \(error)")
            }
        }

        XCTAssertEqual(mockSE.generateCallCount, 1,
                       "SE key should not be generated for duplicate Modern High import")
    }

    func test_importKey_binaryFormat_legacy_fingerprintMatches() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: service, name: "Binary Import A")
        let passphrase = "binary-test-pass-a"

        // Export produces ASCII armor
        let armoredData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        XCTAssertTrue(String(data: armoredData.prefix(5), encoding: .utf8)?.hasPrefix("-----") == true)

        // Convert to binary OpenPGP format
        let binaryData = try engine.dearmor(armored: armoredData)
        XCTAssertNotEqual(binaryData.first, UInt8(ascii: "-"),
                          "Dearmored data should not start with ASCII armor header")

        // Delete the original
        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        // Import using binary format — this is the same path that views now use
        let imported = try await service.importKey(
            armoredData: binaryData,
            passphrase: passphrase
        )

        XCTAssertEqual(imported.fingerprint, identity.fingerprint,
                       "Binary import should produce same fingerprint as original")
        XCTAssertEqual(imported.softwareSuite, .ed25519LegacyCurve25519Legacy)
        XCTAssertEqual(imported.keyVersion, 4)
        XCTAssertFalse(imported.revocationCert.isEmpty, "Imported key should immediately store a revocation signature")
    }

    func test_importKey_binaryFormat_modernHigh_fingerprintMatches() async throws {
        let identity = try await TestHelpers.generateModernHighKey(service: service, name: "Binary Import B")
        let passphrase = "binary-test-pass-b"

        let armoredData = try await service.exportKey(fingerprint: identity.fingerprint, passphrase: passphrase)
        let binaryData = try engine.dearmor(armored: armoredData)

        try service.deleteKey(fingerprint: identity.fingerprint)
        XCTAssertTrue(service.keys.isEmpty)

        let imported = try await service.importKey(
            armoredData: binaryData,
            passphrase: passphrase
        )

        XCTAssertEqual(imported.fingerprint, identity.fingerprint,
                       "Binary import should produce same fingerprint as original")
        XCTAssertEqual(imported.softwareSuite, .ed448X448)
        XCTAssertEqual(imported.keyVersion, 6)
        XCTAssertFalse(imported.revocationCert.isEmpty)
    }

}
