import XCTest
@testable import CypherAir

final class PGPKeyOperationAdapterTests: XCTestCase {

    func test_generateKey_zeroizesSecretCertWhenPostGenerationHelperThrows() async {
        let engine = GeneratedKeyParseFailureEngine(noHandle: .init())
        let zeroizer = SpySecretDataZeroizer()
        let adapter = PGPKeyOperationAdapter(
            engine: engine,
            zeroizeSecretData: { data in
                zeroizer.zeroize(&data)
            }
        )

        do {
            _ = try await adapter.generateKey(
                name: "Alice",
                email: nil,
                expirySeconds: nil,
                profile: .universal
            )
            XCTFail("Expected generateKey to throw")
        } catch {
            // Expected: parseKeyInfo failed after generated secret material existed.
        }

        XCTAssertEqual(zeroizer.capturedData, [engine.secretCert])
    }

    func test_importSecretKey_zeroizesSecretCertWhenPostImportHelperThrows() async {
        let engine = ImportedSecretKeyDetectProfileFailureEngine(noHandle: .init())
        let zeroizer = SpySecretDataZeroizer()
        let adapter = PGPKeyOperationAdapter(
            engine: engine,
            zeroizeSecretData: { data in
                zeroizer.zeroize(&data)
            }
        )

        do {
            _ = try await adapter.importSecretKey(
                armoredData: Data("armored".utf8),
                passphrase: "passphrase"
            )
            XCTFail("Expected importSecretKey to throw")
        } catch {
            // Expected: detectProfile failed after imported secret material existed.
        }

        XCTAssertEqual(zeroizer.capturedData, [engine.secretCert])
    }

    func test_successfulSecretReturningOperationsDoNotInvokeAdapterZeroizer() async throws {
        let generateEngine = GeneratedKeySuccessEngine(noHandle: .init())
        let generateZeroizer = SpySecretDataZeroizer()
        let generateAdapter = PGPKeyOperationAdapter(
            engine: generateEngine,
            zeroizeSecretData: { data in
                generateZeroizer.zeroize(&data)
            }
        )

        let generated = try await generateAdapter.generateKey(
            name: "Alice",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        XCTAssertEqual(generated.certData, generateEngine.secretCert)
        XCTAssertTrue(generateZeroizer.capturedData.isEmpty)

        let importEngine = ImportedSecretKeySuccessEngine(noHandle: .init())
        let importZeroizer = SpySecretDataZeroizer()
        let importAdapter = PGPKeyOperationAdapter(
            engine: importEngine,
            zeroizeSecretData: { data in
                importZeroizer.zeroize(&data)
            }
        )

        let imported = try await importAdapter.importSecretKey(
            armoredData: Data("armored".utf8),
            passphrase: "passphrase"
        )

        XCTAssertEqual(imported.secretKeyData, importEngine.secretCert)
        XCTAssertTrue(importZeroizer.capturedData.isEmpty)
    }
}

private final class SpySecretDataZeroizer: @unchecked Sendable {
    private(set) var capturedData: [Data] = []

    func zeroize(_ data: inout Data) {
        capturedData.append(data)
        data.zeroize()
    }
}

private class GeneratedKeySuccessEngine: PgpEngine {
    let secretCert = Data([0xA1, 0xA2, 0xA3])
    let publicKey = Data([0xB1, 0xB2])
    let revocation = Data([0xC1])

    override func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: KeyProfile
    ) throws -> GeneratedKey {
        GeneratedKey(
            certData: secretCert,
            publicKeyData: publicKey,
            revocationCert: revocation,
            fingerprint: "generated-fingerprint",
            keyVersion: 4,
            profile: profile
        )
    }

    override func parseKeyInfo(keyData: Data) throws -> KeyInfo {
        keyInfo()
    }
}

private final class GeneratedKeyParseFailureEngine: GeneratedKeySuccessEngine {
    override func parseKeyInfo(keyData: Data) throws -> KeyInfo {
        throw PgpError.InvalidKeyData(reason: "parse failed")
    }
}

private class ImportedSecretKeySuccessEngine: PgpEngine {
    let secretCert = Data([0xD1, 0xD2, 0xD3])
    let publicKey = Data([0xE1, 0xE2])
    let revocation = Data([0xF1])

    override func importSecretKey(
        armoredData: Data,
        passphrase: String
    ) throws -> Data {
        secretCert
    }

    override func parseKeyInfo(keyData: Data) throws -> KeyInfo {
        keyInfo()
    }

    override func detectProfile(certData: Data) throws -> KeyProfile {
        .universal
    }

    override func armorPublicKey(certData: Data) throws -> Data {
        Data("armored-public-key".utf8)
    }

    override func dearmor(armored: Data) throws -> Data {
        publicKey
    }

    override func generateKeyRevocation(secretCert: Data) throws -> Data {
        revocation
    }
}

private final class ImportedSecretKeyDetectProfileFailureEngine: ImportedSecretKeySuccessEngine {
    override func detectProfile(certData: Data) throws -> KeyProfile {
        throw PgpError.InvalidKeyData(reason: "profile detection failed")
    }
}

private func keyInfo() -> KeyInfo {
    KeyInfo(
        fingerprint: "test-fingerprint",
        keyVersion: 4,
        userId: "Test User",
        hasEncryptionSubkey: true,
        isRevoked: false,
        isExpired: false,
        profile: .universal,
        primaryAlgo: "Ed25519",
        subkeyAlgo: "X25519",
        expiryTimestamp: nil
    )
}
