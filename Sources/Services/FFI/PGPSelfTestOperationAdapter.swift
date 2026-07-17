import Foundation

struct PGPSelfTestGeneratedKey: Sendable {
    var certData: Data
    let publicKeyData: Data
    let keyVersion: UInt8

    mutating func zeroizeSensitiveMaterial() {
        certData.resetBytes(in: 0..<certData.count)
    }
}

/// FFI-owned operations used by the one-tap self-test diagnostics.
final class PGPSelfTestOperationAdapter: @unchecked Sendable {
    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        suite: PGPKeySuite
    ) async throws -> PGPSelfTestGeneratedKey {
        do {
            return try await Self.performGenerateKey(
                engine: engine,
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                suite: suite
            )
        } catch {
            throw PGPErrorMapper.map(error) { .keyGenerationFailed(reason: $0) }
        }
    }

    func exportSecretKey(
        certData: Data,
        passphrase: String
    ) async throws -> Data {
        do {
            return try await Self.performExportSecretKey(
                engine: engine,
                certData: certData,
                passphrase: passphrase
            )
        } catch {
            throw PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
        }
    }

    func importSecretKey(
        armoredData: Data,
        passphrase: String
    ) async throws -> Data {
        do {
            return try await Self.performImportSecretKey(
                engine: engine,
                armoredData: armoredData,
                passphrase: passphrase
            )
        } catch {
            throw PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
        }
    }

    func metadata(forKeyData keyData: Data) async throws -> PGPKeyMetadata {
        do {
            return try await Self.performMetadata(engine: engine, keyData: keyData)
        } catch {
            throw PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
        }
    }

    func encodeQrUrl(publicKeyData: Data) async throws -> String {
        do {
            return try await Self.performEncodeQrUrl(engine: engine, publicKeyData: publicKeyData)
        } catch {
            throw PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
        }
    }

    func decodeQrUrl(_ urlString: String) async throws -> Data {
        do {
            return try await Self.performDecodeQrUrl(engine: engine, urlString: urlString)
        } catch {
            throw CypherAirError.invalidQRCode
        }
    }

    @concurrent
    private static func performGenerateKey(
        engine: PgpEngine,
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        suite: PGPKeySuite
    ) async throws -> PGPSelfTestGeneratedKey {
        var generated = try engine.generateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            suite: suite.ffiValue
        )
        // Self-test never stores the revocation certificate, so per the
        // GeneratedKey contract the sole in-memory copy is zeroized here.
        generated.revocationCert.resetBytes(in: 0..<generated.revocationCert.count)
        return PGPSelfTestGeneratedKey(
            certData: generated.certData,
            publicKeyData: generated.publicKeyData,
            keyVersion: generated.keyVersion
        )
    }

    @concurrent
    private static func performExportSecretKey(
        engine: PgpEngine,
        certData: Data,
        passphrase: String
    ) async throws -> Data {
        try engine.exportSecretKey(
            certData: certData,
            passphrase: passphrase
        )
    }

    @concurrent
    private static func performImportSecretKey(
        engine: PgpEngine,
        armoredData: Data,
        passphrase: String
    ) async throws -> Data {
        try engine.importSecretKey(
            armoredData: armoredData,
            passphrase: passphrase
        )
    }

    @concurrent
    private static func performMetadata(
        engine: PgpEngine,
        keyData: Data
    ) async throws -> PGPKeyMetadata {
        let keyInfo = try engine.parseKeyInfo(keyData: keyData)
        return PGPKeyMetadataAdapter.metadata(from: keyInfo)
    }

    @concurrent
    private static func performEncodeQrUrl(
        engine: PgpEngine,
        publicKeyData: Data
    ) async throws -> String {
        try engine.encodeQrUrl(publicKeyData: publicKeyData)
    }

    @concurrent
    private static func performDecodeQrUrl(
        engine: PgpEngine,
        urlString: String
    ) async throws -> Data {
        try engine.decodeQrUrl(url: urlString)
    }
}
