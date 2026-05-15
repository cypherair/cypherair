import Foundation

struct PGPSelfTestGeneratedKey: Sendable {
    var certData: Data
    let publicKeyData: Data
    var revocationCert: Data
    let fingerprint: String
    let keyVersion: UInt8
    let profile: PGPKeyProfile

    mutating func zeroizeSensitiveMaterial() {
        certData.resetBytes(in: 0..<certData.count)
        revocationCert.resetBytes(in: 0..<revocationCert.count)
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
        profile: PGPKeyProfile
    ) async throws -> PGPSelfTestGeneratedKey {
        do {
            return try await Self.performGenerateKey(
                engine: engine,
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                profile: profile
            )
        } catch {
            throw PGPErrorMapper.map(error) { .keyGenerationFailed(reason: $0) }
        }
    }

    func exportSecretKey(
        certData: Data,
        passphrase: String,
        profile: PGPKeyProfile
    ) async throws -> Data {
        do {
            return try await Self.performExportSecretKey(
                engine: engine,
                certData: certData,
                passphrase: passphrase,
                profile: profile
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
        profile: PGPKeyProfile
    ) async throws -> PGPSelfTestGeneratedKey {
        let generated = try engine.generateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            profile: profile.ffiValue
        )
        return PGPSelfTestGeneratedKey(
            certData: generated.certData,
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            fingerprint: generated.fingerprint,
            keyVersion: generated.keyVersion,
            profile: generated.profile.appProfile
        )
    }

    @concurrent
    private static func performExportSecretKey(
        engine: PgpEngine,
        certData: Data,
        passphrase: String,
        profile: PGPKeyProfile
    ) async throws -> Data {
        try engine.exportSecretKey(
            certData: certData,
            passphrase: passphrase,
            profile: profile.ffiValue
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
