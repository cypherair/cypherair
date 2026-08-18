import Foundation

/// FFI-owned mapping for parsed key metadata and suite values.
enum PGPKeyMetadataAdapter {
    static func metadata(from keyInfo: KeyInfo) -> PGPKeyMetadata {
        PGPKeyMetadata(
            fingerprint: keyInfo.fingerprint,
            keyVersion: keyInfo.keyVersion,
            userId: keyInfo.userId,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            isRevoked: keyInfo.isRevoked,
            isExpired: keyInfo.isExpired,
            suite: keyInfo.suite?.appSuite,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo,
            expiryTimestamp: keyInfo.expiryTimestamp
        )
    }

    static func metadata(
        from validation: PublicCertificateValidationResult
    ) -> PGPKeyMetadata {
        metadata(from: validation.keyInfo)
    }
}

extension PGPKeySuite {
    var ffiValue: KeySuite {
        switch self {
        case .ed25519LegacyCurve25519Legacy: .ed25519LegacyCurve25519Legacy
        case .ecdsaNistP256EcdhNistP256V4: .ecdsaNistP256EcdhNistP256V4
        case .ed25519X25519: .ed25519X25519
        case .ecdsaNistP256EcdhNistP256: .ecdsaNistP256EcdhNistP256
        case .ed448X448: .ed448X448
        case .mlDsa65Ed25519MlKem768X25519: .mlDsa65Ed25519MlKem768X25519
        case .mlDsa87Ed448MlKem1024X448: .mlDsa87Ed448MlKem1024X448
        }
    }
}

extension KeySuite {
    var appSuite: PGPKeySuite {
        switch self {
        case .ed25519LegacyCurve25519Legacy: .ed25519LegacyCurve25519Legacy
        case .ecdsaNistP256EcdhNistP256V4: .ecdsaNistP256EcdhNistP256V4
        case .ed25519X25519: .ed25519X25519
        case .ecdsaNistP256EcdhNistP256: .ecdsaNistP256EcdhNistP256
        case .ed448X448: .ed448X448
        case .mlDsa65Ed25519MlKem768X25519: .mlDsa65Ed25519MlKem768X25519
        case .mlDsa87Ed448MlKem1024X448: .mlDsa87Ed448MlKem1024X448
        }
    }
}
