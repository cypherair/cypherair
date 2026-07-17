import Foundation

/// FFI-owned mapping for generated key metadata and suite values.
enum PGPKeyMetadataAdapter {
    static func metadata(from keyInfo: KeyInfo) -> PGPKeyMetadata {
        metadata(from: keyInfo, suite: keyInfo.suite)
    }

    /// `suite: nil` means the certificate has no software suite classification
    /// (P-256 Secure Enclave custody), not a classification failure.
    static func metadata(
        from keyInfo: KeyInfo,
        suite: KeySuite?
    ) -> PGPKeyMetadata {
        PGPKeyMetadata(
            fingerprint: keyInfo.fingerprint,
            keyVersion: keyInfo.keyVersion,
            userId: keyInfo.userId,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            isRevoked: keyInfo.isRevoked,
            isExpired: keyInfo.isExpired,
            suite: suite?.appSuite,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo,
            expiryTimestamp: keyInfo.expiryTimestamp
        )
    }

    static func metadata(
        from validation: PublicCertificateValidationResult
    ) -> PGPKeyMetadata {
        metadata(from: validation.keyInfo, suite: validation.suite)
    }
}

extension PGPKeySuite {
    var ffiValue: KeySuite {
        switch self {
        case .ed25519LegacyCurve25519Legacy: .ed25519LegacyCurve25519Legacy
        case .ed25519X25519: .ed25519X25519
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
        case .ed25519X25519: .ed25519X25519
        case .ed448X448: .ed448X448
        case .mlDsa65Ed25519MlKem768X25519: .mlDsa65Ed25519MlKem768X25519
        case .mlDsa87Ed448MlKem1024X448: .mlDsa87Ed448MlKem1024X448
        }
    }
}
