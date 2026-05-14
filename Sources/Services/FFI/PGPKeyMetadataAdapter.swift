import Foundation

/// FFI-owned mapping for generated key metadata and profile values.
enum PGPKeyMetadataAdapter {
    static func metadata(from keyInfo: KeyInfo) -> PGPKeyMetadata {
        metadata(from: keyInfo, profile: keyInfo.profile)
    }

    static func metadata(
        from keyInfo: KeyInfo,
        profile: KeyProfile
    ) -> PGPKeyMetadata {
        PGPKeyMetadata(
            fingerprint: keyInfo.fingerprint,
            keyVersion: keyInfo.keyVersion,
            userId: keyInfo.userId,
            hasEncryptionSubkey: keyInfo.hasEncryptionSubkey,
            isRevoked: keyInfo.isRevoked,
            isExpired: keyInfo.isExpired,
            profile: profile.appProfile,
            primaryAlgo: keyInfo.primaryAlgo,
            subkeyAlgo: keyInfo.subkeyAlgo,
            expiryTimestamp: keyInfo.expiryTimestamp
        )
    }

    static func metadata(
        from validation: PublicCertificateValidationResult
    ) -> PGPKeyMetadata {
        metadata(from: validation.keyInfo, profile: validation.profile)
    }
}

extension PGPKeyProfile {
    var ffiValue: KeyProfile {
        switch self {
        case .universal: .universal
        case .advanced: .advanced
        }
    }
}

extension KeyProfile {
    var appProfile: PGPKeyProfile {
        switch self {
        case .universal: .universal
        case .advanced: .advanced
        }
    }
}
