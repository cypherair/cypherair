import Foundation

extension PGPKeyConfiguration.Identity {
    /// Stable presentation order for key-family selection and key-detail surfaces.
    static let orderedFamilies: [PGPKeyConfiguration.Identity] = [
        .compatibleSoftwareV4,
        .modernSoftwareV6,
        .compatibleP256V4,
        .modernP256V6,
    ]

    /// Whether this family's private key is device-bound Secure Enclave custody.
    var isDeviceBoundFamily: Bool {
        switch self {
        case .compatibleSoftwareV4, .modernSoftwareV6:
            false
        case .compatibleP256V4, .modernP256V6:
            true
        }
    }

    /// User-facing family name.
    var familyDisplayName: String {
        switch self {
        case .compatibleSoftwareV4:
            String(localized: "keyFamily.portableCompatible.name", defaultValue: "Portable Compatible")
        case .modernSoftwareV6:
            String(localized: "keyFamily.portableModern.name", defaultValue: "Portable Modern")
        case .compatibleP256V4:
            String(localized: "keyFamily.deviceBoundCompatible.name", defaultValue: "Device-Bound Compatible")
        case .modernP256V6:
            String(localized: "keyFamily.deviceBoundModern.name", defaultValue: "Device-Bound Modern")
        }
    }

    /// One-line description for key-family selection UI.
    var familyDescription: String {
        switch self {
        case .compatibleSoftwareV4:
            String(
                localized: "keyFamily.portableCompatible.description",
                defaultValue: "Works with all PGP tools including GnuPG. The private key can be exported and backed up."
            )
        case .modernSoftwareV6:
            String(
                localized: "keyFamily.portableModern.description",
                defaultValue: "Uses the latest encryption standard (RFC 9580) with stronger algorithms. Not compatible with GnuPG. The private key can be exported and backed up."
            )
        case .compatibleP256V4:
            String(
                localized: "keyFamily.deviceBoundCompatible.description",
                defaultValue: "Works with GnuPG and other OpenPGP tools. The private key lives in this device's Secure Enclave and cannot be exported or backed up."
            )
        case .modernP256V6:
            String(
                localized: "keyFamily.deviceBoundModern.description",
                defaultValue: "Uses the latest OpenPGP standard (RFC 9580). Not compatible with GnuPG. The private key lives in this device's Secure Enclave and cannot be exported or backed up."
            )
        }
    }

    /// Approximate security level for key-detail display.
    var familySecurityLevel: String {
        switch self {
        case .compatibleSoftwareV4:
            String(localized: "keyFamily.portableCompatible.securityLevel", defaultValue: "~128 bit")
        case .modernSoftwareV6:
            String(localized: "keyFamily.portableModern.securityLevel", defaultValue: "~224 bit")
        case .compatibleP256V4:
            String(localized: "keyFamily.deviceBoundCompatible.securityLevel", defaultValue: "~128 bit")
        case .modernP256V6:
            String(localized: "keyFamily.deviceBoundModern.securityLevel", defaultValue: "~128 bit")
        }
    }

    /// Algorithm details for the key-family detail sheet.
    var familyAlgorithmSummary: String {
        switch self {
        case .compatibleSoftwareV4:
            String(localized: "keyFamily.portableCompatible.algorithms", defaultValue: "Ed25519 signing + X25519 encryption")
        case .modernSoftwareV6:
            String(localized: "keyFamily.portableModern.algorithms", defaultValue: "Ed448 signing + X448 encryption")
        case .compatibleP256V4, .modernP256V6:
            String(localized: "keyFamily.deviceBound.algorithms", defaultValue: "P-256 signing + P-256 key agreement")
        }
    }

    /// OpenPGP key version for the key-family detail sheet.
    var familyKeyVersionDisplay: String {
        switch self {
        case .compatibleSoftwareV4, .compatibleP256V4:
            String(localized: "keyFamily.version.v4", defaultValue: "v4")
        case .modernSoftwareV6, .modernP256V6:
            String(localized: "keyFamily.version.v6", defaultValue: "v6")
        }
    }

    /// Message format preference advertised by this key family.
    var familyMessageFormatDisplay: String {
        switch self {
        case .compatibleSoftwareV4, .compatibleP256V4:
            String(localized: "keyFamily.messageFormat.seipdv1", defaultValue: "SEIPDv1 (MDC)")
        case .modernSoftwareV6, .modernP256V6:
            String(localized: "keyFamily.messageFormat.seipdv2", defaultValue: "SEIPDv2 (AEAD OCB)")
        }
    }

    /// Private-key export and backup capability for the key-family detail sheet.
    var familyExportabilityDisplay: String {
        switch self {
        case .compatibleSoftwareV4, .modernSoftwareV6:
            String(localized: "keyFamily.exportability.portable", defaultValue: "Private key can be exported and backed up")
        case .compatibleP256V4, .modernP256V6:
            String(localized: "keyFamily.exportability.deviceBound", defaultValue: "Private key cannot be exported or backed up")
        }
    }

    /// GnuPG compatibility statement for the key-family detail sheet.
    var familyGnuPGCompatibilityDisplay: String {
        switch self {
        case .compatibleSoftwareV4, .compatibleP256V4:
            String(localized: "keyFamily.gnupg.compatible", defaultValue: "Compatible with GnuPG")
        case .modernSoftwareV6, .modernP256V6:
            String(localized: "keyFamily.gnupg.notCompatible", defaultValue: "Not compatible with GnuPG")
        }
    }

    /// Custody model for the key-family detail sheet.
    var familyCustodyDisplay: String {
        switch self {
        case .compatibleSoftwareV4, .modernSoftwareV6:
            String(localized: "keyFamily.custody.portable", defaultValue: "Portable software key")
        case .compatibleP256V4, .modernP256V6:
            String(localized: "keyFamily.custody.deviceBound", defaultValue: "Device-bound Secure Enclave custody")
        }
    }

    /// Fixed biometric requirement for device-bound Secure Enclave custody keys.
    static var deviceBoundBiometricRequirement: String {
        String(
            localized: "keyFamily.deviceBound.biometricRequirement",
            defaultValue: "Device-bound keys always require biometric authentication. For security, this enforcement is fixed and cannot be changed."
        )
    }
}
