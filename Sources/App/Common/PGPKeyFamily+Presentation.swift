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
}
