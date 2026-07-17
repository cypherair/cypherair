import Foundation

extension PGPKeyFamily {
    /// Stable presentation order for key-family selection and key-detail surfaces.
    static let orderedFamilies: [PGPKeyFamily] = [
        .portableEd25519LegacyCurve25519Legacy,
        .portableEd25519X25519,
        .portableEd448X448,
        .portableMlDsa65Ed25519MlKem768X25519,
        .portableMlDsa87Ed448MlKem1024X448,
        .deviceBoundEcdsaNistP256EcdhNistP256V4,
        .deviceBoundEcdsaNistP256EcdhNistP256,
        .deviceBoundMlDsa65Ed25519MlKem768X25519,
        .deviceBoundMlDsa87Ed448MlKem1024X448,
    ]

    /// User-facing family name.
    var familyDisplayName: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy:
            String(localized: "keyFamily.portableEd25519LegacyCurve25519Legacy.name", defaultValue: "Portable Legacy")
        case .portableEd25519X25519:
            String(localized: "keyFamily.portableModern.name", defaultValue: "Portable Modern")
        case .portableEd448X448:
            String(localized: "keyFamily.portableModernHigh.name", defaultValue: "Portable Modern · High")
        case .portableMlDsa65Ed25519MlKem768X25519:
            String(localized: "keyFamily.portablePostQuantum.name", defaultValue: "Portable Post-Quantum")
        case .portableMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.portablePostQuantumHigh.name", defaultValue: "Portable Post-Quantum · High")
        case .deviceBoundEcdsaNistP256EcdhNistP256V4:
            String(localized: "keyFamily.deviceBoundEcdsaNistP256EcdhNistP256V4.name", defaultValue: "Device-Bound Legacy")
        case .deviceBoundEcdsaNistP256EcdhNistP256:
            String(localized: "keyFamily.deviceBoundModern.name", defaultValue: "Device-Bound Modern")
        case .deviceBoundMlDsa65Ed25519MlKem768X25519:
            String(localized: "keyFamily.deviceBoundPostQuantum.name", defaultValue: "Device-Bound Post-Quantum")
        case .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.deviceBoundPostQuantumHigh.name", defaultValue: "Device-Bound Post-Quantum · High")
        }
    }

    /// One-line description for key-family selection UI.
    var familyDescription: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy:
            String(
                localized: "keyFamily.portableEd25519LegacyCurve25519Legacy.description",
                defaultValue: "Works with all PGP tools including GnuPG. The private key can be exported and backed up."
            )
        case .portableEd25519X25519:
            String(
                localized: "keyFamily.portableModern.description",
                defaultValue: "Uses the modern OpenPGP standard (RFC 9580), widely supported by up-to-date tools. Not compatible with GnuPG. The private key can be exported and backed up."
            )
        case .portableEd448X448:
            String(
                localized: "keyFamily.portableModernHigh.description",
                defaultValue: "Uses the modern OpenPGP standard (RFC 9580) with the stronger Ed448 curve; some tools do not yet support it. Not compatible with GnuPG. The private key can be exported and backed up."
            )
        case .portableMlDsa65Ed25519MlKem768X25519:
            String(
                localized: "keyFamily.portablePostQuantum.description",
                defaultValue: "Uses post-quantum encryption (RFC 9980) designed to resist future quantum computers. Not compatible with GnuPG. The private key can be exported and backed up."
            )
        case .portableMlDsa87Ed448MlKem1024X448:
            String(
                localized: "keyFamily.portablePostQuantumHigh.description",
                defaultValue: "Uses the strongest post-quantum encryption (RFC 9980, ML-KEM-1024) designed to resist future quantum computers. Not compatible with GnuPG. The private key can be exported and backed up."
            )
        case .deviceBoundEcdsaNistP256EcdhNistP256V4:
            String(
                localized: "keyFamily.deviceBoundEcdsaNistP256EcdhNistP256V4.description",
                defaultValue: "Works with GnuPG and other OpenPGP tools. The private key lives in this device's Secure Enclave and cannot be exported or backed up."
            )
        case .deviceBoundEcdsaNistP256EcdhNistP256:
            String(
                localized: "keyFamily.deviceBoundModern.description",
                defaultValue: "Uses the latest OpenPGP standard (RFC 9580). Not compatible with GnuPG. The private key lives in this device's Secure Enclave and cannot be exported or backed up."
            )
        case .deviceBoundMlDsa65Ed25519MlKem768X25519:
            String(
                localized: "keyFamily.deviceBoundPostQuantum.description",
                defaultValue: "Uses post-quantum encryption (RFC 9980) designed to resist future quantum computers. Not compatible with GnuPG. The key is split for this device: the post-quantum half lives in the Secure Enclave, the classical half is sealed to this device. It cannot be exported or backed up."
            )
        case .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(
                localized: "keyFamily.deviceBoundPostQuantumHigh.description",
                defaultValue: "Uses the strongest post-quantum encryption (RFC 9980, ML-KEM-1024) designed to resist future quantum computers. Not compatible with GnuPG. The key is split for this device: the post-quantum half lives in the Secure Enclave, the classical half is sealed to this device. It cannot be exported or backed up."
            )
        }
    }

    /// Concise algorithm line (curve + format) shown as the picker row subtitle.
    var familyAlgorithmSubtitle: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy:
            String(localized: "keyFamily.portableEd25519LegacyCurve25519Legacy.subtitle", defaultValue: "Curve25519 · OpenPGP v4")
        case .portableEd25519X25519:
            String(localized: "keyFamily.portableModern.subtitle", defaultValue: "Ed25519 · OpenPGP v6")
        case .portableEd448X448:
            String(localized: "keyFamily.portableModernHigh.subtitle", defaultValue: "Ed448 · OpenPGP v6")
        case .portableMlDsa65Ed25519MlKem768X25519:
            String(localized: "keyFamily.portablePostQuantum.subtitle", defaultValue: "ML-KEM-768 + X25519 · OpenPGP v6")
        case .portableMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.portablePostQuantumHigh.subtitle", defaultValue: "ML-KEM-1024 + X448 · OpenPGP v6")
        case .deviceBoundEcdsaNistP256EcdhNistP256V4:
            String(localized: "keyFamily.deviceBoundEcdsaNistP256EcdhNistP256V4.subtitle", defaultValue: "NIST P-256 · OpenPGP v4")
        case .deviceBoundEcdsaNistP256EcdhNistP256:
            String(localized: "keyFamily.deviceBoundModern.subtitle", defaultValue: "NIST P-256 · OpenPGP v6")
        case .deviceBoundMlDsa65Ed25519MlKem768X25519:
            String(localized: "keyFamily.deviceBoundPostQuantum.subtitle", defaultValue: "ML-KEM-768 + X25519 · OpenPGP v6")
        case .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.deviceBoundPostQuantumHigh.subtitle", defaultValue: "ML-KEM-1024 + X448 · OpenPGP v6")
        }
    }

    /// Short positioning tagline shown in the picker (the Legacy families own the
    /// GnuPG/older-tools story; the modern families are compatible too, so they
    /// carry none). Returns nil when there is nothing distinctive to surface.
    var familyPositioningTagline: String? {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy, .deviceBoundEcdsaNistP256EcdhNistP256V4:
            String(localized: "keyFamily.tagline.legacy", defaultValue: "GnuPG & older tools")
        case .portableEd25519X25519, .portableEd448X448, .portableMlDsa65Ed25519MlKem768X25519,
             .portableMlDsa87Ed448MlKem1024X448, .deviceBoundEcdsaNistP256EcdhNistP256, .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            nil
        }
    }

    /// Whether this family is the recommended default selection.
    var isRecommended: Bool {
        self == .portableMlDsa65Ed25519MlKem768X25519
    }

    /// In-flow interoperability warning surfaced during selection. Nil for the v4
    /// Legacy families, which are broadly compatible and need no caution.
    var familyInteropWarning: String? {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy, .deviceBoundEcdsaNistP256EcdhNistP256V4:
            nil
        case .portableEd25519X25519, .deviceBoundEcdsaNistP256EcdhNistP256:
            String(
                localized: "keyFamily.interop.modernV6.warning",
                defaultValue: "Uses OpenPGP v6; not readable by GnuPG or older tools."
            )
        case .portableEd448X448:
            String(
                localized: "keyFamily.interop.ed448.warning",
                defaultValue: "Requires modern OpenPGP tools; some do not yet support Ed448/X448."
            )
        case .portableMlDsa65Ed25519MlKem768X25519, .portableMlDsa87Ed448MlKem1024X448, .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(
                localized: "keyFamily.interop.postQuantum.warning",
                defaultValue: "Post-quantum keys work only with modern OpenPGP tools (RFC 9580/9980), not GnuPG or older software."
            )
        }
    }

    /// Interoperability statement for the (i) detail sheet — the in-flow warning
    /// when one applies, otherwise the positive broad-compatibility statement.
    var familyInteropDisplay: String {
        familyInteropWarning ?? String(
            localized: "keyFamily.interop.broad",
            defaultValue: "Broad compatibility, including GnuPG and older OpenPGP tools."
        )
    }

    /// Key/signature size guidance for the (i) detail sheet. Post-quantum material
    /// is large enough to matter for QR export; classical material is compact.
    var familySizeNote: String {
        switch self {
        case .portableMlDsa65Ed25519MlKem768X25519, .portableMlDsa87Ed448MlKem1024X448, .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(
                localized: "keyFamily.size.postQuantum",
                defaultValue: "Large public key and signatures; the public key may not fit in a single QR code."
            )
        case .portableEd25519LegacyCurve25519Legacy, .portableEd25519X25519, .portableEd448X448,
             .deviceBoundEcdsaNistP256EcdhNistP256V4, .deviceBoundEcdsaNistP256EcdhNistP256:
            String(
                localized: "keyFamily.size.compact",
                defaultValue: "Compact public key and signatures."
            )
        }
    }

    /// Approximate security level for key-detail display.
    var familySecurityLevel: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy:
            String(localized: "keyFamily.portableEd25519LegacyCurve25519Legacy.securityLevel", defaultValue: "~128 bit")
        case .portableEd25519X25519:
            String(localized: "keyFamily.portableModern.securityLevel", defaultValue: "~128 bit")
        case .portableEd448X448:
            String(localized: "keyFamily.portableModernHigh.securityLevel", defaultValue: "~224 bit")
        case .portableMlDsa65Ed25519MlKem768X25519:
            String(localized: "keyFamily.portablePostQuantum.securityLevel", defaultValue: "~192 bit, quantum-resistant")
        case .portableMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.portablePostQuantumHigh.securityLevel", defaultValue: "~256 bit, quantum-resistant")
        case .deviceBoundEcdsaNistP256EcdhNistP256V4:
            String(localized: "keyFamily.deviceBoundEcdsaNistP256EcdhNistP256V4.securityLevel", defaultValue: "~128 bit")
        case .deviceBoundEcdsaNistP256EcdhNistP256:
            String(localized: "keyFamily.deviceBoundModern.securityLevel", defaultValue: "~128 bit")
        case .deviceBoundMlDsa65Ed25519MlKem768X25519:
            String(localized: "keyFamily.deviceBoundPostQuantum.securityLevel", defaultValue: "~192 bit, quantum-resistant")
        case .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.deviceBoundPostQuantumHigh.securityLevel", defaultValue: "~256 bit, quantum-resistant")
        }
    }

    /// Algorithm details for the key-family detail sheet. Component names follow
    /// the RFC 9580 / RFC 9980 registry display names (e.g. `EdDSALegacy` for the
    /// deprecated v4 signing algorithm id 22, not Sequoia's `EdDSA`).
    var familyAlgorithmSummary: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy:
            String(
                localized: "keyFamily.portableEd25519LegacyCurve25519Legacy.algorithms",
                defaultValue: "EdDSALegacy (22, Ed25519Legacy) signing + ECDH (18, Curve25519) encryption"
            )
        case .portableEd25519X25519:
            String(
                localized: "keyFamily.portableModern.algorithms",
                defaultValue: "Ed25519 (27) signing + X25519 (25) encryption"
            )
        case .portableEd448X448:
            String(
                localized: "keyFamily.portableModernHigh.algorithms",
                defaultValue: "Ed448 (28) signing + X448 (26) encryption"
            )
        case .portableMlDsa65Ed25519MlKem768X25519:
            String(
                localized: "keyFamily.portablePostQuantum.algorithms",
                defaultValue: "ML-DSA-65+Ed25519 (30) signing + ML-KEM-768+X25519 (35) encryption"
            )
        case .portableMlDsa87Ed448MlKem1024X448:
            String(
                localized: "keyFamily.portablePostQuantumHigh.algorithms",
                defaultValue: "ML-DSA-87+Ed448 (31) signing + ML-KEM-1024+X448 (36) encryption"
            )
        case .deviceBoundEcdsaNistP256EcdhNistP256V4, .deviceBoundEcdsaNistP256EcdhNistP256:
            String(
                localized: "keyFamily.deviceBound.algorithms",
                defaultValue: "ECDSA (19, NIST P-256) signing + ECDH (18, NIST P-256) key agreement"
            )
        case .deviceBoundMlDsa65Ed25519MlKem768X25519:
            String(
                localized: "keyFamily.portablePostQuantum.algorithms",
                defaultValue: "ML-DSA-65+Ed25519 (30) signing + ML-KEM-768+X25519 (35) encryption"
            )
        case .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(
                localized: "keyFamily.portablePostQuantumHigh.algorithms",
                defaultValue: "ML-DSA-87+Ed448 (31) signing + ML-KEM-1024+X448 (36) encryption"
            )
        }
    }

    /// OpenPGP key version for the key-family detail sheet.
    var familyKeyVersionDisplay: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy, .deviceBoundEcdsaNistP256EcdhNistP256V4:
            String(localized: "keyFamily.version.v4", defaultValue: "v4")
        case .portableEd25519X25519, .portableEd448X448, .portableMlDsa65Ed25519MlKem768X25519,
             .portableMlDsa87Ed448MlKem1024X448, .deviceBoundEcdsaNistP256EcdhNistP256, .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.version.v6", defaultValue: "v6")
        }
    }

    /// Message format preference advertised by this key family.
    var familyMessageFormatDisplay: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy, .deviceBoundEcdsaNistP256EcdhNistP256V4:
            String(localized: "keyFamily.messageFormat.seipdv1", defaultValue: "SEIPDv1 (MDC)")
        case .portableEd25519X25519, .portableEd448X448, .portableMlDsa65Ed25519MlKem768X25519,
             .portableMlDsa87Ed448MlKem1024X448, .deviceBoundEcdsaNistP256EcdhNistP256, .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.messageFormat.seipdv2", defaultValue: "SEIPDv2 (AEAD OCB)")
        }
    }

    /// Private-key export and backup capability for the key-family detail sheet.
    var familyExportabilityDisplay: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy, .portableEd25519X25519, .portableEd448X448,
             .portableMlDsa65Ed25519MlKem768X25519, .portableMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.exportability.portable", defaultValue: "Private key can be exported and backed up")
        case .deviceBoundEcdsaNistP256EcdhNistP256V4, .deviceBoundEcdsaNistP256EcdhNistP256, .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.exportability.deviceBound", defaultValue: "Private key cannot be exported or backed up")
        }
    }

    /// GnuPG compatibility statement for the key-family detail sheet.
    var familyGnuPGCompatibilityDisplay: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy, .deviceBoundEcdsaNistP256EcdhNistP256V4:
            String(localized: "keyFamily.gnupg.compatible", defaultValue: "Compatible with GnuPG")
        case .portableEd25519X25519, .portableEd448X448, .portableMlDsa65Ed25519MlKem768X25519,
             .portableMlDsa87Ed448MlKem1024X448, .deviceBoundEcdsaNistP256EcdhNistP256, .deviceBoundMlDsa65Ed25519MlKem768X25519,
             .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.gnupg.notCompatible", defaultValue: "Not compatible with GnuPG")
        }
    }

    /// Custody model for the key-family detail sheet.
    var familyCustodyDisplay: String {
        switch self {
        case .portableEd25519LegacyCurve25519Legacy, .portableEd25519X25519, .portableEd448X448,
             .portableMlDsa65Ed25519MlKem768X25519, .portableMlDsa87Ed448MlKem1024X448:
            String(localized: "keyFamily.custody.portable", defaultValue: "Portable software key")
        case .deviceBoundEcdsaNistP256EcdhNistP256V4, .deviceBoundEcdsaNistP256EcdhNistP256:
            String(localized: "keyFamily.custody.deviceBound", defaultValue: "Device-bound Secure Enclave custody")
        case .deviceBoundMlDsa65Ed25519MlKem768X25519, .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(
                localized: "keyFamily.custody.deviceBoundSplit",
                defaultValue: "Device-bound split custody: post-quantum in the Secure Enclave, classical sealed to this device"
            )
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

// MARK: - Generation picker taxonomy

extension PGPKeyFamily.Custody {
    var displayName: String {
        switch self {
        case .portable:
            String(localized: "keyFamily.custodyOption.portable", defaultValue: "Portable")
        case .deviceBound:
            String(localized: "keyFamily.custodyOption.deviceBound", defaultValue: "Device-Bound")
        }
    }
}

extension PGPKeyFamily.Tier {
    var displayName: String {
        switch self {
        case .legacy:
            String(localized: "keyFamily.tier.legacy", defaultValue: "Legacy")
        case .modern:
            String(localized: "keyFamily.tier.modern", defaultValue: "Modern")
        case .modernHigh:
            String(localized: "keyFamily.tier.modernHigh", defaultValue: "Modern · High")
        case .postQuantum:
            String(localized: "keyFamily.tier.postQuantum", defaultValue: "Post-Quantum")
        case .postQuantumHigh:
            String(localized: "keyFamily.tier.postQuantumHigh", defaultValue: "Post-Quantum · High")
        }
    }
}

extension PGPKeyFamily {
    /// Short tier label for picker cells; custody is conveyed by the column or
    /// segmented control, so the cell needs only the tier.
    var tierDisplayName: String {
        tier.displayName
    }

    /// Families of a given custody within the supplied catalog, sorted by
    /// ascending tier so the picker's row order stays stable no matter how new
    /// families are later appended to `orderedFamilies`.
    static func families(
        custody: Custody,
        in families: [PGPKeyFamily]
    ) -> [PGPKeyFamily] {
        families
            .filter { $0.custody == custody }
            .sorted { $0.tier.rawValue < $1.tier.rawValue }
    }

    /// The family pre-selected when the generation picker opens.
    static var recommendedDefault: PGPKeyFamily {
        orderedFamilies.first(where: { $0.isRecommended }) ?? orderedFamilies[0]
    }
}
