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

    /// Whether this family is device-bound split custody (post-quantum halves
    /// in the Secure Enclave, classical halves sealed to the device).
    private var isSplitCustody: Bool {
        custody == .deviceBound && (tier == .postQuantum || tier == .postQuantumHigh)
    }

    /// User-facing family name, composed from the custody and tier names the
    /// picker already shows — one format per language, not nine strings.
    var familyDisplayName: String {
        String(
            localized: "keyFamily.name.composed",
            defaultValue: "\(custody.displayName) \(tier.displayName)"
        )
    }

    /// One-line description for key-family selection UI: the tier's
    /// interoperability sentence followed by the custody consequence.
    var familyDescription: String {
        String(
            localized: "keyFamily.description.composed",
            defaultValue: "\(tier.interopDescription) \(custodyConsequenceDescription)"
        )
    }

    private var custodyConsequenceDescription: String {
        if isSplitCustody {
            String(
                localized: "keyFamily.description.custody.deviceBoundSplit",
                defaultValue: "The key is split for this device: the post-quantum half lives in the Secure Enclave, the classical half is sealed to this device. It cannot be exported or backed up."
            )
        } else if custody == .deviceBound {
            String(
                localized: "keyFamily.description.custody.deviceBound",
                defaultValue: "The private key lives in this device's Secure Enclave and cannot be exported or backed up."
            )
        } else {
            String(
                localized: "keyFamily.description.custody.portable",
                defaultValue: "The private key can be exported and backed up."
            )
        }
    }

    /// Concise algorithm line (curve + format) shown as the picker row
    /// subtitle. Algorithm tokens and "OpenPGP v4/v6" are language-neutral,
    /// so the line composes without a localization table.
    var familyAlgorithmSubtitle: String {
        "\(familyAlgorithmToken) · OpenPGP v\(keyVersion)"
    }

    private var familyAlgorithmToken: String {
        if custody == .deviceBound, deviceBoundCustodyTier == .classicalP256 {
            return "NIST P-256"
        }
        switch tier {
        case .legacy:
            return "Curve25519"
        case .modern:
            return "Ed25519"
        case .modernHigh:
            return "Ed448"
        case .postQuantum:
            return "ML-KEM-768 + X25519"
        case .postQuantumHigh:
            return "ML-KEM-1024 + X448"
        }
    }

    /// Short positioning tagline shown in the picker (the Legacy tier owns
    /// the GnuPG/older-tools story; the modern tiers are compatible too, so
    /// they carry none). Returns nil when there is nothing distinctive.
    var familyPositioningTagline: String? {
        tier == .legacy
            ? String(localized: "keyFamily.tagline.legacy", defaultValue: "GnuPG & older tools")
            : nil
    }

    /// Whether this family is the recommended default selection.
    var isRecommended: Bool {
        self == .portableMlDsa65Ed25519MlKem768X25519
    }

    /// In-flow interoperability warning surfaced during selection. Nil for the
    /// Legacy (v4) tier, which is broadly compatible and needs no caution.
    var familyInteropWarning: String? {
        switch tier {
        case .legacy:
            nil
        case .modern:
            String(
                localized: "keyFamily.interop.modernV6.warning",
                defaultValue: "Uses OpenPGP v6; not readable by GnuPG or older tools."
            )
        case .modernHigh:
            String(
                localized: "keyFamily.interop.ed448.warning",
                defaultValue: "Requires modern OpenPGP tools; some do not yet support Ed448/X448."
            )
        case .postQuantum, .postQuantumHigh:
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

    /// Key/signature size guidance for the (i) detail sheet. Post-quantum
    /// material is large enough to matter for QR export; classical material is
    /// compact.
    var familySizeNote: String {
        switch tier {
        case .postQuantum, .postQuantumHigh:
            String(
                localized: "keyFamily.size.postQuantum",
                defaultValue: "Large public key and signatures; the public key may not fit in a single QR code."
            )
        case .legacy, .modern, .modernHigh:
            String(
                localized: "keyFamily.size.compact",
                defaultValue: "Compact public key and signatures."
            )
        }
    }

    /// Approximate security level for key-detail display — a property of the
    /// tier, stated once per tier.
    var familySecurityLevel: String {
        tier.securityLevelDisplay
    }

    /// Algorithm details for the key-family detail sheet. Component names follow
    /// the RFC 9580 / RFC 9980 registry display names (e.g. `EdDSALegacy` for the
    /// deprecated v4 signing algorithm id 22, not Sequoia's `EdDSA`). The two
    /// P-256 families share one entry because they share their algorithms and
    /// differ only in certificate version; every other family owns its entry.
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
                localized: "keyFamily.deviceBoundPostQuantum.algorithms",
                defaultValue: "ML-DSA-65+Ed25519 (30) signing + ML-KEM-768+X25519 (35) encryption"
            )
        case .deviceBoundMlDsa87Ed448MlKem1024X448:
            String(
                localized: "keyFamily.deviceBoundPostQuantumHigh.algorithms",
                defaultValue: "ML-DSA-87+Ed448 (31) signing + ML-KEM-1024+X448 (36) encryption"
            )
        }
    }

    /// OpenPGP key version for the key-family detail sheet — the generation
    /// target, rendered language-neutrally.
    var familyKeyVersionDisplay: String {
        "v\(keyVersion)"
    }

    /// Message format preference advertised by this key family. The Legacy
    /// (v4) tier advertises SEIPDv1; every v6 tier advertises SEIPDv2.
    var familyMessageFormatDisplay: String {
        tier == .legacy
            ? String(localized: "keyFamily.messageFormat.seipdv1", defaultValue: "SEIPDv1 (MDC)")
            : String(localized: "keyFamily.messageFormat.seipdv2", defaultValue: "SEIPDv2 (AEAD OCB)")
    }

    /// Private-key export and backup capability for the key-family detail sheet.
    var familyExportabilityDisplay: String {
        switch custody {
        case .portable:
            String(localized: "keyFamily.exportability.portable", defaultValue: "Private key can be exported and backed up")
        case .deviceBound:
            String(localized: "keyFamily.exportability.deviceBound", defaultValue: "Private key cannot be exported or backed up")
        }
    }

    /// GnuPG compatibility statement for the key-family detail sheet. GnuPG
    /// reads v4 only, so the Legacy tier is exactly the compatible one.
    var familyGnuPGCompatibilityDisplay: String {
        tier == .legacy
            ? String(localized: "keyFamily.gnupg.compatible", defaultValue: "Compatible with GnuPG")
            : String(localized: "keyFamily.gnupg.notCompatible", defaultValue: "Not compatible with GnuPG")
    }

    /// Custody model for the key-family detail sheet.
    var familyCustodyDisplay: String {
        if isSplitCustody {
            String(
                localized: "keyFamily.custody.deviceBoundSplit",
                defaultValue: "Device-bound split custody: post-quantum in the Secure Enclave, classical sealed to this device"
            )
        } else if custody == .deviceBound {
            String(localized: "keyFamily.custody.deviceBound", defaultValue: "Device-bound Secure Enclave custody")
        } else {
            String(localized: "keyFamily.custody.portable", defaultValue: "Portable software key")
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

    /// The tier's interoperability sentence for family descriptions.
    var interopDescription: String {
        switch self {
        case .legacy:
            String(
                localized: "keyFamily.description.interop.legacy",
                defaultValue: "Works with all PGP tools including GnuPG."
            )
        case .modern:
            String(
                localized: "keyFamily.description.interop.modern",
                defaultValue: "Uses the modern OpenPGP standard (RFC 9580), widely supported by up-to-date tools. Not compatible with GnuPG."
            )
        case .modernHigh:
            String(
                localized: "keyFamily.description.interop.modernHigh",
                defaultValue: "Uses the modern OpenPGP standard (RFC 9580) with the stronger Ed448 curve; some tools do not yet support it. Not compatible with GnuPG."
            )
        case .postQuantum:
            String(
                localized: "keyFamily.description.interop.postQuantum",
                defaultValue: "Uses post-quantum encryption (RFC 9980) designed to resist future quantum computers. Not compatible with GnuPG."
            )
        case .postQuantumHigh:
            String(
                localized: "keyFamily.description.interop.postQuantumHigh",
                defaultValue: "Uses the strongest post-quantum encryption (RFC 9980, ML-KEM-1024) designed to resist future quantum computers. Not compatible with GnuPG."
            )
        }
    }

    /// Approximate security level, stated once per tier.
    var securityLevelDisplay: String {
        switch self {
        case .legacy:
            String(localized: "keyFamily.securityLevel.legacy", defaultValue: "~128 bit")
        case .modern:
            String(localized: "keyFamily.securityLevel.modern", defaultValue: "~128 bit")
        case .modernHigh:
            String(localized: "keyFamily.securityLevel.modernHigh", defaultValue: "~224 bit")
        case .postQuantum:
            String(localized: "keyFamily.securityLevel.postQuantum", defaultValue: "~192 bit, quantum-resistant")
        case .postQuantumHigh:
            String(localized: "keyFamily.securityLevel.postQuantumHigh", defaultValue: "~256 bit, quantum-resistant")
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
