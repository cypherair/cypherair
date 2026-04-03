import SwiftUI

/// Confirmation sheet displayed when importing a public key via URL scheme.
/// Shows key details and requires explicit user confirmation before adding to contacts.
struct ImportConfirmView: View {
    let keyInfo: KeyInfo
    let detectedProfile: KeyProfile
    let onImportVerified: () -> Void
    let onImportUnverified: (() -> Void)?
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            List {
                Section {
                    LabeledContent(
                        String(localized: "import.name", defaultValue: "Name"),
                        value: IdentityPresentation.displayName(from: keyInfo.userId)
                    )

                    if let email = IdentityPresentation.email(from: keyInfo.userId) {
                        LabeledContent(
                            String(localized: "import.email", defaultValue: "Email"),
                            value: email
                        )
                    }

                    if let userId = keyInfo.userId {
                        LabeledContent(
                            String(localized: "import.userId", defaultValue: "User ID"),
                            value: userId
                        )
                    }

                    let profileLabel = detectedProfile == .advanced
                        ? String(localized: "import.profileB", defaultValue: "Advanced Security (Profile B)")
                        : String(localized: "import.profileA", defaultValue: "Universal Compatible (Profile A)")
                    LabeledContent(String(localized: "import.profile", defaultValue: "Profile"), value: profileLabel)

                    LabeledContent(String(localized: "import.algorithm", defaultValue: "Algorithm"), value: keyInfo.primaryAlgo)
                    LabeledContent(
                        String(localized: "import.shortKeyId", defaultValue: "Short Key ID"),
                        value: IdentityPresentation.shortKeyId(from: keyInfo.fingerprint)
                    )
                    LabeledContent(
                        String(localized: "import.canEncrypt", defaultValue: "Can Encrypt To"),
                        value: (keyInfo.hasEncryptionSubkey && !keyInfo.isRevoked && !keyInfo.isExpired)
                            ? String(localized: "common.yes", defaultValue: "Yes")
                            : String(localized: "common.no", defaultValue: "No")
                    )

                    if keyInfo.isRevoked {
                        Label(
                            String(localized: "import.revoked", defaultValue: "This key has been revoked"),
                            systemImage: "exclamationmark.triangle.fill"
                        )
                        .foregroundStyle(.red)
                    }

                    if keyInfo.isExpired {
                        Label(
                            String(localized: "import.expired", defaultValue: "This key has expired"),
                            systemImage: "clock.badge.exclamationmark"
                        )
                        .foregroundStyle(.orange)
                    }
                }

                Section {
                    let formatted = PGPKeyIdentity.formatFingerprint(keyInfo.fingerprint)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(String(localized: "import.fingerprint", defaultValue: "Fingerprint"))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(formatted)
                            .font(.system(.body, design: .monospaced))
                            .accessibilityLabel(
                                IdentityPresentation.fingerprintAccessibilityLabel(keyInfo.fingerprint)
                            )
                    }
                }

                Section {
                    Text(String(localized: "import.verifyWarning", defaultValue: "Verify this fingerprint with the key owner before adding."))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } footer: {
                    if onImportUnverified != nil {
                        Text(
                            String(
                                localized: "import.unverified.warning",
                                defaultValue: "You can add this key without verifying it now, but it will remain marked as unverified until you confirm the fingerprint later."
                            )
                        )
                    }
                }
            }
            .navigationTitle(String(localized: "import.confirm.title", defaultValue: "Import Public Key"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "import.cancel", defaultValue: "Cancel")) {
                        onCancel()
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                VStack(spacing: 12) {
                    Button(action: onImportVerified) {
                        Text(String(localized: "import.addVerified", defaultValue: "Verify and Add to Contacts"))
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)

                    if let onImportUnverified {
                        Button(action: onImportUnverified) {
                            Text(String(localized: "import.addUnverified", defaultValue: "Add as Unverified"))
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .padding()
                .background(.bar)
            }
        }
    }
}
