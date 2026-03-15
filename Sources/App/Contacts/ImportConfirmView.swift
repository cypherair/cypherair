import SwiftUI

/// Confirmation sheet displayed when importing a public key via URL scheme.
/// Shows key details and requires explicit user confirmation before adding to contacts.
///
/// Per PRD Section 4.2: URL scheme import requires user confirmation before adding key.
struct ImportConfirmView: View {
    let keyInfo: KeyInfo
    let detectedProfile: KeyProfile
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if let userId = keyInfo.userId {
                        LabeledContent(String(localized: "import.userId", defaultValue: "User ID"), value: userId)
                    }

                    let profileLabel = (detectedProfile == .advanced)
                        ? String(localized: "import.profileB", defaultValue: "Advanced Security (Profile B)")
                        : String(localized: "import.profileA", defaultValue: "Universal Compatible (Profile A)")
                    LabeledContent(String(localized: "import.profile", defaultValue: "Profile"), value: profileLabel)

                    LabeledContent(String(localized: "import.algorithm", defaultValue: "Algorithm"), value: keyInfo.primaryAlgo)

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
                                formatted
                                    .split(separator: " ")
                                    .map { $0.map(String.init).joined(separator: " ") }
                                    .joined(separator: ", ")
                            )
                    }
                }

                Section {
                    Text(String(localized: "import.verifyWarning", defaultValue: "Verify this fingerprint with the key owner before adding."))
                        .font(.callout)
                        .foregroundStyle(.secondary)
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
                Button(action: onConfirm) {
                    Text(String(localized: "import.addToContacts", defaultValue: "Add to Contacts"))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .padding()
            }
        }
    }

}
