import SwiftUI

/// Confirmation sheet displayed before importing a public key.
/// Shows key details and requires explicit confirmation before adding a contact.
struct ImportConfirmView: View {
    let keyInfo: KeyInfo
    let detectedProfile: KeyProfile
    let onImportVerified: () -> Void
    let onImportUnverified: (() -> Void)?
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        summaryCard
                        fingerprintCard
                        warningCard
                    }
                    .frame(maxWidth: 560, alignment: .leading)
                    .padding(20)
                    .padding(.bottom, 12)
                }

                Divider()

                actionBar
            }
            .navigationTitle(String(localized: "import.confirm.title", defaultValue: "Import Public Key"))
            .accessibilityIdentifier("importconfirm.root")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "import.cancel", defaultValue: "Cancel")) {
                        onCancel()
                    }
                }
            }
            #if os(macOS)
            .frame(minWidth: 560, idealWidth: 600, maxWidth: 680, minHeight: 500, idealHeight: 560)
            #endif
        }
    }

    private var summaryCard: some View {
        confirmationCard {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 12) {
                    Image(systemName: "person.crop.rectangle.badge.plus")
                        .font(.title2)
                        .foregroundStyle(.tint)
                        .accessibilityHidden(true)

                    VStack(alignment: .leading, spacing: 4) {
                        Text(IdentityPresentation.displayName(from: keyInfo.userId))
                            .font(.headline)

                        if let email = IdentityPresentation.email(from: keyInfo.userId) {
                            Text(email)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Spacer()
                }

                VStack(alignment: .leading, spacing: 12) {
                    infoRow(
                        String(localized: "import.profile", defaultValue: "Profile"),
                        value: profileLabel
                    )
                    infoRow(
                        String(localized: "import.algorithm", defaultValue: "Algorithm"),
                        value: keyInfo.primaryAlgo
                    )
                    infoRow(
                        String(localized: "import.shortKeyId", defaultValue: "Short Key ID"),
                        value: IdentityPresentation.shortKeyId(from: keyInfo.fingerprint)
                    )
                    infoRow(
                        String(localized: "import.canEncrypt", defaultValue: "Can Encrypt To"),
                        value: canEncryptLabel
                    )

                    if let userId = keyInfo.userId {
                        infoRow(
                            String(localized: "import.userId", defaultValue: "User ID"),
                            value: userId,
                            monospaced: false
                        )
                    }
                }

                if keyInfo.isRevoked || keyInfo.isExpired {
                    VStack(alignment: .leading, spacing: 10) {
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
                }
            }
        }
    }

    private var fingerprintCard: some View {
        confirmationCard {
            VStack(alignment: .leading, spacing: 10) {
                Text(String(localized: "import.fingerprint", defaultValue: "Fingerprint"))
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)

                FingerprintView(
                    fingerprint: keyInfo.fingerprint,
                    textSelectionEnabled: true
                )
            }
        }
    }

    private var warningCard: some View {
        confirmationCard {
            VStack(alignment: .leading, spacing: 12) {
                Label(
                    String(localized: "import.verifyWarning", defaultValue: "Verify this fingerprint with the key owner before adding."),
                    systemImage: "checkmark.shield"
                )
                .foregroundStyle(.secondary)

                if onImportUnverified != nil {
                    Text(
                        String(
                            localized: "import.unverified.warning",
                            defaultValue: "You can add this key without verifying it now, but it will remain marked as unverified until you confirm the fingerprint later."
                        )
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var actionBar: some View {
        VStack(spacing: 12) {
            Button(action: onImportVerified) {
                Text(String(localized: "import.addVerified", defaultValue: "Verify and Add to Contacts"))
                    .cypherPrimaryActionLabelFrame(minWidth: 260)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("importconfirm.verified")

            if let onImportUnverified {
                Button(action: onImportUnverified) {
                    Text(String(localized: "import.addUnverified", defaultValue: "Add as Unverified"))
                        .cypherPrimaryActionLabelFrame(minWidth: 260)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("importconfirm.unverified")
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .background(.bar)
    }

    private var profileLabel: String {
        detectedProfile == .advanced
            ? String(localized: "import.profileB", defaultValue: "Advanced Security (Profile B)")
            : String(localized: "import.profileA", defaultValue: "Universal Compatible (Profile A)")
    }

    private var canEncryptLabel: String {
        (keyInfo.hasEncryptionSubkey && !keyInfo.isRevoked && !keyInfo.isExpired)
            ? String(localized: "common.yes", defaultValue: "Yes")
            : String(localized: "common.no", defaultValue: "No")
    }

    @ViewBuilder
    private func confirmationCard<Content: View>(
        @ViewBuilder content: () -> Content
    ) -> some View {
        content()
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(18)
            .tutorialCardChrome(.standard)
    }

    @ViewBuilder
    private func infoRow(
        _ label: String,
        value: String,
        monospaced: Bool = false
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)

            Text(value)
                .font(monospaced ? .system(.body, design: .monospaced) : .body)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
    }
}
