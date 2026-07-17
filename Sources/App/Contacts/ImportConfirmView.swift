import SwiftUI

/// Confirmation sheet displayed before importing a public key.
/// Shows key details and requires explicit confirmation before adding a contact.
struct ImportConfirmView: View {
    let metadata: PGPKeyMetadata
    let candidateMatch: ContactCandidateMatch?
    let onImportVerified: () -> Void
    let onImportUnverified: (() -> Void)?
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        summaryCard
                        if let candidateMatch {
                            conflictWarningCard(candidateMatch)
                        }
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
                        Text(IdentityDisplayPresentation.displayName(from: metadata.userId))
                            .font(.headline)

                        if let email = IdentityPresentation.email(from: metadata.userId) {
                            Text(email)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Spacer()
                }

                VStack(alignment: .leading, spacing: 12) {
                    // Contact imports always carry a detected software suite;
                    // the row simply disappears in the impossible nil case.
                    if let suite = metadata.suite {
                        infoRow(
                            String(localized: "import.keyType", defaultValue: "Key Type"),
                            value: suite.contactKeyKindDisplayName
                        )
                    }
                    infoRow(
                        String(localized: "import.algorithm", defaultValue: "Algorithm"),
                        value: metadata.primaryAlgo
                    )
                    infoRow(
                        String(localized: "import.shortKeyId", defaultValue: "Short Key ID"),
                        value: IdentityPresentation.shortKeyId(from: metadata.fingerprint)
                    )
                    infoRow(
                        String(localized: "import.canEncrypt", defaultValue: "Can Encrypt To"),
                        value: canEncryptLabel
                    )

                    if let userId = metadata.userId {
                        infoRow(
                            String(localized: "import.userId", defaultValue: "User ID"),
                            value: userId,
                            monospaced: false
                        )
                    }
                }

                if metadata.isRevoked || metadata.isExpired {
                    VStack(alignment: .leading, spacing: 10) {
                        if metadata.isRevoked {
                            Label(
                                String(localized: "import.revoked", defaultValue: "This key has been revoked"),
                                systemImage: "exclamationmark.triangle.fill"
                            )
                            .foregroundStyle(.red)
                        }

                        if metadata.isExpired {
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
                    fingerprint: metadata.fingerprint,
                    textSelectionEnabled: true
                )
            }
        }
    }

    private func conflictWarningCard(_ candidateMatch: ContactCandidateMatch) -> some View {
        confirmationCard {
            VStack(alignment: .leading, spacing: 12) {
                Label(
                    String(localized: "import.conflict.title", defaultValue: "Possible Existing Contact"),
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.headline)
                .foregroundStyle(.orange)

                Text(conflictWarningMessage(for: candidateMatch))
                    .font(.callout)
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(alignment: .leading, spacing: 4) {
                    Text(String(localized: "import.conflict.existingContact", defaultValue: "Existing contact"))
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(IdentityDisplayPresentation.displayName(candidateMatch.displayName))
                        .font(.body)
                    if let primaryEmail = candidateMatch.primaryEmail {
                        Text(primaryEmail)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }

                Text(String(localized: "import.conflict.mergeHint", defaultValue: "If this is a legitimate key replacement, import it only after checking the new fingerprint, then merge the contacts from Contact Detail."))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
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

    private var canEncryptLabel: String {
        (metadata.hasEncryptionSubkey && !metadata.isRevoked && !metadata.isExpired)
            ? String(localized: "common.yes", defaultValue: "Yes")
            : String(localized: "common.no", defaultValue: "No")
    }

    private func conflictWarningMessage(for candidateMatch: ContactCandidateMatch) -> String {
        switch candidateMatch.strength {
        case .strong:
            String(localized: "import.conflict.strong", defaultValue: "This key matches an existing contact email but has a different fingerprint. It may be a real key replacement, or it may be an impersonation attempt.")
        case .weak:
            String(localized: "import.conflict.weak", defaultValue: "This key matches an existing User ID but has a different fingerprint. It may be a real key replacement, or it may be an impersonation attempt.")
        case .ambiguousStrong:
            String(localized: "import.conflict.ambiguousStrong", defaultValue: "This key matches multiple existing contacts but has a different fingerprint. Confirm the owner carefully before adding it.")
        }
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
