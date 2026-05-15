import SwiftUI

struct ContactKeySummaryView: View {
    let key: ContactKeySummary
    let configuration: ContactDetailView.Configuration
    let allowsUsageActions: Bool
    let markVerified: (String) -> Void
    let setPreferred: (String) -> Void
    let markHistorical: (String) -> Void
    let markAdditionalActive: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Label(
                    IdentityDisplayPresentation.displayName(key.displayName),
                    systemImage: key.usageState.systemImage
                )
                    .font(.body.weight(.medium))
                Spacer()
                usageBadge
            }

            if let email = key.email {
                Text(email)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            LabeledContent(
                String(localized: "contactdetail.profile", defaultValue: "Profile"),
                value: key.profile.displayName
            )
            LabeledContent(
                String(localized: "contactdetail.shortKeyId", defaultValue: "Short Key ID"),
                value: key.shortKeyId
            )
            LabeledContent(
                String(localized: "contactdetail.algo", defaultValue: "Algorithm"),
                value: [key.primaryAlgo, key.subkeyAlgo].compactMap { $0 }.joined(separator: " + ")
            )

            FingerprintView(fingerprint: key.fingerprint)

            HStack {
                Text(String(localized: "contactdetail.canEncrypt", defaultValue: "Can Encrypt To"))
                Spacer()
                Image(systemName: key.canEncryptTo ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundStyle(key.canEncryptTo ? .green : .red)
            }

            if !key.isVerified {
                Label(
                    String(
                        localized: "contactdetail.unverified",
                        defaultValue: "This key has not been verified yet. Confirm the fingerprint with the key owner before relying on it."
                    ),
                    systemImage: "exclamationmark.triangle.fill"
                )
                .foregroundStyle(.orange)
            }

            HStack {
                Text(
                    String(
                        localized: "contactdetail.openpgpCertification",
                        defaultValue: "OpenPGP Certification"
                    )
                )
                Spacer()
                CypherStatusBadge(
                    title: certificationStatusTitle,
                    color: certificationStatusColor
                )
            }

            actionButtons
        }
        .padding(.vertical, 6)
    }

    private var usageBadge: some View {
        CypherStatusBadge(
            title: key.usageState.contactDetailLabel,
            color: key.usageState.statusColor
        )
    }

    @ViewBuilder
    private var actionButtons: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !key.isVerified {
                Button {
                    markVerified(key.fingerprint)
                } label: {
                    Label(
                        String(localized: "contactdetail.markVerified", defaultValue: "I Verified This Fingerprint"),
                        systemImage: "checkmark.shield"
                    )
                }
            }

            if allowsUsageActions && key.canEncryptTo && key.usageState != .preferred {
                Button {
                    setPreferred(key.fingerprint)
                } label: {
                    Label(
                        String(localized: "contactdetail.setPreferredKey", defaultValue: "Make Preferred Key"),
                        systemImage: "star.fill"
                    )
                }
            }

            if allowsUsageActions && key.usageState != .historical {
                Button {
                    markHistorical(key.fingerprint)
                } label: {
                    Label(
                        String(localized: "contactdetail.markHistorical", defaultValue: "Move to Historical"),
                        systemImage: "archivebox"
                    )
                }
            }

            if allowsUsageActions && key.usageState == .historical && key.canEncryptTo {
                Button {
                    markAdditionalActive(key.fingerprint)
                } label: {
                    Label(
                        String(localized: "contactdetail.markAdditionalActive", defaultValue: "Move to Active Keys"),
                        systemImage: "key"
                    )
                }
            }

            if configuration.showsCertificateSignatureEntry {
                NavigationLink(
                    value: AppRoute.contactCertification(
                        contactId: key.contactId,
                        keyId: key.keyId,
                        intent: .details
                    )
                ) {
                    Label(
                        String(
                            localized: "contactdetail.certificationDetails",
                            defaultValue: "Certification Details"
                        ),
                        systemImage: "checkmark.seal"
                    )
                }
                .disabled(!configuration.allowsCertificateSignatureLaunch)
                .accessibilityIdentifier("contactdetail.certificationDetails")
            }

            if let restrictionMessage = configuration.certificateSignatureRestrictionMessage {
                Text(restrictionMessage)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.borderless)
    }

    private var certificationStatusTitle: String {
        switch key.certificationProjection.status {
        case .notCertified:
            String(localized: "contactdetail.openpgpCertification.none", defaultValue: "Not Certified")
        case .certified:
            String(localized: "contactdetail.openpgpCertification.certified", defaultValue: "Certified")
        case .invalidOrStale:
            String(localized: "contactdetail.openpgpCertification.invalid", defaultValue: "Invalid or Stale")
        case .revalidationNeeded:
            String(localized: "contactdetail.openpgpCertification.revalidation", defaultValue: "Revalidation Needed")
        }
    }

    private var certificationStatusColor: Color {
        switch key.certificationProjection.status {
        case .notCertified:
            .secondary
        case .certified:
            .green
        case .invalidOrStale:
            .red
        case .revalidationNeeded:
            .orange
        }
    }
}
