import SwiftUI

struct ContactKeySummaryView: View {
    let key: ContactKeySummary
    let configuration: ContactDetailView.Configuration
    let allowsUsageActions: Bool
    let setVerification: (ContactVerificationState, String) -> Void
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
                String(localized: "contactdetail.keyType", defaultValue: "Key Type"),
                value: key.suite.contactKeyKindDisplayName
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

            trustSection

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

    /// Two separate statements, kept visibly apart: what the app is willing to
    /// vouch for about this key, and what its stored certification signatures
    /// currently do. The second never colours the first — certifications
    /// existing is not an endorsement of anybody.
    @ViewBuilder
    private var trustSection: some View {
        let trust = key.trust

        HStack {
            Text(String(localized: "contacttrust.heading", defaultValue: "Trust"))
            Spacer()
            CypherStatusBadge(
                title: trust.anchor.badgeTitle,
                systemImage: trust.anchor.badgeSystemImage,
                color: trust.anchor.badgeColor
            )
        }

        if !trust.vouchers.isEmpty {
            Text(
                String(
                    localized: "contacttrust.vouchedBy.detail",
                    defaultValue: "Vouched for by \(trust.vouchersDescription), whose fingerprints you verified."
                )
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
        }

        if !trust.isVerifiedByUser {
            Label(
                trust.vouchers.isEmpty
                    ? String(
                        localized: "contactdetail.unverified",
                        defaultValue: "You have not verified this key. Confirm the fingerprint with its owner before relying on it."
                    )
                    : String(
                        localized: "contactdetail.unverified.vouched",
                        defaultValue: "Someone you trust vouches for this key, but you have not checked its fingerprint yourself. Confirm it with the owner before relying on it."
                    ),
                systemImage: "exclamationmark.triangle.fill"
            )
            .foregroundStyle(.orange)
        }

        HStack {
            Text(
                String(
                    localized: "contactdetail.openpgpCertification",
                    defaultValue: "Certification Signatures"
                )
            )
            Spacer()
            CypherStatusBadge(
                title: key.certificationProjection.signatureState.badgeTitle,
                color: key.certificationProjection.signatureState.badgeColor
            )
        }
    }

    @ViewBuilder
    private var actionButtons: some View {
        VStack(alignment: .leading, spacing: 8) {
            if key.isVerified {
                Button {
                    setVerification(.unverified, key.fingerprint)
                } label: {
                    Label(
                        String(
                            localized: "contactdetail.withdrawVerification",
                            defaultValue: "Withdraw My Fingerprint Verification"
                        ),
                        systemImage: "xmark.shield"
                    )
                }
            } else {
                Button {
                    setVerification(.verified, key.fingerprint)
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
                        keyId: key.keyId
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
}
