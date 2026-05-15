import SwiftUI

struct SignatureIdentityCardView: View {
    let verification: SignatureVerification

    var body: some View {
        if let signerIdentity = verification.signerIdentity {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top) {
                    CypherStatusBadge(
                        title: signerIdentity.sourceLabel,
                        color: badgeColor(for: signerIdentity)
                    )

                    Spacer()
                }

                Text(signerIdentity.presentationDisplayName)
                    .font(.headline)

                if let secondaryText = signerIdentity.secondaryText, !secondaryText.isEmpty {
                    Text(secondaryText)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                if let shortKeyId = signerIdentity.shortKeyId {
                    LabeledContent(
                        String(localized: "signature.shortKeyId", defaultValue: "Short Key ID"),
                        value: shortKeyId
                    )
                    .font(.caption)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text(String(localized: "signature.fingerprint", defaultValue: "Fingerprint"))
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    FingerprintView(
                        fingerprint: signerIdentity.fingerprint,
                        font: .system(.footnote, design: .monospaced),
                        textSelectionEnabled: true
                    )
                }

                if let verificationNote = signerIdentity.verificationNote {
                    Label(verificationNote, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func badgeColor(for signerIdentity: SignatureVerification.SignerIdentity) -> Color {
        switch signerIdentity.source {
        case .contact:
            return signerIdentity.isVerifiedContact ? .secondary : .orange
        case .ownKey:
            return .blue
        case .unknown:
            return .orange
        }
    }
}
