import SwiftUI

struct SignatureIdentityCardView: View {
    let verification: SignatureVerification

    var body: some View {
        if let signerIdentity = verification.signerIdentity {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top) {
                    Text(signerIdentity.sourceLabel)
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(badgeBackgroundColor(for: signerIdentity), in: Capsule())
                        .foregroundStyle(badgeForegroundColor(for: signerIdentity))

                    Spacer()
                }

                Text(signerIdentity.displayName)
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

    private func badgeBackgroundColor(for signerIdentity: SignatureVerification.SignerIdentity) -> Color {
        switch signerIdentity.source {
        case .contact:
            return signerIdentity.isVerifiedContact
                ? Color.secondary.opacity(0.12)
                : Color.orange.opacity(0.16)
        case .ownKey:
            return Color.blue.opacity(0.14)
        case .unknown:
            return Color.orange.opacity(0.16)
        }
    }

    private func badgeForegroundColor(for signerIdentity: SignatureVerification.SignerIdentity) -> Color {
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
