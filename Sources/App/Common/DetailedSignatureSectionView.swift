import SwiftUI

struct DetailedSignatureSectionView: View {
    struct ResetToken: Hashable {
        enum ScreenContext: String, Hashable {
            case verify
            case decrypt
        }

        let screenContext: ScreenContext
        let modeIdentifier: String
        let presentationEpoch: Int
    }

    let verification: DetailedSignatureVerification
    let resetToken: ResetToken

    @State private var isExpanded = false

    var body: some View {
        Section {
            DisclosureGroup(
                String(
                    localized: "signature.detailed.section",
                    defaultValue: "Detailed Signatures"
                ),
                isExpanded: $isExpanded
            ) {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(Array(verification.signatures.enumerated()), id: \.offset) { index, entry in
                        let entryVerification = SignatureVerification(entry: entry)

                        VStack(alignment: .leading, spacing: 12) {
                            HStack(alignment: .top, spacing: 10) {
                                Image(systemName: entryVerification.symbolName)
                                    .foregroundStyle(entryVerification.statusColor)

                                Text(entryVerification.statusDescription)
                                    .font(.subheadline)
                            }
                            .accessibilityElement(children: .combine)

                            if entryVerification.shouldShowSignerIdentity {
                                SignatureIdentityCardView(verification: entryVerification)
                            }
                        }

                        if index < verification.signatures.count - 1 {
                            Divider()
                        }
                    }
                }
                .padding(.top, 12)
            }
        }
        .onChange(of: resetToken) { _, _ in
            isExpanded = false
        }
    }
}

private extension SignatureVerification {
    init(entry: DetailedSignatureVerification.Entry) {
        self.init(
            status: SignatureStatus(from: entry.status),
            signerFingerprint: entry.signerPrimaryFingerprint,
            signerContact: nil,
            signerIdentity: entry.signerIdentity
        )
    }
}

private extension SignatureStatus {
    init(from status: DetailedSignatureVerification.Entry.Status) {
        switch status {
        case .valid:
            self = .valid
        case .unknownSigner:
            self = .unknownSigner
        case .bad:
            self = .bad
        case .expired:
            self = .expired
        }
    }
}
