import SwiftUI

struct DetailedSignatureSectionView: View {
    let verification: DetailedSignatureVerification
    let resultTitle: LocalizedStringKey
    let signerTitle: LocalizedStringKey

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 16) {
                if signatureEntries.isEmpty {
                    statusRow(for: verification.summaryVerification)
                } else {
                    ForEach(Array(signatureEntries.enumerated()), id: \.offset) { index, entryVerification in
                        statusRow(for: entryVerification)

                        if index < signatureEntries.count - 1 {
                            Divider()
                        }
                    }
                }
            }
        } header: {
            Text(resultTitle)
        }

        if !signerEntries.isEmpty {
            Section {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(Array(signerEntries.enumerated()), id: \.offset) { index, signerVerification in
                        SignatureIdentityCardView(verification: signerVerification)

                        if index < signerEntries.count - 1 {
                            Divider()
                        }
                    }
                }
            } header: {
                Text(signerTitle)
            }
        }
    }

    private var signatureEntries: [SignatureVerification] {
        verification.signatures.map(SignatureVerification.init(entry:))
    }

    private var signerEntries: [SignatureVerification] {
        if signatureEntries.isEmpty {
            // No per-signature entries → no signer identity to show. Empty `signatures` carries no
            // observed signer; the summary status row already conveys the not-signed/invalid/expired
            // outcome.
            return []
        }

        return signatureEntries.filter(\.shouldShowSignerIdentity)
    }

    @ViewBuilder
    private func statusRow(for verification: SignatureVerification) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: verification.symbolName)
                .foregroundStyle(verification.statusColor)

            Text(verification.statusDescription)
                .font(.subheadline)
        }
        .accessibilityElement(children: .combine)
    }
}

private extension SignatureVerification {
    init(entry: DetailedSignatureVerification.Entry) {
        self.init(
            signerFingerprint: entry.signerPrimaryFingerprint,
            signerIdentity: entry.signerIdentity,
            verificationState: entry.verificationState,
            contactsUnavailableReason: entry.contactsUnavailableReason
        )
    }
}
