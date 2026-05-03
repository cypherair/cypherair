import SwiftUI

struct DetailedSignatureSectionView: View {
    let verification: DetailedSignatureVerification
    let resultTitle: LocalizedStringKey
    let signerTitle: LocalizedStringKey

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 16) {
                if signatureEntries.isEmpty {
                    statusRow(for: verification.legacyVerification)
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
            return verification.legacyVerification.shouldShowSignerIdentity
                ? [verification.legacyVerification]
                : []
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
            status: SignatureStatus(from: entry.status),
            signerFingerprint: entry.signerPrimaryFingerprint,
            signerContact: nil,
            signerIdentity: entry.signerIdentity,
            verificationState: entry.verificationState,
            signerEvidence: entry.signerEvidence,
            contactsUnavailableReason: entry.contactsUnavailableReason
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
