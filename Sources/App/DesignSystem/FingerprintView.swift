import SwiftUI

struct FingerprintView: View {
    let fingerprint: String
    var font: Font = .system(.body, design: .monospaced)
    var foregroundColor: Color?
    var textSelectionEnabled = false
    var multilineTextAlignment: TextAlignment = .leading
    var expandsHorizontally = true

    private var groups: [String] {
        IdentityPresentation.fingerprintGroups(fingerprint)
    }

    var body: some View {
        configuredText
            .accessibilityRepresentation {
                accessibilityGroups
            }
    }

    @ViewBuilder
    private var configuredText: some View {
        let text = Text(IdentityPresentation.formattedFingerprint(fingerprint))
            .font(font)
            .fixedSize(horizontal: false, vertical: true)
            .multilineTextAlignment(multilineTextAlignment)

        if let foregroundColor {
            if expandsHorizontally {
                baseText(text.foregroundStyle(foregroundColor))
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                baseText(text.foregroundStyle(foregroundColor))
            }
        } else if expandsHorizontally {
            baseText(text)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            baseText(text)
        }
    }

    @ViewBuilder
    private func baseText<Content: View>(_ text: Content) -> some View {
        if textSelectionEnabled {
            text.textSelection(.enabled)
        } else {
            text
        }
    }

    private var accessibilityGroups: some View {
        HStack(spacing: 8) {
            ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                Text(group)
                    .accessibilityLabel(IdentityPresentation.fingerprintAccessibilityGroupLabel(group))
            }
        }
        .accessibilityElement(children: .contain)
    }
}
