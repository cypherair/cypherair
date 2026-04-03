import SwiftUI

enum TutorialAnchorID: Hashable {
    case homeEncryptAction
    case homeDecryptAction
    case keysGenerateButton
    case contactsAddButton
    case keyRow(fingerprint: String)
    case keyDetailBackupButton
    case settingsAuthModePicker
    case settingsModeConfirmButton
}

private struct TutorialAnchorPreferenceKey: PreferenceKey {
    static let defaultValue: [TutorialAnchorID: Anchor<CGRect>] = [:]

    static func reduce(
        value: inout [TutorialAnchorID: Anchor<CGRect>],
        nextValue: () -> [TutorialAnchorID: Anchor<CGRect>]
    ) {
        value.merge(nextValue(), uniquingKeysWith: { _, new in new })
    }
}

struct TutorialSpotlightOverlay: View {
    let target: TutorialAnchorID?

    var body: some View {
        overlayBody
    }

    @ViewBuilder
    private var overlayBody: some View {
        GeometryReader { proxy in
            Color.clear
                .overlayPreferenceValue(TutorialAnchorPreferenceKey.self) { anchors in
                    if let target,
                       let anchor = anchors[target] {
                        let rect = proxy[anchor]
                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                            .strokeBorder(Color.accentColor, lineWidth: 3)
                            .background(
                                RoundedRectangle(cornerRadius: 16, style: .continuous)
                                    .fill(Color.accentColor.opacity(0.08))
                            )
                            .frame(width: rect.width + 12, height: rect.height + 12)
                            .position(x: rect.midX, y: rect.midY)
                            .allowsHitTesting(false)
                            .animation(.easeInOut(duration: 0.2), value: rect)
                    }
                }
        }
    }
}

extension View {
    func tutorialAnchor(_ id: TutorialAnchorID?) -> some View {
        anchorPreference(
            key: TutorialAnchorPreferenceKey.self,
            value: .bounds
        ) { anchor in
            guard let id else { return [:] }
            return [id: anchor]
        }
    }
}
