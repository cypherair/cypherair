#if canImport(UIKit)
import SwiftUI
import UIKit

/// Dedicated page for selecting an alternate app icon.
struct AppIconPickerView: View {
    @State private var currentIconName: String? = UIApplication.shared.alternateIconName

    var body: some View {
        List {
            Section {
                ForEach(AppIconOption.allCases) { option in
                    AppIconRow(
                        option: option,
                        isSelected: AppIconOption.current(from: currentIconName) == option
                    ) {
                        setIcon(option)
                    }
                }
            }
        }
        .navigationTitle(String(localized: "settings.appIcon", defaultValue: "App Icon"))
        .navigationBarTitleDisplayMode(.inline)
    }

    private func setIcon(_ option: AppIconOption) {
        guard UIApplication.shared.supportsAlternateIcons else { return }
        let selected = AppIconOption.current(from: currentIconName)
        guard option != selected else { return }

        Task {
            do {
                try await UIApplication.shared.setAlternateIconName(option.iconName)
                currentIconName = option.iconName
            } catch {
                // Icon change failed — system state unchanged
            }
        }
    }
}

// MARK: - Data Model

/// Available app icon options.
enum AppIconOption: String, CaseIterable, Identifiable {
    case silver = "AppIconA"
    case glass = "AppIcon"
    case azure = "AppIconB"
    case slate = "AppIconC"
    case obsidian = "AppIconD"
    case violet = "AppIconE"

    private static let primary: AppIconOption = .glass

    var id: String { rawValue }

    /// The name passed to `setAlternateIconName`. `nil` means the primary icon configured at build time.
    var iconName: String? {
        self == Self.primary ? nil : rawValue
    }

    /// Bundle resource filename for the preview thumbnail (without extension).
    var previewImageName: String {
        rawValue + "Preview"
    }

    /// Load the preview image from the app bundle.
    var previewImage: UIImage? {
        if let path = Bundle.main.path(forResource: previewImageName, ofType: "png") {
            return UIImage(contentsOfFile: path)
        }
        return nil
    }

    var displayName: String {
        switch self {
        case .silver:
            String(localized: "settings.appIcon.silver", defaultValue: "Silver")
        case .glass:
            String(localized: "settings.appIcon.glass", defaultValue: "Glass")
        case .azure:
            String(localized: "settings.appIcon.azure", defaultValue: "Azure")
        case .slate:
            String(localized: "settings.appIcon.slate", defaultValue: "Slate")
        case .obsidian:
            String(localized: "settings.appIcon.obsidian", defaultValue: "Obsidian")
        case .violet:
            String(localized: "settings.appIcon.violet", defaultValue: "Violet")
        }
    }

    /// Match the current `alternateIconName` to an option.
    static func current(from alternateIconName: String?) -> AppIconOption {
        guard let name = alternateIconName else { return primary }
        return AppIconOption(rawValue: name) ?? primary
    }
}

// MARK: - Row View

/// A single icon list row: thumbnail, name, and a trailing selection checkmark.
/// Rows grow vertically with Dynamic Type, so long names never break alignment.
private struct AppIconRow: View {
    let option: AppIconOption
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                iconImage
                    .frame(width: 44, height: 44)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))

                Text(option.displayName)
                    .font(.body)
                    .foregroundStyle(.primary)

                Spacer(minLength: 8)

                if isSelected {
                    Image(systemName: "checkmark")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(Color.accentColor)
                        .accessibilityHidden(true)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(option.displayName)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    @ViewBuilder
    private var iconImage: some View {
        // Load preview PNG from the app bundle (e.g. AppIconAPreview.png).
        if let uiImage = option.previewImage {
            Image(uiImage: uiImage)
                .resizable()
                .aspectRatio(contentMode: .fill)
        } else {
            // Fallback: placeholder with icon name
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(.quaternary)
                .overlay {
                    Text(option.displayName.prefix(1))
                        .font(.title3.bold())
                        .foregroundStyle(.secondary)
                }
        }
    }
}

#endif
