#if canImport(UIKit)
import SwiftUI
import UIKit

/// Dedicated page for selecting an alternate app icon.
struct AppIconPickerView: View {
    @State private var currentIconName: String? = UIApplication.shared.alternateIconName

    private let columns = Array(repeating: GridItem(.flexible(), spacing: 20), count: 4)

    var body: some View {
        ScrollView {
            LazyVGrid(columns: columns, spacing: 20) {
                ForEach(AppIconOption.allCases) { option in
                    AppIconCell(
                        option: option,
                        isSelected: AppIconOption.current(from: currentIconName) == option
                    ) {
                        setIcon(option)
                    }
                }
            }
            .padding()
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

    var id: String { rawValue }

    /// The name passed to `setAlternateIconName`. `nil` means the primary icon (AppIconA).
    var iconName: String? {
        self == .silver ? nil : rawValue
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
        }
    }

    /// Match the current `alternateIconName` to an option.
    static func current(from alternateIconName: String?) -> AppIconOption {
        guard let name = alternateIconName else { return .silver }
        return AppIconOption(rawValue: name) ?? .silver
    }
}

// MARK: - Cell View

/// A single icon thumbnail cell with label and selection indicator.
private struct AppIconCell: View {
    let option: AppIconOption
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                ZStack(alignment: .bottomTrailing) {
                    iconImage
                        .frame(width: 68, height: 68)
                        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 16, style: .continuous)
                                .strokeBorder(isSelected ? Color.accentColor : Color.clear, lineWidth: 2.5)
                        )

                    if isSelected {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 20))
                            .foregroundStyle(.white, .blue)
                            .accessibilityHidden(true)
                            .offset(x: 4, y: 4)
                    }
                }

                Text(option.displayName)
                    .font(.caption)
                    .foregroundStyle(isSelected ? .primary : .secondary)
                    .lineLimit(1)
            }
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
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(.quaternary)
                .overlay {
                    Text(option.displayName.prefix(1))
                        .font(.title2.bold())
                        .foregroundStyle(.secondary)
                }
        }
    }
}

#endif
