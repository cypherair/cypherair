import SwiftUI

enum CypherModePickerPlacement {
    static func usesToolbar(horizontalSizeClass: UserInterfaceSizeClass?) -> Bool {
        #if os(macOS)
        true
        #elseif os(iOS)
        horizontalSizeClass != .compact
        #else
        false
        #endif
    }
}

struct CypherModePicker<SelectionValue: Hashable, PickerContent: View>: View {
    let title: String
    let selectedValueLabel: String
    let isDisabled: Bool
    let accessibilityIdentifier: String?

    @Binding private var selection: SelectionValue
    private let pickerContent: PickerContent

    init(
        title: String,
        selection: Binding<SelectionValue>,
        selectedValueLabel: String,
        isDisabled: Bool = false,
        accessibilityIdentifier: String? = nil,
        @ViewBuilder content: () -> PickerContent
    ) {
        self.title = title
        self.selectedValueLabel = selectedValueLabel
        self.isDisabled = isDisabled
        self.accessibilityIdentifier = accessibilityIdentifier
        _selection = selection
        pickerContent = content()
    }

    var body: some View {
        Picker(title, selection: $selection) {
            pickerContent
        }
        // Xcode 26.5 does not expose SwiftUI's TabsPickerStyle yet. Keep the
        // segmented fallback centralized and leave toolbar visuals platform-owned.
        .pickerStyle(.segmented)
        .labelsHidden()
        .disabled(isDisabled)
        .accessibilityLabel(Text(title))
        .accessibilityValue(Text(selectedValueLabel))
        .cypherAccessibilityIdentifier(accessibilityIdentifier)
    }
}

private struct OptionalAccessibilityIdentifierModifier: ViewModifier {
    let identifier: String?

    @ViewBuilder
    func body(content: Content) -> some View {
        if let identifier {
            content.accessibilityIdentifier(identifier)
        } else {
            content
        }
    }
}

private extension View {
    func cypherAccessibilityIdentifier(_ identifier: String?) -> some View {
        modifier(OptionalAccessibilityIdentifierModifier(identifier: identifier))
    }
}
