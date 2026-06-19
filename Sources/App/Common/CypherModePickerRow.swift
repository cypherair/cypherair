import SwiftUI

enum CypherModePickerProminence {
    case workflow
    case form
}

enum CypherModePickerLayout {
    case automatic
    case stacked
}

/// Shared mode-switching row that keeps CypherAir's mode pickers native while
/// giving them consistent spacing and control sizing across Apple platforms.
struct CypherModePickerRow<SelectionValue: Hashable, PickerContent: View>: View {
    let title: String
    @Binding private var selection: SelectionValue

    private let prominence: CypherModePickerProminence
    private let layout: CypherModePickerLayout
    private let isDisabled: Bool
    private let pickerContent: PickerContent

    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    init(
        title: String,
        selection: Binding<SelectionValue>,
        prominence: CypherModePickerProminence = .workflow,
        layout: CypherModePickerLayout = .automatic,
        isDisabled: Bool = false,
        @ViewBuilder content: () -> PickerContent
    ) {
        self.title = title
        _selection = selection
        self.prominence = prominence
        self.layout = layout
        self.isDisabled = isDisabled
        pickerContent = content()
    }

    var body: some View {
        Group {
            if usesStackedLayout {
                VStack(alignment: .leading, spacing: 10) {
                    visibleLabel
                    picker
                        .frame(maxWidth: .infinity)
                }
            } else {
                HStack(alignment: .center, spacing: 16) {
                    visibleLabel

                    Spacer(minLength: 16)

                    picker
                        .frame(
                            minWidth: minimumRowPickerWidth,
                            maxWidth: maximumRowPickerWidth,
                            alignment: .trailing
                        )
                }
            }
        }
        .padding(.vertical, verticalPadding)
        .disabled(isDisabled)
    }

    private var visibleLabel: some View {
        Text(title)
            .font(.body.weight(.medium))
            .foregroundStyle(.primary)
            .accessibilityHidden(true)
    }

    private var picker: some View {
        Picker(title, selection: $selection) {
            pickerContent
        }
        .labelsHidden()
        .pickerStyle(.segmented)
        .controlSize(resolvedControlSize)
        .accessibilityLabel(Text(title))
    }

    private var usesStackedLayout: Bool {
        switch layout {
        case .stacked:
            true
        case .automatic:
            #if os(macOS)
            false
            #else
            horizontalSizeClass == .compact
            #endif
        }
    }

    private var resolvedControlSize: ControlSize {
        #if os(macOS)
        switch prominence {
        case .workflow:
            .large
        case .form:
            .regular
        }
        #else
        horizontalSizeClass == .compact ? .regular : .large
        #endif
    }

    private var minimumRowPickerWidth: CGFloat {
        switch prominence {
        case .workflow:
            180
        case .form:
            220
        }
    }

    private var maximumRowPickerWidth: CGFloat {
        switch prominence {
        case .workflow:
            320
        case .form:
            420
        }
    }

    private var verticalPadding: CGFloat {
        switch prominence {
        case .workflow:
            4
        case .form:
            2
        }
    }
}
