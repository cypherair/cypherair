import SwiftUI

/// Generation step 1: a custody-first key-family picker. Compact width shows a
/// segmented custody control above a single column of families; regular width
/// shows the custodies as side-by-side columns. Both are data-driven over the
/// offered family catalog, so new families slot in without layout changes.
struct KeyFamilyCustodyPickerView: View {
    let model: KeyGenerationScreenModel

    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    private var isRegularWidth: Bool { horizontalSizeClass == .regular }
    #else
    private var isRegularWidth: Bool { true }
    #endif

    private var isSelectionLocked: Bool {
        model.configuration.lockedFamily != nil
    }

    var body: some View {
        Group {
            if isRegularWidth {
                regularLayout
            } else {
                compactLayout
            }
        }
        .accessibilityIdentifier("keygen.familyPicker")
    }

    // MARK: Compact (iPhone)

    private var compactLayout: some View {
        Form {
            if model.availableCustodies.count > 1 {
                Section {
                    custodyPicker
                } header: {
                    Text(String(localized: "keygen.custody.header", defaultValue: "Custody"))
                }
            }

            Section {
                ForEach(model.families(for: model.selectedCustody), id: \.self) { family in
                    familyRow(family)
                }
            } header: {
                Text(String(localized: "keygen.keyType.header", defaultValue: "Key Type"))
            }

            Section {
                continueButton
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
    }

    private var custodyPicker: some View {
        Picker(
            String(localized: "keygen.custody.header", defaultValue: "Custody"),
            selection: Binding(
                get: { model.selectedCustody },
                set: { model.selectCustody($0) }
            )
        ) {
            ForEach(model.availableCustodies, id: \.self) { custody in
                Text(custody.displayName).tag(custody)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .disabled(isSelectionLocked)
        .accessibilityIdentifier("keygen.custodyPicker")
    }

    // MARK: Regular (iPad / Mac)

    private var regularLayout: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: CypherSpacing.section) {
                HStack(alignment: .top, spacing: CypherSpacing.standard) {
                    ForEach(model.availableCustodies, id: \.self) { custody in
                        custodyColumn(custody)
                    }
                }

                HStack {
                    Spacer(minLength: 0)
                    continueButton
                        .frame(maxWidth: 320)
                    Spacer(minLength: 0)
                }
            }
            .padding(CypherSpacing.standard)
            .cypherMacReadableContent()
        }
    }

    private func custodyColumn(_ custody: PGPKeyConfiguration.Identity.Custody) -> some View {
        let families = model.families(for: custody)
        return VStack(alignment: .leading, spacing: 0) {
            Text(custody.displayName)
                .font(.headline)
                .padding(.horizontal, CypherSpacing.tight)
                .padding(.top, CypherSpacing.tight)
                .padding(.bottom, CypherSpacing.compact)
                .accessibilityAddTraits(.isHeader)

            ForEach(Array(families.enumerated()), id: \.element) { index, family in
                if index > 0 {
                    Divider()
                        .padding(.leading, CypherSpacing.tight)
                }
                familyRow(family)
                    .padding(CypherSpacing.tight)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cypherSurface(.card)
    }

    // MARK: Shared

    private func familyRow(_ family: PGPKeyConfiguration.Identity) -> some View {
        KeyFamilySelectionRow(
            family: family,
            isSelected: model.selectedFamily == family,
            isEnabled: !isSelectionLocked,
            onSelect: { model.selectFamily(family) },
            onInfo: { model.presentFamilyDetail(family) }
        )
    }

    private var continueButton: some View {
        Button {
            model.continueToDetails()
        } label: {
            Text(String(localized: "keygen.continue", defaultValue: "Continue"))
                .cypherPrimaryActionLabelFrame()
        }
        .buttonStyle(.borderedProminent)
        .accessibilityIdentifier("keygen.continue")
    }
}
