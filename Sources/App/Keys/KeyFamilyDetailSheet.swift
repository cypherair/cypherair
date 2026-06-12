import SwiftUI

/// Read-only detail sheet for one key-family option in key generation.
struct KeyFamilyDetailSheet: View {
    let family: PGPKeyConfiguration.Identity
    let onDismiss: () -> Void

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(family.familyDescription)
                        .font(.callout)
                }

                Section {
                    LabeledContent(
                        String(localized: "keyFamily.detail.algorithms", defaultValue: "Algorithms"),
                        value: family.familyAlgorithmSummary
                    )
                    LabeledContent(
                        String(localized: "keyFamily.detail.version", defaultValue: "Key Version"),
                        value: family.familyKeyVersionDisplay
                    )
                    LabeledContent(
                        String(localized: "keyFamily.detail.messageFormat", defaultValue: "Message Format"),
                        value: family.familyMessageFormatDisplay
                    )
                    LabeledContent(
                        String(localized: "keyFamily.detail.securityLevel", defaultValue: "Approx. Security Level"),
                        value: family.familySecurityLevel
                    )
                    LabeledContent(
                        String(localized: "keyFamily.detail.exportability", defaultValue: "Exportability"),
                        value: family.familyExportabilityDisplay
                    )
                    LabeledContent(
                        String(localized: "keyFamily.detail.gnupg", defaultValue: "GnuPG Compatibility"),
                        value: family.familyGnuPGCompatibilityDisplay
                    )
                    LabeledContent(
                        String(localized: "keyFamily.detail.custody", defaultValue: "Custody"),
                        value: family.familyCustodyDisplay
                    )
                } header: {
                    Text(String(localized: "keyFamily.detail.header", defaultValue: "Details"))
                }

                if family.isDeviceBoundFamily {
                    Section {
                        Label {
                            Text(PGPKeyConfiguration.Identity.deviceBoundBiometricRequirement)
                                .font(.callout)
                        } icon: {
                            Image(systemName: "faceid")
                                .foregroundStyle(Color.accentColor)
                        }
                    }
                }
            }
            .cypherMacReadableContent()
            .accessibilityIdentifier("keygen.family.\(family.rawValue).detail")
            .navigationTitle(family.familyDisplayName)
            #if !os(macOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "common.done", defaultValue: "Done")) {
                        onDismiss()
                    }
                    .accessibilityIdentifier("keygen.family.detail.done")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 520, minHeight: 420)
        #endif
    }
}
