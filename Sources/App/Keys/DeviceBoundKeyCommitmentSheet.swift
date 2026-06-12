import SwiftUI

/// Pre-generation commitment sheet for device-bound Secure Enclave custody keys.
/// The user must understand the portability consequence before the key exists.
struct DeviceBoundKeyCommitmentSheet: View {
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            List {
                Section {
                    commitmentRow(
                        systemImage: "cpu",
                        text: String(
                            localized: "keygen.deviceBound.confirm.custody",
                            defaultValue: "The private key is created inside this device's Secure Enclave and never leaves this device."
                        )
                    )
                    commitmentRow(
                        systemImage: "square.and.arrow.up.badge.clock",
                        text: String(
                            localized: "keygen.deviceBound.confirm.portability",
                            defaultValue: "It cannot be exported, backed up, or moved to another device."
                        )
                    )
                    commitmentRow(
                        systemImage: "exclamationmark.triangle",
                        text: String(
                            localized: "keygen.deviceBound.confirm.loss",
                            defaultValue: "If this device is lost or erased, or its biometric access is removed, messages to this key become permanently unreadable."
                        )
                    )
                    commitmentRow(
                        systemImage: "doc.text",
                        text: String(
                            localized: "keygen.deviceBound.confirm.publicMaterial",
                            defaultValue: "You can export the public key and a revocation certificate, but they are not private-key backups."
                        )
                    )
                }

                Section {
                    Button {
                        onConfirm()
                    } label: {
                        Text(String(
                            localized: "keygen.deviceBound.confirm.create",
                            defaultValue: "Create Device-Bound Key"
                        ))
                        .cypherPrimaryActionLabelFrame()
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("keygen.deviceBound.confirm.create")
                }
            }
            .cypherMacReadableContent()
            .accessibilityIdentifier("keygen.deviceBound.confirm.root")
            .navigationTitle(String(
                localized: "keygen.deviceBound.confirm.title",
                defaultValue: "Create a Device-Bound Key?"
            ))
            #if !os(macOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                        onCancel()
                    }
                    .accessibilityIdentifier("keygen.deviceBound.confirm.cancel")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 480, minHeight: 400)
        #endif
    }

    private func commitmentRow(systemImage: String, text: String) -> some View {
        Label {
            Text(text)
                .font(.callout)
        } icon: {
            Image(systemName: systemImage)
                .foregroundStyle(Color.accentColor)
        }
    }
}
