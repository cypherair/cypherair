import SwiftUI

/// Shown after key generation to prompt the user to back up and share their key.
/// Per PRD Section 4.1: "Done → Prompt: back up private key & share public key"
struct PostGenerationPromptView: View {
    let identity: PGPKeyIdentity
    let onDone: (() -> Void)?

    @Environment(\.dismiss) private var dismiss

    init(
        identity: PGPKeyIdentity,
        onDone: (() -> Void)? = nil
    ) {
        self.identity = identity
        self.onDone = onDone
    }

    var body: some View {
        List {
            Section {
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 48))
                        .foregroundStyle(.green)
                        .accessibilityHidden(true)

                    Text(String(localized: "postgen.success", defaultValue: "Key Generated"))
                        .font(.headline)

                    Text(String(localized: "postgen.subtitle", defaultValue: "Back up your private key and share your public key with contacts."))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical)
            }

            Section {
                NavigationLink(value: AppRoute.backupKey(fingerprint: identity.fingerprint)) {
                    Label(
                        String(localized: "postgen.backup", defaultValue: "Back Up Private Key"),
                        systemImage: "lock.doc"
                    )
                }
                .accessibilityIdentifier("postgen.backup")

                NavigationLink(value: AppRoute.qrDisplay(publicKeyData: identity.publicKeyData, displayName: identity.userId ?? identity.shortKeyId)) {
                    Label(
                        String(localized: "postgen.shareQR", defaultValue: "Share Public Key via QR"),
                        systemImage: "qrcode"
                    )
                }
                .accessibilityIdentifier("postgen.qr")

                NavigationLink(value: AppRoute.keyDetail(fingerprint: identity.fingerprint)) {
                    Label(
                        String(localized: "postgen.viewKey", defaultValue: "View Key Details"),
                        systemImage: "key"
                    )
                }
                .accessibilityIdentifier("postgen.keyDetail")
            } header: {
                Text(String(localized: "postgen.nextSteps", defaultValue: "Next Steps"))
            }
        }
        .accessibilityIdentifier("postgen.root")
        .screenReady("postgen.ready")
        .navigationTitle(String(localized: "postgen.title", defaultValue: "Key Ready"))
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(String(localized: "postgen.done", defaultValue: "Done")) {
                    handleDone()
                }
                .accessibilityIdentifier("postgen.done")
            }
        }
    }

    private func handleDone() {
        if let onDone {
            onDone()
        } else {
            dismiss()
        }
    }
}
