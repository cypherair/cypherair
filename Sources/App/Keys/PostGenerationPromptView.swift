import SwiftUI

/// Shown after key generation to prompt the user to back up and share their key.
/// Per PRD Section 4.1: "Done → Prompt: back up private key & share public key"
struct PostGenerationPromptView: View {
    let identity: PGPKeyIdentity

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: 12) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 48))
                            .foregroundStyle(.green)

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

                    NavigationLink(value: AppRoute.qrDisplay(publicKeyData: identity.publicKeyData, displayName: identity.userId ?? identity.shortKeyId)) {
                        Label(
                            String(localized: "postgen.shareQR", defaultValue: "Share Public Key via QR"),
                            systemImage: "qrcode"
                        )
                    }

                    NavigationLink(value: AppRoute.keyDetail(fingerprint: identity.fingerprint)) {
                        Label(
                            String(localized: "postgen.viewKey", defaultValue: "View Key Details"),
                            systemImage: "key"
                        )
                    }
                } header: {
                    Text(String(localized: "postgen.nextSteps", defaultValue: "Next Steps"))
                }
            }
            .navigationTitle(String(localized: "postgen.title", defaultValue: "Key Ready"))
            .navigationDestination(for: AppRoute.self) { route in
                switch route {
                case .backupKey(let fp):
                    BackupKeyView(fingerprint: fp)
                case .qrDisplay(let data, let name):
                    QRDisplayView(publicKeyData: data, displayName: name)
                case .keyDetail(let fp):
                    KeyDetailView(fingerprint: fp)
                default:
                    EmptyView()
                }
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "postgen.done", defaultValue: "Done")) {
                        dismiss()
                    }
                }
            }
        }
    }
}
