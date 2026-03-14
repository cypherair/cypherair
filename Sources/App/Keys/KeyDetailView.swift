import SwiftUI
import UIKit

/// Detailed view of a single key identity.
struct KeyDetailView: View {
    let fingerprint: String

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config
    @Environment(\.dismiss) private var dismiss

    @State private var showDeleteConfirmation = false
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var armoredPublicKey: Data?
    @State private var showCopiedNotice = false

    private var key: PGPKeyIdentity? {
        keyManagement.keys.first { $0.fingerprint == fingerprint }
    }

    var body: some View {
        Group {
            if let key {
                List {
                    Section {
                        LabeledContent(
                            String(localized: "keydetail.name", defaultValue: "Name"),
                            value: key.userId ?? "—"
                        )
                        LabeledContent(
                            String(localized: "keydetail.profile", defaultValue: "Profile"),
                            value: key.profile.displayName
                        )
                        LabeledContent(
                            String(localized: "keydetail.version", defaultValue: "Key Version"),
                            value: "v\(key.keyVersion)"
                        )
                        LabeledContent(
                            String(localized: "keydetail.algo", defaultValue: "Algorithm"),
                            value: [key.primaryAlgo, key.subkeyAlgo].compactMap { $0 }.joined(separator: " + ")
                        )
                        LabeledContent(
                            String(localized: "keydetail.security", defaultValue: "Security Level"),
                            value: key.profile.securityLevel
                        )
                        LabeledContent(
                            String(localized: "keydetail.shortKeyId", defaultValue: "Short Key ID"),
                            value: key.shortKeyId
                        )
                        .foregroundStyle(.secondary)
                    } header: {
                        Text(String(localized: "keydetail.info", defaultValue: "Key Information"))
                    }

                    Section {
                        Text(key.formattedFingerprint)
                            .font(.system(.body, design: .monospaced))
                            .accessibilityLabel(
                                key.formattedFingerprint
                                    .split(separator: " ")
                                    .map { $0.map(String.init).joined(separator: " ") }
                                    .joined(separator: ", ")
                            )
                    } header: {
                        Text(String(localized: "keydetail.fingerprint", defaultValue: "Fingerprint"))
                    }

                    Section {
                        if let armoredPublicKey {
                            ShareLink(
                                item: armoredPublicKey,
                                preview: SharePreview(
                                    "\(key.shortKeyId).asc",
                                    image: Image(systemName: "key")
                                )
                            ) {
                                Label(
                                    String(localized: "keydetail.sharePublicKey", defaultValue: "Share Public Key"),
                                    systemImage: "square.and.arrow.up"
                                )
                            }
                        }

                        NavigationLink(value: AppRoute.qrDisplay(publicKeyData: key.publicKeyData, displayName: key.userId ?? key.shortKeyId)) {
                            Label(
                                String(localized: "keydetail.showQR", defaultValue: "Show QR Code"),
                                systemImage: "qrcode"
                            )
                        }

                        Button {
                            if let armoredPublicKey,
                               let armoredString = String(data: armoredPublicKey, encoding: .utf8) {
                                UIPasteboard.general.string = armoredString
                                showCopiedNotice = true
                            }
                        } label: {
                            Label(
                                String(localized: "keydetail.copyPublicKey", defaultValue: "Copy Public Key"),
                                systemImage: "doc.on.doc"
                            )
                        }
                        .disabled(armoredPublicKey == nil)
                    } header: {
                        Text(String(localized: "keydetail.publicKey", defaultValue: "Public Key"))
                    }

                    Section {
                        HStack {
                            Text(String(localized: "keydetail.backup", defaultValue: "Backup Status"))
                            Spacer()
                            if key.isBackedUp {
                                Label(
                                    String(localized: "keydetail.backed", defaultValue: "Backed Up"),
                                    systemImage: "checkmark.circle.fill"
                                )
                                .foregroundStyle(.green)
                            } else {
                                Label(
                                    String(localized: "keydetail.notBacked", defaultValue: "Not Backed Up"),
                                    systemImage: "exclamationmark.triangle.fill"
                                )
                                .foregroundStyle(.orange)
                            }
                        }

                        NavigationLink(value: AppRoute.backupKey(fingerprint: fingerprint)) {
                            Label(
                                String(localized: "keydetail.exportBackup", defaultValue: "Export Backup"),
                                systemImage: "square.and.arrow.up"
                            )
                        }

                        if !key.revocationCert.isEmpty {
                            ShareLink(
                                item: key.revocationCert,
                                preview: SharePreview(
                                    "revocation-\(key.shortKeyId).asc",
                                    image: Image(systemName: "xmark.seal")
                                )
                            ) {
                                Label(
                                    String(localized: "keydetail.exportRevocation", defaultValue: "Export Revocation Certificate"),
                                    systemImage: "xmark.seal"
                                )
                            }
                        }
                    } header: {
                        Text(String(localized: "keydetail.actions", defaultValue: "Actions"))
                    }

                    if !key.isDefault {
                        Section {
                            Button {
                                keyManagement.setDefaultKey(fingerprint: fingerprint)
                            } label: {
                                Label(
                                    String(localized: "keydetail.setDefault", defaultValue: "Set as Default"),
                                    systemImage: "star"
                                )
                            }
                        }
                    }

                    Section {
                        Button(role: .destructive) {
                            showDeleteConfirmation = true
                        } label: {
                            Label(
                                String(localized: "keydetail.delete", defaultValue: "Delete Key"),
                                systemImage: "trash"
                            )
                        }
                    }
                }
            } else {
                ContentUnavailableView(
                    String(localized: "keydetail.notFound", defaultValue: "Key Not Found"),
                    systemImage: "key.slash"
                )
            }
        }
        .navigationTitle(String(localized: "keydetail.title", defaultValue: "Key Detail"))
        .confirmationDialog(
            String(localized: "keydetail.delete.title", defaultValue: "Delete Key"),
            isPresented: $showDeleteConfirmation,
            titleVisibility: .visible
        ) {
            Button(String(localized: "keydetail.delete.confirm", defaultValue: "Delete Permanently"), role: .destructive) {
                do {
                    try keyManagement.deleteKey(fingerprint: fingerprint)
                    dismiss()
                } catch {
                    self.error = CypherAirError.from(error) { .keychainError($0) }
                    showError = true
                }
            }
        } message: {
            Text(String(localized: "keydetail.delete.message", defaultValue: "This will permanently delete this key from your device. This action cannot be undone. Make sure you have a backup."))
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .alert(
            String(localized: "clipboard.copied.title", defaultValue: "Copied"),
            isPresented: $showCopiedNotice
        ) {
            Button(String(localized: "clipboard.copied.ok", defaultValue: "OK")) {}
        } message: {
            Text(String(localized: "clipboard.copied.publicKey", defaultValue: "Public key copied to clipboard."))
        }
        .task {
            do {
                armoredPublicKey = try keyManagement.exportPublicKey(fingerprint: fingerprint)
            } catch {
                // Non-critical — sharing buttons will be disabled
            }
        }
    }
}
