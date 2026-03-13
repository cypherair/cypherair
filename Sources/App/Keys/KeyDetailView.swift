import SwiftUI

/// Detailed view of a single key identity.
struct KeyDetailView: View {
    let fingerprint: String

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.dismiss) private var dismiss

    @State private var showDeleteConfirmation = false
    @State private var error: CypherAirError?
    @State private var showError = false

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
    }
}
