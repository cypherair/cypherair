import SwiftUI

/// Detailed view of a single key identity.
struct KeyDetailView: View {
    let fingerprint: String

    @Environment(KeyManagementService.self) private var keyManagement

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
                            // Deletion is handled via confirmation dialog
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
    }
}
