import SwiftUI
import UniformTypeIdentifiers
#if canImport(AppKit)
import AppKit
#endif
#if canImport(UIKit)
import UIKit
#endif

/// Detailed view of a single key identity.
struct KeyDetailView: View {
    struct Configuration {
        var allowsPublicKeySave = true
        var allowsPublicKeyCopy = true
        var allowsRevocationExport = true
        var outputInterceptionPolicy: OutputInterceptionPolicy = .passthrough

        static let `default` = Configuration()
    }

    let fingerprint: String
    let configuration: Configuration

    @Environment(AppConfiguration.self) private var config
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.dismiss) private var dismiss
    @Environment(\.macPresentationController) private var macPresentationController

    init(
        fingerprint: String,
        configuration: Configuration = .default
    ) {
        self.fingerprint = fingerprint
        self.configuration = configuration
    }

    var body: some View {
        KeyDetailScreenHostView(
            fingerprint: fingerprint,
            config: config,
            keyManagement: keyManagement,
            macPresentationController: macPresentationController,
            configuration: configuration,
            dismissAction: { dismiss() }
        )
    }
}

private struct KeyDetailScreenHostView: View {
    @State private var model: KeyDetailScreenModel

    init(
        fingerprint: String,
        config: AppConfiguration,
        keyManagement: KeyManagementService,
        macPresentationController: MacPresentationController?,
        configuration: KeyDetailView.Configuration,
        dismissAction: @escaping @MainActor () -> Void
    ) {
        _model = State(
            initialValue: KeyDetailScreenModel(
                fingerprint: fingerprint,
                config: config,
                keyManagement: keyManagement,
                macPresentationController: macPresentationController,
                configuration: configuration,
                dismissAction: dismissAction
            )
        )
    }

    var body: some View {
        @Bindable var model = model
        let exportController = model.exportController

        Group {
            if let key = model.key {
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
                        HStack {
                            Text(String(localized: "keydetail.expiry", defaultValue: "Expiry"))
                            Spacer()
                            if key.isExpired {
                                HStack(spacing: 4) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.red)
                                    Text(String(localized: "keydetail.expiry.expired", defaultValue: "Expired"))
                                        .foregroundStyle(.red)
                                    Text(key.expiryDate?.formatted(date: .abbreviated, time: .omitted) ?? "—")
                                        .foregroundStyle(.red)
                                }
                            } else if let expiryDate = key.expiryDate {
                                Text(expiryDate.formatted(date: .abbreviated, time: .omitted))
                            } else {
                                Text(String(localized: "keydetail.expiry.never", defaultValue: "Never"))
                                    .foregroundStyle(.secondary)
                            }
                        }

                        Button {
                            model.presentModifyExpiry()
                        } label: {
                            Label(
                                String(localized: "keydetail.modifyExpiry", defaultValue: "Modify Expiry"),
                                systemImage: "calendar.badge.clock"
                            )
                        }
                        .accessibilityIdentifier("keydetail.modifyExpiry")
                    } header: {
                        Text(String(localized: "keydetail.validity", defaultValue: "Validity"))
                    }

                    Section {
                        FingerprintView(fingerprint: key.fingerprint)
                    } header: {
                        Text(String(localized: "keydetail.fingerprint", defaultValue: "Fingerprint"))
                    }

                    Section {
                        if model.armoredPublicKey != nil {
                            Button {
                                model.exportPublicKey()
                            } label: {
                                Label(
                                    String(localized: "keydetail.sharePublicKey", defaultValue: "Save Public Key"),
                                    systemImage: "square.and.arrow.down"
                                )
                            }
                            .disabled(model.armoredPublicKey == nil || !model.configuration.allowsPublicKeySave)
                        }

                        NavigationLink(value: AppRoute.qrDisplay(publicKeyData: key.publicKeyData, displayName: key.userId ?? key.shortKeyId)) {
                            Label(
                                String(localized: "keydetail.showQR", defaultValue: "Show QR Code"),
                                systemImage: "qrcode"
                            )
                        }
                        .accessibilityIdentifier("keydetail.qr")

                        Button {
                            model.copyPublicKey()
                        } label: {
                            Label(
                                String(localized: "keydetail.copyPublicKey", defaultValue: "Copy Public Key"),
                                systemImage: "doc.on.doc"
                            )
                        }
                        .disabled(model.armoredPublicKey == nil || !model.configuration.allowsPublicKeyCopy)
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

                        NavigationLink(value: AppRoute.backupKey(fingerprint: model.fingerprint)) {
                            Label(
                                String(localized: "keydetail.exportBackup", defaultValue: "Export Backup"),
                                systemImage: "square.and.arrow.up"
                            )
                        }
                        .tutorialAnchor(.keyDetailBackupButton)
                        .accessibilityIdentifier("keydetail.backup")

                        Button {
                            model.exportRevocationCertificate()
                        } label: {
                            Label(
                                String(localized: "keydetail.exportRevocation", defaultValue: "Export Revocation Certificate"),
                                systemImage: "xmark.seal"
                            )
                        }
                        .disabled(!model.configuration.allowsRevocationExport || model.isPreparingRevocationExport)
                    } header: {
                        Text(String(localized: "keydetail.actions", defaultValue: "Actions"))
                    }

                    if !key.isDefault {
                        Section {
                            Button {
                                model.setDefaultKey()
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
                            model.showDeleteConfirmation = true
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
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .accessibilityIdentifier("keydetail.root")
        .screenReady("keydetail.ready")
        .navigationTitle(String(localized: "keydetail.title", defaultValue: "Key Detail"))
        .confirmationDialog(
            String(localized: "keydetail.delete.title", defaultValue: "Delete Key"),
            isPresented: $model.showDeleteConfirmation,
            titleVisibility: .visible
        ) {
            Button(String(localized: "keydetail.delete.confirm", defaultValue: "Delete Permanently"), role: .destructive) {
                model.deleteKey()
            }
        } message: {
            Text(String(localized: "keydetail.delete.message", defaultValue: "This will permanently delete this key from your device. This action cannot be undone. Make sure you have a backup."))
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: Binding(
                get: { model.showError },
                set: { if !$0 { model.dismissError() } }
            ),
            presenting: model.error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                model.dismissError()
            }
        } message: { err in
            Text(err.localizedDescription)
        }
        .alert(
            String(localized: "clipboard.copied.title", defaultValue: "Copied"),
            isPresented: Binding(
                get: { model.showCopiedNotice },
                set: { if !$0 { model.dismissCopiedNotice() } }
            )
        ) {
            Button(String(localized: "clipboard.copied.ok", defaultValue: "OK")) {
                model.dismissCopiedNotice()
            }
        } message: {
            Text(String(localized: "clipboard.copied.publicKey", defaultValue: "Public key copied to clipboard."))
        }
        .sheet(item: Binding(
            get: { model.localModifyExpiryRequest },
            set: { if $0 == nil { model.dismissModifyExpiryPresentation() } }
        )) { request in
            NavigationStack {
                ModifyExpirySheetView(request: request)
            }
            #if os(macOS)
            .frame(minWidth: 500, idealWidth: 540, minHeight: 320, idealHeight: 380)
            #endif
            #if canImport(UIKit)
            .presentationDetents([.medium])
            #endif
        }
        .fileExporter(
            isPresented: Binding(
                get: { exportController.isPresented },
                set: { if !$0 { model.finishExport() } }
            ),
            item: exportController.payload,
            contentTypes: [.data],
            defaultFilename: exportController.defaultFilename
        ) { result in
            model.finishExport()
            if case .failure(let exportError) = result {
                model.handleExportError(exportError)
            }
        }
        .onAppear {
            model.prepareIfNeeded()
        }
    }
}
