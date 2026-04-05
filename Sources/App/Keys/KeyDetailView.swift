import SwiftUI
import UniformTypeIdentifiers
#if canImport(UIKit)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
#endif

/// Detailed view of a single key identity.
struct KeyDetailView: View {
    let fingerprint: String

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config
    @Environment(\.dismiss) private var dismiss
    @Environment(\.macPresentationController) private var macPresentationController

    @State private var showDeleteConfirmation = false
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var armoredPublicKey: Data?
    @State private var showCopiedNotice = false
    @State private var activeExport: ExportType?
    @State private var showExpirySheet = false
    @State private var newExpiryDate = Calendar.current.date(byAdding: .year, value: 2, to: Date()) ?? Date()
    @State private var isModifyingExpiry = false

    private enum ExportType {
        case publicKey
        case revocation
    }

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
                            presentModifyExpiry()
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
                        if armoredPublicKey != nil {
                            Button {
                                activeExport = .publicKey
                            } label: {
                                Label(
                                    String(localized: "keydetail.sharePublicKey", defaultValue: "Save Public Key"),
                                    systemImage: "square.and.arrow.down"
                                )
                            }
                        }

                        NavigationLink(value: AppRoute.qrDisplay(publicKeyData: key.publicKeyData, displayName: key.userId ?? key.shortKeyId)) {
                            Label(
                                String(localized: "keydetail.showQR", defaultValue: "Show QR Code"),
                                systemImage: "qrcode"
                            )
                        }
                        .accessibilityIdentifier("keydetail.qr")

                        Button {
                            if let armoredPublicKey,
                               let armoredString = String(data: armoredPublicKey, encoding: .utf8) {
                                #if canImport(UIKit)
                                UIPasteboard.general.string = armoredString
                                #elseif canImport(AppKit)
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(armoredString, forType: .string)
                                #endif
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
                        .tutorialAnchor(.keyDetailBackupButton)
                        .accessibilityIdentifier("keydetail.backup")

                        if !key.revocationCert.isEmpty {
                            Button {
                                activeExport = .revocation
                            } label: {
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
                                do {
                                    try keyManagement.setDefaultKey(fingerprint: fingerprint)
                                } catch {
                                    self.error = CypherAirError.from(error) { .keychainError($0) }
                                    showError = true
                                }
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
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .accessibilityIdentifier("keydetail.root")
        .screenReady("keydetail.ready")
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
        .sheet(isPresented: $showExpirySheet) {
            NavigationStack {
                Form {
                    Section {
                        DatePicker(
                            String(localized: "keydetail.expiry.newDate", defaultValue: "New Expiry Date"),
                            selection: $newExpiryDate,
                            in: (Calendar.current.date(byAdding: .day, value: 1, to: Date()) ?? Date())...(Calendar.current.date(byAdding: .year, value: 10, to: Date()) ?? Date()),
                            displayedComponents: .date
                        )
                    } header: {
                        Text(String(localized: "keydetail.expiry.setDate", defaultValue: "Set Expiry Date"))
                    }

                    Section {
                        Button {
                            performModifyExpiry(seconds: nil)
                        } label: {
                            Label(
                                String(localized: "keydetail.expiry.removeExpiry", defaultValue: "Remove Expiry (Never Expire)"),
                                systemImage: "infinity"
                            )
                        }
                    }
                }
                .navigationTitle(String(localized: "keydetail.expiry.title", defaultValue: "Modify Expiry"))
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button(String(localized: "keydetail.expiry.cancel", defaultValue: "Cancel")) {
                            showExpirySheet = false
                        }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button(String(localized: "keydetail.expiry.save", defaultValue: "Save")) {
                            let seconds = UInt64(max(0, newExpiryDate.timeIntervalSinceNow))
                            performModifyExpiry(seconds: seconds)
                        }
                        .disabled(isModifyingExpiry)
                    }
                }
                .overlay {
                    if isModifyingExpiry {
                        ProgressView()
                    }
                }
                .disabled(isModifyingExpiry)
            }
            #if os(macOS)
            .frame(minWidth: 500, idealWidth: 540, minHeight: 320, idealHeight: 380)
            #endif
            #if canImport(UIKit)
            .presentationDetents([.medium])
            #endif
        }
        .task {
            do {
                armoredPublicKey = try keyManagement.exportPublicKey(fingerprint: fingerprint)
            } catch {
                // Non-critical — sharing buttons will be disabled.
            }
        }
        .fileExporter(
            isPresented: Binding(
                get: { activeExport != nil },
                set: { if !$0 { activeExport = nil } }
            ),
            item: exportItem,
            contentTypes: [.data],
            defaultFilename: exportFilename
        ) { result in
            activeExport = nil
            if case .failure(let exportError) = result {
                error = CypherAirError.from(exportError) { .keychainError($0) }
                showError = true
            }
        }
    }

    private var exportItem: Data? {
        switch activeExport {
        case .publicKey:
            armoredPublicKey
        case .revocation:
            key?.revocationCert
        case nil:
            nil
        }
    }

    private var exportFilename: String {
        switch activeExport {
        case .publicKey:
            "\(key?.shortKeyId ?? "key").asc"
        case .revocation:
            "revocation-\(key?.shortKeyId ?? "key").asc"
        case nil:
            "export.asc"
        }
    }

    private func performModifyExpiry(seconds: UInt64?) {
        isModifyingExpiry = true
        let service = keyManagement
        let fp = fingerprint
        let authMode = config.authMode
        Task {
            do {
                _ = try await service.modifyExpiry(
                    fingerprint: fp,
                    newExpirySeconds: seconds,
                    authMode: authMode
                )
                armoredPublicKey = try? service.exportPublicKey(fingerprint: fp)
                showExpirySheet = false
            } catch {
                self.error = CypherAirError.from(error) { .keychainError($0) }
                showError = true
            }
            isModifyingExpiry = false
        }
    }

    private func presentModifyExpiry() {
        if let macPresentationController {
            macPresentationController.present(
                .modifyExpiry(
                    ModifyExpiryRequest(
                        fingerprint: fingerprint,
                        initialDate: newExpiryDate
                    )
                )
            )
        } else {
            showExpirySheet = true
        }
    }
}

@MainActor
struct ModifyExpiryRequest: Identifiable {
    let id = UUID()
    let fingerprint: String
    let initialDate: Date
}

struct ModifyExpirySheetView: View {
    let request: ModifyExpiryRequest

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config
    @Environment(\.dismiss) private var dismiss

    @State private var newExpiryDate: Date
    @State private var isModifyingExpiry = false
    @State private var error: CypherAirError?
    @State private var showError = false

    init(request: ModifyExpiryRequest) {
        self.request = request
        _newExpiryDate = State(initialValue: request.initialDate)
    }

    var body: some View {
        Form {
            Section {
                DatePicker(
                    String(localized: "keydetail.expiry.newDate", defaultValue: "New Expiry Date"),
                    selection: $newExpiryDate,
                    in: (Calendar.current.date(byAdding: .day, value: 1, to: Date()) ?? Date())...(Calendar.current.date(byAdding: .year, value: 10, to: Date()) ?? Date()),
                    displayedComponents: .date
                )
            } header: {
                Text(String(localized: "keydetail.expiry.setDate", defaultValue: "Set Expiry Date"))
            }

            Section {
                Button {
                    performModifyExpiry(seconds: nil)
                } label: {
                    Label(
                        String(localized: "keydetail.expiry.removeExpiry", defaultValue: "Remove Expiry (Never Expire)"),
                        systemImage: "infinity"
                    )
                }
            }
        }
        .accessibilityIdentifier("modifyexpiry.root")
        .screenReady("modifyexpiry.ready")
        .navigationTitle(String(localized: "keydetail.expiry.title", defaultValue: "Modify Expiry"))
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "keydetail.expiry.cancel", defaultValue: "Cancel")) {
                    dismiss()
                }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(String(localized: "keydetail.expiry.save", defaultValue: "Save")) {
                    let seconds = UInt64(max(0, newExpiryDate.timeIntervalSinceNow))
                    performModifyExpiry(seconds: seconds)
                }
                .accessibilityIdentifier("modifyexpiry.save")
                .disabled(isModifyingExpiry)
            }
        }
        .overlay {
            if isModifyingExpiry {
                ProgressView()
            }
        }
        .disabled(isModifyingExpiry)
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

    private func performModifyExpiry(seconds: UInt64?) {
        isModifyingExpiry = true
        let service = keyManagement
        let fingerprint = request.fingerprint
        let authMode = config.authMode

        Task {
            do {
                _ = try await service.modifyExpiry(
                    fingerprint: fingerprint,
                    newExpirySeconds: seconds,
                    authMode: authMode
                )
                dismiss()
            } catch {
                self.error = CypherAirError.from(error) { .keychainError($0) }
                showError = true
            }
            isModifyingExpiry = false
        }
    }
}
