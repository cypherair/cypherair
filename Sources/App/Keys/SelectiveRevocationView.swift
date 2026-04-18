import SwiftUI
import UniformTypeIdentifiers

struct SelectiveRevocationView: View {
    struct Configuration {
        var outputInterceptionPolicy: OutputInterceptionPolicy = .passthrough

        static let `default` = Configuration()
    }

    let fingerprint: String
    let configuration: Configuration

    @Environment(KeyManagementService.self) private var keyManagement

    init(
        fingerprint: String,
        configuration: Configuration = .default
    ) {
        self.fingerprint = fingerprint
        self.configuration = configuration
    }

    var body: some View {
        SelectiveRevocationScreenHostView(
            fingerprint: fingerprint,
            keyManagement: keyManagement,
            configuration: configuration
        )
    }
}

private struct SelectiveRevocationScreenHostView: View {
    @State private var model: SelectiveRevocationScreenModel

    init(
        fingerprint: String,
        keyManagement: KeyManagementService,
        configuration: SelectiveRevocationView.Configuration
    ) {
        _model = State(
            initialValue: SelectiveRevocationScreenModel(
                fingerprint: fingerprint,
                keyManagement: keyManagement,
                configuration: configuration
            )
        )
    }

    var body: some View {
        @Bindable var model = model
        let exportController = model.exportController

        Form {
            content
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .accessibilityIdentifier("selectiverevocation.root")
        .screenReady("selectiverevocation.ready")
        .navigationTitle(String(localized: "selectiverevocation.title", defaultValue: "Selective Revocation"))
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
            model.loadIfNeeded()
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.loadState {
        case .idle, .loading:
            loadingSection
        case .failed:
            failedSection
        case .loaded:
            overviewSection
            subkeySection
            userIdSection
        }
    }

    private var loadingSection: some View {
        Section {
            HStack(spacing: 12) {
                ProgressView()
                Text(String(localized: "selectiverevocation.loading", defaultValue: "Loading selectable revocation targets..."))
            }
        }
    }

    private var failedSection: some View {
        Section {
            ContentUnavailableView {
                Label(
                    String(localized: "selectiverevocation.loadFailed.title", defaultValue: "Could Not Load Revocation Targets"),
                    systemImage: "exclamationmark.triangle"
                )
            } description: {
                Text(model.loadError?.localizedDescription ?? String(localized: "error.generic", defaultValue: "An error occurred."))
            } actions: {
                Button(String(localized: "common.retry", defaultValue: "Retry")) {
                    model.retry()
                }
            }
        }
    }

    private var overviewSection: some View {
        Section {
            Text(
                String(
                    localized: "selectiverevocation.explanation",
                    defaultValue: "Export a revocation signature for one subkey or one User ID. This does not modify the stored key and does not save a new revocation artifact in CypherAir."
                )
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            if let key = model.key {
                LabeledContent(
                    String(localized: "selectiverevocation.key", defaultValue: "Key"),
                    value: key.userId ?? key.shortKeyId
                )
                LabeledContent(
                    String(localized: "keydetail.shortKeyId", defaultValue: "Short Key ID"),
                    value: key.shortKeyId
                )
            }
        } header: {
            Text(String(localized: "selectiverevocation.overview", defaultValue: "Overview"))
        }
    }

    private var subkeySection: some View {
        Section {
            if model.subkeys.isEmpty {
                Label(
                    String(localized: "selectiverevocation.subkeys.empty", defaultValue: "No selectable subkeys were found."),
                    systemImage: "key.slash"
                )
                .foregroundStyle(.secondary)
            } else {
                ForEach(model.subkeys, id: \.self) { subkey in
                    Button {
                        model.selectSubkey(subkey)
                    } label: {
                        SelectiveSubkeyRow(
                            subkey: subkey,
                            isSelected: model.selectedSubkey == subkey
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(model.isExportLocked)
                }

                Button {
                    model.exportSelectedSubkey()
                } label: {
                    ExportButtonLabel(
                        title: String(localized: "selectiverevocation.subkey.export", defaultValue: "Export Subkey Revocation"),
                        isRunning: model.activeExportOperation == .subkey
                    )
                }
                .buttonStyle(.borderedProminent)
                .disabled(!model.canExportSubkey)
            }
        } header: {
            Text(String(localized: "selectiverevocation.subkeys", defaultValue: "Subkey Revocation"))
        } footer: {
            Text(String(localized: "selectiverevocation.subkeys.footer", defaultValue: "Choose exactly one discovered subkey. Selector values come from the certificate, not from display text."))
        }
    }

    private var userIdSection: some View {
        Section {
            if model.userIds.isEmpty {
                Label(
                    String(localized: "selectiverevocation.userIds.empty", defaultValue: "No selectable User IDs were found."),
                    systemImage: "person.slash"
                )
                .foregroundStyle(.secondary)
            } else {
                ForEach(model.userIds, id: \.self) { userId in
                    Button {
                        model.selectUserId(userId)
                    } label: {
                        SelectiveUserIdRow(
                            userId: userId,
                            isSelected: model.selectedUserId == userId
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(model.isExportLocked)
                }

                Button {
                    model.exportSelectedUserId()
                } label: {
                    ExportButtonLabel(
                        title: String(localized: "selectiverevocation.userId.export", defaultValue: "Export User ID Revocation"),
                        isRunning: model.activeExportOperation == .userId
                    )
                }
                .buttonStyle(.borderedProminent)
                .disabled(!model.canExportUserId)
            }
        } header: {
            Text(String(localized: "selectiverevocation.userIds", defaultValue: "User ID Revocation"))
        } footer: {
            Text(String(localized: "selectiverevocation.userIds.footer", defaultValue: "Duplicate User IDs remain separate choices. The occurrence number identifies the exact packet selected for revocation."))
        }
    }
}

private struct SelectiveSubkeyRow: View {
    let subkey: SubkeySelectionOption
    let isSelected: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text(subkey.algorithmDisplay.isEmpty ? String(localized: "selectiverevocation.subkey", defaultValue: "Subkey") : subkey.algorithmDisplay)
                    .font(.headline)
                Text(IdentityPresentation.formattedFingerprint(subkey.fingerprint))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                HStack {
                    if subkey.isCurrentlyTransportEncryptionCapable {
                        StatusBadge(
                            title: String(localized: "selectiverevocation.status.encryptCapable", defaultValue: "Encrypt-capable"),
                            color: .green
                        )
                    }
                    if subkey.isCurrentlyRevoked {
                        StatusBadge(
                            title: String(localized: "selectiverevocation.status.revoked", defaultValue: "Revoked"),
                            color: .red
                        )
                    }
                    if subkey.isCurrentlyExpired {
                        StatusBadge(
                            title: String(localized: "selectiverevocation.status.expired", defaultValue: "Expired"),
                            color: .orange
                        )
                    }
                }
            }

            Spacer()

            if isSelected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.tint)
            }
        }
        .contentShape(Rectangle())
    }
}

private struct SelectiveUserIdRow: View {
    let userId: UserIdSelectionOption
    let isSelected: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text(userId.displayText)
                    .font(.headline)
                Text(String(localized: "selectiverevocation.userId.occurrence", defaultValue: "Occurrence \(userId.occurrenceIndex + 1)"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    if userId.isCurrentlyPrimary {
                        StatusBadge(
                            title: String(localized: "selectiverevocation.status.primary", defaultValue: "Primary"),
                            color: .blue
                        )
                    }
                    if userId.isCurrentlyRevoked {
                        StatusBadge(
                            title: String(localized: "selectiverevocation.status.revoked", defaultValue: "Revoked"),
                            color: .red
                        )
                    }
                }
            }

            Spacer()

            if isSelected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.tint)
            }
        }
        .contentShape(Rectangle())
    }
}

private struct ExportButtonLabel: View {
    let title: String
    let isRunning: Bool

    var body: some View {
        if isRunning {
            HStack {
                ProgressView()
                Text(String(localized: "common.exporting", defaultValue: "Exporting..."))
            }
            .frame(maxWidth: .infinity)
        } else {
            Text(title)
                .frame(maxWidth: .infinity)
        }
    }
}

private struct StatusBadge: View {
    let title: String
    let color: Color

    var body: some View {
        Text(title)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.14), in: Capsule())
            .foregroundStyle(color)
    }
}
