import SwiftUI

/// Lists the user's own PGP key identities.
struct MyKeysView: View {
    @Environment(KeyManagementService.self) private var keyManagement

    #if os(macOS)
    @State private var showKeyGeneration = false
    @State private var showImportKey = false
    #endif

    var body: some View {
        List {
            ForEach(keyManagement.keys) { key in
                NavigationLink(value: AppRoute.keyDetail(fingerprint: key.fingerprint)) {
                    KeyRowView(key: key)
                }
            }
        }
        .overlay {
            if keyManagement.keys.isEmpty {
                ContentUnavailableView {
                    Label(
                        String(localized: "keys.empty.title", defaultValue: "No Keys"),
                        systemImage: "key.slash"
                    )
                } description: {
                    Text(String(localized: "keys.empty.description", defaultValue: "Generate or import a key to get started."))
                } actions: {
                    #if os(macOS)
                    Button(String(localized: "keys.generate", defaultValue: "Generate Key")) {
                        showKeyGeneration = true
                    }
                    .buttonStyle(.borderedProminent)
                    #else
                    NavigationLink(value: AppRoute.keyGeneration) {
                        Text(String(localized: "keys.generate", defaultValue: "Generate Key"))
                    }
                    .buttonStyle(.borderedProminent)
                    #endif
                }
            }
        }
        .navigationTitle(String(localized: "keys.title", defaultValue: "My Keys"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    #if os(macOS)
                    Button {
                        showKeyGeneration = true
                    } label: {
                        Label(
                            String(localized: "keys.action.generate", defaultValue: "Generate Key"),
                            systemImage: "plus"
                        )
                    }
                    Button {
                        showImportKey = true
                    } label: {
                        Label(
                            String(localized: "keys.action.import", defaultValue: "Import Key"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                    #else
                    NavigationLink(value: AppRoute.keyGeneration) {
                        Label(
                            String(localized: "keys.action.generate", defaultValue: "Generate Key"),
                            systemImage: "plus"
                        )
                    }
                    NavigationLink(value: AppRoute.importKey) {
                        Label(
                            String(localized: "keys.action.import", defaultValue: "Import Key"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                    #endif
                } label: {
                    Image(systemName: "plus")
                }
            }
        }
        .navigationDestination(for: AppRoute.self) { route in
            switch route {
            case .keyGeneration: KeyGenerationView()
            case .keyDetail(let fp): KeyDetailView(fingerprint: fp)
            case .backupKey(let fp): BackupKeyView(fingerprint: fp)
            case .importKey: ImportKeyView()
            case .qrDisplay(let data, let name): QRDisplayView(publicKeyData: data, displayName: name)
            default: Text(String(localized: "common.comingSoon", defaultValue: "Coming soon"))
            }
        }
        #if os(macOS)
        .sheet(isPresented: $showKeyGeneration) {
            NavigationStack {
                KeyGenerationView()
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                                showKeyGeneration = false
                            }
                        }
                    }
            }
            .frame(minWidth: 450, minHeight: 400)
        }
        .sheet(isPresented: $showImportKey) {
            NavigationStack {
                ImportKeyView()
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                                showImportKey = false
                            }
                        }
                    }
            }
            .frame(minWidth: 450, minHeight: 400)
        }
        #endif
    }
}

/// Row view for a single key identity in the list.
private struct KeyRowView: View {
    let key: PGPKeyIdentity

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(key.userId ?? key.shortKeyId)
                        .font(.body.weight(.medium))
                    if key.isDefault {
                        Text(String(localized: "keys.default", defaultValue: "Default"))
                            .font(.caption2)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(.tint.opacity(0.15), in: Capsule())
                    }
                }
                Text(key.profile.displayName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if !key.isBackedUp {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
                    .accessibilityLabel(String(localized: "keys.notBackedUp", defaultValue: "Not backed up"))
            }
        }
    }
}
