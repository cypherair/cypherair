import SwiftUI

/// Lists the user's own PGP key identities.
struct MyKeysView: View {
    @Environment(KeyManagementService.self) private var keyManagement

    var body: some View {
        List {
            if keyManagement.keys.isEmpty {
                ContentUnavailableView {
                    Label(
                        String(localized: "keys.empty.title", defaultValue: "No Keys"),
                        systemImage: "key.slash"
                    )
                } description: {
                    Text(String(localized: "keys.empty.description", defaultValue: "Generate or import a key to get started."))
                } actions: {
                    NavigationLink(value: AppRoute.keyGeneration) {
                        Text(String(localized: "keys.generate", defaultValue: "Generate Key"))
                    }
                    .buttonStyle(.borderedProminent)
                }
            } else {
                ForEach(keyManagement.keys) { key in
                    NavigationLink(value: AppRoute.keyDetail(fingerprint: key.fingerprint)) {
                        KeyRowView(key: key)
                    }
                }
            }
        }
        .navigationTitle(String(localized: "keys.title", defaultValue: "My Keys"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
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
            default: Text("Coming soon")
            }
        }
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
