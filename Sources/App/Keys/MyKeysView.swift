import SwiftUI

/// Lists the user's own PGP key identities.
struct MyKeysView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.appRouteNavigator) private var routeNavigator
    var body: some View {
        content
            .navigationTitle(String(localized: "keys.title", defaultValue: "My Keys"))
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    actionsMenu
                        .disabled(keyManagement.metadataLoadState != .loaded)
                }
            }
    }

    @ViewBuilder
    private var content: some View {
        switch keyManagement.metadataLoadState {
        case .locked:
            metadataStateContent(
                title: String(localized: "keys.locked.title", defaultValue: "Keys Locked"),
                subtitle: String(localized: "keys.locked.description", defaultValue: "Unlock CypherAir to show your keys."),
                systemImage: "lock"
            )
        case .loading:
            metadataStateContent(
                title: String(localized: "keys.loading.title", defaultValue: "Loading Keys"),
                subtitle: String(localized: "keys.loading.description", defaultValue: "Your protected key metadata is opening."),
                systemImage: "key"
            )
        case .recoveryNeeded:
            metadataStateContent(
                title: String(localized: "keys.recovery.title", defaultValue: "Key Metadata Needs Recovery"),
                subtitle: String(localized: "keys.recovery.description", defaultValue: "Protected key metadata could not be opened. Use protected data recovery or reset local data."),
                systemImage: "exclamationmark.triangle"
            )
        case .loaded:
            if keyManagement.keys.isEmpty {
                emptyStateContent
            } else {
                keyList
            }
        }
    }

    private var keyList: some View {
        List {
            ForEach(keyManagement.keys) { key in
                NavigationLink(value: AppRoute.keyDetail(fingerprint: key.fingerprint)) {
                    KeyRowView(key: key)
                }
                .tutorialAnchor(.keyRow(fingerprint: key.fingerprint))
            }
        }
    }

    private var actionsMenu: some View {
        Menu {
            Button {
                routeNavigator.open(.keyGeneration)
            } label: {
                Label(
                    String(localized: "keys.action.generate", defaultValue: "Generate Key"),
                    systemImage: "plus"
                )
            }
            .tutorialAnchor(.keysGenerateButton)

            Button {
                routeNavigator.open(.importKey)
            } label: {
                Label(
                    String(localized: "keys.action.import", defaultValue: "Import Key"),
                    systemImage: "square.and.arrow.down"
                )
            }
        } label: {
            Image(systemName: "plus")
        }
        .accessibilityLabel(String(localized: "keys.actions.menu", defaultValue: "Key Actions"))
        .accessibilityHint(String(localized: "keys.actions.menu.hint", defaultValue: "Open actions to generate or import a key."))
    }

    private func metadataStateContent(
        title: String,
        subtitle: String,
        systemImage: String
    ) -> some View {
        ContentUnavailableView {
            Label(title, systemImage: systemImage)
        } description: {
            Text(subtitle)
        }
    }

    private var emptyStateContent: some View {
        ContentUnavailableView {
            Label(
                String(localized: "keys.empty.title", defaultValue: "No Keys"),
                systemImage: "key.slash"
            )
        } description: {
            Text(String(localized: "keys.empty.description", defaultValue: "Generate or import a key to get started."))
        } actions: {
            Button {
                routeNavigator.open(.keyGeneration)
            } label: {
                Text(String(localized: "keys.generate", defaultValue: "Generate Key"))
            }
            .buttonStyle(.borderedProminent)
            .tutorialAnchor(.keysGenerateButton)
            .accessibilityIdentifier("keys.generate")
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
