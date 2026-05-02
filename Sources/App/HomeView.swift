import SwiftUI

/// Home screen with quick-access actions for core operations.
struct HomeView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(ProtectedOrdinarySettingsCoordinator.self) private var protectedOrdinarySettings
    @Environment(\.appRouteNavigator) private var routeNavigator
    var body: some View {
        content
        .navigationTitle(String(localized: "home.title", defaultValue: "CypherAir"))
    }

    @ViewBuilder
    private var content: some View {
        switch keyManagement.metadataLoadState {
        case .locked:
            metadataStateContent(
                title: String(localized: "home.keysLocked.title", defaultValue: "Keys Locked"),
                subtitle: String(localized: "home.keysLocked.subtitle", defaultValue: "Unlock CypherAir to show your key list."),
                systemImage: "lock"
            )
        case .loading:
            metadataStateContent(
                title: String(localized: "home.keysLoading.title", defaultValue: "Loading Keys"),
                subtitle: String(localized: "home.keysLoading.subtitle", defaultValue: "Your protected key metadata is opening."),
                systemImage: "key"
            )
        case .recoveryNeeded:
            metadataStateContent(
                title: String(localized: "home.keysRecovery.title", defaultValue: "Key Metadata Needs Recovery"),
                subtitle: String(localized: "home.keysRecovery.subtitle", defaultValue: "Protected key metadata could not be opened. Use protected data recovery or reset local data."),
                systemImage: "exclamationmark.triangle"
            )
        case .loaded:
            if keyManagement.keys.isEmpty {
                noKeysContent
            } else {
                hasKeysContent
            }
        }
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

    private var noKeysContent: some View {
        ContentUnavailableView {
            Label(
                String(localized: "home.noKeys.title", defaultValue: "No Keys Yet"),
                systemImage: "key.slash"
            )
        } description: {
            Text(String(localized: "home.noKeys.subtitle", defaultValue: "Generate a key to start encrypting and signing messages."))
        } actions: {
            Button {
                routeNavigator.open(.keyGeneration)
            } label: {
                Text(String(localized: "home.generateKey", defaultValue: "Generate Key"))
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("home.generate")
        }
    }

    private var hasKeysContent: some View {
        ScrollView {
            VStack(spacing: 20) {
                defaultKeyInfo

                quickActionsGrid
            }
            .padding()
        }
    }

    private var defaultKeyInfo: some View {
        Group {
            if let defaultKey = keyManagement.defaultKey {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "key.fill")
                            .foregroundStyle(.tint)
                            .accessibilityHidden(true)
                        if let userId = defaultKey.userId {
                            Text(userId)
                                .font(.headline)
                        } else {
                            Text(defaultKey.shortKeyId)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(defaultKey.profile.displayName)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    FingerprintView(
                        fingerprint: defaultKey.fingerprint,
                        font: .caption.monospaced(),
                        foregroundColor: .secondary,
                        expandsHorizontally: false
                    )
                }
                .padding()
                .background(.fill.tertiary, in: RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    private var quickActionsGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 16) {
            actionButton(
                title: String(localized: "home.encrypt", defaultValue: "Encrypt"),
                icon: "lock.fill",
                tint: protectedOrdinarySettings.colorTheme.actionColors.encrypt,
                route: .encrypt,
                anchor: .homeEncryptAction
            )
            actionButton(
                title: String(localized: "home.decrypt", defaultValue: "Decrypt"),
                icon: "lock.open.fill",
                tint: protectedOrdinarySettings.colorTheme.actionColors.decrypt,
                route: .decrypt,
                anchor: .homeDecryptAction
            )
            actionButton(
                title: String(localized: "home.sign", defaultValue: "Sign"),
                icon: "signature",
                tint: protectedOrdinarySettings.colorTheme.actionColors.sign,
                route: .sign
            )
            actionButton(
                title: String(localized: "home.verify", defaultValue: "Verify"),
                icon: "checkmark.seal",
                tint: protectedOrdinarySettings.colorTheme.actionColors.verify,
                route: .verify
            )
        }
    }

    private func actionButton(
        title: String,
        icon: String,
        tint: Color,
        route: AppRoute,
        anchor: TutorialAnchorID? = nil
    ) -> some View {
        NavigationLink(value: route) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                    .accessibilityHidden(true)
                Text(title)
                    .font(.subheadline.weight(.medium))
            }
            .frame(maxWidth: .infinity, minHeight: 80)
        }
        #if os(visionOS)
        .buttonStyle(.borderedProminent)
        #else
        .buttonStyle(.glass)
        #endif
        .tint(tint)
        .accessibilityLabel(title)
        .tutorialAnchor(anchor)
    }
}
