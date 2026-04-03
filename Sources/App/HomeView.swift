import SwiftUI

/// Home screen with quick-access actions for core operations.
struct HomeView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config
    @Environment(\.appRouteNavigator) private var routeNavigator

    var body: some View {
        Group {
            if keyManagement.keys.isEmpty {
                noKeysContent
            } else {
                hasKeysContent
            }
        }
        .navigationTitle(String(localized: "home.title", defaultValue: "CypherAir"))
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
        }
    }

    private var hasKeysContent: some View {
        ScrollView {
            VStack(spacing: 20) {
                defaultKeyInfo

                #if canImport(UIKit)
                quickActionsGrid
                #else
                Text(String(localized: "home.macOS.hint", defaultValue: "Use the sidebar to encrypt, decrypt, sign, or verify messages."))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                #endif
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

                    Text(defaultKey.formattedFingerprint)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .accessibilityLabel(
                            IdentityPresentation.fingerprintAccessibilityLabel(defaultKey.fingerprint)
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
                tint: config.colorTheme.actionColors.encrypt,
                route: .encrypt,
                anchor: .homeEncryptAction
            )
            actionButton(
                title: String(localized: "home.decrypt", defaultValue: "Decrypt"),
                icon: "lock.open.fill",
                tint: config.colorTheme.actionColors.decrypt,
                route: .decrypt,
                anchor: .homeDecryptAction
            )
            actionButton(
                title: String(localized: "home.sign", defaultValue: "Sign"),
                icon: "signature",
                tint: config.colorTheme.actionColors.sign,
                route: .sign
            )
            actionButton(
                title: String(localized: "home.verify", defaultValue: "Verify"),
                icon: "checkmark.seal",
                tint: config.colorTheme.actionColors.verify,
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
        .buttonStyle(.glass)
        .tint(tint)
        .accessibilityLabel(title)
        .tutorialAnchor(anchor)
    }
}
