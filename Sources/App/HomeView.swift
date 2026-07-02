import SwiftUI

/// Home screen with quick-access actions for core operations.
struct HomeView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.appRouteNavigator) private var routeNavigator
    var body: some View {
        content
        .navigationTitle(AppProductIdentity.localizedDisplayName)
    }

    @ViewBuilder
    private var content: some View {
        switch keyManagement.metadataLoadState {
        case .locked:
            metadataStateContent(
                title: String(localized: "home.keysLocked.title", defaultValue: "Keys Locked"),
                subtitle: String(localized: "home.keysLocked.subtitle", defaultValue: "Unlock CypherAir X to show your key list."),
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
            VStack(spacing: CypherSpacing.section) {
                defaultKeyInfo

                quickActionsGrid
            }
            .padding()
            .cypherMacReadableContent()
        }
    }

    private var defaultKeyInfo: some View {
        Group {
            if let defaultKey = keyManagement.defaultKey {
                NavigationLink(value: AppRoute.keyDetail(fingerprint: defaultKey.fingerprint)) {
                    HStack(spacing: CypherSpacing.tight) {
                        VStack(alignment: .leading, spacing: CypherSpacing.compact) {
                            HStack {
                                Image(systemName: "key.fill")
                                    .symbolRenderingMode(.hierarchical)
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
                                Text(defaultKey.openPGPConfigurationIdentity.familyDisplayName)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }

                            FingerprintView(
                                fingerprint: defaultKey.fingerprint,
                                font: .caption.monospaced(),
                                foregroundColor: .secondary,
                                expandsHorizontally: false
                            )

                            if defaultKey.privateKeyCustodyKind == .appleSecureEnclavePrivateOperations {
                                KeyCustodyBadge(style: .badge)
                            } else {
                                KeyBackupStatusBadge(isBackedUp: defaultKey.isBackedUp, style: .badge)
                            }
                        }

                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.tertiary)
                            .accessibilityHidden(true)
                    }
                    .padding()
                    .cypherSurface(.card)
                }
                .buttonStyle(.plain)
                #if os(iOS) || os(visionOS)
                // Plain-style links lose the automatic hover/gaze highlight.
                .hoverEffect(.automatic)
                #endif
                .cypherPressFeedback()
                .accessibilityElement(children: .combine)
                .accessibilityHint(Text(String(localized: "home.defaultKey.hint", defaultValue: "Opens key details")))
                .accessibilityIdentifier("home.defaultKey")
            }
        }
    }

    private var quickActionsGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: CypherSpacing.standard) {
            actionButton(
                title: String(localized: "home.encrypt", defaultValue: "Encrypt"),
                icon: "lock.fill",
                route: .encrypt,
                anchor: .homeEncryptAction
            )
            actionButton(
                title: String(localized: "home.decrypt", defaultValue: "Decrypt"),
                icon: "lock.open.fill",
                route: .decrypt,
                anchor: .homeDecryptAction
            )
            actionButton(
                title: String(localized: "home.sign", defaultValue: "Sign"),
                icon: "signature",
                route: .sign
            )
            actionButton(
                title: String(localized: "home.verify", defaultValue: "Verify"),
                icon: "checkmark.seal",
                route: .verify
            )
        }
    }

    private func actionButton(
        title: String,
        icon: String,
        route: AppRoute,
        anchor: TutorialAnchorID? = nil
    ) -> some View {
        NavigationLink(value: route) {
            VStack(spacing: CypherSpacing.compact) {
                Image(systemName: icon)
                    .font(.title2)
                    .symbolRenderingMode(.hierarchical)
                    .accessibilityHidden(true)
                Text(title)
                    .font(.subheadline.weight(.medium))
            }
            .frame(maxWidth: .infinity, minHeight: 80)
        }
        // .buttonStyle(.glass) is @available(visionOS, unavailable) in the
        // visionOS 26.5 SDK; visionOS gets its native prominent chrome.
        #if os(visionOS)
        .buttonStyle(.borderedProminent)
        #else
        .buttonStyle(.glass)
        #endif
        .accessibilityLabel(title)
        .tutorialAnchor(anchor)
        .cypherPressFeedback()
    }
}
