import SwiftUI

/// Home: the default key, or the way to make one, beside the four tools.
/// The tools show whether or not a key exists: encrypting to a contact and
/// verifying a signature need no key of one's own, and Decrypt and Sign say
/// so themselves when there is none.
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
                title: String(localized: "home.keysRecovery.title", defaultValue: "Key Metadata Is Damaged"),
                subtitle: String(localized: "home.keysRecovery.subtitle", defaultValue: "Protected key metadata could not be opened. Reset All Local Data is the only remedy."),
                systemImage: "exclamationmark.triangle"
            )
        case .loaded:
            loadedContent
        }
    }

    private func metadataStateContent(
        title: String,
        subtitle: String,
        systemImage: String
    ) -> some View {
        CypherFoldClearContent {
            ContentUnavailableView {
                Label(title, systemImage: systemImage)
            } description: {
                Text(subtitle)
            }
        }
    }

    private var loadedContent: some View {
        CypherSplitArrangement { isSplit in
            ScrollView {
                VStack(spacing: CypherSpacing.section) {
                    keyCard

                    if !isSplit {
                        toolGrid
                    }
                }
                .padding()
                .cypherMacReadableContent()
            }
            .scrollBounceBehavior(.basedOnSize)
        } secondary: {
            ScrollView {
                toolGrid
                    .padding()
            }
            .scrollBounceBehavior(.basedOnSize)
        }
    }

    @ViewBuilder
    private var keyCard: some View {
        if let defaultKey = keyManagement.defaultKey {
            defaultKeyCard(defaultKey)
        } else {
            noKeyCard
        }
    }

    private func defaultKeyCard(_ defaultKey: PGPKeyIdentity) -> some View {
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
                        Text(defaultKey.keyFamily.familyDisplayName)
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

    private var noKeyCard: some View {
        VStack(spacing: CypherSpacing.tight) {
            Label(
                String(localized: "home.noKeys.title", defaultValue: "No Keys Yet"),
                systemImage: "key.slash"
            )
            .font(.headline)

            Text(String(
                localized: "home.noKeys.subtitle",
                defaultValue: "Generate a key of your own to decrypt messages sent to you and sign the ones you send."
            ))
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)

            Button {
                routeNavigator.open(.keyGeneration)
            } label: {
                Text(String(localized: "home.generateKey", defaultValue: "Generate My Key"))
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("home.generate")
        }
        .padding()
        .frame(maxWidth: .infinity)
        .cypherSurface(.card)
    }

    private var toolGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: CypherSpacing.standard) {
            ForEach(AppTool.allCases, id: \.self) { tool in
                toolButton(tool)
            }
        }
    }

    private func toolButton(_ tool: AppTool) -> some View {
        NavigationLink(value: tool.route) {
            VStack(spacing: CypherSpacing.compact) {
                Image(systemName: tool.systemImage)
                    .font(.title2)
                    .symbolRenderingMode(.hierarchical)
                    .accessibilityHidden(true)
                Text(tool.title)
                    .font(.subheadline.weight(.medium))
            }
            .frame(maxWidth: .infinity, minHeight: 80)
        }
        // .glass is unavailable on visionOS, which gets its native prominent chrome.
        #if os(visionOS)
        .buttonStyle(.borderedProminent)
        #else
        .buttonStyle(.glass)
        #endif
        .accessibilityLabel(tool.title)
        .tutorialAnchor(tutorialAnchor(for: tool))
        .cypherPressFeedback()
    }

    private func tutorialAnchor(for tool: AppTool) -> TutorialAnchorID? {
        switch tool {
        case .encrypt:
            .homeEncryptAction
        case .decrypt:
            .homeDecryptAction
        case .sign, .verify:
            nil
        }
    }
}
