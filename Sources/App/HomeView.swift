import SwiftUI

/// Home screen with quick-access actions for core operations.
struct HomeView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @State private var path = NavigationPath()

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(spacing: 20) {
                    // Status header
                    if keyManagement.keys.isEmpty {
                        noKeysPrompt
                    } else {
                        defaultKeyInfo
                    }

                    // Quick actions
                    quickActionsGrid
                }
                .padding()
            }
            .navigationTitle(String(localized: "home.title", defaultValue: "CypherAir"))
            .navigationDestination(for: AppRoute.self) { route in
                destinationView(for: route)
            }
        }
    }

    // MARK: - Subviews

    private var noKeysPrompt: some View {
        VStack(spacing: 12) {
            Image(systemName: "key.slash")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)

            Text(String(localized: "home.noKeys.title", defaultValue: "No Keys Yet"))
                .font(.headline)

            Text(String(localized: "home.noKeys.subtitle", defaultValue: "Generate a key to start encrypting and signing messages."))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Button {
                path.append(AppRoute.keyGeneration)
            } label: {
                Label(
                    String(localized: "home.generateKey", defaultValue: "Generate My Key"),
                    systemImage: "plus.circle.fill"
                )
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(.vertical, 32)
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
                tint: .blue,
                route: .encrypt
            )
            actionButton(
                title: String(localized: "home.decrypt", defaultValue: "Decrypt"),
                icon: "lock.open.fill",
                tint: .green,
                route: .decrypt
            )
            actionButton(
                title: String(localized: "home.sign", defaultValue: "Sign"),
                icon: "signature",
                tint: .orange,
                route: .sign
            )
            actionButton(
                title: String(localized: "home.verify", defaultValue: "Verify"),
                icon: "checkmark.seal",
                tint: .purple,
                route: .verify
            )
        }
    }

    private func actionButton(title: String, icon: String, tint: Color, route: AppRoute) -> some View {
        Button {
            path.append(route)
        } label: {
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
    }

    // MARK: - Navigation Destinations

    @ViewBuilder
    private func destinationView(for route: AppRoute) -> some View {
        switch route {
        case .keyGeneration:
            KeyGenerationView()
        case .keyDetail(let fp):
            KeyDetailView(fingerprint: fp)
        case .backupKey(let fp):
            BackupKeyView(fingerprint: fp)
        case .importKey:
            ImportKeyView()
        case .encrypt:
            EncryptView()
        case .decrypt:
            DecryptView()

        case .sign:
            SignView()
        case .verify:
            VerifyView()
        case .contactDetail(let fp):
            ContactDetailView(fingerprint: fp)
        case .addContact:
            AddContactView()
        case .qrDisplay(let data, let name):
            QRDisplayView(publicKeyData: data, displayName: name)
        case .qrPhotoImport:
            QRPhotoImportView()
        case .selfTest:
            SelfTestView()
        case .about:
            AboutView()
        case .appIcon:
            #if canImport(UIKit)
            AppIconPickerView()
            #else
            Text(String(localized: "common.comingSoon", defaultValue: "Coming soon"))
            #endif
        }
    }
}
