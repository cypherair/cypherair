import SwiftUI

/// Home screen with quick-access actions for core operations.
struct HomeView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @State private var path = NavigationPath()
    #if os(macOS)
    @State private var showKeyGeneration = false
    #endif

    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if keyManagement.keys.isEmpty {
                    noKeysContent
                } else {
                    hasKeysContent
                }
            }
            .navigationTitle(String(localized: "home.title", defaultValue: "CypherAir"))
            .navigationDestination(for: AppRoute.self) { route in
                destinationView(for: route)
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
            #endif
        }
    }

    // MARK: - Subviews

    private var noKeysContent: some View {
        ContentUnavailableView {
            Label(
                String(localized: "home.noKeys.title", defaultValue: "No Keys Yet"),
                systemImage: "key.slash"
            )
        } description: {
            Text(String(localized: "home.noKeys.subtitle", defaultValue: "Generate a key to start encrypting and signing messages."))
        } actions: {
            #if os(macOS)
            Button(String(localized: "home.generateKey", defaultValue: "Generate Key")) {
                showKeyGeneration = true
            }
            .buttonStyle(.borderedProminent)
            #else
            NavigationLink(value: AppRoute.keyGeneration) {
                Text(String(localized: "home.generateKey", defaultValue: "Generate Key"))
            }
            .buttonStyle(.borderedProminent)
            #endif
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
                            defaultKey.formattedFingerprint
                                .split(separator: " ")
                                .map { $0.map(String.init).joined(separator: " ") }
                                .joined(separator: ", ")
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
