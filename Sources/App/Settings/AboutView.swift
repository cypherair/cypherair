import SwiftUI
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// About page: app identity, positioning, licensing, and source links.
struct AboutView: View {
    private let repositoryURLCopyAction = RepositoryURLCopyAction()

    @State private var didCopyRepositoryURL = false

    var body: some View {
        List {
            Section {
                appIdentityHeader
                    .frame(maxWidth: .infinity)
                    .listRowBackground(Color.clear)
            }

            Section {
                Text(String(
                    localized: "about.cypherAirX.description",
                    defaultValue: "CypherAir X is the enhanced edition of CypherAir — a fully offline OpenPGP encryption tool with zero network access and minimal permissions. Beyond CypherAir’s Portable Legacy and Portable Modern · High keys, it adds four more key families: Device-Bound Legacy, Device-Bound Modern, and Device-Bound Post-Quantum keys kept in this device’s Secure Enclave, plus Portable Post-Quantum keys that resist future quantum computers. CypherAir X remains fully open source on GitHub."
                ))
                .font(.subheadline)
                .foregroundStyle(.secondary)
            }

            Section {
                LabeledContent(
                    String(localized: "about.license", defaultValue: "License"),
                    value: "GPL-3.0-or-later OR MPL-2.0"
                )

                VStack(alignment: .leading, spacing: CypherSpacing.compact) {
                    Text(String(localized: "license.detail.repository", defaultValue: "Repository"))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    CypherScrollableTextLine(text: AppProductIdentity.repositoryURLString)

                    Button {
                        didCopyRepositoryURL = repositoryURLCopyAction.copyIfPresent(
                            AppProductIdentity.repositoryURLString
                        )
                    } label: {
                        Label(
                            didCopyRepositoryURL
                                ? String(localized: "license.detail.copied", defaultValue: "Copied")
                                : String(localized: "license.detail.copy", defaultValue: "Copy Repository URL"),
                            systemImage: didCopyRepositoryURL ? "checkmark" : "doc.on.doc"
                        )
                    }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("about.repository.copy")
                }
                .padding(.vertical, 4)

                NavigationLink(value: AppRoute.sourceCompliance) {
                    Label(
                        String(
                            localized: "about.sourceCompliance",
                            defaultValue: "Source & Compliance"
                        ),
                        systemImage: "doc.badge.gearshape"
                    )
                }
                .accessibilityIdentifier("about.sourceCompliance")
            }

            Section {
                Text(AppProductIdentity.localizedCopyright)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .listRowBackground(Color.clear)
            }
        }
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .cypherMacReadableContent()
        .accessibilityIdentifier("about.root")
        .screenReady("about.ready")
        .navigationTitle(String(localized: "about.title", defaultValue: "About"))
    }

    private var appIdentityHeader: some View {
        VStack(spacing: CypherSpacing.compact) {
            appIconImage
                .frame(width: 76, height: 76)
                .clipShape(RoundedRectangle(cornerRadius: 17, style: .continuous))
                .accessibilityHidden(true)

            Text(AppProductIdentity.localizedDisplayName)
                .font(.title2.bold())

            Text(String(
                localized: "about.version.caption",
                defaultValue: "Version \(appVersion) (\(appBuild))"
            ))
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
        .padding(.vertical, CypherSpacing.compact)
    }

    @ViewBuilder
    private var appIconImage: some View {
        // The picker preview PNGs double as the About thumbnail on UIKit
        // platforms; macOS reads the app icon AppKit already resolved.
        #if canImport(UIKit)
        if let icon = AppIconOption.current(from: UIApplication.shared.alternateIconName).previewImage {
            Image(uiImage: icon)
                .resizable()
                .aspectRatio(contentMode: .fill)
        } else {
            fallbackIcon
        }
        #elseif canImport(AppKit)
        if let icon = NSImage(named: NSImage.applicationIconName) {
            Image(nsImage: icon)
                .resizable()
                .aspectRatio(contentMode: .fit)
        } else {
            fallbackIcon
        }
        #endif
    }

    private var fallbackIcon: some View {
        RoundedRectangle(cornerRadius: 17, style: .continuous)
            .fill(.quaternary)
            .overlay {
                Image(systemName: "app")
                    .font(.title)
                    .foregroundStyle(.secondary)
            }
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
    }

    private var appBuild: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "—"
    }
}
