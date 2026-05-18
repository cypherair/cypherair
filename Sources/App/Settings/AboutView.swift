import SwiftUI

/// About page with app metadata and product-line context.
struct AboutView: View {
    var body: some View {
        List {
            Section {
                LabeledContent(
                    String(localized: "about.app", defaultValue: "App"),
                    value: AppProductIdentity.displayName
                )
                LabeledContent(
                    String(localized: "about.version", defaultValue: "Version"),
                    value: appVersion
                )
                LabeledContent(
                    String(localized: "about.license", defaultValue: "License"),
                    value: "GPL-3.0-or-later OR MPL-2.0"
                )
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

            if AppProductIdentity.showsCypherAirXAboutCopy {
                Section(AppProductIdentity.displayName) {
                    Text(String(
                        localized: "about.cypherAirX.description",
                        defaultValue: "CypherAir X is CypherAir’s exploratory product line for new directions still under evaluation, such as new encryption options, visual design updates, and interaction improvements. These explorations do not change CypherAir’s fully offline, no-network privacy model."
                    ))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                }
            }

            Section {
                Text(String(localized: "about.description", defaultValue: "Fully offline OpenPGP encryption tool. Zero network access. Minimal permissions."))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
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

    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "—"
        return "\(version) (\(build))"
    }
}
