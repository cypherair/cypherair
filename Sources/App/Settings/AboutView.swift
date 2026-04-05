import SwiftUI

/// About page with app-level metadata only.
struct AboutView: View {
    @Environment(\.tutorialInlineHeaderContext) private var tutorialInlineHeaderContext

    var body: some View {
        List {
            if let tutorialInlineHeaderContext {
                Section {
                    TutorialInlineHeaderView(context: tutorialInlineHeaderContext)
                }
            }

            Section {
                LabeledContent(
                    String(localized: "about.app", defaultValue: "App"),
                    value: "CypherAir"
                )
                LabeledContent(
                    String(localized: "about.version", defaultValue: "Version"),
                    value: appVersion
                )
                LabeledContent(
                    String(localized: "about.license", defaultValue: "License"),
                    value: "GPLv3"
                )
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
