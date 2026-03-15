import SwiftUI

/// About page with app info and licenses.
struct AboutView: View {
    var body: some View {
        List {
            Section {
                LabeledContent(
                    String(localized: "about.app", defaultValue: "App"),
                    value: "Cypher Air"
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

            Section(String(localized: "about.dependencies", defaultValue: "Dependencies")) {
                LabeledContent(
                    String(localized: "about.pgp", defaultValue: "Sequoia PGP"),
                    value: "2.2.0"
                )
                LabeledContent(
                    String(localized: "about.openssl", defaultValue: "OpenSSL"),
                    value: "3.5.5"
                )
                LabeledContent(
                    String(localized: "about.ffi", defaultValue: "UniFFI"),
                    value: "0.31.0"
                )
                LabeledContent(
                    String(localized: "about.zeroize", defaultValue: "zeroize"),
                    value: "1.8.2"
                )
                LabeledContent(
                    String(localized: "about.base64", defaultValue: "base64"),
                    value: "0.22.1"
                )
                LabeledContent(
                    String(localized: "about.thiserror", defaultValue: "thiserror"),
                    value: "2.0.18"
                )
            }

            Section {
                Text(String(localized: "about.description", defaultValue: "Fully offline OpenPGP encryption tool. Zero network access. Minimal permissions."))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle(String(localized: "about.title", defaultValue: "About"))
    }

    /// Version string from Info.plist (e.g. "1.0.0 (1)").
    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "—"
        return "\(version) (\(build))"
    }
}
