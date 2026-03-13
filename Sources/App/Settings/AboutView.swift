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
                    String(localized: "about.license", defaultValue: "License"),
                    value: "GPLv3"
                )
                LabeledContent(
                    String(localized: "about.pgp", defaultValue: "PGP Engine"),
                    value: "Sequoia 2.2.0"
                )
                LabeledContent(
                    String(localized: "about.ffi", defaultValue: "FFI"),
                    value: "UniFFI 0.29"
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
}
