import SwiftUI
#if canImport(AppKit)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif

struct SourceComplianceView: View {
    private let store: SourceComplianceStore

    @State private var info: SourceComplianceInfo?
    @State private var loadError: String?
    @State private var didCopy = false

    init(store: SourceComplianceStore = SourceComplianceStore()) {
        self.store = store
    }

    var body: some View {
        List {
            if let info {
                buildSection(info)
                dependencySection(info)
                releaseSection(info)
            } else if let loadError {
                Text(loadError)
                    .foregroundStyle(.secondary)
            } else {
                ProgressView()
                    .frame(maxWidth: .infinity, alignment: .center)
            }
        }
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .cypherMacReadableContent()
        .accessibilityIdentifier("sourcecompliance.root")
        .screenReady("sourcecompliance.ready")
        .navigationTitle(
            String(
                localized: "sourceCompliance.title",
                defaultValue: "Source & Compliance"
            )
        )
        .task {
            guard info == nil, loadError == nil else { return }
            loadInfo()
        }
    }

    @ViewBuilder
    private func buildSection(_ info: SourceComplianceInfo) -> some View {
        Section {
            LabeledContent(
                String(
                    localized: "sourceCompliance.version",
                    defaultValue: "Version"
                ),
                value: info.versionDisplay
            )
            LabeledContent(
                String(
                    localized: "sourceCompliance.commit",
                    defaultValue: "Commit"
                ),
                value: info.commitSHA
            )
            LabeledContent(
                String(
                    localized: "sourceCompliance.license",
                    defaultValue: "First-Party License"
                ),
                value: info.firstPartyLicense
            )
            LabeledContent(
                String(
                    localized: "sourceCompliance.fulfillmentBasis",
                    defaultValue: "Fulfillment Basis"
                ),
                value: info.fulfillmentBasis
            )
        } header: {
            Text(
                String(
                    localized: "sourceCompliance.section.build",
                    defaultValue: "Build"
                )
            )
        }
    }

    @ViewBuilder
    private func dependencySection(_ info: SourceComplianceInfo) -> some View {
        Section(
            String(
                localized: "sourceCompliance.section.dependencies",
                defaultValue: "Key Dependencies"
            )
        ) {
            ForEach(info.dependencies) { dependency in
                LabeledContent(dependency.name, value: dependency.version)
            }
        }
    }

    @ViewBuilder
    private func releaseSection(_ info: SourceComplianceInfo) -> some View {
        Section(
            String(
                localized: "sourceCompliance.section.release",
                defaultValue: "Stable Release"
            )
        ) {
            LabeledContent(
                String(
                    localized: "sourceCompliance.releaseTag",
                    defaultValue: "Release Tag"
                ),
                value: info.stableReleaseTag.isEmpty
                    ? String(
                        localized: "sourceCompliance.unavailable",
                        defaultValue: "Unavailable"
                    )
                    : info.stableReleaseTag
            )

            VStack(alignment: .leading, spacing: 8) {
                Text(
                    String(
                        localized: "sourceCompliance.releaseURL",
                        defaultValue: "Release URL"
                    )
                )
                .font(.subheadline)
                .foregroundStyle(.secondary)

                Text(verbatim: releaseURLText(info))
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .accessibilityIdentifier("sourcecompliance.url")

                Button {
                    didCopy = copyIfPresent(info.stableReleaseURL)
                } label: {
                    Label(
                        didCopy
                            ? String(
                                localized: "sourceCompliance.copied",
                                defaultValue: "Copied"
                            )
                            : String(
                                localized: "sourceCompliance.copy",
                                defaultValue: "Copy Release URL"
                            ),
                        systemImage: didCopy ? "checkmark" : "doc.on.doc"
                    )
                }
                .buttonStyle(.borderless)
                .disabled(info.stableReleaseURL.isEmpty)
                .accessibilityIdentifier("sourcecompliance.copy")
            }
            .padding(.vertical, 4)
        }
    }

    private func releaseURLText(_ info: SourceComplianceInfo) -> String {
        if info.stableReleaseURL.isEmpty {
            return String(
                localized: "sourceCompliance.localBuild",
                defaultValue: "Unavailable for local or internal builds"
            )
        }
        return info.stableReleaseURL
    }

    private func loadInfo() {
        do {
            info = try store.loadInfo()
        } catch {
            loadError = error.localizedDescription
        }
    }

    @discardableResult
    private func copyIfPresent(_ releaseURL: String) -> Bool {
        guard !releaseURL.isEmpty else {
            return false
        }

        #if canImport(AppKit)
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(releaseURL, forType: .string)
        #elseif canImport(UIKit)
        UIPasteboard.general.string = releaseURL
        #endif

        return true
    }
}
