import SwiftUI

struct LicenseDetailView: View {
    private let notice: OpenSourceNotice
    private let store: OpenSourceNoticeStore
    private let repositoryURLCopyAction: RepositoryURLCopyAction

    @State private var licenseText: String?
    @State private var loadError: String?
    @State private var didCopy = false

    init(
        notice: OpenSourceNotice,
        store: OpenSourceNoticeStore = OpenSourceNoticeStore(),
        repositoryURLCopyAction: RepositoryURLCopyAction = RepositoryURLCopyAction()
    ) {
        self.notice = notice
        self.store = store
        self.repositoryURLCopyAction = repositoryURLCopyAction
    }

    var body: some View {
        List {
            Section {
                LabeledContent(
                    String(localized: "license.detail.version", defaultValue: "Version"),
                    value: notice.version
                )
                LabeledContent(
                    String(localized: "license.detail.license", defaultValue: "License"),
                    value: notice.licenseName
                )
                LabeledContent(
                    String(localized: "license.detail.source", defaultValue: "License Source"),
                    value: sourceLabel
                )

                VStack(alignment: .leading, spacing: 8) {
                    Text(String(localized: "license.detail.repository", defaultValue: "Repository"))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    CypherScrollableTextLine(text: notice.repositoryURL)

                    Button {
                        didCopy = repositoryURLCopyAction.copyIfPresent(notice.repositoryURL)
                    } label: {
                        Label(
                            didCopy
                                ? String(localized: "license.detail.copied", defaultValue: "Copied")
                                : String(localized: "license.detail.copy", defaultValue: "Copy Repository URL"),
                            systemImage: didCopy ? "checkmark" : "doc.on.doc"
                        )
                    }
                    .buttonStyle(.borderless)
                }
                .padding(.vertical, 4)
            }

            if !notice.licenseSourceItems.isEmpty {
                Section(String(localized: "license.detail.sourceItems", defaultValue: "Source Details")) {
                    ForEach(notice.licenseSourceItems, id: \.self) { item in
                        CypherScrollableTextLine(text: item)
                    }
                }
            }

            Section(String(localized: "license.detail.text", defaultValue: "License Text")) {
                if let licenseText {
                    CypherOutputTextBlock(
                        text: licenseText,
                        font: .system(.callout, design: .monospaced),
                        minHeight: 220,
                        maxHeight: 520
                    )
                } else if let loadError {
                    Text(loadError)
                        .foregroundStyle(.secondary)
                } else {
                    ProgressView()
                        .frame(maxWidth: .infinity, alignment: .center)
                }
            }
        }
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .cypherMacReadableContent(maxWidth: MacPresentationWidth.textHeavy)
        .navigationTitle(notice.displayName)
        .task {
            guard licenseText == nil, loadError == nil else { return }
            loadLicenseText()
        }
    }

    private func loadLicenseText() {
        do {
            licenseText = try store.loadLicenseText(for: notice)
        } catch {
            loadError = error.localizedDescription
        }
    }

    private var sourceLabel: String {
        switch notice.licenseSourceKind {
        case .projectFile:
            return String(localized: "license.source.projectFile", defaultValue: "Project file")
        case .cratePackage:
            return String(localized: "license.source.cratePackage", defaultValue: "Crate package")
        case .repositoryArchive:
            return String(localized: "license.source.repositoryArchive", defaultValue: "Repository archive")
        case .spdxFallback:
            return String(localized: "license.source.spdxFallback", defaultValue: "SPDX fallback")
        }
    }
}
