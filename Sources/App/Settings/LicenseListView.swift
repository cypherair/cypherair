import SwiftUI

struct LicenseListView: View {
    private let store: OpenSourceNoticeStore

    @State private var notices: [OpenSourceNotice] = []
    @State private var hasLoaded = false
    @State private var loadError: String?
    @State private var searchText = ""

    init(store: OpenSourceNoticeStore = OpenSourceNoticeStore()) {
        self.store = store
    }

    var body: some View {
        Group {
            if let loadError {
                ContentUnavailableView {
                    Label(
                        String(localized: "license.title", defaultValue: "Licenses"),
                        systemImage: "doc.text.magnifyingglass"
                    )
                } description: {
                    Text(loadError)
                }
            } else if !hasLoaded {
                ProgressView()
            } else if sections.isEmpty {
                ContentUnavailableView {
                    Label(
                        String(localized: "license.empty.title", defaultValue: "No Matching Components"),
                        systemImage: "doc.text.magnifyingglass"
                    )
                } description: {
                    Text(String(localized: "license.empty.message", defaultValue: "Try a different search term."))
                }
            } else {
                List {
                    if !sections.appNotices.isEmpty {
                        Section(String(localized: "license.section.app", defaultValue: "CypherAir")) {
                            noticeRows(for: sections.appNotices)
                        }
                    }

                    if !sections.coreDependencyNotices.isEmpty {
                        Section(String(localized: "license.section.core", defaultValue: "Core Dependencies")) {
                            noticeRows(for: sections.coreDependencyNotices)
                        }
                    }

                    if !sections.thirdPartyNotices.isEmpty {
                        Section(String(localized: "license.section.thirdParty", defaultValue: "Third-Party Components")) {
                            noticeRows(for: sections.thirdPartyNotices)
                        }
                    }
                }
                .searchable(
                    text: $searchText,
                    prompt: Text(String(localized: "license.search", defaultValue: "Search components"))
                )
                #if os(macOS)
                .listStyle(.inset)
                #endif
            }
        }
        .navigationTitle(String(localized: "license.title", defaultValue: "Licenses"))
        .task {
            guard !hasLoaded, loadError == nil else { return }
            loadNotices()
        }
    }

    private var sections: OpenSourceNoticeStore.Sections {
        store.sections(for: notices, searchText: searchText)
    }

    @ViewBuilder
    private func noticeRows(for notices: [OpenSourceNotice]) -> some View {
        ForEach(notices) { notice in
            NavigationLink {
                LicenseDetailView(notice: notice, store: store)
            } label: {
                VStack(alignment: .leading, spacing: 4) {
                    Text(notice.displayName)
                    Text("\(notice.version) • \(notice.licenseName)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func loadNotices() {
        do {
            notices = try store.loadNotices()
            hasLoaded = true
        } catch {
            loadError = error.localizedDescription
            hasLoaded = true
        }
    }
}
