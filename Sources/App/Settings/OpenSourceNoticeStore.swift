import Foundation

struct OpenSourceNoticeStore {
    struct Sections: Equatable {
        let appNotices: [OpenSourceNotice]
        let coreDependencyNotices: [OpenSourceNotice]
        let thirdPartyNotices: [OpenSourceNotice]

        var isEmpty: Bool {
            appNotices.isEmpty && coreDependencyNotices.isEmpty && thirdPartyNotices.isEmpty
        }
    }

    enum StoreError: LocalizedError, Equatable {
        case noticesFileMissing
        case noticesFileUnreadable
        case noticesDecodingFailed
        case licenseFileMissing(fileName: String)
        case licenseFileUnreadable(fileName: String)
        case licenseFileInvalidEncoding(fileName: String)

        var errorDescription: String? {
            switch self {
            case .noticesFileMissing:
                return String(localized: "license.error.manifestMissing", defaultValue: "Open source notice list is missing.")
            case .noticesFileUnreadable:
                return String(localized: "license.error.manifestUnreadable", defaultValue: "Open source notice list could not be read.")
            case .noticesDecodingFailed:
                return String(localized: "license.error.manifestDecoding", defaultValue: "Open source notice list is invalid.")
            case .licenseFileMissing(let fileName):
                return String.localizedStringWithFormat(
                    String(localized: "license.error.textMissing", defaultValue: "License text is missing for %@."),
                    fileName
                )
            case .licenseFileUnreadable(let fileName):
                return String.localizedStringWithFormat(
                    String(localized: "license.error.textUnreadable", defaultValue: "License text could not be read for %@."),
                    fileName
                )
            case .licenseFileInvalidEncoding(let fileName):
                return String.localizedStringWithFormat(
                    String(localized: "license.error.textEncoding", defaultValue: "License text is not valid UTF-8 for %@."),
                    fileName
                )
            }
        }
    }

    private static let manifestName = "open_source_notices"
    private static let manifestExtension = "json"
    private static let resourcesSubdirectory = "OpenSourceNotices"

    private let bundle: Bundle
    private let subdirectory: String

    init(bundle: Bundle = .main, subdirectory: String = resourcesSubdirectory) {
        self.bundle = bundle
        self.subdirectory = subdirectory
    }

    func loadNotices() throws -> [OpenSourceNotice] {
        guard let manifestURL = bundledResourceURL(
            forResource: Self.manifestName,
            withExtension: Self.manifestExtension
        ) else {
            throw StoreError.noticesFileMissing
        }

        let data: Data
        do {
            data = try Data(contentsOf: manifestURL)
        } catch {
            throw StoreError.noticesFileUnreadable
        }

        let notices: [OpenSourceNotice]
        do {
            notices = try JSONDecoder().decode([OpenSourceNotice].self, from: data)
        } catch {
            throw StoreError.noticesDecodingFailed
        }

        let resolvedNotices = notices.map(resolveAppVersion(for:))
        return resolvedNotices.sorted { noticeSort(lhs: $0, rhs: $1) }
    }

    func loadLicenseText(for notice: OpenSourceNotice) throws -> String {
        let resourceName = (notice.licenseFileResourceName as NSString).deletingPathExtension
        let resourceExtension = (notice.licenseFileResourceName as NSString).pathExtension

        guard let licenseURL = bundledResourceURL(
            forResource: resourceName,
            withExtension: resourceExtension.isEmpty ? nil : resourceExtension
        ) else {
            throw StoreError.licenseFileMissing(fileName: notice.licenseFileResourceName)
        }

        let data: Data
        do {
            data = try Data(contentsOf: licenseURL)
        } catch {
            throw StoreError.licenseFileUnreadable(fileName: notice.licenseFileResourceName)
        }

        guard let licenseText = String(data: data, encoding: .utf8) else {
            throw StoreError.licenseFileInvalidEncoding(fileName: notice.licenseFileResourceName)
        }

        return licenseText
    }

    func sections(for notices: [OpenSourceNotice], searchText: String) -> Sections {
        let filtered = filter(notices: notices, searchText: searchText)
        return Sections(
            appNotices: filtered.filter { $0.kind == .app },
            coreDependencyNotices: filtered.filter { $0.kind == .thirdParty && $0.isDirectDependency }.sorted {
                $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
            },
            thirdPartyNotices: filtered.filter { $0.kind == .thirdParty && !$0.isDirectDependency }.sorted {
                $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
            }
        )
    }

    private func filter(notices: [OpenSourceNotice], searchText: String) -> [OpenSourceNotice] {
        let trimmed = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return notices
        }

        return notices.filter { notice in
            notice.searchTokens.contains { token in
                token.localizedCaseInsensitiveContains(trimmed)
            }
        }
    }

    private func bundledResourceURL(forResource name: String, withExtension ext: String?) -> URL? {
        if let nestedURL = bundle.url(forResource: name, withExtension: ext, subdirectory: subdirectory) {
            return nestedURL
        }

        return bundle.url(forResource: name, withExtension: ext)
    }

    private func noticeSort(lhs: OpenSourceNotice, rhs: OpenSourceNotice) -> Bool {
        if lhs.kind != rhs.kind {
            return lhs.kind == .app
        }
        return lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName) == .orderedAscending
    }

    private func resolveAppVersion(for notice: OpenSourceNotice) -> OpenSourceNotice {
        guard notice.kind == .app else {
            return notice
        }

        let version = bundle.infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
        let build = bundle.infoDictionary?["CFBundleVersion"] as? String ?? ""

        if !version.isEmpty && !build.isEmpty {
            return notice.replacingVersion("\(version) (\(build))")
        }
        if !version.isEmpty {
            return notice.replacingVersion(version)
        }
        if !build.isEmpty {
            return notice.replacingVersion(build)
        }
        return notice
    }
}
