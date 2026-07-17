import Foundation

struct SourceComplianceStore {
    enum StoreError: LocalizedError, Equatable {
        case fileMissing
        case fileUnreadable
        case fileDecodingFailed

        var errorDescription: String? {
            switch self {
            case .fileMissing:
                return String(
                    localized: "sourceCompliance.error.fileMissing",
                    defaultValue: "Source compliance information is missing."
                )
            case .fileUnreadable:
                return String(
                    localized: "sourceCompliance.error.fileUnreadable",
                    defaultValue: "Source compliance information could not be read."
                )
            case .fileDecodingFailed:
                return String(
                    localized: "sourceCompliance.error.fileDecoding",
                    defaultValue: "Source compliance information is invalid."
                )
            }
        }
    }

    private let bundle: Bundle
    private let resourceName: String
    private let resourceExtension: String
    private let subdirectory: String?

    init(
        bundle: Bundle = .main,
        resourceName: String = "SourceComplianceInfo",
        resourceExtension: String = "json",
        subdirectory: String? = nil
    ) {
        self.bundle = bundle
        self.resourceName = resourceName
        self.resourceExtension = resourceExtension
        self.subdirectory = subdirectory
    }

    func loadInfo() throws -> SourceComplianceInfo {
        guard let url = bundle.url(
            forResource: resourceName,
            withExtension: resourceExtension,
            subdirectory: subdirectory
        ) else {
            throw StoreError.fileMissing
        }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw StoreError.fileUnreadable
        }

        do {
            return try JSONDecoder().decode(SourceComplianceInfo.self, from: data)
        } catch {
            throw StoreError.fileDecodingFailed
        }
    }
}
