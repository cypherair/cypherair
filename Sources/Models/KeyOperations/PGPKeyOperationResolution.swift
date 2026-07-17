import Foundation

/// Operation support result annotated with an optional stable failure category.
struct PGPKeyOperationResolution: Codable, Equatable, Hashable, Sendable {
    let support: PGPKeyOperationSupport
    let failureCategory: PGPKeyOperationFailureCategory?

    private enum CodingKeys: String, CodingKey {
        case support
        case failureCategory
    }

    private init(
        support: PGPKeyOperationSupport,
        failureCategory: PGPKeyOperationFailureCategory?
    ) {
        self.support = support
        self.failureCategory = failureCategory
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let support = try container.decode(PGPKeyOperationSupport.self, forKey: .support)
        let failureCategory = try container.decodeIfPresent(
            PGPKeyOperationFailureCategory.self,
            forKey: .failureCategory
        )

        switch support {
        case .supported:
            guard failureCategory == nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: .failureCategory,
                    in: container,
                    debugDescription: "Supported key operation resolutions must not carry a failure category."
                )
            }
        case .unsupported,
             .notImplemented,
             .unavailable:
            guard failureCategory != nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: .failureCategory,
                    in: container,
                    debugDescription: "Failed key operation resolutions require a failure category."
                )
            }
        }

        self.support = support
        self.failureCategory = failureCategory
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(support, forKey: .support)

        switch support {
        case .supported:
            guard failureCategory == nil else {
                throw EncodingError.invalidValue(
                    failureCategory as Any,
                    EncodingError.Context(
                        codingPath: container.codingPath + [CodingKeys.failureCategory],
                        debugDescription: "Supported key operation resolutions must not carry a failure category."
                    )
                )
            }
        case .unsupported,
             .notImplemented,
             .unavailable:
            guard let failureCategory else {
                throw EncodingError.invalidValue(
                    self,
                    EncodingError.Context(
                        codingPath: container.codingPath,
                        debugDescription: "Failed key operation resolutions require a failure category."
                    )
                )
            }
            try container.encode(failureCategory, forKey: .failureCategory)
        }
    }

    static let supported = PGPKeyOperationResolution(
        support: .supported,
        failureCategory: nil
    )

    static func unsupported(_ category: PGPKeyOperationFailureCategory) -> PGPKeyOperationResolution {
        PGPKeyOperationResolution(support: .unsupported, failureCategory: category)
    }

    static func notImplemented(_ category: PGPKeyOperationFailureCategory) -> PGPKeyOperationResolution {
        PGPKeyOperationResolution(support: .notImplemented, failureCategory: category)
    }

    static func unavailable(_ category: PGPKeyOperationFailureCategory) -> PGPKeyOperationResolution {
        PGPKeyOperationResolution(support: .unavailable, failureCategory: category)
    }
}
