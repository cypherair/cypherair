import Foundation

struct SourceComplianceInfo: Decodable, Equatable {
    let marketingVersion: String
    let buildNumber: String
    let commitSHA: String
    let stableReleaseTag: String
    let stableReleaseURL: String
    let dependencies: [SourceComplianceDependency]
    let firstPartyLicense: String
    let fulfillmentBasis: String
    let isStableReleaseBuild: Bool

    var versionDisplay: String {
        "\(marketingVersion) (\(buildNumber))"
    }
}
