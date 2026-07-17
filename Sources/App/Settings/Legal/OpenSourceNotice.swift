import Foundation

struct OpenSourceNotice: Decodable, Equatable, Identifiable {
    enum Kind: String, Decodable {
        case app
        case thirdParty
    }

    enum LicenseSourceKind: String, Decodable {
        case projectFile
        case cratePackage
        case repositoryArchive
        case spdxFallback
    }

    let id: String
    let displayName: String
    let version: String
    let repositoryURL: String
    let licenseName: String
    let licenseFileResourceName: String
    let kind: Kind
    let isDirectDependency: Bool
    let licenseSourceKind: LicenseSourceKind
    let licenseSourceItems: [String]

    var searchTokens: [String] {
        [
            displayName,
            version,
            repositoryURL,
            licenseName,
            licenseSourceItems.joined(separator: " "),
        ]
    }

    func replacingVersion(_ version: String) -> OpenSourceNotice {
        OpenSourceNotice(
            id: id,
            displayName: displayName,
            version: version,
            repositoryURL: repositoryURL,
            licenseName: licenseName,
            licenseFileResourceName: licenseFileResourceName,
            kind: kind,
            isDirectDependency: isDirectDependency,
            licenseSourceKind: licenseSourceKind,
            licenseSourceItems: licenseSourceItems
        )
    }
}
