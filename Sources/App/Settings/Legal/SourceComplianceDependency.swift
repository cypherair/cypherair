import Foundation

struct SourceComplianceDependency: Decodable, Equatable, Identifiable {
    let name: String
    let version: String

    var id: String { name }
}
