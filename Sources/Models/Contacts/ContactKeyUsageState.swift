import Foundation

enum ContactKeyUsageState: String, Codable, Equatable, Hashable, Sendable {
    case preferred
    case additionalActive
    case historical
}
