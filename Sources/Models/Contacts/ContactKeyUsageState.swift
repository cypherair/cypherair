import Foundation

enum ContactKeyUsageState: String, Codable, Equatable, Sendable {
    case preferred
    case additionalActive
    case historical
}
