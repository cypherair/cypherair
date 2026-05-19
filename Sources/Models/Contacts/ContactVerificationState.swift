import Foundation

enum ContactVerificationState: String, Codable, Hashable, Sendable {
    case verified
    case unverified

    var isVerified: Bool {
        self == .verified
    }
}
