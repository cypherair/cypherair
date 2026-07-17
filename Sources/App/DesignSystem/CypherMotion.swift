import SwiftUI

enum CypherMotion {
    static let pressScale: CGFloat = 0.975

    static func spring(reduceMotion: Bool) -> Animation? {
        guard !reduceMotion else { return nil }
        return .spring(response: 0.32, dampingFraction: 0.88)
    }

    static func quickEaseOut(reduceMotion: Bool) -> Animation? {
        guard !reduceMotion else { return nil }
        return .easeOut(duration: 0.18)
    }
}
