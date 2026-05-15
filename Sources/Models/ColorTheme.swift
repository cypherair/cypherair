import Foundation

/// Color theme presets for app-wide accent customization.
enum ColorTheme: String, CaseIterable, Identifiable, Codable {
    case systemDefault

    case defaultBlue
    case indigo
    case purple
    case teal
    case mint
    case pink
    case orange
    case red
    case graphite

    case prideRainbow
    case transPride
    case bisexualPride
    case nonBinary

    var id: String { rawValue }
}
