import Foundation
import XCTest

/// Loads pre-generated fixture files from the test bundle.
/// Fixtures are copied from Tests/Fixtures/ via a Run Script build phase.
enum FixtureLoader {
    private final class BundleMarker {}
    static let bundle = Bundle(for: BundleMarker.self)

    /// Load a fixture file as raw Data.
    static func loadData(_ name: String, ext: String) throws -> Data {
        guard let url = bundle.url(forResource: name, withExtension: ext, subdirectory: "Fixtures") else {
            throw FixtureError.notFound("\(name).\(ext)")
        }
        return try Data(contentsOf: url)
    }

    /// Load a fixture file as a UTF-8 String.
    static func loadString(_ name: String, ext: String) throws -> String {
        let data = try loadData(name, ext: ext)
        guard let string = String(data: data, encoding: .utf8) else {
            throw FixtureError.invalidEncoding("\(name).\(ext)")
        }
        return string
    }

    enum FixtureError: Error, CustomStringConvertible {
        case notFound(String)
        case invalidEncoding(String)

        var description: String {
            switch self {
            case .notFound(let file): return "Fixture not found in test bundle: \(file)"
            case .invalidEncoding(let file): return "Fixture is not valid UTF-8: \(file)"
            }
        }
    }
}
