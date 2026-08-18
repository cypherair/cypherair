import Foundation

/// The name an exported file is offered to the user under.
///
/// Sanitising happens here and nowhere else: a value of this type is always one
/// path component the file system will accept — no directory parts, no control
/// characters, no leading dot, short enough to write. An artifact is named once,
/// where it is produced, and nothing downstream re-derives or re-checks the name.
struct ExportFilename: Equatable, Hashable, Sendable {
    /// The longest name APFS accepts, in UTF-8 bytes.
    private static let maximumByteLength = 255

    /// Stands in when a proposed name sanitises away to nothing.
    private static let fallbackBase = "export"

    let value: String

    /// A complete name: its final path extension, when it has one, survives as
    /// given and the rest is sanitised.
    init(_ proposedName: String) {
        let component = Self.pathComponent(of: proposedName)
        let pathExtension = (component as NSString).pathExtension
        let base = pathExtension.isEmpty
            ? component
            : (component as NSString).deletingPathExtension
        value = Self.compose(base: Self.sanitized(base), pathExtension: pathExtension)
    }

    /// The app's own extension appended to `base`, keeping every extension
    /// `base` already carries: `photo.jpg` encrypts to `photo.jpg.gpg`.
    init(base: String, pathExtension: String) {
        value = Self.compose(
            base: Self.sanitized(Self.pathComponent(of: base)),
            pathExtension: pathExtension
        )
    }

    private static func pathComponent(of proposedName: String) -> String {
        (proposedName as NSString).lastPathComponent
    }

    /// Control characters render as garbage or truncate the name a picker
    /// shows, and a leading dot hides the file the user just saved. Directory
    /// parts are already gone by the time this runs.
    private static func sanitized(_ base: String) -> String {
        let printableScalars = base.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0)
        }
        var sanitized = String(String.UnicodeScalarView(printableScalars))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        while sanitized.hasPrefix(".") {
            sanitized.removeFirst()
        }
        return sanitized.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func compose(base: String, pathExtension: String) -> String {
        let suffix = pathExtension.isEmpty ? "" : "." + pathExtension
        var base = base.isEmpty ? fallbackBase : base
        while !base.isEmpty, base.utf8.count + suffix.utf8.count > maximumByteLength {
            base.removeLast()
        }
        // An extension long enough to leave no room at all is pathological;
        // a generic name still saves, an over-long one does not.
        return base.isEmpty ? fallbackBase : base + suffix
    }
}
