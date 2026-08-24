import Foundation

/// The name an exported file is offered to the user under.
///
/// Sanitising happens here and nowhere else: a value of this type is always one
/// path component the file system will accept — no directory parts, no control
/// or invisible characters in any position, no leading dot, short enough to
/// write. An artifact is named once, where it is produced, and nothing
/// downstream re-derives or re-checks the name.
struct ExportFilename: Equatable, Hashable, Sendable {
    /// The longest name APFS accepts, in UTF-8 bytes.
    private static let maximumByteLength = 255

    /// Stands in when a proposed name sanitises away to nothing.
    private static let fallbackBase = "export"

    let value: String

    /// A complete name, split at its final path extension so that both halves
    /// are sanitised and the extension keeps its meaning.
    init(_ proposedName: String) {
        let component = Self.pathComponent(of: proposedName)
        let pathExtension = (component as NSString).pathExtension
        let base = pathExtension.isEmpty
            ? component
            : (component as NSString).deletingPathExtension
        value = Self.compose(base: base, pathExtension: pathExtension)
    }

    /// The app's own extension appended to `base`, keeping every extension
    /// `base` already carries: `photo.jpg` encrypts to `photo.jpg.gpg`.
    init(base: String, pathExtension: String) {
        value = Self.compose(base: Self.pathComponent(of: base), pathExtension: pathExtension)
    }

    private static func pathComponent(of proposedName: String) -> String {
        (proposedName as NSString).lastPathComponent
    }

    /// Strip what a name must not carry in *any* position, extension included.
    ///
    /// Foundation's `controlCharacters` is Unicode categories Cc and Cf, which is
    /// what reaches the invisible ones: a soft hyphen or a zero-width space is
    /// what makes `invoice.pd<U+00AD>f` read as `invoice.pdf` while opening as
    /// neither, and a newline truncates the single-line field a picker shows.
    /// The ciphertext filename this can come from is chosen by whoever sent it.
    private static func printable(_ text: String) -> String {
        String(String.UnicodeScalarView(
            text.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }
        ))
    }

    /// The base additionally loses a leading dot, which would hide the file the
    /// user just saved, and surrounding whitespace, which no picker renders.
    ///
    /// Run to a fixed point rather than once each: the two hide behind each
    /// other, so `". .secret"` survives a single strip-then-trim as `.secret`.
    private static func sanitizedBase(_ base: String) -> String {
        var sanitized = printable(base)
        var previous: String
        repeat {
            previous = sanitized
            sanitized = sanitized.trimmingCharacters(in: .whitespacesAndNewlines)
            if sanitized.hasPrefix(".") {
                sanitized.removeFirst()
            }
        } while sanitized != previous
        return sanitized
    }

    private static func compose(base: String, pathExtension: String) -> String {
        let pathExtension = printable(pathExtension).trimmingCharacters(in: .whitespacesAndNewlines)
        let suffix = pathExtension.isEmpty ? "" : "." + pathExtension
        var base = sanitizedBase(base)
        if base.isEmpty {
            base = fallbackBase
        }

        let budget = maximumByteLength - suffix.utf8.count
        // An extension long enough to leave no room at all is pathological; a
        // generic name still saves, an over-long one does not.
        guard budget > 0 else { return fallbackBase }
        guard base.utf8.count > budget else { return base + suffix }

        // Over the limit, so something has to go. Trim the stem and never the
        // extensions: what a saved file opens as — and what decryption gives
        // back ([PRODUCT.md] §5) — lives at the end of the name.
        let innerExtension = (base as NSString).pathExtension
        let innerSuffix = innerExtension.isEmpty ? "" : "." + innerExtension
        if innerSuffix.utf8.count < budget {
            // Whole `Character`s come off, so one multi-byte grapheme can take
            // the stem from over-budget straight to empty — and an empty stem
            // would leave the name starting at the inner extension's dot, which
            // is a hidden file. Keeping the name's own extension is the
            // preference here, not a rule that outranks staying visible.
            let stem = truncated(
                innerSuffix.isEmpty ? base : (base as NSString).deletingPathExtension,
                toByteBudget: budget - innerSuffix.utf8.count
            )
            if !stem.isEmpty {
                return stem + innerSuffix + suffix
            }
        }

        // Nothing of the name's own extension can be kept, so trim the name.
        let trimmedBase = truncated(base, toByteBudget: budget)
        return trimmedBase.isEmpty ? fallbackBase : trimmedBase + suffix
    }

    /// Drops whole `Character`s, so a truncation can never split a scalar or a
    /// grapheme cluster.
    private static func truncated(_ text: String, toByteBudget budget: Int) -> String {
        var text = text
        while text.utf8.count > budget {
            text.removeLast()
        }
        return text
    }
}
