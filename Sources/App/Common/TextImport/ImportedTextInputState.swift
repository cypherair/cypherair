import Foundation

/// Tracks an imported text file whose original bytes should remain authoritative
/// until the user edits the visible text.
struct ImportedTextInputState {
    private(set) var rawData: Data?
    private(set) var fileName: String?
    private(set) var textSnapshot: String?

    var hasImportedFile: Bool {
        rawData != nil && fileName != nil
    }

    mutating func setImportedFile(data: Data, fileName: String, text: String) {
        rawData = data
        self.fileName = fileName
        textSnapshot = text
    }

    @discardableResult
    mutating func invalidateIfEditedTextDiffers(_ text: String) -> Bool {
        guard let textSnapshot, rawData != nil else {
            return false
        }

        guard text != textSnapshot else {
            return false
        }

        clear()
        return true
    }

    mutating func clear() {
        rawData = nil
        fileName = nil
        textSnapshot = nil
    }
}
