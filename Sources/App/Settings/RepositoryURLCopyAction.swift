import Foundation

#if canImport(AppKit)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif

protocol RepositoryURLCopying {
    func copy(_ repositoryURL: String)
}

struct RepositoryURLCopyAction {
    private let repositoryURLClipboard: any RepositoryURLCopying

    init(repositoryURLClipboard: any RepositoryURLCopying = SystemRepositoryURLClipboard()) {
        self.repositoryURLClipboard = repositoryURLClipboard
    }

    @discardableResult
    func copyIfPresent(_ repositoryURL: String) -> Bool {
        guard !repositoryURL.isEmpty else {
            return false
        }
        repositoryURLClipboard.copy(repositoryURL)
        return true
    }
}

private struct SystemRepositoryURLClipboard: RepositoryURLCopying {
    func copy(_ repositoryURL: String) {
        #if canImport(AppKit)
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(repositoryURL, forType: .string)
        #elseif canImport(UIKit)
        UIPasteboard.general.string = repositoryURL
        #endif
    }
}
