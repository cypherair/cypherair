struct RepositoryURLCopyAction {
    private let copy: @MainActor (String) -> Void

    init(copy: @escaping @MainActor (String) -> Void = CypherClipboard.copy) {
        self.copy = copy
    }

    @MainActor
    @discardableResult
    func copyIfPresent(_ repositoryURL: String) -> Bool {
        guard !repositoryURL.isEmpty else {
            return false
        }
        copy(repositoryURL)
        return true
    }
}
