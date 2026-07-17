import Foundation

/// Bridges public ScreenModel file actions with internal per-operation progress.
///
/// Tests and tutorial overrides can inject progress-free actions, while default
/// service-backed actions still receive the reporter created for the current
/// `runFileOperation` invocation.
@MainActor
struct FileOperationAction<Request, Result> {
    typealias InjectedAction = @MainActor (Request) async throws -> Result
    typealias DefaultAction = @MainActor (Request, FileProgressReporter) async throws -> Result

    private let injectedAction: InjectedAction?
    private let defaultAction: DefaultAction

    init(
        injectedAction: InjectedAction?,
        defaultAction: @escaping DefaultAction
    ) {
        self.injectedAction = injectedAction
        self.defaultAction = defaultAction
    }

    func callAsFunction(
        _ request: Request,
        progress: FileProgressReporter
    ) async throws -> Result {
        if let injectedAction {
            return try await injectedAction(request)
        }
        return try await defaultAction(request, progress)
    }
}
