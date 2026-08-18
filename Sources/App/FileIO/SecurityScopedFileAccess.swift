import Foundation

/// A file the app reads through the sandbox.
///
/// A protocol rather than `URL` alone so the access bookkeeping can be exercised
/// without a real sandboxed file.
protocol SecurityScopedResource {
    func startAccessingSecurityScopedResource() -> Bool
    func stopAccessingSecurityScopedResource()
}

extension URL: SecurityScopedResource {}

/// Runs work while holding whatever sandbox extension the files carry.
///
/// A URL from a document picker, or from a document the system opened in place,
/// carries an extension that has to be claimed before the bytes can be read, and
/// released afterwards. A URL naming a file inside the app's own container —
/// what the system leaves in `Documents/Inbox` when another app hands the app a
/// copy — carries none, and `startAccessingSecurityScopedResource()` answers
/// `false` for it. That answer means "there was no extension to claim", not
/// "you may not read this", so the work runs either way and only what was
/// actually claimed is released. What the read may touch is the sandbox's
/// decision, not this type's; a file that truly cannot be read fails at the
/// read, where the reason is known.
enum SecurityScopedFileAccess {
    static func withAccess<Resource: SecurityScopedResource, T>(
        to resource: Resource,
        operation: () throws -> T
    ) rethrows -> T {
        let claimed = resource.startAccessingSecurityScopedResource()
        defer {
            if claimed {
                resource.stopAccessingSecurityScopedResource()
            }
        }
        return try operation()
    }

    static func withAccess<Resource: SecurityScopedResource, T>(
        to resources: [Resource],
        operation: () async throws -> T
    ) async rethrows -> T {
        let claimed = resources.filter { $0.startAccessingSecurityScopedResource() }
        defer {
            claimed.reversed().forEach { $0.stopAccessingSecurityScopedResource() }
        }
        return try await operation()
    }
}
