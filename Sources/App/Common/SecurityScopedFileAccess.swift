import Foundation

/// Abstracts `startAccessingSecurityScopedResource()` for easier testing.
protocol SecurityScopedResource {
    func startAccessingSecurityScopedResource() -> Bool
    func stopAccessingSecurityScopedResource()
}

extension URL: SecurityScopedResource {}

struct SecurityScopedAccessRequest<Resource: SecurityScopedResource> {
    let resource: Resource
    let failure: CypherAirError

    init(resource: Resource, failure: CypherAirError) {
        self.resource = resource
        self.failure = failure
    }
}

/// Executes work while holding one or more security-scoped resources.
enum SecurityScopedFileAccess {
    static func withAccess<Resource: SecurityScopedResource, T>(
        to requests: [SecurityScopedAccessRequest<Resource>],
        operation: () async throws -> T
    ) async throws -> T {
        var startedResources: [Resource] = []

        for request in requests {
            guard request.resource.startAccessingSecurityScopedResource() else {
                startedResources.reversed().forEach { $0.stopAccessingSecurityScopedResource() }
                throw request.failure
            }
            startedResources.append(request.resource)
        }

        defer {
            startedResources.reversed().forEach { $0.stopAccessingSecurityScopedResource() }
        }

        return try await operation()
    }
}
