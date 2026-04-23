import Foundation

/// Debug-only in-memory trace of auth and lifecycle decisions.
final class AuthLifecycleTraceStore: @unchecked Sendable {
    enum Category: String, Equatable {
        case prompt
        case lifecycle
        case session
        case operation
    }

    struct Entry: Equatable {
        let sequence: Int
        let timestamp: Date
        let category: Category
        let name: String
        let metadata: [String: String]
    }

    private let lock = NSLock()
    private let capacity: Int
    private let sink: @Sendable (String) -> Void
    private let isEnabled: Bool

    private var nextSequence = 1
    private var entries: [Entry] = []

    init(
        isEnabled: Bool,
        capacity: Int = 200,
        sink: (@Sendable (String) -> Void)? = nil
    ) {
        self.capacity = max(capacity, 1)
        self.sink = sink ?? Self.defaultSink
#if DEBUG
        self.isEnabled = isEnabled
#else
        self.isEnabled = false
#endif
    }

    var tracingEnabled: Bool {
        isEnabled
    }

    var recentEntries: [Entry] {
        lock.withLock {
            entries
        }
    }

    func record(
        category: Category,
        name: String,
        metadata: [String: String] = [:]
    ) {
        guard isEnabled else {
            return
        }

        let entry = lock.withLock { () -> Entry in
            let entry = Entry(
                sequence: nextSequence,
                timestamp: Date(),
                category: category,
                name: name,
                metadata: metadata
            )
            nextSequence += 1
            entries.append(entry)
            if entries.count > capacity {
                entries.removeFirst(entries.count - capacity)
            }
            return entry
        }

        sink(Self.format(entry))
    }

    private static func format(_ entry: Entry) -> String {
        var components = [
            "[AuthTrace]",
            "#\(entry.sequence)",
            String(format: "%.6f", entry.timestamp.timeIntervalSinceReferenceDate),
            entry.category.rawValue,
            entry.name
        ]

        if !entry.metadata.isEmpty {
            let details = entry.metadata
                .sorted(by: { $0.key < $1.key })
                .map { "\($0.key)=\($0.value)" }
                .joined(separator: " ")
            components.append(details)
        }

        return components.joined(separator: " ")
    }

    private static func defaultSink(_ line: String) {
#if DEBUG
        print(line)
#endif
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
