import Foundation

struct ContactsSearchIndex {
    private enum MatchRank: Int {
        case exact = 0
        case prefix = 1
        case substring = 2
    }

    private struct ContactEntry {
        let contactId: String
        let tagIds: Set<String>
        let fields: [String]
        let defaultOrder: Int
    }

    private struct TagEntry {
        let summary: ContactTagSummary
        let fields: [String]
        let defaultOrder: Int
    }

    private let contactEntriesByID: [String: ContactEntry]
    private let tagEntries: [TagEntry]

    init(snapshot: ContactsDomainSnapshot) {
        let projector = ContactSummaryProjector()
        let tagSummaries = projector.tagSummaries(from: snapshot)
        let tagSummariesByID = Dictionary(
            uniqueKeysWithValues: tagSummaries.map { ($0.tagId, $0) }
        )
        let keyRecordsByContactID = Dictionary(grouping: snapshot.keyRecords, by: \.contactId)
        let orderedContactIDs = projector.identitySummaries(from: snapshot).map(\.contactId)
        let defaultOrderByContactID = Dictionary(
            uniqueKeysWithValues: orderedContactIDs.enumerated().map { ($0.element, $0.offset) }
        )

        contactEntriesByID = Dictionary(
            uniqueKeysWithValues: snapshot.identities.map { identity in
                let keyRecords = keyRecordsByContactID[identity.contactId] ?? []
                let tagFields = identity.tagIds.compactMap { tagSummariesByID[$0]?.displayName }
                let keyFields = keyRecords.flatMap { keyRecord in
                    [
                        keyRecord.fingerprint,
                        IdentityPresentation.shortKeyId(from: keyRecord.fingerprint)
                    ]
                }
                let fields = Self.normalizedFields(
                    [identity.displayName, identity.primaryEmail].compactMap(\.self) +
                        tagFields +
                        keyFields
                )
                return (
                    identity.contactId,
                    ContactEntry(
                        contactId: identity.contactId,
                        tagIds: Set(identity.tagIds),
                        fields: fields,
                        defaultOrder: defaultOrderByContactID[identity.contactId] ?? .max
                    )
                )
            }
        )

        tagEntries = tagSummaries.enumerated().map { offset, summary in
            TagEntry(
                summary: summary,
                fields: Self.normalizedFields([summary.displayName, summary.normalizedName]),
                defaultOrder: offset
            )
        }
    }

    func filterContacts<Summary>(
        _ summaries: [Summary],
        matching query: String,
        tagFilterIds: Set<String>,
        contactId: (Summary) -> String
    ) -> [Summary] {
        let normalizedQuery = Self.normalizedSearchText(query)
        let rankedContactIds = contactEntriesByID.values
            .compactMap { entry -> (contactId: String, rank: MatchRank, defaultOrder: Int)? in
                guard tagFilterIds.isSubset(of: entry.tagIds) else {
                    return nil
                }
                guard !normalizedQuery.isEmpty else {
                    return (entry.contactId, .exact, entry.defaultOrder)
                }
                guard let rank = Self.rank(entry.fields, for: normalizedQuery) else {
                    return nil
                }
                return (entry.contactId, rank, entry.defaultOrder)
            }
            .sorted { lhs, rhs in
                if lhs.rank.rawValue != rhs.rank.rawValue {
                    return lhs.rank.rawValue < rhs.rank.rawValue
                }
                return lhs.defaultOrder < rhs.defaultOrder
            }
            .map(\.contactId)

        let summariesByContactID = Dictionary(
            uniqueKeysWithValues: summaries.map { (contactId($0), $0) }
        )
        return rankedContactIds.compactMap { summariesByContactID[$0] }
    }

    func tagSuggestions(matching query: String) -> [ContactTagSummary] {
        let normalizedQuery = Self.normalizedSearchText(query)
        return tagEntries
            .compactMap { entry -> (summary: ContactTagSummary, rank: MatchRank, defaultOrder: Int)? in
                guard !normalizedQuery.isEmpty else {
                    return (entry.summary, .exact, entry.defaultOrder)
                }
                guard let rank = Self.rank(entry.fields, for: normalizedQuery) else {
                    return nil
                }
                return (entry.summary, rank, entry.defaultOrder)
            }
            .sorted { lhs, rhs in
                if lhs.rank.rawValue != rhs.rank.rawValue {
                    return lhs.rank.rawValue < rhs.rank.rawValue
                }
                return lhs.defaultOrder < rhs.defaultOrder
            }
            .map(\.summary)
    }

    static func normalizedSearchText(_ text: String) -> String {
        text
            .split(whereSeparator: { $0.isWhitespace })
            .joined(separator: " ")
            .lowercased()
    }

    private static func normalizedFields(_ fields: [String]) -> [String] {
        fields
            .map(normalizedSearchText)
            .filter { !$0.isEmpty }
    }

    private static func rank(_ fields: [String], for query: String) -> MatchRank? {
        if fields.contains(query) {
            return .exact
        }
        if fields.contains(where: { $0.hasPrefix(query) }) {
            return .prefix
        }
        if fields.contains(where: { $0.contains(query) }) {
            return .substring
        }
        return nil
    }
}
