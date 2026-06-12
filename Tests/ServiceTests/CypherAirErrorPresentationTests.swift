import Foundation
import XCTest
@testable import CypherAir

/// Per-category key-operation failure presentation (stage 7C): every sanitized
/// failure category must carry its own user-facing copy.
final class CypherAirErrorPresentationTests: XCTestCase {
    func test_everyFailureCategory_hasNonEmptyDescription() {
        for category in PGPKeyOperationFailureCategory.allCases {
            let description = CypherAirError.keyOperationUnavailable(category: category)
                .errorDescription
            XCTAssertNotNil(description, "Missing copy for \(category)")
            XCTAssertFalse(description?.isEmpty ?? true, "Empty copy for \(category)")
        }
    }

    func test_everyFailureCategory_hasDistinctDescription() {
        let descriptions = PGPKeyOperationFailureCategory.allCases.compactMap {
            CypherAirError.keyOperationUnavailable(category: $0).errorDescription
        }

        XCTAssertEqual(descriptions.count, PGPKeyOperationFailureCategory.allCases.count)
        XCTAssertEqual(
            Set(descriptions).count,
            descriptions.count,
            "Two failure categories share copy — per-category presentation requires distinct strings."
        )
    }

    func test_noCategoryResolvesToRetiredGenericString() {
        for category in PGPKeyOperationFailureCategory.allCases {
            XCTAssertNotEqual(
                CypherAirError.keyOperationUnavailable(category: category).errorDescription,
                "This key operation is unavailable.",
                "\(category) still resolves to the retired generic copy."
            )
        }
    }

    func test_authenticationCancellation_isNeutralStatement() {
        let description = CypherAirError
            .keyOperationUnavailable(category: .localAuthenticationCancelled)
            .errorDescription

        XCTAssertEqual(description, "Authentication was cancelled. Nothing was changed.")
        // A user-initiated cancel is not a failure: the copy must not read as one.
        XCTAssertFalse(description?.lowercased().contains("failed") ?? true)
        XCTAssertFalse(description?.lowercased().contains("error") ?? true)
    }

    func test_deviceBoundFailureCopy_staysSanitized() {
        // Sanitized categories must not leak implementation vocabulary the
        // security model keeps out of user surfaces.
        for category in PGPKeyOperationFailureCategory.allCases {
            let description = CypherAirError.keyOperationUnavailable(category: category)
                .errorDescription?.lowercased() ?? ""
            XCTAssertFalse(description.contains("keychain"), "\(category) leaks storage vocabulary")
            XCTAssertFalse(description.contains("fingerprint"), "\(category) leaks identifier vocabulary")
            XCTAssertFalse(description.contains("passcode"), "\(category) names a passcode fallback that does not exist")
        }
    }
}
