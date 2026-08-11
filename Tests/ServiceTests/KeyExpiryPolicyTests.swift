import Foundation
import XCTest
@testable import CypherAir

private let secondsPerDay: TimeInterval = 24 * 60 * 60

/// Seconds of validity, or nil for no expiry — the shape these assertions compare in.
private func termSeconds(_ validity: PGPKeyValidity) -> TimeInterval? {
    switch validity {
    case .never: nil
    case .expiresIn(let seconds): TimeInterval(seconds)
    }
}

final class KeyExpiryPolicyTests: XCTestCase {
    /// The whole point of one policy: a term generation offers that the modify
    /// sheet would refuse to set is the incoherence this type exists to prevent.
    func test_everyOfferedTermIsAlsoADateTheModifySheetAccepts() throws {
        let range = KeyExpiryPolicy.settableDateRange()
        let earliest = try XCTUnwrap(termSeconds(KeyExpiryPolicy.validity(until: range.lowerBound)))
        let latest = try XCTUnwrap(termSeconds(KeyExpiryPolicy.validity(until: range.upperBound)))

        for term in KeyExpiryPolicy.offeredTerms {
            // No expiry is offered on both paths and bounded by neither.
            guard let seconds = termSeconds(KeyExpiryPolicy.validity(for: term)) else {
                continue
            }
            // Every quantity here is measured from its own read of the clock, so
            // compare with a day of slack — the drift this guards is years wide.
            XCTAssertGreaterThan(
                seconds,
                earliest - secondsPerDay,
                "\(term) expires sooner than the modify sheet would allow"
            )
            XCTAssertLessThan(
                seconds,
                latest + secondsPerDay,
                "\(term) outlives what the modify sheet would allow"
            )
        }
    }

    func test_defaultTermIsOneOfTheOfferedTerms() {
        XCTAssertTrue(
            KeyExpiryPolicy.offeredTerms.contains(KeyExpiryPolicy.defaultTerm),
            "the generation picker opens on a term it does not list"
        )
    }

    /// The picker's only term without an expiry is the one that says so.
    func test_neverIsTheOnlyOfferedTermThatDoesNotExpire() {
        for term in KeyExpiryPolicy.offeredTerms {
            XCTAssertEqual(
                KeyExpiryPolicy.validity(for: term) == .never,
                term == .never,
                "\(term) disagrees with itself about whether it expires"
            )
        }
    }
}
