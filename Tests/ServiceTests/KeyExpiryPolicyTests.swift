import Foundation
import XCTest
@testable import CypherAir

private let secondsPerDay: TimeInterval = 24 * 60 * 60

final class KeyExpiryPolicyTests: XCTestCase {
    /// The whole point of one policy: a term generation offers that the modify
    /// sheet would refuse to set is the incoherence this type exists to prevent.
    func test_everyOfferedTermIsAlsoADateTheModifySheetAccepts() {
        let range = KeyExpiryPolicy.settableDateRange()
        let earliest = TimeInterval(KeyExpiryPolicy.expirySeconds(until: range.lowerBound))
        let latest = TimeInterval(KeyExpiryPolicy.expirySeconds(until: range.upperBound))

        for term in KeyExpiryPolicy.offeredTerms {
            // No expiry is offered on both paths and bounded by neither.
            guard let seconds = KeyExpiryPolicy.expirySeconds(for: term) else {
                continue
            }
            // Every quantity here is measured from its own read of the clock, so
            // compare with a day of slack — the drift this guards is years wide.
            XCTAssertGreaterThan(
                TimeInterval(seconds),
                earliest - secondsPerDay,
                "\(term) expires sooner than the modify sheet would allow"
            )
            XCTAssertLessThan(
                TimeInterval(seconds),
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
}
