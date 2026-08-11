import Foundation

/// A validity choice offered when a key is created: a whole number of years, or
/// no expiry at all.
enum KeyExpiry: Hashable {
    case years(Int)
    case never
}

/// How long the keys CypherAir X creates and amends stay valid.
///
/// Both expiry surfaces read this instead of carrying a bound of their own. Key
/// generation offers `offeredTerms` and starts on `defaultTerm`; the modify-expiry
/// sheet opens the same term out and takes any date in `settableDateRange()`.
/// Declining an expiry is offered on both paths — `KeyExpiry.never` in the
/// generation picker, Remove Expiry on the modify sheet — and reaches the engine as
/// an absent expiry rather than as a distant date. The two surfaces differ in how
/// they ask; they do not differ in what they will set.
enum KeyExpiryPolicy {
    /// What the generation picker offers, in order.
    static let offeredTerms: [KeyExpiry] = offeredYears.map(KeyExpiry.years) + [.never]

    /// Where a user who does not choose lands, on either surface.
    static let defaultTerm = KeyExpiry.years(defaultYears)

    /// The date the modify-expiry sheet opens on: `defaultTerm` from now.
    static func defaultExpiryDate() -> Date {
        expiryDate(inYears: defaultYears)
    }

    /// Dates the modify-expiry sheet offers — no sooner than a day out, because an
    /// expiry that lands before the user can act on it is not one they meant to
    /// set, and no later than the longest term generation offers.
    static func settableDateRange() -> ClosedRange<Date> {
        let now = Date()
        return now.addingTimeInterval(secondsPerDay)...expiryDate(inYears: maximumYears, from: now)
    }

    /// `date` moved to the nearest date the sheet can offer, so an expiry that
    /// arrives from outside the band cannot be saved back unseen.
    static func settableDate(nearest date: Date) -> Date {
        let range = settableDateRange()
        return min(max(date, range.lowerBound), range.upperBound)
    }

    /// Seconds until a key created now under `term` expires — `nil` only for
    /// `.never`, which is the engine's absent expiry.
    static func expirySeconds(for term: KeyExpiry) -> UInt64? {
        switch term {
        case .never:
            nil
        case .years(let years):
            expirySeconds(until: expiryDate(inYears: years))
        }
    }

    /// Seconds until `date`, for an expiry chosen as an instant rather than a term.
    static func expirySeconds(until date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSinceNow))
    }

    private static let defaultYears = 3

    /// The longest finite validity the app sets on any path: the generation
    /// picker's last preset and the modify sheet's ceiling.
    private static let maximumYears = 10

    private static let offeredYears = [1, 2, 3, 4, 5, maximumYears]

    private static let secondsPerDay: TimeInterval = 24 * 60 * 60

    /// A failed calendar addition falls back to the mean Gregorian year: a finite
    /// term must never collapse into the absent expiry that `nil` stands for.
    private static func expiryDate(inYears years: Int, from reference: Date = Date()) -> Date {
        Calendar.current.date(byAdding: .year, value: years, to: reference)
            ?? reference.addingTimeInterval(TimeInterval(years) * 365.2425 * secondsPerDay)
    }
}
