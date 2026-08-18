import Foundation

/// A validity offered when a key is created: a whole number of years, or no
/// expiry at all.
enum KeyExpiryTerm: Hashable, Sendable {
    case years(Int)
    case never
}

/// How long the keys CypherAir X creates and amends stay valid.
///
/// Both expiry surfaces read this rather than carrying a bound of their own. Key
/// generation offers `offeredTerms` and starts on `defaultTerm`; the
/// modify-expiry sheet opens on the same default and takes any date in
/// `settableDateRange()`. Declining an expiry is offered on both — `.never` in
/// the generation picker, Remove Expiry on the modify sheet — and reaches the
/// engine as `PGPKeyValidity.never` rather than as a distant date. The two
/// surfaces differ in how they ask and how finely, never in what they will set.
enum KeyExpiryPolicy {
    /// What the generation picker offers, in order.
    static let offeredTerms: [KeyExpiryTerm] = offeredYears.map(KeyExpiryTerm.years) + [.never]

    /// Where a user who does not choose lands, on either surface.
    static let defaultTerm = KeyExpiryTerm.years(defaultYears)

    /// The validity a key created now under `term` should be given.
    static func validity(for term: KeyExpiryTerm) -> PGPKeyValidity {
        switch term {
        case .never:
            return .never
        case .years(let years):
            return validity(until: expiryDate(inYears: years))
        }
    }

    /// The validity for an expiry chosen as an instant rather than as a term.
    static func validity(until date: Date) -> PGPKeyValidity {
        .expiresIn(seconds: UInt64(max(0, date.timeIntervalSinceNow)))
    }

    /// The date the modify-expiry sheet opens on: `defaultTerm` from now.
    static func defaultExpiryDate() -> Date {
        expiryDate(inYears: defaultYears)
    }

    /// Dates the modify-expiry sheet offers — no sooner than a day out, because an
    /// expiry landing before the user can act on it is not one they meant to set,
    /// and no later than the longest term generation offers.
    static func settableDateRange() -> ClosedRange<Date> {
        let now = Date()
        return now.addingTimeInterval(secondsPerDay)...expiryDate(inYears: maximumYears, from: now)
    }

    private static let defaultYears = 3

    /// The longest finite validity the app sets on any path: the generation
    /// picker's last term and the modify sheet's ceiling.
    private static let maximumYears = 10

    private static let offeredYears = [1, 2, 3, 4, 5, maximumYears]

    private static let secondsPerDay: TimeInterval = 24 * 60 * 60

    /// The terms are labelled in Gregorian years and must last that long whatever
    /// calendar the device runs on: under a Hijri `Calendar.current`, adding three
    /// years lands about a hundred days short of what the row promises.
    private static let calendar = Calendar(identifier: .gregorian)

    /// A failed calendar addition falls back to the mean Gregorian year, because a
    /// finite term must never collapse to the reference date and expire on sight.
    private static func expiryDate(inYears years: Int, from reference: Date = Date()) -> Date {
        calendar.date(byAdding: .year, value: years, to: reference)
            ?? reference.addingTimeInterval(TimeInterval(years) * 365.2425 * secondsPerDay)
    }
}
