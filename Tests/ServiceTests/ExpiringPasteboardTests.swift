#if canImport(AppKit)
import AppKit
import XCTest
@testable import CypherAir

/// The macOS clipboard expiry has no system behind it — the app is the clock,
/// and both halves of the promise are the app's to keep: its own copy goes
/// away, and a copy the user made elsewhere does not.
///
/// The lifetimes here are sub-second; the assertions are about elapsed time
/// relative to the lifetime, never about wall-clock instants, so a slow machine
/// makes the test slower rather than wrong.
@MainActor
final class ExpiringPasteboardTests: XCTestCase {
    func test_expiringPasteboard_clearsItsOwnCopy_afterAFullLifetimeOfTheLatestWrite() async throws {
        let pasteboard = NSPasteboard.withUniqueName()
        defer { pasteboard.releaseGlobally() }
        let lifetime: TimeInterval = 0.25
        let clipboard = ExpiringPasteboard(pasteboard: pasteboard, lifetime: lifetime)

        clipboard.write("first ciphertext")
        try await Task.sleep(for: .seconds(lifetime / 2))

        let secondWrite = ContinuousClock.now
        clipboard.write("second ciphertext")
        XCTAssertEqual(pasteboard.string(forType: .string), "second ciphertext")

        let elapsedWhenCleared = try await waitUntilCleared(pasteboard, timeout: .seconds(lifetime * 20))
        XCTAssertGreaterThanOrEqual(
            secondWrite.duration(to: elapsedWhenCleared),
            .seconds(lifetime),
            "the newer copy must get its own full lifetime, not the remainder of the older one's"
        )
    }

    func test_expiringPasteboard_leavesAlone_aCopyTheUserMadeElsewhere() async throws {
        let pasteboard = NSPasteboard.withUniqueName()
        defer { pasteboard.releaseGlobally() }
        let lifetime: TimeInterval = 0.1
        let clipboard = ExpiringPasteboard(pasteboard: pasteboard, lifetime: lifetime)

        clipboard.write("our ciphertext")
        pasteboard.clearContents()
        pasteboard.setString("a shopping list", forType: .string)

        try await Task.sleep(for: .seconds(lifetime * 6))

        XCTAssertEqual(pasteboard.string(forType: .string), "a shopping list")
    }

    private func waitUntilCleared(
        _ pasteboard: NSPasteboard,
        timeout: Duration
    ) async throws -> ContinuousClock.Instant {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            if pasteboard.string(forType: .string) == nil {
                return ContinuousClock.now
            }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTFail("the pasteboard still holds the app's copy after \(timeout)")
        return ContinuousClock.now
    }
}
#endif
