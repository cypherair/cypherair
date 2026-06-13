import XCTest
#if canImport(AppKit)
import AppKit
#endif
@testable import CypherAir

#if os(macOS)
/// Security + behavior tests for the FB23066215 pooled-field mitigation (issue #499).
///
/// The pooled `NSTextField`/`NSSecureTextField`/`NSTextView` are deliberately never
/// deallocated (that is what avoids the `weak_clear_no_lock` MTE fault on macOS 27). These
/// tests pin the two properties that make that safe: the pool actually reuses instances,
/// and — critically for passphrase safety — a field/view is scrubbed on recycle so a reused
/// instance can never carry a prior value (including a passphrase) into its next mount.
@MainActor
final class MIEPooledFieldStoreTests: XCTestCase {

    // MARK: - Single-line pool (NSTextField / NSSecureTextField)

    func test_obtain_returnsRequestedFieldKind() {
        let store = MIEPooledFieldStore()
        let plain = store.obtain(.plain)
        let secure = store.obtain(.secure)

        XCTAssertFalse(plain is NSSecureTextField, "Plain kind must not vend a secure field.")
        XCTAssertTrue(secure is NSSecureTextField, "Secure kind must vend an NSSecureTextField.")
    }

    func test_recycle_reusesTheSameInstance() {
        let store = MIEPooledFieldStore()
        let first = store.obtain(.plain)
        store.recycle(first, kind: .plain)
        let second = store.obtain(.plain)

        XCTAssertTrue(first === second, "A recycled field must be reused, never reallocated.")
    }

    /// Negative / security: a recycled field must not retain its prior contents, so a reused
    /// field cannot leak a previously-entered passphrase to the next screen.
    func test_recycle_scrubsContents_noValueLeakAcrossReuse() {
        let store = MIEPooledFieldStore()
        let field = store.obtain(.secure)
        field.stringValue = "correct horse battery staple"

        store.recycle(field, kind: .secure)
        XCTAssertEqual(field.stringValue, "", "Recycle must scrub the field's value.")

        let reused = store.obtain(.secure)
        XCTAssertTrue(reused === field, "Expected the scrubbed instance to be the one reused.")
        XCTAssertEqual(reused.stringValue, "", "A reused field must not carry a prior passphrase.")
    }

    func test_recycle_detachesDelegateAndTarget() {
        final class DelegateProbe: NSObject, NSTextFieldDelegate {}
        let store = MIEPooledFieldStore()
        let field = store.obtain(.plain)
        let probe = DelegateProbe()
        field.delegate = probe
        field.target = probe

        store.recycle(field, kind: .plain)

        XCTAssertNil(field.delegate, "Recycle must drop the delegate.")
        XCTAssertNil(field.target, "Recycle must drop the target.")
        XCTAssertNil(field.action, "Recycle must drop the action.")
    }

    // MARK: - Multiline pool (NSTextView in NSScrollView)

    func test_textViewStore_reusesInstance() {
        let store = MIEPooledTextViewStore()
        let scroll = store.obtain()
        store.recycle(scroll)
        let reused = store.obtain()

        XCTAssertTrue(scroll === reused, "A recycled scroll/text view must be reused, never reallocated.")
    }

    /// Negative / security: a recycled multiline editor must be scrubbed too (it backs the
    /// plaintext message editors).
    func test_textViewStore_recycleScrubsText() {
        let store = MIEPooledTextViewStore()
        let scroll = store.obtain()
        (scroll.documentView as? NSTextView)?.string = "secret plaintext"

        store.recycle(scroll)

        XCTAssertEqual(
            (scroll.documentView as? NSTextView)?.string,
            "",
            "Recycle must scrub the text view's contents."
        )
    }
}
#endif
