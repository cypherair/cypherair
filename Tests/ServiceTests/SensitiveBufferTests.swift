import Foundation
import os
import XCTest
@testable import CypherAir

final class SensitiveBufferTests: XCTestCase {
    private let secretBytes: [UInt8] = (0..<32).map { UInt8(0xC0 + $0) }

    // MARK: - The primitive

    /// The barrier must clear the whole region. An erase that stops early — at a
    /// word, at a page, at one of the two lengths `memset_s` takes — leaves a
    /// secret's tail behind, so the region here is far larger than any key the app
    /// holds.
    func test_sensitiveErase_clearsEveryByteOfTheRegion() {
        let byteCount = 4096
        let region = UnsafeMutableRawBufferPointer.allocate(byteCount: byteCount, alignment: 16)
        defer { region.deallocate() }
        region.initializeMemory(as: UInt8.self, repeating: 0xA5)

        sensitiveErase(region)

        XCTAssertEqual(region.count, byteCount, "the erase must not resize the region")
        XCTAssertNil(region.firstIndex(where: { $0 != 0 }), "sensitiveErase left a byte behind")
    }

    // MARK: - The physics the design rests on

    /// Zeroizing a copy-on-write `Data` does not reach the secret. Foundation
    /// copies on the write, the erase lands in the copy, and the original bytes
    /// are still there in the value that was not written to. Convention-based
    /// zeroization cannot see this happen; that is why secrets get an owner whose
    /// storage cannot be shared in the first place.
    ///
    /// If this test ever fails, Foundation changed and the premise behind
    /// `SensitiveBuffer` must be re-derived rather than assumed.
    func test_copyOnWriteData_cannotBeZeroized() {
        let original = Data(secretBytes)
        var alias = original

        let originalAddress = original.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
        let aliasAddress = alias.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
        XCTAssertEqual(
            originalAddress,
            aliasAddress,
            "the two values must share one buffer, or this test proves nothing about sharing"
        )

        alias.resetBytes(in: 0..<alias.count)

        let addressAfterErase = alias.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
        XCTAssertNotEqual(originalAddress, addressAfterErase, "the write was expected to copy first")
        XCTAssertTrue(alias.allSatisfy { $0 == 0 }, "the erase landed somewhere")
        XCTAssertEqual(Array(original), secretBytes, "and the secret survived its own zeroization")
    }

    // MARK: - The buffer

    func test_initConsuming_takesTheBytesAndErasesTheSource() {
        var source = Data(secretBytes)

        let buffer = SensitiveBuffer(consuming: &source)

        XCTAssertEqual(source.count, secretBytes.count, "only the bytes go; the source keeps its length")
        XCTAssertTrue(source.allSatisfy { $0 == 0 }, "init(consuming:) must leave the source erased")
        XCTAssertEqual(buffer.count, secretBytes.count)
        buffer.withUnsafeBytes { XCTAssertEqual(Array($0), secretBytes) }
    }

    /// Empty is a real shape — an empty passphrase, a zero-length payload — and it
    /// runs the whole path: a zero-byte allocation, a zero-byte copy, an erase of
    /// nothing, and a `deinit` that has to release that allocation rather than
    /// trap on it. This is the test that lets `sensitiveErase` carry only a null
    /// check instead of an emptiness check as well.
    func test_emptySource_consumesWithoutTrapping() {
        var source = Data()

        let buffer = SensitiveBuffer(consuming: &source)

        XCTAssertTrue(buffer.isEmpty)
        XCTAssertEqual(buffer.count, 0)
    }

    /// A fill that writes part of the buffer must leave zeros behind it, not
    /// whatever the allocator last held there.
    func test_partialFill_leavesTheRemainderZeroed() {
        let buffer = SensitiveBuffer(count: 32) { destination in
            destination[0] = 0xFF
        }

        buffer.withUnsafeBytes { bytes in
            XCTAssertEqual(bytes[0], 0xFF)
            XCTAssertNil(bytes.dropFirst().firstIndex(where: { $0 != 0 }), "unfilled bytes must be zero")
        }
    }

    /// A fill that fails — a random-bytes call returning an error, a derivation
    /// that refuses — must propagate rather than be swallowed, and must not leave
    /// the half-written allocation behind. `self` is never fully initialized on
    /// that path, so `deinit` does not run and the initializer cleans up itself.
    ///
    /// The error arrives typed, not as `any Error`, which is why the initializer
    /// takes `throws(E)` rather than `rethrows`: a caller that already speaks one
    /// error type keeps speaking it through the allocation. `XCTAssertThrowsError`
    /// is generic over a `Copyable` result and so cannot be used here at all —
    /// noncopyable results need `do`/`catch`, which will hold for every XCTest
    /// helper the later stages reach for.
    func test_failingFill_propagatesTypedAndDoesNotStrandTheAllocation() {
        struct FillFailure: Error {
            let marker: UInt8
        }

        do {
            _ = try SensitiveBuffer(count: 64) { destination throws(FillFailure) in
                destination[0] = 0xFF
                throw FillFailure(marker: 0x5A)
            }
            XCTFail("a failing fill must not produce a buffer")
        } catch {
            XCTAssertEqual(error.marker, 0x5A, "the fill's own error must reach the caller intact")
        }
    }

    func test_withUnsafeMutableBytes_writesThroughToTheBuffer() {
        let buffer = SensitiveBuffer(count: secretBytes.count) { _ in }

        buffer.withUnsafeMutableBytes { $0.copyBytes(from: secretBytes) }

        buffer.withUnsafeBytes { XCTAssertEqual(Array($0), secretBytes) }
    }

    // MARK: - Holder shapes

    /// The homes the staged plan needs, exercised so that the compiler answers the
    /// only question that matters about them: whether a secret can live there at
    /// all. Each is a place where the language decides reachability — a stored
    /// optional, a dictionary, a lock's state, an escaping closure's result — and
    /// no runtime assertion can stand in for that answer. The complement is not
    /// written here at all: a shared `SensitiveBuffer` does not compile, and
    /// simulating that at runtime would be theatre.
    func test_holderShapes_keepTheirBytesReachable() throws {
        let holder = WrappingRootKeyHolder(key: SensitiveBuffer(count: 32) { _ in })
        XCTAssertEqual(holder.keyLength(), 32)

        let homes = DomainKeyHomes()

        homes.byDomain["contacts"] = SensitiveKeyBox(SensitiveBuffer(count: 16) { _ in })
        XCTAssertEqual(homes.byDomain["contacts"]?.buffer.count, 16)

        homes.session.withLock { $0 = SensitiveKeyBox(SensitiveBuffer(count: 32) { _ in }) }
        XCTAssertEqual(homes.session.withLock { $0?.buffer.count }, 32)

        homes.provider = { SensitiveKeyBox(SensitiveBuffer(count: 8) { _ in }) }
        XCTAssertEqual(try homes.provider?().buffer.count, 8)
    }
}

private struct WrappingRootKeyHolder: ~Copyable {
    var key: SensitiveBuffer?

    /// `guard let key` consumes the stored property and does not compile;
    /// `switch` binds it borrowing. Written down because `guard let` is what
    /// anyone reaches for first.
    borrowing func keyLength() -> Int {
        switch key {
        case .some(let key): key.count
        case .none: 0
        }
    }
}

private final class DomainKeyHomes {
    var byDomain: [String: SensitiveKeyBox] = [:]
    let session = OSAllocatedUnfairLock<SensitiveKeyBox?>(initialState: nil)
    var provider: (@Sendable () throws -> SensitiveKeyBox)?
}
