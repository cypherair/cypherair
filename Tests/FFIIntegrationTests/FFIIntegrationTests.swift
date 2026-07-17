import XCTest
@testable import CypherAir

/// FFI Boundary Integration Tests
/// Validates that data crosses the Rust↔Swift UniFFI boundary correctly.
final class FFIIntegrationTests: XCTestCase {

    var engine: PgpEngine!

    override func setUp() {
        super.setUp()
        engine = PgpEngine()
    }

    override func tearDown() {
        engine = nil
        super.tearDown()
    }

    func loadFixture(_ name: String) throws -> Data {
        try FixtureLoader.loadData(name, ext: "gpg")
    }

    func loadArmoredFixture(_ name: String, ext: String = "asc") throws -> Data {
        try FixtureLoader.loadData(name, ext: ext)
    }

    func loadArmoredFixtureAsBinary(_ name: String, ext: String = "asc") throws -> Data {
        try engine.dearmor(armored: loadArmoredFixture(name, ext: ext))
    }

    func loadTextFixture(_ name: String, ext: String = "txt") throws -> Data {
        try FixtureLoader.loadData(name, ext: ext)
    }

    func writeTempFile(
        _ data: Data,
        filename: String = "ffi-\(UUID().uuidString).bin"
    ) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(filename)
        try data.write(to: url)
        return url
    }

    func makeTempOutputURL(
        filename: String = "ffi-out-\(UUID().uuidString).bin"
    ) -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(filename)
    }

    func selectorInput(userIdData: Data, occurrenceIndex: UInt64) -> UserIdSelectorInput {
        UserIdSelectorInput(
            userIdData: userIdData,
            occurrenceIndex: occurrenceIndex
        )
    }

    func userIdSelector(for certData: Data, occurrenceIndex: Int = 0) throws -> UserIdSelectorInput {
        let discovered = try engine.discoverCertificateSelectors(certData: certData)
        let userId = discovered.userIds[occurrenceIndex]
        return selectorInput(
            userIdData: userId.userIdData,
            occurrenceIndex: userId.occurrenceIndex
        )
    }
}
