import CryptoKit
import Foundation
import Stores
import XCTest

final class SealedDomainTests: XCTestCase {
    private struct Contacts: Codable, Equatable, Sendable { var names: [String] }

    private var directory: ProtectedDataDirectory!
    private let key = SymmetricKey(size: .bits256)

    override func setUpWithError() throws {
        try super.setUpWithError()
        let url = FileManager.default.temporaryDirectory.appending(path: "SealedDomainTests-\(UUID().uuidString)")
        directory = try ProtectedDataDirectory(url: url)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory.url)
        try super.tearDownWithError()
    }

    private var contacts: SealedDomain<Contacts> { SealedDomain(domain: "contacts", schemaVersion: 1, directory: directory) }

    func test_saveThenLoad_roundTrips_andReplacesInPlace() throws {
        XCTAssertFalse(contacts.exists)
        try contacts.save(Contacts(names: ["a"]), key: key)
        XCTAssertTrue(contacts.exists)
        XCTAssertEqual(try contacts.load(key: key), Contacts(names: ["a"]))
        try contacts.save(Contacts(names: ["a", "b"]), key: key)
        XCTAssertEqual(try contacts.load(key: key), Contacts(names: ["a", "b"]))
        XCTAssertEqual(contacts.integrity(key: key), .intact)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.url.path).count, 1, "no temporary file left behind")
    }

    func test_missingAndDamaged_areDistinguished_andNeverDefault() throws {
        XCTAssertEqual(contacts.integrity(key: key), .missing)
        XCTAssertThrowsError(try contacts.load(key: key)) { XCTAssertEqual($0 as? StoreError, .missing) }
        try contacts.save(Contacts(names: ["a"]), key: key)
        let fileURL = directory.url.appending(path: "contacts.sealed")
        var bytes = try Data(contentsOf: fileURL); bytes[bytes.count / 2] ^= 0xFF
        try bytes.write(to: fileURL)
        XCTAssertEqual(contacts.integrity(key: key), .damaged)
        XCTAssertThrowsError(try contacts.load(key: key)) { XCTAssertEqual($0 as? StoreError, .damaged) }
        XCTAssertEqual(contacts.integrity(key: SymmetricKey(size: .bits256)), .damaged, "a wrong key reads as damage, never as empty")
    }

    func test_strayTemporaryFile_isIgnoredAndSwept() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        let stray = directory.url.appending(path: "contacts.\(UUID().uuidString).tmp")
        try Data("garbage".utf8).write(to: stray)
        XCTAssertEqual(try contacts.load(key: key), Contacts(names: ["a"]))
        directory.sweepTemporaries()
        XCTAssertFalse(FileManager.default.fileExists(atPath: stray.path))
        XCTAssertTrue(contacts.exists)
    }

    func test_domainsDoNotReadEachOther() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        let settings = SealedDomain<Contacts>(domain: "settings", schemaVersion: 1, directory: directory)
        XCTAssertEqual(settings.integrity(key: key), .missing)
        let renamed = directory.url.appending(path: "settings.sealed")
        try FileManager.default.copyItem(at: directory.url.appending(path: "contacts.sealed"), to: renamed)
        XCTAssertEqual(settings.integrity(key: key), .damaged, "a file moved between domains fails its binding")
    }

    func test_savedFile_carriesCompleteProtection() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        let attributes = try FileManager.default.attributesOfItem(atPath: directory.url.appending(path: "contacts.sealed").path)
        XCTAssertEqual(attributes[.protectionKey] as? FileProtectionType, .complete)
    }
}
