import CryptoKit
import Foundation
import Stores
import XCTest

private struct Contacts: Codable, Equatable, Sendable { var names: [String] }

/// The sealing rules of a domain, on files held in memory.
final class SealedDomainTests: XCTestCase {
    private let files = InMemoryDomainFiles()
    private let key = SymmetricKey(size: .bits256)

    private func domain(_ name: String = "contacts", version: Int = 1) -> SealedDomain<Contacts> {
        SealedDomain(domain: name, schemaVersion: version, files: files)
    }

    private func flipByte(of name: String) throws {
        var bytes = try XCTUnwrap(try files.read(name))
        bytes[bytes.count / 2] ^= 0xFF
        try files.replace(name, with: bytes)
    }

    func test_saveThenLoad_roundTrips_andReplacesInPlace() throws {
        try domain().save(Contacts(names: ["a"]), key: key)
        XCTAssertEqual(try domain().load(key: key), Contacts(names: ["a"]))
        try domain().save(Contacts(names: ["a", "b"]), key: key)
        XCTAssertEqual(try domain().load(key: key), Contacts(names: ["a", "b"]))
        XCTAssertEqual(domain().integrity(key: key), .intact)
    }

    func test_fileSize_movesOnlyInStepsOfThePadding() throws {
        try domain().save(Contacts(names: []), key: key)
        let empty = try XCTUnwrap(try files.read("contacts")).count
        try domain().save(Contacts(names: (0..<100).map { "contact \($0)" }), key: key)
        XCTAssertEqual(try XCTUnwrap(try files.read("contacts")).count, empty)
        try domain().save(Contacts(names: [String(repeating: "x", count: SealedDomain<Contacts>.paddingStep)]), key: key)
        XCTAssertEqual(try XCTUnwrap(try files.read("contacts")).count, empty + SealedDomain<Contacts>.paddingStep)
        XCTAssertEqual(try domain().load(key: key).names.first?.count, SealedDomain<Contacts>.paddingStep)
    }

    func test_missingAndDamaged_areDistinguished_andNeverDefault() throws {
        XCTAssertEqual(domain().integrity(key: key), .missing)
        XCTAssertThrowsError(try domain().load(key: key)) { XCTAssertEqual($0 as? StoreError, .missing) }
        try domain().save(Contacts(names: ["a"]), key: key)
        try flipByte(of: "contacts")
        XCTAssertEqual(domain().integrity(key: key), .damaged)
        XCTAssertThrowsError(try domain().load(key: key)) { XCTAssertEqual($0 as? StoreError, .damaged) }
        try domain().save(Contacts(names: ["a"]), key: key)
        XCTAssertEqual(domain().integrity(key: SymmetricKey(size: .bits256)), .damaged, "a wrong key reads as damage, never as empty")
    }

    func test_fileFromAnotherVersion_isNamedApartFromDamage() throws {
        try domain(version: 2).save(Contacts(names: ["a"]), key: key)
        XCTAssertEqual(domain(version: 3).integrity(key: key), .otherVersion)
        XCTAssertThrowsError(try domain(version: 3).load(key: key)) { XCTAssertEqual($0 as? StoreError, .otherVersion) }
    }

    func test_aFileMovedBetweenDomains_isDamage_whateverItsVersion() throws {
        try domain("contacts", version: 2).save(Contacts(names: ["a"]), key: key)
        try files.replace("settings", with: try XCTUnwrap(try files.read("contacts")))
        XCTAssertEqual(domain("settings", version: 2).integrity(key: key), .damaged)
        XCTAssertEqual(domain("settings", version: 3).integrity(key: key), .damaged)
    }
}

/// The protected directory on disk. Skips on a volume without file protection.
final class ProtectedDataDirectoryTests: XCTestCase {
    private var directory: ProtectedDataDirectory!
    private let key = SymmetricKey(size: .bits256)

    override func setUpWithError() throws {
        try super.setUpWithError()
        let temporary = FileManager.default.temporaryDirectory
        // Decided apart from the code under test, so a wrong rejection by the
        // vault fails here rather than skipping. Virtual machines, such as
        // hosted CI runners, have no Data Protection.
        let values = try temporary.resourceValues(forKeys: [.volumeSupportsFileProtectionKey])
        if values.allValues[.volumeSupportsFileProtectionKey] as? Bool == false {
            throw XCTSkip("the volume holding the temporary directory reports no file protection")
        }
        directory = try ProtectedDataDirectory(url: temporary.appending(path: "ProtectedDataDirectoryTests-\(UUID().uuidString)"))
    }

    override func tearDownWithError() throws {
        if let directory { try? FileManager.default.removeItem(at: directory.url) }
        try super.tearDownWithError()
    }

    private var contacts: SealedDomain<Contacts> { SealedDomain(domain: "contacts", schemaVersion: 1, files: directory) }

    func test_saveThenLoad_onDisk_leavesNoTemporaryFile() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        try contacts.save(Contacts(names: ["a", "b"]), key: key)
        XCTAssertEqual(try contacts.load(key: key), Contacts(names: ["a", "b"]))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.url.path), ["contacts.sealed"])
    }

    func test_strayTemporaryFile_isIgnoredAndSwept() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        let stray = directory.url.appending(path: "contacts.\(UUID().uuidString).tmp")
        try Data("garbage".utf8).write(to: stray)
        XCTAssertEqual(try contacts.load(key: key), Contacts(names: ["a"]))
        directory.sweepTemporaries()
        XCTAssertFalse(FileManager.default.fileExists(atPath: stray.path))
        XCTAssertEqual(try contacts.load(key: key), Contacts(names: ["a"]))
    }

    func test_savedFile_carriesCompleteProtection() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        let attributes = try FileManager.default.attributesOfItem(atPath: directory.url.appending(path: "contacts.sealed").path)
        XCTAssertEqual(attributes[.protectionKey] as? FileProtectionType, .complete)
    }

    func test_directory_isExcludedFromBackups_atEveryStart() throws {
        var url = directory.url
        var values = URLResourceValues()
        values.isExcludedFromBackup = false
        try url.setResourceValues(values)

        _ = try ProtectedDataDirectory(url: directory.url)

        url.removeAllCachedResourceValues()
        XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
    }

    func test_aFileThatCannotBeRead_isAnError_notMissing() throws {
        try FileManager.default.createDirectory(at: directory.url.appending(path: "contacts.sealed"), withIntermediateDirectories: false)
        XCTAssertThrowsError(try directory.read("contacts")) { XCTAssertEqual($0 as? StoreError, .io("read failed")) }
        XCTAssertNil(try directory.read("settings"))
    }

    func test_eraseAll_removesEveryFile() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        try Data("garbage".utf8).write(to: directory.url.appending(path: "contacts.\(UUID().uuidString).tmp"))
        try directory.eraseAll()
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.url.path), [])
    }
}
