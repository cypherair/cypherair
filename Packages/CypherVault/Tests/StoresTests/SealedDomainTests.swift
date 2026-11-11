import CryptoKit
import Foundation
import Stores
import Testing

private struct Contacts: Codable, Equatable, Sendable { var names: [String] }

/// The sealing rules of a domain, on files held in memory.
struct SealedDomainTests {
    private let files = InMemoryDomainFiles()
    private let key = SymmetricKey(size: .bits256)

    private func domain(_ name: String = "contacts", version: Int = 1) -> SealedDomain<Contacts> {
        SealedDomain(domain: name, schemaVersion: version, files: files)
    }

    private func flipByte(of name: String) throws {
        var bytes = try #require(try files.read(name))
        bytes[bytes.count / 2] ^= 0xFF
        try files.replace(name, with: bytes)
    }

    @Test func `File size moves only in steps of the padding`() throws {
        let step = SealedDomain<Contacts>.paddingStep
        try domain().save(Contacts(names: []), key: key)
        let empty = try #require(try files.read("contacts")).count
        try domain().save(Contacts(names: (0..<100).map { "contact \($0)" }), key: key)
        let hundred = try #require(try files.read("contacts"))
        #expect(hundred.count == empty)
        try domain().save(Contacts(names: [String(repeating: "x", count: step)]), key: key)
        let oneStepMore = try #require(try files.read("contacts"))
        #expect(oneStepMore.count == empty + step)
        #expect(try domain().load(key: key).names.first?.count == step)
    }

    @Test func `Missing and damaged are distinguished and never default`() throws {
        #expect(domain().integrity(key: key) == .missing)
        #expect(throws: StoreError.missing) { try domain().load(key: key) }
        try domain().save(Contacts(names: ["a"]), key: key)
        try flipByte(of: "contacts")
        #expect(domain().integrity(key: key) == .damaged)
        #expect(throws: StoreError.damaged) { try domain().load(key: key) }
        try domain().save(Contacts(names: ["a"]), key: key)
        #expect(domain().integrity(key: SymmetricKey(size: .bits256)) == .damaged, "a wrong key reads as damage, never as empty")
    }

    @Test func `A file from another version is named apart from damage`() throws {
        try domain(version: 2).save(Contacts(names: ["a"]), key: key)
        #expect(domain(version: 3).integrity(key: key) == .otherVersion)
        #expect(throws: StoreError.otherVersion) { try domain(version: 3).load(key: key) }
    }

    @Test func `A file moved between domains is damage, whatever its version`() throws {
        try domain("contacts", version: 2).save(Contacts(names: ["a"]), key: key)
        try files.replace("settings", with: try #require(try files.read("contacts")))
        #expect(domain("settings", version: 2).integrity(key: key) == .damaged)
        #expect(domain("settings", version: 3).integrity(key: key) == .damaged)
    }
}

/// Virtual machines, such as hosted CI runners, have no Data Protection. This is
/// decided apart from the code under test, so a wrong rejection by the vault
/// fails the suite rather than skipping it.
private func temporaryVolumeHasFileProtection() throws -> Bool {
    let values = try FileManager.default.temporaryDirectory.resourceValues(forKeys: [.volumeSupportsFileProtectionKey])
    return values.allValues[.volumeSupportsFileProtectionKey] as? Bool != false
}

/// The protected directory on disk. A class, so `deinit` removes the directory.
@Suite(.enabled(if: try temporaryVolumeHasFileProtection(), "the volume holding the temporary directory reports no file protection"))
final class ProtectedDataDirectoryTests {
    private let directory: ProtectedDataDirectory
    private let key = SymmetricKey(size: .bits256)

    init() throws {
        directory = try ProtectedDataDirectory(url: FileManager.default.temporaryDirectory.appending(path: "ProtectedDataDirectoryTests-\(UUID().uuidString)"))
    }

    deinit {
        try? FileManager.default.removeItem(at: directory.url)
    }

    private var contacts: SealedDomain<Contacts> { SealedDomain(domain: "contacts", schemaVersion: 1, files: directory) }

    @Test func `Save then load on disk leaves no temporary file`() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        try contacts.save(Contacts(names: ["a", "b"]), key: key)
        #expect(try contacts.load(key: key) == Contacts(names: ["a", "b"]))
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.url.path) == ["contacts.sealed"])
    }

    @Test func `A stray temporary file is ignored and swept`() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        let stray = directory.url.appending(path: "contacts.\(UUID().uuidString).tmp")
        try Data("garbage".utf8).write(to: stray)
        #expect(try contacts.load(key: key) == Contacts(names: ["a"]))
        directory.sweepTemporaries()
        #expect(!FileManager.default.fileExists(atPath: stray.path))
        #expect(try contacts.load(key: key) == Contacts(names: ["a"]))
    }

    @Test func `A saved file carries complete protection`() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        let attributes = try FileManager.default.attributesOfItem(atPath: directory.url.appending(path: "contacts.sealed").path)
        #expect(attributes[.protectionKey] as? FileProtectionType == .complete)
    }

    @Test func `The directory is excluded from backups at every start`() throws {
        var url = directory.url
        var values = URLResourceValues()
        values.isExcludedFromBackup = false
        try url.setResourceValues(values)

        _ = try ProtectedDataDirectory(url: directory.url)

        url.removeAllCachedResourceValues()
        #expect(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    @Test func `A file that cannot be read is an error, not missing`() throws {
        try FileManager.default.createDirectory(at: directory.url.appending(path: "contacts.sealed"), withIntermediateDirectories: false)
        #expect(throws: StoreError.io("read failed")) { try directory.read("contacts") }
        #expect(try directory.read("settings") == nil)
    }

    @Test func `Erase all removes every file`() throws {
        try contacts.save(Contacts(names: ["a"]), key: key)
        try Data("garbage".utf8).write(to: directory.url.appending(path: "contacts.\(UUID().uuidString).tmp"))
        try directory.eraseAll()
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.url.path) == [])
    }
}
