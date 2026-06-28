import Foundation
import SQLCipher

struct SQLCipherPreflightResult: Equatable {
    let cipherVersion: String
    let hasCodecCompileOption: Bool
    let tempStoreCompileOption: Bool
    let remainingDatabaseSidecars: [String]
}

enum SQLCipherPreflightError: Error, Equatable {
    case openFailed(operation: String, code: Int32)
    case closeFailed(code: Int32)
    case invalidRawKeyLength(Int)
    case keyFailed(code: Int32)
    case execFailed(operation: String, code: Int32)
    case queryFailed(operation: String, code: Int32)
    case unexpectedValue(operation: String)
    case wrongKeyAccepted
}

enum SQLCipherPreflightProbe {
    private static let databaseBaseName = "sqlcipher-preflight.sqlite"
    private static let rawKeyLength = 32

    static func run(in directory: URL) throws -> SQLCipherPreflightResult {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let databaseURL = directory.appendingPathComponent(databaseBaseName, isDirectory: false)
        try cleanupDatabaseFiles(for: databaseURL)

        let cipherVersion = try readCipherVersion()
        let hasCodec = sqlite3_compileoption_used("SQLITE_HAS_CODEC") != 0
        let tempStore = sqlite3_compileoption_used("SQLITE_TEMP_STORE=2") != 0

        var goodKey = Array(UInt8(0)...UInt8(31))
        var wrongKey = Array(goodKey.reversed())
        defer {
            zeroizeKey(&goodKey)
            zeroizeKey(&wrongKey)
            try? cleanupDatabaseFiles(for: databaseURL)
        }

        try createEncryptedDatabase(at: databaseURL, key: &goodKey)
        try readEncryptedDatabase(at: databaseURL, key: &goodKey)
        try assertWrongKeyFails(at: databaseURL, key: &wrongKey)
        try cleanupDatabaseFiles(for: databaseURL)

        return SQLCipherPreflightResult(
            cipherVersion: cipherVersion,
            hasCodecCompileOption: hasCodec,
            tempStoreCompileOption: tempStore,
            remainingDatabaseSidecars: existingDatabaseSidecars(for: databaseURL)
        )
    }

    private static func readCipherVersion() throws -> String {
        let db = try openDatabase(path: ":memory:", operation: "open-memory")
        defer { _ = sqlite3_close(db) }
        return try querySingleString(db, sql: "PRAGMA cipher_version;", operation: "cipher-version")
    }

    private static func createEncryptedDatabase(at url: URL, key: inout [UInt8]) throws {
        let db = try openDatabase(path: url.path, operation: "create-open")
        defer { _ = sqlite3_close(db) }
        try applyKey(key, to: db)
        try exec(db, sql: "CREATE TABLE preflight(value TEXT NOT NULL);", operation: "create-table")
        try exec(db, sql: "INSERT INTO preflight(value) VALUES('preflight-ok');", operation: "insert-row")
    }

    private static func readEncryptedDatabase(at url: URL, key: inout [UInt8]) throws {
        let db = try openDatabase(path: url.path, operation: "read-open")
        defer { _ = sqlite3_close(db) }
        try applyKey(key, to: db)
        let value = try querySingleString(db, sql: "SELECT value FROM preflight;", operation: "read-row")
        guard value == "preflight-ok" else {
            throw SQLCipherPreflightError.unexpectedValue(operation: "read-row")
        }
    }

    private static func assertWrongKeyFails(at url: URL, key: inout [UInt8]) throws {
        let db = try openDatabase(path: url.path, operation: "wrong-key-open")
        defer { _ = sqlite3_close(db) }
        try applyKey(key, to: db)
        do {
            _ = try querySingleString(db, sql: "SELECT value FROM preflight;", operation: "wrong-key-read")
            throw SQLCipherPreflightError.wrongKeyAccepted
        } catch SQLCipherPreflightError.wrongKeyAccepted {
            throw SQLCipherPreflightError.wrongKeyAccepted
        } catch {
            return
        }
    }

    private static func openDatabase(path: String, operation: String) throws -> OpaquePointer {
        var db: OpaquePointer?
        let rc = sqlite3_open(path, &db)
        guard rc == SQLITE_OK, let db else {
            if let db {
                _ = sqlite3_close(db)
            }
            throw SQLCipherPreflightError.openFailed(operation: operation, code: rc)
        }
        return db
    }

    private static func applyKey(_ key: [UInt8], to db: OpaquePointer) throws {
        var keySpec = try rawKeySpec(for: key)
        defer {
            zeroizeKey(&keySpec)
        }

        let rc = keySpec.withUnsafeBytes { buffer in
            sqlite3_key_v2(db, "main", buffer.baseAddress, Int32(buffer.count))
        }
        guard rc == SQLITE_OK else {
            throw SQLCipherPreflightError.keyFailed(code: rc)
        }
    }

    private static func rawKeySpec(for key: [UInt8]) throws -> [UInt8] {
        guard key.count == rawKeyLength else {
            throw SQLCipherPreflightError.invalidRawKeyLength(key.count)
        }

        let hexDigits = Array("0123456789abcdef".utf8)
        var keySpec = [UInt8]()
        keySpec.reserveCapacity(67)
        keySpec.append(UInt8(ascii: "x"))
        keySpec.append(UInt8(ascii: "'"))
        for byte in key {
            keySpec.append(hexDigits[Int(byte >> 4)])
            keySpec.append(hexDigits[Int(byte & 0x0f)])
        }
        keySpec.append(UInt8(ascii: "'"))
        return keySpec
    }

    private static func zeroizeKey(_ key: inout [UInt8]) {
        guard !key.isEmpty else { return }
        key.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return }
            opaqueZero(base, buffer.count)
        }
    }

    private static func exec(_ db: OpaquePointer, sql: String, operation: String) throws {
        var errorMessage: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &errorMessage)
        if let errorMessage {
            sqlite3_free(errorMessage)
        }
        guard rc == SQLITE_OK else {
            throw SQLCipherPreflightError.execFailed(operation: operation, code: rc)
        }
    }

    private static func querySingleString(
        _ db: OpaquePointer,
        sql: String,
        operation: String
    ) throws -> String {
        var statement: OpaquePointer?
        let prepareRC = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard prepareRC == SQLITE_OK, let statement else {
            throw SQLCipherPreflightError.queryFailed(operation: operation, code: prepareRC)
        }
        defer { sqlite3_finalize(statement) }

        let stepRC = sqlite3_step(statement)
        guard stepRC == SQLITE_ROW else {
            throw SQLCipherPreflightError.queryFailed(operation: operation, code: stepRC)
        }
        guard let text = sqlite3_column_text(statement, 0) else {
            throw SQLCipherPreflightError.unexpectedValue(operation: operation)
        }
        return String(cString: text)
    }

    private static func cleanupDatabaseFiles(for databaseURL: URL) throws {
        for name in databaseSidecarNames(for: databaseURL) {
            let url = databaseURL.deletingLastPathComponent().appendingPathComponent(name)
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.removeItem(at: url)
            }
        }
    }

    private static func existingDatabaseSidecars(for databaseURL: URL) -> [String] {
        databaseSidecarNames(for: databaseURL).filter { name in
            let url = databaseURL.deletingLastPathComponent().appendingPathComponent(name)
            return FileManager.default.fileExists(atPath: url.path)
        }
    }

    private static func databaseSidecarNames(for databaseURL: URL) -> [String] {
        let name = databaseURL.lastPathComponent
        return [
            name,
            "\(name)-wal",
            "\(name)-shm",
            "\(name)-journal",
        ]
    }
}

@_optimize(none)
private func opaqueZero(_ ptr: UnsafeMutablePointer<UInt8>, _ count: Int) {
    ptr.initialize(repeating: 0, count: count)
}
