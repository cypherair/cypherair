import CryptoKit
import Foundation
import XCTest
@testable import CypherAir

/// The tutorial sandbox's zero-bytes-on-disk property: a full sandbox flow —
/// container construction, contacts open, key generation, contact import —
/// writes nothing to the filesystem and nothing to any preferences domain.
/// The isolation is structural (the container names no path), and this guards
/// the two reintroduction routes a later change could open: routing sandbox
/// artifacts through the temporary-artifact store, and resurrecting the
/// machine-global tutorial defaults suite.
@MainActor
final class TutorialSandboxZeroDiskTests: XCTestCase {
    private static let retiredTutorialDefaultsSuiteName = "com.cypherair.tutorial.sandbox"

    func test_fullSandboxFlow_writesNothingToDiskOrPreferences() async throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("The sandbox's ephemeral key wrapping requires a Secure Enclave.")
        }

        let observedTemporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirZeroDiskProbe-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: observedTemporaryDirectory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: observedTemporaryDirectory) }

        let container = TutorialSandboxContainer(
            temporaryArtifactStore: AppTemporaryArtifactStore(
                temporaryDirectory: observedTemporaryDirectory
            )
        )
        defer { container.cleanup() }

        try await container.openContactsIfNeeded()
        XCTAssertEqual(container.contactService.contactsAvailability, .availableProtectedDomain)

        let alice = try await container.keyManagement.generateKey(
            name: "Alice Demo",
            email: "alice@demo.invalid",
            expirySeconds: nil,
            family: .portableEd25519X25519
        )
        let bob = try container.engine.generateKey(
            name: "Bob Demo",
            email: "bob@demo.invalid",
            expirySeconds: nil,
            suite: .ed25519LegacyCurve25519Legacy
        )
        _ = try container.contactService.importContact(publicKeyData: bob.publicKeyData)

        XCTAssertFalse(alice.fingerprint.isEmpty)
        XCTAssertEqual(container.contactService.runtimeContactCountForDiagnostics, 1)

        let leftoverItems = try FileManager.default.contentsOfDirectory(
            at: observedTemporaryDirectory,
            includingPropertiesForKeys: nil
        )
        XCTAssertEqual(
            leftoverItems, [],
            "The sandbox flow must not route a single byte through the temporary store."
        )

        let strayTutorialDirectories = try FileManager.default.contentsOfDirectory(
            at: FileManager.default.temporaryDirectory,
            includingPropertiesForKeys: nil
        ).filter { $0.lastPathComponent.hasPrefix("CypherAirGuidedTutorial-") }
        XCTAssertEqual(strayTutorialDirectories, [])

        XCTAssertNil(
            UserDefaults.standard.persistentDomain(forName: Self.retiredTutorialDefaultsSuiteName),
            "The machine-global tutorial defaults suite must stay retired."
        )
        let retiredPlist = FileManager.default
            .urls(for: .libraryDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Preferences", isDirectory: true)
            .appendingPathComponent("\(Self.retiredTutorialDefaultsSuiteName).plist")
        XCTAssertFalse(FileManager.default.fileExists(atPath: retiredPlist.path))
    }
}
