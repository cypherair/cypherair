import CryptoKit
import Foundation
import XCTest
@testable import Sealing

final class RootDerivationsTests: XCTestCase {
    private func root(_ byte: UInt8) -> SensitiveBuffer {
        SensitiveBuffer(count: RootDerivations.rootSecretLength) { $0.initializeMemory(as: UInt8.self, repeating: byte) }
    }

    func test_sessionValues_andDomainKeys_areDistinctAndDeterministic() {
        let secret = root(0x01)
        let wrapping = RootDerivations.wrappingRootKey(rootSecret: secret)
        let identity = RootDerivations.identityCredential(rootSecret: secret)
        XCTAssertEqual(identity.count, RootDerivations.identityCredentialLength)
        let identityBytes = identity.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(wrapping.withUnsafeBytes { Data($0) }, identityBytes)
        XCTAssertEqual(RootDerivations.identityCredential(rootSecret: root(0x01)).withUnsafeBytes { Data($0) }, identityBytes)
        XCTAssertNotEqual(RootDerivations.identityCredential(rootSecret: root(0x02)).withUnsafeBytes { Data($0) }, identityBytes)
        let contacts = RootDerivations.domainKey(wrappingRootKey: wrapping, domain: "contacts")
        let settings = RootDerivations.domainKey(wrappingRootKey: wrapping, domain: "settings")
        XCTAssertNotEqual(contacts, settings)
        XCTAssertEqual(contacts, RootDerivations.domainKey(wrappingRootKey: wrapping, domain: "contacts"))
    }

    func test_knownAnswer_pinsLabels() {
        let secret = root(0xA5)
        let identity = RootDerivations.identityCredential(rootSecret: secret).withUnsafeBytes { Data($0) }
        let contacts = RootDerivations.domainKey(wrappingRootKey: RootDerivations.wrappingRootKey(rootSecret: secret), domain: "contacts").withUnsafeBytes { Data($0) }
        XCTAssertEqual(identity.map { String(format: "%02x", $0) }.joined(), KnownAnswers.identityCredential)
        XCTAssertEqual(contacts.map { String(format: "%02x", $0) }.joined(), KnownAnswers.contactsDomainKey)
    }
}
