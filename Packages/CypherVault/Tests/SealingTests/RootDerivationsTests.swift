import CryptoKit
import Foundation
import Testing
@testable import Sealing

struct RootDerivationsTests {
    private func root(_ byte: UInt8) -> SensitiveBuffer {
        SensitiveBuffer(count: RootDerivations.rootSecretLength) { $0.initializeMemory(as: UInt8.self, repeating: byte) }
    }

    @Test func `Known answer pins labels`() {
        let secret = root(0xA5)
        let identity = RootDerivations.identityCredential(rootSecret: secret).withUnsafeBytes { Data($0) }
        let contacts = RootDerivations.domainKey(wrappingRootKey: RootDerivations.wrappingRootKey(rootSecret: secret), domain: "contacts").withUnsafeBytes { Data($0) }
        #expect(identity.map { String(format: "%02x", $0) }.joined() == KnownAnswers.identityCredential)
        #expect(contacts.map { String(format: "%02x", $0) }.joined() == KnownAnswers.contactsDomainKey)
    }
}
