import Foundation
import XCTest
@testable import CypherAir

func makeKeyRouteTestIdentity(fingerprint: String) -> PGPKeyIdentity {
    PGPKeyIdentity(
        fingerprint: fingerprint,
        userId: "Alice <alice@example.com>",
        hasEncryptionSubkey: true,
        isRevoked: false,
        isExpired: false,
        isDefault: true,
        isBackedUp: false,
        publicKeyData: Data("public-\(fingerprint)".utf8),
        revocationCert: Data("revocation-\(fingerprint)".utf8),
        primaryAlgo: "Ed448",
        subkeyAlgo: "X448",
        expiryDate: nil,
        keyFamily: .portableEd448X448,
        privateKeyCustodyKind: .softwareSecretCertificate
    )
}

@MainActor
func waitUntilKeyRoute(
    _ description: String,
    timeout: TimeInterval = 2,
    condition: @escaping @MainActor () async -> Bool
) async {
    let deadline = Date().addingTimeInterval(timeout)

    while Date() < deadline {
        if await condition() {
            return
        }
        await Task.yield()
    }

    XCTFail("Timed out waiting for \(description)")
}

@MainActor
func drainKeyRouteMainActor() async {
    for _ in 0..<5 {
        await Task.yield()
    }
}
