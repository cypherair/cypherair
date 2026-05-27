import Foundation
import Security

struct SecureEnclaveCustodyAccessControlPolicy: Equatable, Sendable {
    static let privateKeyUsageBiometryAny = SecureEnclaveCustodyAccessControlPolicy(
        accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String,
        requiresPrivateKeyUsage: true,
        requiresBiometryAny: true,
        permitsDevicePasscodeFallback: false
    )

    let accessibility: String
    let requiresPrivateKeyUsage: Bool
    let requiresBiometryAny: Bool
    let permitsDevicePasscodeFallback: Bool

    func makeSecAccessControl() throws -> SecAccessControl {
        guard accessibility == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String),
              requiresPrivateKeyUsage,
              requiresBiometryAny,
              !permitsDevicePasscodeFallback else {
            throw SecureEnclaveCustodyHandleError.accessPolicyUnavailable
        }

        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            &error
        ) else {
            error?.release()
            throw SecureEnclaveCustodyHandleError.accessPolicyUnavailable
        }
        return accessControl
    }
}
