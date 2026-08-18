import Foundation
import Security

/// The one access control every device-bound custody Secure Enclave key is
/// created under, shared by the enclave handle store and the split-custody
/// classical-component store.
///
/// Device-bound biometric enforcement is fixed — `WhenUnlockedThisDeviceOnly`
/// with `[.privateKeyUsage, .biometryAny]`, never a passcode fallback — which is
/// what exempts device-bound keys from the mode-switch re-wrap (docs/CUSTODY.md
/// §4). Deliberately a constructor rather than a policy value: a type able to
/// represent other policies would only exist to be guarded against.
enum SecureEnclaveCustodyAccessControl {
    static func deviceBound() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            &error
        ) else {
            _ = error?.takeRetainedValue()
            throw SecureEnclaveCustodyHandleError.accessPolicyUnavailable
        }
        return accessControl
    }
}
