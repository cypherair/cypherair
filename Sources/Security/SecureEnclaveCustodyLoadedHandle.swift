import Foundation
import Security

struct SecureEnclaveCustodyLoadedHandle {
    let binding: SecureEnclaveCustodyHandlePublicBinding
    let privateKey: SecKey?

    var reference: SecureEnclaveCustodyHandleReference {
        binding.reference
    }

    var role: PGPPrivateOperationRole {
        binding.role
    }
}
