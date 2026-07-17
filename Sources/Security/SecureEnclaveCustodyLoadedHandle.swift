import CryptoKit
import Foundation

/// A reconstructed CryptoKit Secure Enclave private key for one role,
/// validated against its stored public binding. The private key never leaves
/// the Secure Enclave; the reconstructed value is a handle whose operations
/// the enclave gates through the access policy baked in at creation.
struct SecureEnclaveCustodyLoadedHandle {
    enum PrivateKey {
        case p256Signing(SecureEnclave.P256.Signing.PrivateKey)
        case p256KeyAgreement(SecureEnclave.P256.KeyAgreement.PrivateKey)
        case mldsa65Signing(SecureEnclave.MLDSA65.PrivateKey)
        case mlkem768KeyAgreement(SecureEnclave.MLKEM768.PrivateKey)
        case mldsa87Signing(SecureEnclave.MLDSA87.PrivateKey)
        case mlkem1024KeyAgreement(SecureEnclave.MLKEM1024.PrivateKey)
    }

    let binding: SecureEnclaveCustodyHandlePublicBinding
    // Nil only in unit-test fixtures, which cannot construct enclave-resident
    // key types; the system key store always populates it, and every private
    // operation fails closed on nil.
    let privateKey: PrivateKey?

    var reference: SecureEnclaveCustodyHandleReference {
        binding.reference
    }

    var role: PGPPrivateOperationRole {
        binding.reference.role
    }
}
