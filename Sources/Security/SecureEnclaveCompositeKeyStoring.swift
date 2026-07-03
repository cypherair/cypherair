import Foundation
import LocalAuthentication

/// Storage abstraction for Secure Enclave composite (post-quantum) private-key
/// blobs. Production: data-protection keychain generic-password rows holding
/// CryptoKit `dataRepresentation` blobs. Tests substitute an in-memory store.
///
/// SECURITY-CRITICAL: the blobs are Secure Enclave-wrapped key material —
/// useless off-device, but their lifecycle (single blob per reference,
/// clean deletion, reset cleanup) is part of the custody model.
/// See docs/SECURITY.md Section 10 and docs/POST_QUANTUM.md Section 3.
protocol SecureEnclaveCompositeKeyStoring: Sendable {
    /// Create a fresh Secure Enclave key for the reference's role and persist
    /// its blob. Fails if a blob already exists for the reference. The
    /// caller's authenticated context is attached to the returned key so
    /// generation-time signing consumes the already-evaluated session.
    func createKey(
        reference: SecureEnclaveCompositeHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCompositeLoadedHandle

    /// Reconstruct the key stored for a reference, attaching the caller's
    /// authenticated context for the enclave operations that follow.
    /// Returns nil when no blob exists for the reference.
    func loadKey(
        reference: SecureEnclaveCompositeHandleReference,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCompositeLoadedHandle?

    /// All stored composite blobs' public bindings (no private reconstruction
    /// beyond what binding validation requires, no authentication).
    func inventoryBindings() throws -> [SecureEnclaveCompositeHandlePublicBinding]

    /// Delete the blob for a reference. Missing rows throw `.privateHandleMissing`.
    func deleteKey(reference: SecureEnclaveCompositeHandleReference) throws
}
