import Foundation
import LocalAuthentication

/// Storage abstraction for Secure Enclave custody private-key blobs.
/// Production: data-protection keychain generic-password rows holding CryptoKit
/// `dataRepresentation` blobs. Tests substitute an in-memory store.
///
/// SECURITY-CRITICAL: the blobs are Secure Enclave-wrapped key material —
/// useless off-device, but their lifecycle (single blob per reference, clean
/// deletion, reset cleanup) is part of the custody model.
/// See docs/SECURITY.md Section 10 and docs/SECURE_ENCLAVE_CUSTODY.md.
protocol SecureEnclaveCustodyKeyStoring: Sendable {
    /// Create a fresh Secure Enclave key for the reference's tier and role and
    /// persist its blob. Fails if a blob already exists for the reference. The
    /// caller's authenticated context is attached to the returned key so
    /// generation-time signing consumes the already-evaluated session.
    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle

    /// Reconstruct the key stored for a reference, attaching the caller's
    /// authenticated context for the enclave operations that follow.
    /// Returns nil when no blob exists for the reference.
    func loadKey(
        reference: SecureEnclaveCustodyHandleReference,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle?

    /// All stored blobs' public bindings across every tier and role (no
    /// private reconstruction, no authentication), plus the count of app-owned
    /// rows whose attributes do not decode to a valid binding.
    func inventory() throws -> SecureEnclaveCustodyHandleInventory

    /// Delete the blob for a reference. Missing rows throw `.privateHandleMissing`.
    func deleteKey(reference: SecureEnclaveCustodyHandleReference) throws

    /// Delete every row in one tier/role namespace, including rows whose
    /// attributes no longer decode. Tolerates an already-empty namespace.
    func deleteAllKeys(tier: SecureEnclaveCustodyTier, role: PGPPrivateOperationRole) throws
}
