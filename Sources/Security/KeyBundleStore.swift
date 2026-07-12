import Foundation
import Security

/// Storage namespace for SE-wrapped key bundles.
enum KeyBundleNamespace: Equatable, Sendable {
    case permanent
    case pending
}

/// Receipt for the bundle row created by one save operation.
struct KeyBundleWriteReceipt: Equatable, Sendable {
    let services: [String]
}

/// Availability state for a wrapped key bundle.
///
/// The bundle is a single self-contained `PrivateKeyEnvelope` row, so `bundleState`
/// only ever returns `.missing` or `.complete`. `.partial` is retained so the
/// interrupted-rewrap recovery coordinators stay exhaustive and fail closed if a
/// future storage shape can ever observe a partial row.
enum KeyBundleState: Equatable {
    case missing
    case partial
    case complete
}

/// Shared Keychain-backed storage for the single-row SE-wrapped key bundle.
/// Handles pending promotion, residual replacement, and bundle state inspection.
struct KeyBundleStore {
    private let keychain: any KeychainManageable

    init(keychain: any KeychainManageable) {
        self.keychain = keychain
    }

    func loadBundle(
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws -> WrappedKeyBundle {
        let service = serviceName(for: fingerprint, namespace: namespace)
        return WrappedKeyBundle(
            envelope: try keychain.load(
                service: service,
                account: KeychainConstants.defaultAccount
            )
        )
    }

    /// Save the bundle row.
    func saveBundle(
        _ bundle: WrappedKeyBundle,
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws {
        _ = try saveNewBundle(bundle, fingerprint: fingerprint, namespace: namespace)
    }

    /// Save the bundle row and return a receipt for the item created by this call.
    /// A single Keychain write is atomic: it either persists the row or throws with
    /// nothing written, so there is no intra-bundle partial state to roll back.
    func saveNewBundle(
        _ bundle: WrappedKeyBundle,
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws -> KeyBundleWriteReceipt {
        let service = serviceName(for: fingerprint, namespace: namespace)
        try keychain.save(
            bundle.envelope,
            service: service,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        return KeyBundleWriteReceipt(
            services: [service]
        )
    }

    /// Best-effort rollback of the item created by the matching save operation.
    /// Used when a later, unrelated commit step fails after the bundle was stored.
    func rollback(_ receipt: KeyBundleWriteReceipt) {
        for service in receipt.services {
            try? keychain.delete(service: service, account: KeychainConstants.defaultAccount)
        }
    }

    /// Delete the bundle row. Used when we want failures to surface to the caller.
    func deleteBundle(
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws {
        let service = serviceName(for: fingerprint, namespace: namespace)
        try keychain.delete(service: service, account: KeychainConstants.defaultAccount)
    }

    /// Delete the bundle row, ignoring only item-not-found errors.
    /// Any other delete failure is surfaced to the caller.
    func deleteBundleAllowingMissing(
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws {
        let service = serviceName(for: fingerprint, namespace: namespace)
        do {
            try keychain.delete(service: service, account: KeychainConstants.defaultAccount)
        } catch {
            guard Self.isItemNotFound(error) else {
                throw error
            }
        }
    }

    /// Promote a complete pending bundle into the permanent namespace.
    func promotePendingToPermanent(fingerprint: String) throws {
        let pending = try loadBundle(fingerprint: fingerprint, namespace: .pending)
        try persistPermanentBundle(pending, fingerprint: fingerprint)
        cleanupPendingBundle(fingerprint: fingerprint)
    }

    /// Replace any residual permanent bundle row with the complete pending bundle.
    /// The residual permanent entry is deleted first, tolerating only item-not-found.
    func replacePermanentWithPending(fingerprint: String) throws {
        let pending = try loadBundle(fingerprint: fingerprint, namespace: .pending)
        try deleteBundleAllowingMissing(fingerprint: fingerprint, namespace: .permanent)
        try persistPermanentBundle(pending, fingerprint: fingerprint)
        cleanupPendingBundle(fingerprint: fingerprint)
    }

    private func persistPermanentBundle(
        _ bundle: WrappedKeyBundle,
        fingerprint: String
    ) throws {
        try keychain.save(
            bundle.envelope,
            service: serviceName(for: fingerprint, namespace: .permanent),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
    }

    /// Best-effort cleanup of the pending bundle row.
    func cleanupPendingBundle(fingerprint: String) {
        let service = serviceName(for: fingerprint, namespace: .pending)
        try? keychain.delete(service: service, account: KeychainConstants.defaultAccount)
    }

    func bundleState(
        fingerprint: String,
        namespace: KeyBundleNamespace
    ) -> KeyBundleState {
        let service = serviceName(for: fingerprint, namespace: namespace)
        let exists = keychain.exists(
            service: service,
            account: KeychainConstants.defaultAccount
        )
        return exists ? .complete : .missing
    }

    private func serviceName(
        for fingerprint: String,
        namespace: KeyBundleNamespace
    ) -> String {
        switch namespace {
        case .permanent:
            return KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint)
        case .pending:
            return KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint)
        }
    }

    private static func isItemNotFound(_ error: Error) -> Bool {
        KeychainFailureClassifier.isItemNotFound(error)
    }
}
