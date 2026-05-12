import Foundation
import Security

/// Storage namespace for SE-wrapped key bundles.
enum KeyBundleNamespace: Equatable, Sendable {
    case permanent
    case pending
}

/// Receipt for bundle items created by one save operation.
struct KeyBundleWriteReceipt: Equatable, Sendable {
    let fingerprint: String
    let namespace: KeyBundleNamespace
    let services: [String]
}

/// Availability state for a three-item wrapped key bundle.
enum KeyBundleState: Equatable {
    case missing
    case partial
    case complete
}

/// Shared Keychain-backed storage for SE-wrapped key bundles.
/// Handles write rollback, pending promotion, and bundle state inspection.
struct KeyBundleStore {
    private let keychain: any KeychainManageable

    init(keychain: any KeychainManageable) {
        self.keychain = keychain
    }

    func loadBundle(
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws -> WrappedKeyBundle {
        let services = serviceNames(for: fingerprint, namespace: namespace)
        return WrappedKeyBundle(
            seKeyData: try keychain.load(
                service: services.seKey,
                account: KeychainConstants.defaultAccount
            ),
            salt: try keychain.load(
                service: services.salt,
                account: KeychainConstants.defaultAccount
            ),
            sealedBox: try keychain.load(
                service: services.sealed,
                account: KeychainConstants.defaultAccount
            )
        )
    }

    /// Save all three bundle items, rolling back on partial failure.
    func saveBundle(
        _ bundle: WrappedKeyBundle,
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws {
        _ = try saveNewBundle(bundle, fingerprint: fingerprint, namespace: namespace)
    }

    /// Save all three bundle items and return a receipt for the items created by this call.
    func saveNewBundle(
        _ bundle: WrappedKeyBundle,
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws -> KeyBundleWriteReceipt {
        let services = serviceNames(for: fingerprint, namespace: namespace)
        var savedServices: [String] = []

        do {
            try keychain.save(
                bundle.seKeyData,
                service: services.seKey,
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
            savedServices.append(services.seKey)

            try keychain.save(
                bundle.salt,
                service: services.salt,
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
            savedServices.append(services.salt)

            try keychain.save(
                bundle.sealedBox,
                service: services.sealed,
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
            savedServices.append(services.sealed)
            return KeyBundleWriteReceipt(
                fingerprint: fingerprint,
                namespace: namespace,
                services: savedServices
            )
        } catch {
            rollback(
                KeyBundleWriteReceipt(
                    fingerprint: fingerprint,
                    namespace: namespace,
                    services: savedServices
                )
            )
            throw error
        }
    }

    /// Best-effort rollback of only the items created by the matching save operation.
    func rollback(_ receipt: KeyBundleWriteReceipt) {
        for service in receipt.services {
            try? keychain.delete(service: service, account: KeychainConstants.defaultAccount)
        }
    }

    /// Delete the three bundle items in sequence.
    /// Used when we want failures to surface to the caller.
    func deleteBundle(
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws {
        let services = serviceNames(for: fingerprint, namespace: namespace)
        try keychain.delete(service: services.seKey, account: KeychainConstants.defaultAccount)
        try keychain.delete(service: services.salt, account: KeychainConstants.defaultAccount)
        try keychain.delete(service: services.sealed, account: KeychainConstants.defaultAccount)
    }

    /// Delete the three bundle items, ignoring only item-not-found errors.
    /// Any other delete failure is surfaced to the caller.
    func deleteBundleAllowingMissing(
        fingerprint: String,
        namespace: KeyBundleNamespace = .permanent
    ) throws {
        let services = serviceNames(for: fingerprint, namespace: namespace)
        for service in [services.seKey, services.salt, services.sealed] {
            do {
                try keychain.delete(service: service, account: KeychainConstants.defaultAccount)
            } catch {
                guard Self.isItemNotFound(error) else {
                    throw error
                }
            }
        }
    }

    /// Promote a complete pending bundle into the permanent namespace.
    /// Permanent writes are rolled back on partial failure to preserve pending-only state.
    func promotePendingToPermanent(
        fingerprint: String,
        seKeyAccessControl: SecAccessControl? = nil
    ) throws {
        let pending = try loadBundle(fingerprint: fingerprint, namespace: .pending)
        try persistPermanentBundle(
            pending,
            fingerprint: fingerprint,
            seKeyAccessControl: seKeyAccessControl
        )
        cleanupPendingBundle(fingerprint: fingerprint)
    }

    /// Replace any residual permanent bundle items with the complete pending bundle.
    /// Residual permanent entries are deleted first, tolerating only item-not-found.
    func replacePermanentWithPending(
        fingerprint: String,
        seKeyAccessControl: SecAccessControl? = nil
    ) throws {
        let pending = try loadBundle(fingerprint: fingerprint, namespace: .pending)
        try deleteBundleAllowingMissing(fingerprint: fingerprint, namespace: .permanent)
        try persistPermanentBundle(
            pending,
            fingerprint: fingerprint,
            seKeyAccessControl: seKeyAccessControl
        )
        cleanupPendingBundle(fingerprint: fingerprint)
    }

    private func persistPermanentBundle(
        _ bundle: WrappedKeyBundle,
        fingerprint: String,
        seKeyAccessControl: SecAccessControl?
    ) throws {
        let permanentServices = serviceNames(for: fingerprint, namespace: .permanent)
        var savedPermanentServices: [String] = []

        do {
            try keychain.save(
                bundle.seKeyData,
                service: permanentServices.seKey,
                account: KeychainConstants.defaultAccount,
                accessControl: seKeyAccessControl
            )
            savedPermanentServices.append(permanentServices.seKey)

            try keychain.save(
                bundle.salt,
                service: permanentServices.salt,
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
            savedPermanentServices.append(permanentServices.salt)

            try keychain.save(
                bundle.sealedBox,
                service: permanentServices.sealed,
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            for service in savedPermanentServices {
                try? keychain.delete(service: service, account: KeychainConstants.defaultAccount)
            }
            throw error
        }
    }

    /// Best-effort cleanup of pending bundle items.
    func cleanupPendingBundle(fingerprint: String) {
        let services = serviceNames(for: fingerprint, namespace: .pending)
        try? keychain.delete(service: services.seKey, account: KeychainConstants.defaultAccount)
        try? keychain.delete(service: services.salt, account: KeychainConstants.defaultAccount)
        try? keychain.delete(service: services.sealed, account: KeychainConstants.defaultAccount)
    }

    func bundleState(
        fingerprint: String,
        namespace: KeyBundleNamespace
    ) -> KeyBundleState {
        let services = serviceNames(for: fingerprint, namespace: namespace)
        let account = KeychainConstants.defaultAccount

        let exists = [
            keychain.exists(service: services.seKey, account: account),
            keychain.exists(service: services.salt, account: account),
            keychain.exists(service: services.sealed, account: account)
        ]

        if exists.allSatisfy({ !$0 }) {
            return .missing
        }
        if exists.allSatisfy({ $0 }) {
            return .complete
        }
        return .partial
    }

    private func serviceNames(
        for fingerprint: String,
        namespace: KeyBundleNamespace
    ) -> (seKey: String, salt: String, sealed: String) {
        switch namespace {
        case .permanent:
            return (
                KeychainConstants.seKeyService(fingerprint: fingerprint),
                KeychainConstants.saltService(fingerprint: fingerprint),
                KeychainConstants.sealedKeyService(fingerprint: fingerprint)
            )
        case .pending:
            return (
                KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                KeychainConstants.pendingSaltService(fingerprint: fingerprint),
                KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint)
            )
        }
    }

    private static func isItemNotFound(_ error: Error) -> Bool {
        if let keychainError = error as? KeychainError,
           case .itemNotFound = keychainError {
            return true
        }
        if let mockError = error as? MockKeychainError,
           case .itemNotFound = mockError {
            return true
        }
        return false
    }
}
