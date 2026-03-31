import Foundation
import Security

/// Storage namespace for SE-wrapped key bundles.
enum KeyBundleNamespace {
    case permanent
    case pending
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
        let services = serviceNames(for: fingerprint, namespace: namespace)

        do {
            try keychain.save(
                bundle.seKeyData,
                service: services.seKey,
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            throw error
        }

        do {
            try keychain.save(
                bundle.salt,
                service: services.salt,
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            try? keychain.delete(
                service: services.seKey,
                account: KeychainConstants.defaultAccount
            )
            throw error
        }

        do {
            try keychain.save(
                bundle.sealedBox,
                service: services.sealed,
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
        } catch {
            try? keychain.delete(
                service: services.seKey,
                account: KeychainConstants.defaultAccount
            )
            try? keychain.delete(
                service: services.salt,
                account: KeychainConstants.defaultAccount
            )
            throw error
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

    /// Promote a complete pending bundle into the permanent namespace.
    /// Permanent writes are rolled back on partial failure to preserve pending-only state.
    func promotePendingToPermanent(
        fingerprint: String,
        seKeyAccessControl: SecAccessControl? = nil
    ) throws {
        let pending = try loadBundle(fingerprint: fingerprint, namespace: .pending)
        let permanentServices = serviceNames(for: fingerprint, namespace: .permanent)

        var savedPermanentServices: [String] = []

        do {
            try keychain.save(
                pending.seKeyData,
                service: permanentServices.seKey,
                account: KeychainConstants.defaultAccount,
                accessControl: seKeyAccessControl
            )
            savedPermanentServices.append(permanentServices.seKey)

            try keychain.save(
                pending.salt,
                service: permanentServices.salt,
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
            savedPermanentServices.append(permanentServices.salt)

            try keychain.save(
                pending.sealedBox,
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

        cleanupPendingBundle(fingerprint: fingerprint)
    }

    /// Best-effort cleanup of pending bundle items.
    func cleanupPendingBundle(fingerprint: String) {
        let services = serviceNames(for: fingerprint, namespace: .pending)
        try? keychain.delete(service: services.seKey, account: KeychainConstants.defaultAccount)
        try? keychain.delete(service: services.salt, account: KeychainConstants.defaultAccount)
        try? keychain.delete(service: services.sealed, account: KeychainConstants.defaultAccount)
    }

    /// Best-effort cleanup of permanent bundle items.
    func rollbackPermanentBundle(fingerprint: String) {
        let services = serviceNames(for: fingerprint, namespace: .permanent)
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
}
