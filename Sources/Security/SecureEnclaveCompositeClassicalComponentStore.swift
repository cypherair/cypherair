import Foundation
import LocalAuthentication
import Security

/// Custody for the classical (Ed25519 + X25519) component secrets of a
/// Device-Bound Post-Quantum identity. The post-quantum halves live in the
/// Secure Enclave (`SecureEnclaveCompositeHandleStore`); this store holds the
/// classical halves, which alone can neither sign nor decrypt anything —
/// every composite operation additionally requires the enclave-resident
/// ML-DSA/ML-KEM component (docs/POST_QUANTUM.md §3).
///
/// The two 32-byte scalars are concatenated and sealed with the existing
/// per-identity Secure Enclave envelope (ephemeral×static ECDH → HKDF-SHA256 →
/// AES-GCM). The wrapping key uses FIXED biometric access — never the app's
/// mode-dependent wrapping key — so the classical component is exempt from
/// Standard/High-Security mode-switch re-wrap, coherent with the enclave
/// handles it accompanies.
///
/// SECURITY-CRITICAL: raw component secrets are handled here. All plaintext
/// buffers are zeroized after use. See docs/SECURITY.md Section 10.
struct SecureEnclaveCompositeClassicalComponentStore {
    static let componentSecretLength = 32
    private static let concatenatedLength = componentSecretLength * 2

    private let secureEnclave: any SecureEnclaveManageable
    private let bundleStore: KeyBundleStore

    init(
        secureEnclave: any SecureEnclaveManageable,
        bundleStore: KeyBundleStore
    ) {
        self.secureEnclave = secureEnclave
        self.bundleStore = bundleStore
    }

    /// Seal `eddsaSecret || ecdhSecret` under a fresh fixed-access Secure
    /// Enclave wrapping key and persist the envelope for `fingerprint`.
    /// Both input buffers are zeroized before returning.
    func store(
        fingerprint: String,
        eddsaSecret: inout Data,
        ecdhSecret: inout Data
    ) throws -> KeyBundleWriteReceipt {
        defer {
            eddsaSecret.resetBytes(in: 0..<eddsaSecret.count)
            ecdhSecret.resetBytes(in: 0..<ecdhSecret.count)
        }
        guard eddsaSecret.count == Self.componentSecretLength,
              ecdhSecret.count == Self.componentSecretLength else {
            throw CypherAirError.invalidKeyData(
                reason: "Composite classical component secrets must each be 32 bytes."
            )
        }

        var concatenated = Data()
        concatenated.reserveCapacity(Self.concatenatedLength)
        concatenated.append(eddsaSecret)
        concatenated.append(ecdhSecret)
        defer { concatenated.resetBytes(in: 0..<concatenated.count) }

        let accessControl = try Self.makeFixedAccessControl()
        let handle = try secureEnclave.generateWrappingKey(
            accessControl: accessControl,
            authenticationContext: nil
        )
        do {
            let bundle = try secureEnclave.wrap(
                privateKey: concatenated,
                using: handle,
                fingerprint: fingerprint
            )
            return try bundleStore.saveNewBundle(bundle, fingerprint: fingerprint)
        } catch {
            try? secureEnclave.deleteKey(handle)
            throw error
        }
    }

    /// Unwrap and return the classical component for `fingerprint`. Triggers a
    /// Secure Enclave biometric unless `authenticationContext` is pre-authenticated.
    /// The caller MUST zeroize both returned buffers after use.
    func load(
        fingerprint: String,
        authenticationContext: LAContext?
    ) throws -> ClassicalComponent {
        let bundle = try bundleStore.loadBundle(fingerprint: fingerprint)
        let seKeyData = try PrivateKeyEnvelopeCodec.seKeyData(
            from: bundle.envelope,
            expectedFingerprint: fingerprint
        )
        let handle = try secureEnclave.reconstructKey(
            from: seKeyData,
            authenticationContext: authenticationContext
        )
        var concatenated = try secureEnclave.unwrap(
            bundle: bundle,
            using: handle,
            fingerprint: fingerprint
        )
        defer { concatenated.resetBytes(in: 0..<concatenated.count) }
        guard concatenated.count == Self.concatenatedLength else {
            throw CypherAirError.invalidKeyData(
                reason: "Composite classical component envelope has an unexpected length."
            )
        }

        let eddsaSecret = concatenated.prefix(Self.componentSecretLength)
        let ecdhSecret = concatenated.suffix(Self.componentSecretLength)
        return ClassicalComponent(
            eddsaSecret: Data(eddsaSecret),
            ecdhSecret: Data(ecdhSecret)
        )
    }

    func delete(fingerprint: String) throws {
        let seKeyData: Data
        do {
            let bundle = try bundleStore.loadBundle(fingerprint: fingerprint)
            seKeyData = try PrivateKeyEnvelopeCodec.seKeyData(
                from: bundle.envelope,
                expectedFingerprint: fingerprint
            )
        } catch {
            if KeychainFailureClassifier.isItemNotFound(error) {
                return
            }
            throw error
        }
        // Best-effort wrapping-key teardown, then remove the envelope row.
        if let handle = try? secureEnclave.reconstructKey(from: seKeyData, authenticationContext: nil) {
            try? secureEnclave.deleteKey(handle)
        }
        try bundleStore.deleteBundle(fingerprint: fingerprint)
    }

    func rollback(_ receipt: KeyBundleWriteReceipt) {
        bundleStore.rollback(receipt)
    }

    /// One identity's classical component. A reference type so the router can
    /// hand it to a consumer through the route value and zeroize the single
    /// shared buffer when the operation window ends.
    final class ClassicalComponent {
        private(set) var eddsaSecret: Data
        private(set) var ecdhSecret: Data

        init(eddsaSecret: Data, ecdhSecret: Data) {
            self.eddsaSecret = eddsaSecret
            self.ecdhSecret = ecdhSecret
        }

        func zeroize() {
            eddsaSecret.resetBytes(in: 0..<eddsaSecret.count)
            ecdhSecret.resetBytes(in: 0..<ecdhSecret.count)
        }

        deinit {
            zeroize()
        }
    }

    private static func makeFixedAccessControl() throws -> SecAccessControl {
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
