import Foundation
import LocalAuthentication
import Security

/// Custody for the classical component secrets (Ed25519 + X25519, or Ed448 +
/// X448 for the · High tier) of a Device-Bound Post-Quantum identity. The
/// post-quantum halves live in the Secure Enclave
/// (`SecureEnclaveCustodyHandleStore`); this store holds the classical
/// halves, which alone can neither sign nor decrypt anything — every composite
/// operation additionally requires the enclave-resident ML-DSA/ML-KEM component
/// (docs/CUSTODY.md §6).
///
/// The two component scalars are concatenated and sealed as a
/// `.splitCustodyClassicalComponent` envelope (ephemeral×static ECDH →
/// HKDF-SHA256 → AES-GCM), in this store's own Keychain namespace. Their
/// lengths depend on the tier: a 32-byte Ed25519 + 32-byte X25519 pair for
/// `.postQuantum`, or a 57-byte Ed448 + 56-byte X448 pair for
/// `.postQuantumHigh`. The wrapping key uses FIXED biometric access — never
/// the app's mode-dependent wrapping key.
///
/// Nothing outside this store can reach the component: it is the only writer
/// and reader of its namespace, and the payload kind is authenticated in the
/// envelope binding, so a software-custody consumer handed one of these rows
/// fails closed instead of opening it (docs/CUSTODY.md §7).
///
/// SECURITY-CRITICAL: raw component secrets are handled here. All plaintext
/// buffers are zeroized after use. See docs/SECURITY.md Section 10.
struct SecureEnclaveCompositeClassicalComponentStore {
    private static let payloadKind = PrivateKeyEnvelopePayloadKind.splitCustodyClassicalComponent

    private let secureEnclave: any SecureEnclaveManageable
    private let keychain: any KeychainManageable

    init(
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable
    ) {
        self.secureEnclave = secureEnclave
        self.keychain = keychain
    }

    /// Seal `eddsaSecret || ecdhSecret` under a fresh fixed-access Secure
    /// Enclave wrapping key and persist the envelope for `fingerprint`.
    /// Both input buffers are zeroized before returning.
    func store(
        fingerprint: String,
        eddsaSecret: inout Data,
        ecdhSecret: inout Data,
        tier: SecureEnclaveCustodyTier
    ) throws {
        defer {
            eddsaSecret.resetBytes(in: 0..<eddsaSecret.count)
            ecdhSecret.resetBytes(in: 0..<ecdhSecret.count)
        }
        guard let lengths = tier.splitCustodyClassicalSecretLengths,
              eddsaSecret.count == lengths.signing,
              ecdhSecret.count == lengths.keyAgreement else {
            throw CypherAirError.invalidKeyData(
                reason: "Composite classical component secrets have an unexpected length."
            )
        }

        var concatenated = Data()
        concatenated.reserveCapacity(lengths.signing + lengths.keyAgreement)
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
                fingerprint: fingerprint,
                payloadKind: Self.payloadKind
            )
            try keychain.save(
                bundle.envelope,
                service: Self.service(for: fingerprint),
                account: KeychainConstants.defaultAccount,
                accessControl: nil
            )
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
        authenticationContext: LAContext?,
        tier: SecureEnclaveCustodyTier
    ) throws -> ClassicalComponent {
        guard let lengths = tier.splitCustodyClassicalSecretLengths else {
            throw CypherAirError.invalidKeyData(
                reason: "The requested custody tier has no classical component."
            )
        }
        let bundle = WrappedKeyBundle(
            envelope: try keychain.load(
                service: Self.service(for: fingerprint),
                account: KeychainConstants.defaultAccount
            )
        )
        let seKeyData = try PrivateKeyEnvelopeCodec.seKeyData(
            from: bundle.envelope,
            expectedFingerprint: fingerprint,
            expectedPayloadKind: Self.payloadKind
        )
        let handle = try secureEnclave.reconstructKey(
            from: seKeyData,
            authenticationContext: authenticationContext
        )
        var concatenated = try secureEnclave.unwrap(
            bundle: bundle,
            using: handle,
            fingerprint: fingerprint,
            payloadKind: Self.payloadKind
        )
        defer { concatenated.resetBytes(in: 0..<concatenated.count) }
        let eddsaLength = lengths.signing
        let ecdhLength = lengths.keyAgreement
        let concatenatedLength = eddsaLength + ecdhLength
        guard concatenated.count == concatenatedLength else {
            throw CypherAirError.invalidKeyData(
                reason: "Composite classical component envelope has an unexpected length."
            )
        }

        // Copy each half into freshly allocated storage that does not alias
        // `concatenated`, so the `defer` above zeroizes the real plaintext
        // buffer in place instead of copy-on-writing a fresh copy and leaving
        // the original intact.
        var eddsaSecret = Data(count: eddsaLength)
        var ecdhSecret = Data(count: ecdhLength)
        concatenated.withUnsafeBytes { raw in
            eddsaSecret.withUnsafeMutableBytes { destination in
                destination.copyBytes(from: raw[0..<eddsaLength])
            }
            ecdhSecret.withUnsafeMutableBytes { destination in
                destination.copyBytes(
                    from: raw[eddsaLength..<concatenatedLength]
                )
            }
        }
        return ClassicalComponent(eddsaSecret: eddsaSecret, ecdhSecret: ecdhSecret)
    }

    /// Whether a committed component exists for `fingerprint`. Non-prompting:
    /// row presence only, nothing is decoded or unwrapped.
    func componentExists(fingerprint: String) -> Bool {
        keychain.exists(
            service: Self.service(for: fingerprint),
            account: KeychainConstants.defaultAccount
        )
    }

    // Deletion of a committed classical component is handled by the shared
    // identity-deletion keychain-material path, which enumerates this store's
    // service name alongside the software envelope rows
    // (KeyMutationService.deleteAllPrivateKeychainMaterial). The wrapping key
    // lives only as `dataRepresentation` inside the envelope, so removing the
    // row destroys it — there is no separate teardown to perform.

    /// Best-effort removal of a component this generation attempt stored,
    /// used when a later step of the same attempt fails.
    func discardStoredComponent(fingerprint: String) {
        try? keychain.delete(
            service: Self.service(for: fingerprint),
            account: KeychainConstants.defaultAccount
        )
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

    private static func service(for fingerprint: String) -> String {
        KeychainConstants.splitCustodyClassicalComponentService(fingerprint: fingerprint)
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
