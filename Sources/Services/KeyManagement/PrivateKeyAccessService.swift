import Foundation
import LocalAuthentication

/// Owns Secure Enclave reconstruction and secret-certificate-material unwrap for callers.
final class PrivateKeyAccessService {
    private let secureEnclave: any SecureEnclaveManageable
    private let bundleStore: KeyBundleStore
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator

    /// Returns the primary-key fingerprint (lowercase hex) of unwrapped
    /// secret-certificate material. Injected so the service stays free of the
    /// UniFFI engine and remains mock-testable; production wires it to
    /// `PGPKeyOperationAdapter.certificatePrimaryFingerprintInspector()`.
    private let certificatePrimaryFingerprint: @Sendable (Data) throws -> String

    init(
        secureEnclave: any SecureEnclaveManageable,
        bundleStore: KeyBundleStore,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        certificatePrimaryFingerprint: @escaping @Sendable (Data) throws -> String
    ) {
        self.secureEnclave = secureEnclave
        self.bundleStore = bundleStore
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.certificatePrimaryFingerprint = certificatePrimaryFingerprint
    }

    /// Triggers device authentication and returns the unwrapped secret certificate material.
    /// Callers must zeroize the returned data after use.
    ///
    /// `authenticationContext`: a pre-authenticated subsystem-B `LAContext` to
    /// consume for the Secure Enclave reconstruction instead of the implicit
    /// system prompt. Production modify-expiry can authenticate once and thread
    /// the same context into its short unwrap and rewrap windows on supported
    /// app platforms. `nil` keeps implicit authentication for callers that
    /// intentionally leave pre-authentication unwired.
    /// The caller retains ownership and invalidates the context after its action.
    func unwrapPrivateKey(
        fingerprint: String,
        authenticationContext: LAContext? = nil
    ) async throws -> Data {
        try await authenticationPromptCoordinator.withOperationPrompt(source: "privateKey.unwrap") {
            let bundle = try bundleStore.loadBundle(fingerprint: fingerprint)

            // Reconstruct + unwrap run OFF the main actor. `reconstructKey` is a
            // SYNCHRONOUS, blocking Secure Enclave biometric; if it ran on the main
            // actor it would block the main thread, so the `.inactive`/`.active`
            // scene transitions the biometric sheet causes would only be delivered
            // AFTER `endOperationPrompt` reset the operation-prompt depth to 0. The
            // app-session lifecycle gate would then never observe the operation
            // in-progress and would mistake the transient blip for a real app
            // backgrounding — under grace period "Immediately" (0) that clears
            // content and shows a spurious second prompt. Running it off-main frees
            // the main actor so `.inactive` is observed while the operation-prompt
            // depth is still > 0, letting the existing gate suppression engage.
            // `loadBundle` above stays on-main: it is a plain Keychain read with no
            // biometric, so it does not block.
            return try await Self.reconstructAndUnwrapOffMainActor(
                secureEnclave: secureEnclave,
                bundle: bundle,
                fingerprint: fingerprint,
                authenticationContext: AuthenticationContextCarrier(context: authenticationContext),
                certificatePrimaryFingerprint: certificatePrimaryFingerprint
            )
        }
    }

    /// Moves an optional caller-authenticated `LAContext` into the off-main
    /// Secure Enclave reconstruction. `LAContext` is intentionally non-Sendable;
    /// this carrier crosses the actor boundary without copying, the context is
    /// consumed by exactly one SE operation here, and the caller invalidates it
    /// after its action completes (the same pattern `AuthenticationManager` uses
    /// for its `LAContext` reply callbacks).
    private struct AuthenticationContextCarrier: @unchecked Sendable {
        let context: LAContext?
    }

    /// Performs the Secure Enclave reconstruct + unwrap off the main actor.
    ///
    /// `@concurrent` hops this work to the cooperative pool so the synchronous,
    /// blocking biometric inside `reconstructKey` does not stall the main actor — see
    /// the rationale in `unwrapPrivateKey`. The `SEKeyHandle` is created and consumed
    /// here so it never crosses the actor boundary; only `Sendable` `Data` crosses.
    /// The returned bytes are secret-certificate material and must be zeroized by the
    /// caller (unchanged from the in-line implementation).
    @concurrent
    private static func reconstructAndUnwrapOffMainActor(
        secureEnclave: any SecureEnclaveManageable,
        bundle: WrappedKeyBundle,
        fingerprint: String,
        authenticationContext: AuthenticationContextCarrier,
        certificatePrimaryFingerprint: @escaping @Sendable (Data) throws -> String
    ) async throws -> Data {
        let seKeyData = try PrivateKeyEnvelopeCodec.seKeyData(
            from: bundle.envelope,
            expectedFingerprint: fingerprint
        )
        let handle = try secureEnclave.reconstructKey(
            from: seKeyData,
            authenticationContext: authenticationContext.context
        )

        var unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)

        // Custody-integrity gate: the envelope's AES-GCM tag and device binding
        // prove the wrapped bytes were sealed by this device, but NOT that they
        // hold the certificate the caller asked for. A tampered bundle (its
        // envelope re-sealing a DIFFERENT identity's secret certificate under
        // the requested fingerprint's keychain row) would unwrap cleanly here
        // and then be handed to a signing/decryption/export consumer as if it
        // were `fingerprint`. Bind the unwrapped material's own primary
        // fingerprint to the requested identity before returning; on mismatch —
        // or if the material does not parse as a certificate at all — zeroize
        // and fail closed. This is the single chokepoint every software
        // secret-certificate consumer funnels through.
        do {
            let unwrappedFingerprint = try certificatePrimaryFingerprint(unwrapped)
            guard unwrappedFingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame else {
                unwrapped.resetBytes(in: 0..<unwrapped.count)
                throw CypherAirError.keyOperationUnavailable(
                    category: .publicCertificateAssociationMismatch
                )
            }
            return unwrapped
        } catch let error as CypherAirError {
            throw error
        } catch {
            unwrapped.resetBytes(in: 0..<unwrapped.count)
            throw CypherAirError.keyOperationUnavailable(
                category: .publicCertificateAssociationMismatch
            )
        }
    }
}
