import Foundation
import LocalAuthentication
import Sealing
import Stores
import Vault

/// Opens a portable key's secret certificate for one operation: one enclave
/// agreement with the identity wrapping key under the caller's context.
final class PrivateKeyAccessService {
    private let vault: AppVault
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let certificatePrimaryFingerprint: @Sendable (Data) throws -> String

    init(
        vault: AppVault,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        certificatePrimaryFingerprint: @escaping @Sendable (Data) throws -> String
    ) {
        self.vault = vault
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.certificatePrimaryFingerprint = certificatePrimaryFingerprint
    }

    /// Prompts for presence through the enclave and returns the secret
    /// certificate. Callers zeroize the returned data after use. A caller that
    /// already holds an authenticated context for this operation passes it.
    func unwrapPrivateKey(fingerprint: String, authenticationContext: LAContext? = nil) async throws -> Data {
        try await authenticationPromptCoordinator.withOperationPrompt {
            let session = try vault.requireSession()
            let context = authenticationContext ?? session.operationContext()
            return try await Self.openOffMainActor(
                store: vault.portableKeys,
                session: session,
                fingerprint: fingerprint,
                context: OperationContextCarrier(context: context),
                certificatePrimaryFingerprint: certificatePrimaryFingerprint
            )
        }
    }

    @concurrent
    private static func openOffMainActor(
        store: IdentityEnvelopeStore,
        session: UnlockedSession,
        fingerprint: String,
        context: OperationContextCarrier,
        certificatePrimaryFingerprint: @escaping @Sendable (Data) throws -> String
    ) async throws -> Data {
        var unwrapped: Data
        do {
            unwrapped = try store.open(fingerprint: fingerprint, session: session, context: context.context).withUnsafeBytes { Data($0) }
        } catch {
            throw CypherAirError.fromStore(error)
        }
        do {
            let actual = try certificatePrimaryFingerprint(unwrapped)
            guard actual.caseInsensitiveCompare(fingerprint) == .orderedSame else {
                throw CypherAirError.keyOperationUnavailable(category: .publicCertificateAssociationMismatch)
            }
            return unwrapped
        } catch let error as CypherAirError {
            unwrapped.resetBytes(in: 0..<unwrapped.count)
            throw error
        } catch {
            unwrapped.resetBytes(in: 0..<unwrapped.count)
            throw CypherAirError.keyOperationUnavailable(category: .publicCertificateAssociationMismatch)
        }
    }
}

/// Carries a context into work that runs off the caller's actor; consumed by
/// exactly one operation and invalidated by its owner afterwards.
struct OperationContextCarrier: @unchecked Sendable {
    let context: LAContext
}
