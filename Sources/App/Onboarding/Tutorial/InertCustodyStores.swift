import Foundation
import LocalAuthentication

/// Inert, fail-closed Secure Enclave custody seams for the tutorial sandbox.
///
/// The guided tutorial offers only software (portable) key families, so the
/// sandbox service graph must never reach real device-bound custody state.
/// Wiring these conformances instead of the `System*` custody stores makes
/// that isolation hold by construction: the sandbox holds no custody rows,
/// reports an empty inventory, and every private custody operation fails
/// closed with `SecureEnclaveCustodyHandleError.hardwareUnavailable`.
struct InertCustodyKeyStore: SecureEnclaveCustodyKeyStoring {
    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        throw SecureEnclaveCustodyHandleError.hardwareUnavailable
    }

    func loadKey(
        reference: SecureEnclaveCustodyHandleReference,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle? {
        nil
    }

    func inventory() throws -> SecureEnclaveCustodyHandleInventory {
        .empty
    }

    func deleteKey(reference: SecureEnclaveCustodyHandleReference) throws {
        throw SecureEnclaveCustodyHandleError.privateHandleMissing(reference.role)
    }

    func deleteAllKeys(tier: SecureEnclaveCustodyTier, role: PGPPrivateOperationRole) throws {
        // The inert namespace is always empty; deleting nothing succeeds,
        // matching the protocol's tolerate-empty contract.
    }
}

struct InertCustodyDigestSigner: SecureEnclaveCustodyDigestSigning {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        throw SecureEnclaveCustodyHandleError.hardwareUnavailable
    }
}

struct InertCustodyKeyAgreement: SecureEnclaveCustodyKeyAgreement {
    func deriveSharedSecret(
        request: ExternalP256KeyAgreementRequest,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSharedSecret {
        throw SecureEnclaveCustodyHandleError.hardwareUnavailable
    }
}

struct InertCustodyCompositeOperations: SecureEnclaveCompositeSigning, SecureEnclaveCompositeDecapsulating {
    func signMlDsa65Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> Data {
        throw SecureEnclaveCustodyHandleError.hardwareUnavailable
    }

    func signMlDsa87Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> Data {
        throw SecureEnclaveCustodyHandleError.hardwareUnavailable
    }

    func decapsulateMlKem768(
        request: ExternalMlKem768DecapsulationRequest,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> Data {
        throw SecureEnclaveCustodyHandleError.hardwareUnavailable
    }

    func decapsulateMlKem1024(
        request: ExternalMlKem1024DecapsulationRequest,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> Data {
        throw SecureEnclaveCustodyHandleError.hardwareUnavailable
    }
}
