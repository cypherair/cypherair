import Foundation
import Sealing
import Vault

/// A secret sealed against the identity wrapping key as a value, for the
/// caller to keep inside the sealed key list: a portable key's secret key
/// packets, or a post-quantum key's classical halves. Sealing is software;
/// opening is one enclave operation under the operation's approval.
public enum SealedSecret {
    public enum Kind: Sendable {
        case secretKeys
        case classicalHalves

        var payloadKind: SealedPayloadKind {
            switch self {
            case .secretKeys: .secretKeys
            case .classicalHalves: .splitCustodyComponent
            }
        }
    }

    /// A constant: the key list binds each value to its entry, and the engine
    /// refuses a secret that does not belong to the certificate.
    static let associatedData = Data()

    public static func seal(_ secret: borrowing SensitiveBuffer, kind: Kind, session: UnlockedSession) throws(StoreError) -> Data {
        let envelope: EnclaveSealedEnvelope
        do {
            envelope = try session.sealForIdentity(plaintext: secret, kind: kind.payloadKind, associatedData: associatedData)
        } catch {
            throw .vault(error)
        }
        do { return try EnclaveSealedEnvelopeCodec.encode(envelope) } catch { throw .internalFailure("envelope encoding failed") }
    }

    /// Checks, without any prompt, that `open` can be tried: the value decodes,
    /// has the kind, and is sealed to this session's identity wrapping key. A
    /// value that passes can still fail to open if its ciphertext was changed.
    public static func check(_ sealed: Data, kind: Kind, session: UnlockedSession) throws(StoreError) {
        guard envelope(of: sealed, kind: kind, session: session) != nil else { throw .damaged }
    }

    /// Opens a value made by `seal` with the same kind. A value of another kind,
    /// or one this vault did not seal, is `damaged`. Blocking.
    public static func open(_ sealed: Data, kind: Kind, approval: OperationApproval) throws(StoreError) -> SensitiveBuffer {
        guard let envelope = envelope(of: sealed, kind: kind, session: approval.session) else { throw .damaged }
        do {
            return try approval.session.openIdentityEnvelope(envelope, kind: kind.payloadKind, approval: approval)
        } catch {
            switch error {
            case .doesNotOpen: throw .damaged
            case .vault(let error): throw .vault(error)
            }
        }
    }

    private static func envelope(of sealed: Data, kind: Kind, session: UnlockedSession) -> EnclaveSealedEnvelope? {
        guard let envelope = try? EnclaveSealedEnvelopeCodec.decode(sealed, expectedKind: kind.payloadKind),
              envelope.associatedData == associatedData,
              envelope.sealingKeyBlob == session.identityWrappingKeyBlob,
              envelope.sealingPublicKeyX963 == session.identityWrappingPublicKeyX963 else {
            return nil
        }
        return envelope
    }
}
