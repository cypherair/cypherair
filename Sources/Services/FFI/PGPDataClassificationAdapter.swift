import Foundation

/// The OpenPGP object a blob of bytes holds.
enum PGPDataKind: Equatable, Sendable {
    case publicCertificate
    case secretKey
    case ciphertext
    /// A signed message carrying the data it signs, so verifying it needs
    /// nothing else.
    case signedMessage
    /// A bare signature over data held somewhere else.
    case detachedSignature
    case revocationCertificate
}

/// FFI-owned classification of bytes whose kind the app has not been told.
///
/// Input that arrives named rather than chosen — a document the system asks the
/// app to open — carries an extension its producer picked and packets that may
/// say something else. This is where the packets get to answer, through the same
/// parser every other route uses.
///
/// The engine is constructed here rather than injected, as in
/// `PGPMessageFormatAdapter`. An injectable engine would be a seam through which
/// a test double could report a kind the real parser does not read, and a
/// content-decides-not-the-name rule proved against a double proves nothing. The
/// call is stateless and touches no custody, so there is nothing to substitute
/// for either.
enum PGPDataClassificationAdapter {
    /// What `data` holds, read from its packets.
    ///
    /// Throws when the bytes are not OpenPGP, or hold something no route acts
    /// on.
    static func kind(of data: Data) throws -> PGPDataKind {
        do {
            return PGPDataKind(try PgpEngine().classifyOpenpgpData(data: data))
        } catch {
            throw PGPErrorMapper.map(error) { .corruptData(reason: $0) }
        }
    }
}

private extension PGPDataKind {
    init(_ kind: OpenPgpDataKind) {
        switch kind {
        case .publicCertificate:
            self = .publicCertificate
        case .secretKey:
            self = .secretKey
        case .ciphertext:
            self = .ciphertext
        case .signedMessage:
            self = .signedMessage
        case .detachedSignature:
            self = .detachedSignature
        case .revocationCertificate:
            self = .revocationCertificate
        }
    }
}
