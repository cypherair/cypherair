import Foundation

/// How long a key stays valid, as the app states it to the engine.
///
/// There is no unspecified case, on either side of the FFI: a key that is to
/// have no expiry says so, and the engine writes no expiration rather than
/// choosing a term nobody asked for. Anything that carries an expiry between the
/// app and the engine carries this.
enum PGPKeyValidity: Hashable, Sendable {
    case never
    case expiresIn(seconds: UInt64)
}
