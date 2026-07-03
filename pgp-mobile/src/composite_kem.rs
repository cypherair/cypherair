//! Vendored RFC 9980 KEM key combiner for split-custody composite decryption.
//!
//! Byte-exact port of `multi_key_combine` from sequoia-openpgp 2.4.0
//! (`src/crypto/asymmetric.rs`), which is `pub(crate)` upstream and therefore
//! unreachable from this crate. Upstream export has been requested
//! (<https://gitlab.com/sequoia-pgp/sequoia/-/issues/1249>); delete this module
//! and call Sequoia's implementation once a release exports it.
//!
//! Only the ML-KEM-768 + X25519 tier (algorithm 35) is supported: the
//! Device-Bound Post-Quantum family never uses the 87/1024 tier because
//! CryptoKit's Secure Enclave does not offer X448/Ed448 classical components.
//!
//! See RFC 9980, Section 4.2.1 (KEM key combiner).

use sequoia_openpgp as openpgp;

use openpgp::crypto::{ecdh, SessionKey};
use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};

pub(crate) const MLKEM768_KEY_SHARE_LENGTH: usize = 32;

/// Combine the ML-KEM-768 and X25519 key shares into the AES-256 key
/// encryption key.
///
/// ```text
/// KEK = SHA3-256(
///           mlkemKeyShare || ecdhKeyShare ||
///           ecdhCipherText || ecdhPublicKey ||
///           algId || domSep || len(domSep)
///       )
/// ```
pub(crate) fn multi_key_combine_mlkem768_x25519(
    mlkem_key_share: &[u8],
    ecdh_key_share: &[u8],
    ecdh_ciphertext: &[u8],
    ecdh_public_key: &[u8],
) -> openpgp::Result<SessionKey> {
    let mut hash = HashAlgorithm::SHA3_256.context()?.for_digest();
    hash.update(mlkem_key_share);
    hash.update(ecdh_key_share);
    hash.update(ecdh_ciphertext);
    hash.update(ecdh_public_key);
    hash.update(&[PublicKeyAlgorithm::MLKEM768_X25519.into()]);
    // Domain separation and length octet.
    hash.update(b"OpenPGPCompositeKDFv1\x15");

    let mut kek = SessionKey::from(vec![0; 32]);
    hash.digest(&mut kek)?;
    Ok(kek)
}

/// Unwrap the RFC 3394-wrapped session key with the combined KEK.
///
/// RFC 9980 fixes the key wrap algorithm for composite KEM recipients at
/// AES-256, independent of the message's session-key cipher.
pub(crate) fn unwrap_session_key(
    kek: &SessionKey,
    wrapped_session_key: &[u8],
) -> openpgp::Result<SessionKey> {
    Ok(ecdh::aes_key_unwrap(
        SymmetricAlgorithm::AES256,
        kek.as_protected(),
        wrapped_session_key,
    )?
    .into())
}
