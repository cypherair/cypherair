//! Vendored RFC 9980 KEM key combiner for split-custody composite decryption.
//!
//! Byte-exact port of `multi_key_combine` from sequoia-openpgp 2.4.0
//! (`src/crypto/asymmetric.rs`), which is `pub(crate)` upstream and therefore
//! unreachable from this crate. Upstream export has been requested
//! (<https://gitlab.com/sequoia-pgp/sequoia/-/issues/1249>); delete this module
//! and call Sequoia's implementation once a release exports it.
//!
//! The combiner itself is algorithm-agnostic: it hashes the supplied key
//! shares, ciphertext, public key, and OpenPGP algorithm id, so both composite
//! KEM tiers share one construction. Two tiers are exercised here — ML-KEM-768
//! + X25519 (algorithm 35) for the Device-Bound Post-Quantum family and
//! ML-KEM-1024 + X448 (algorithm 36) for the Device-Bound Post-Quantum · High
//! family. In both, only the ML-KEM half is Secure Enclave-resident; the
//! classical (X25519 / X448) half is a software component, so the High tier is
//! not blocked by CryptoKit lacking X448/Ed448.
//!
//! See RFC 9980, Section 4.2.1 (KEM key combiner).

use sequoia_openpgp as openpgp;

use openpgp::crypto::{ecdh, SessionKey};
use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};

/// ML-KEM shared secrets are 32 bytes for every FIPS 203 parameter set, so both
/// composite tiers share this length.
pub(crate) const MLKEM768_KEY_SHARE_LENGTH: usize = 32;
pub(crate) const MLKEM1024_KEY_SHARE_LENGTH: usize = 32;

/// Combine the ML-KEM-768 and X25519 key shares into the AES-256 key
/// encryption key.
pub(crate) fn multi_key_combine_mlkem768_x25519(
    mlkem_key_share: &[u8],
    ecdh_key_share: &[u8],
    ecdh_ciphertext: &[u8],
    ecdh_public_key: &[u8],
) -> openpgp::Result<SessionKey> {
    multi_key_combine(
        mlkem_key_share,
        ecdh_key_share,
        ecdh_ciphertext,
        ecdh_public_key,
        PublicKeyAlgorithm::MLKEM768_X25519,
    )
}

/// Combine the ML-KEM-1024 and X448 key shares into the AES-256 key
/// encryption key.
pub(crate) fn multi_key_combine_mlkem1024_x448(
    mlkem_key_share: &[u8],
    ecdh_key_share: &[u8],
    ecdh_ciphertext: &[u8],
    ecdh_public_key: &[u8],
) -> openpgp::Result<SessionKey> {
    multi_key_combine(
        mlkem_key_share,
        ecdh_key_share,
        ecdh_ciphertext,
        ecdh_public_key,
        PublicKeyAlgorithm::MLKEM1024_X448,
    )
}

/// RFC 9980 §4.2.1 KEM key combiner, parameterized by the composite public-key
/// algorithm id exactly as upstream `multi_key_combine`.
///
/// ```text
/// KEK = SHA3-256(
///           mlkemKeyShare || ecdhKeyShare ||
///           ecdhCipherText || ecdhPublicKey ||
///           algId || domSep || len(domSep)
///       )
/// ```
fn multi_key_combine(
    mlkem_key_share: &[u8],
    ecdh_key_share: &[u8],
    ecdh_ciphertext: &[u8],
    ecdh_public_key: &[u8],
    pk_algo: PublicKeyAlgorithm,
) -> openpgp::Result<SessionKey> {
    let mut hash = HashAlgorithm::SHA3_256.context()?.for_digest();
    hash.update(mlkem_key_share);
    hash.update(ecdh_key_share);
    hash.update(ecdh_ciphertext);
    hash.update(ecdh_public_key);
    hash.update(&[pk_algo.into()]);
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
