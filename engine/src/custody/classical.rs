//! The classical curve operations of device custody: the software halves of
//! the post-quantum composite keys (Ed25519 and X25519, Ed448 and X448), and
//! the check of a P-256 point before the device sees it.
//!
//! They run through the vendored OpenSSL, the provider Sequoia's backend uses,
//! so a half computes exactly what Sequoia's own composite code computes.

use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::Signer;
use zeroize::Zeroizing;

/// An operation on a classical half failed: the secret or the peer's point was
/// refused, or the result was degenerate. What that means is the caller's to
/// decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CurveError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    Ed25519,
    X25519,
    Ed448,
    X448,
}

impl Curve {
    fn id(self) -> Id {
        match self {
            Curve::Ed25519 => Id::ED25519,
            Curve::X25519 => Id::X25519,
            Curve::Ed448 => Id::ED448,
            Curve::X448 => Id::X448,
        }
    }

    /// The length of a raw secret, and of a raw public key.
    pub(crate) fn key_length(self) -> usize {
        match self {
            Curve::Ed25519 | Curve::X25519 => 32,
            Curve::Ed448 => 57,
            Curve::X448 => 56,
        }
    }
}

/// A fresh half: its raw secret and its raw public key.
pub(crate) fn generate(curve: Curve) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CurveError> {
    let key = match curve {
        Curve::Ed25519 => PKey::generate_ed25519(),
        Curve::X25519 => PKey::generate_x25519(),
        Curve::Ed448 => PKey::generate_ed448(),
        Curve::X448 => PKey::generate_x448(),
    }
    .map_err(|_| CurveError)?;
    let secret = Zeroizing::new(key.raw_private_key().map_err(|_| CurveError)?);
    let public = key.raw_public_key().map_err(|_| CurveError)?;
    if secret.len() != curve.key_length() || public.len() != curve.key_length() {
        return Err(CurveError);
    }
    Ok((secret, public))
}

/// The public key of a raw secret.
pub(crate) fn public_key(curve: Curve, secret: &[u8]) -> Result<Vec<u8>, CurveError> {
    private_key(curve, secret)?
        .raw_public_key()
        .map_err(|_| CurveError)
}

/// The PureEdDSA signature of an OpenPGP signature digest, as RFC 9980 has
/// the classical half sign it.
pub(crate) fn sign(curve: Curve, secret: &[u8], digest: &[u8]) -> Result<Vec<u8>, CurveError> {
    debug_assert!(matches!(curve, Curve::Ed25519 | Curve::Ed448));
    let key = private_key(curve, secret)?;
    let signature = Signer::new_without_digest(&key)
        .and_then(|mut signer| signer.sign_oneshot_to_vec(digest))
        .map_err(|_| CurveError)?;
    if signature.len() != 2 * curve.key_length() {
        return Err(CurveError);
    }
    Ok(signature)
}

/// The raw shared secret with a peer's public key. A point that gives an
/// all-zero secret, which a low-order point does, is refused.
pub(crate) fn agree(
    curve: Curve,
    secret: &[u8],
    peer: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CurveError> {
    debug_assert!(matches!(curve, Curve::X25519 | Curve::X448));
    if peer.len() != curve.key_length() {
        return Err(CurveError);
    }
    let key = private_key(curve, secret)?;
    let peer = PKey::public_key_from_raw_bytes(peer, curve.id()).map_err(|_| CurveError)?;
    let mut deriver = Deriver::new(&key).map_err(|_| CurveError)?;
    deriver.set_peer(&peer).map_err(|_| CurveError)?;
    let shared = Zeroizing::new(deriver.derive_to_vec().map_err(|_| CurveError)?);
    if shared.len() != curve.key_length() || shared.iter().all(|byte| *byte == 0) {
        return Err(CurveError);
    }
    Ok(shared)
}

fn private_key(curve: Curve, secret: &[u8]) -> Result<PKey<Private>, CurveError> {
    if secret.len() != curve.key_length() || secret.iter().all(|byte| *byte == 0) {
        return Err(CurveError);
    }
    PKey::private_key_from_raw_bytes(secret, curve.id()).map_err(|_| CurveError)
}

/// The length of an uncompressed P-256 point: the tag 0x04, then X and Y.
const P256_POINT_LENGTH: usize = 65;

/// Whether `bytes` is an uncompressed P-256 point on the curve. P-256 has
/// cofactor 1, so a point on the curve is in the group, and the encoding has
/// no form for the point at infinity.
pub(crate) fn is_p256_point(bytes: &[u8]) -> bool {
    if bytes.len() != P256_POINT_LENGTH || bytes[0] != 0x04 {
        return false;
    }
    let (Ok(group), Ok(mut context)) = (
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1),
        BigNumContext::new(),
    ) else {
        return false;
    };
    EcPoint::from_bytes(&group, bytes, &mut context)
        .and_then(|point| point.is_on_curve(&group, &mut context))
        .unwrap_or(false)
}
