//! Classical component operations for RFC 9980 split-custody composite keys.
//!
//! The classical halves of the Device-Bound Post-Quantum families are software
//! components held by the app's envelope machinery; the ML-DSA/ML-KEM halves
//! live in the Secure Enclave. These helpers perform the classical raw scalar
//! operations through the vendored OpenSSL EVP interface — the same provider
//! Sequoia's `crypto-openssl` backend uses — so component outputs are
//! byte-identical to Sequoia's native composite paths.
//!
//! Two tiers are supported: Ed25519 + X25519 for the ML-DSA-65 + ML-KEM-768
//! family, and Ed448 + X448 for the ML-DSA-87 + ML-KEM-1024 · High family.

use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey};
use openssl::sign::Signer;
use zeroize::Zeroizing;

pub(crate) const CLASSICAL_COMPONENT_SECRET_LENGTH: usize = 32;
pub(crate) const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
pub(crate) const ED25519_SIGNATURE_LENGTH: usize = 64;
pub(crate) const X25519_PUBLIC_KEY_LENGTH: usize = 32;
pub(crate) const X25519_SHARED_SECRET_LENGTH: usize = 32;

// Ed448/X448 tier for the Device-Bound Post-Quantum · High family. Unlike the
// Curve25519 tier, the Ed448 and X448 raw secrets differ in length (57 vs. 56),
// so each is validated against its own expected shape.
pub(crate) const ED448_SECRET_LENGTH: usize = 57;
pub(crate) const ED448_PUBLIC_KEY_LENGTH: usize = 57;
pub(crate) const ED448_SIGNATURE_LENGTH: usize = 114;
pub(crate) const X448_SECRET_LENGTH: usize = 56;
pub(crate) const X448_PUBLIC_KEY_LENGTH: usize = 56;
pub(crate) const X448_SHARED_SECRET_LENGTH: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ClassicalComponentError {
    #[error("classical component invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("classical component operation failed: {0}")]
    OperationFailed(&'static str),
}

/// Generate a fresh Ed25519 component. Returns `(secret_seed, public_key)`.
pub(crate) fn generate_ed25519_component(
) -> Result<(Zeroizing<Vec<u8>>, [u8; ED25519_PUBLIC_KEY_LENGTH]), ClassicalComponentError> {
    let key = PKey::generate_ed25519()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed25519 generation failed"))?;
    let secret = Zeroizing::new(
        key.raw_private_key()
            .map_err(|_| ClassicalComponentError::OperationFailed("Ed25519 export failed"))?,
    );
    let public = key
        .raw_public_key()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed25519 export failed"))?;
    if secret.len() != CLASSICAL_COMPONENT_SECRET_LENGTH
        || public.len() != ED25519_PUBLIC_KEY_LENGTH
    {
        return Err(ClassicalComponentError::OperationFailed(
            "Ed25519 generation returned an unexpected shape",
        ));
    }
    let mut public_key = [0u8; ED25519_PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&public);
    Ok((secret, public_key))
}

/// Generate a fresh X25519 component. Returns `(secret_scalar, public_key)`.
pub(crate) fn generate_x25519_component(
) -> Result<(Zeroizing<Vec<u8>>, [u8; X25519_PUBLIC_KEY_LENGTH]), ClassicalComponentError> {
    let key = PKey::generate_x25519()
        .map_err(|_| ClassicalComponentError::OperationFailed("X25519 generation failed"))?;
    let secret = Zeroizing::new(
        key.raw_private_key()
            .map_err(|_| ClassicalComponentError::OperationFailed("X25519 export failed"))?,
    );
    let public = key
        .raw_public_key()
        .map_err(|_| ClassicalComponentError::OperationFailed("X25519 export failed"))?;
    if secret.len() != CLASSICAL_COMPONENT_SECRET_LENGTH || public.len() != X25519_PUBLIC_KEY_LENGTH
    {
        return Err(ClassicalComponentError::OperationFailed(
            "X25519 generation returned an unexpected shape",
        ));
    }
    let mut public_key = [0u8; X25519_PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&public);
    Ok((secret, public_key))
}

/// Derive the Ed25519 public key for a component secret seed.
pub(crate) fn ed25519_public_key(
    secret: &[u8],
) -> Result<[u8; ED25519_PUBLIC_KEY_LENGTH], ClassicalComponentError> {
    let key = ed25519_private_key(secret)?;
    let public = key
        .raw_public_key()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed25519 export failed"))?;
    public
        .as_slice()
        .try_into()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed25519 export failed"))
}

/// Derive the X25519 public key for a component secret scalar.
pub(crate) fn x25519_public_key(
    secret: &[u8],
) -> Result<[u8; X25519_PUBLIC_KEY_LENGTH], ClassicalComponentError> {
    let key = x25519_private_key(secret)?;
    let public = key
        .raw_public_key()
        .map_err(|_| ClassicalComponentError::OperationFailed("X25519 export failed"))?;
    public
        .as_slice()
        .try_into()
        .map_err(|_| ClassicalComponentError::OperationFailed("X25519 export failed"))
}

/// Produce the 64-byte PureEdDSA signature over an OpenPGP signature digest.
pub(crate) fn ed25519_sign(
    secret: &[u8],
    digest: &[u8],
) -> Result<[u8; ED25519_SIGNATURE_LENGTH], ClassicalComponentError> {
    let key = ed25519_private_key(secret)?;
    let mut signer = Signer::new_without_digest(&key)
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed25519 signer setup failed"))?;
    let signature = signer
        .sign_oneshot_to_vec(digest)
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed25519 signing failed"))?;
    signature
        .as_slice()
        .try_into()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed25519 signing failed"))
}

/// Derive the raw 32-byte X25519 shared secret with a peer public key.
///
/// OpenSSL performs RFC 7748 clamping internally and rejects an all-zero
/// shared point, matching the contributory-behavior semantics of Sequoia's
/// native `x25519_shared_point`.
pub(crate) fn x25519_shared_secret(
    secret: &[u8],
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ClassicalComponentError> {
    if peer_public_key.len() != X25519_PUBLIC_KEY_LENGTH {
        return Err(ClassicalComponentError::InvalidInput(
            "X25519 peer public key must be 32 bytes",
        ));
    }
    let key = x25519_private_key(secret)?;
    let peer = PKey::public_key_from_raw_bytes(peer_public_key, Id::X25519).map_err(|_| {
        ClassicalComponentError::InvalidInput("X25519 peer public key rejected by provider")
    })?;
    let mut deriver = Deriver::new(&key)
        .map_err(|_| ClassicalComponentError::OperationFailed("X25519 derive setup failed"))?;
    deriver
        .set_peer(&peer)
        .map_err(|_| ClassicalComponentError::OperationFailed("X25519 derive setup failed"))?;
    let shared = Zeroizing::new(
        deriver
            .derive_to_vec()
            .map_err(|_| ClassicalComponentError::OperationFailed("X25519 derivation failed"))?,
    );
    if shared.len() != X25519_SHARED_SECRET_LENGTH {
        return Err(ClassicalComponentError::OperationFailed(
            "X25519 derivation returned an unexpected shape",
        ));
    }
    if shared.iter().all(|byte| *byte == 0) {
        return Err(ClassicalComponentError::OperationFailed(
            "X25519 derivation returned an all-zero shared secret",
        ));
    }
    Ok(shared)
}

/// Generate a fresh Ed448 component. Returns `(secret_seed, public_key)`.
pub(crate) fn generate_ed448_component(
) -> Result<(Zeroizing<Vec<u8>>, [u8; ED448_PUBLIC_KEY_LENGTH]), ClassicalComponentError> {
    let key = PKey::generate_ed448()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed448 generation failed"))?;
    let secret = Zeroizing::new(
        key.raw_private_key()
            .map_err(|_| ClassicalComponentError::OperationFailed("Ed448 export failed"))?,
    );
    let public = key
        .raw_public_key()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed448 export failed"))?;
    if secret.len() != ED448_SECRET_LENGTH || public.len() != ED448_PUBLIC_KEY_LENGTH {
        return Err(ClassicalComponentError::OperationFailed(
            "Ed448 generation returned an unexpected shape",
        ));
    }
    let mut public_key = [0u8; ED448_PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&public);
    Ok((secret, public_key))
}

/// Generate a fresh X448 component. Returns `(secret_scalar, public_key)`.
pub(crate) fn generate_x448_component(
) -> Result<(Zeroizing<Vec<u8>>, [u8; X448_PUBLIC_KEY_LENGTH]), ClassicalComponentError> {
    let key = PKey::generate_x448()
        .map_err(|_| ClassicalComponentError::OperationFailed("X448 generation failed"))?;
    let secret = Zeroizing::new(
        key.raw_private_key()
            .map_err(|_| ClassicalComponentError::OperationFailed("X448 export failed"))?,
    );
    let public = key
        .raw_public_key()
        .map_err(|_| ClassicalComponentError::OperationFailed("X448 export failed"))?;
    if secret.len() != X448_SECRET_LENGTH || public.len() != X448_PUBLIC_KEY_LENGTH {
        return Err(ClassicalComponentError::OperationFailed(
            "X448 generation returned an unexpected shape",
        ));
    }
    let mut public_key = [0u8; X448_PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&public);
    Ok((secret, public_key))
}

/// Derive the Ed448 public key for a component secret seed.
pub(crate) fn ed448_public_key(
    secret: &[u8],
) -> Result<[u8; ED448_PUBLIC_KEY_LENGTH], ClassicalComponentError> {
    let key = ed448_private_key(secret)?;
    let public = key
        .raw_public_key()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed448 export failed"))?;
    public
        .as_slice()
        .try_into()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed448 export failed"))
}

/// Derive the X448 public key for a component secret scalar.
pub(crate) fn x448_public_key(
    secret: &[u8],
) -> Result<[u8; X448_PUBLIC_KEY_LENGTH], ClassicalComponentError> {
    let key = x448_private_key(secret)?;
    let public = key
        .raw_public_key()
        .map_err(|_| ClassicalComponentError::OperationFailed("X448 export failed"))?;
    public
        .as_slice()
        .try_into()
        .map_err(|_| ClassicalComponentError::OperationFailed("X448 export failed"))
}

/// Produce the 114-byte PureEdDSA (Ed448) signature over an OpenPGP signature digest.
pub(crate) fn ed448_sign(
    secret: &[u8],
    digest: &[u8],
) -> Result<[u8; ED448_SIGNATURE_LENGTH], ClassicalComponentError> {
    let key = ed448_private_key(secret)?;
    let mut signer = Signer::new_without_digest(&key)
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed448 signer setup failed"))?;
    let signature = signer
        .sign_oneshot_to_vec(digest)
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed448 signing failed"))?;
    signature
        .as_slice()
        .try_into()
        .map_err(|_| ClassicalComponentError::OperationFailed("Ed448 signing failed"))
}

/// Derive the raw 56-byte X448 shared secret with a peer public key.
///
/// OpenSSL performs the RFC 7748 X448 scalar multiplication internally and
/// rejects an all-zero shared point, matching the contributory-behavior
/// semantics of Sequoia's native `x448_shared_point`.
pub(crate) fn x448_shared_secret(
    secret: &[u8],
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ClassicalComponentError> {
    if peer_public_key.len() != X448_PUBLIC_KEY_LENGTH {
        return Err(ClassicalComponentError::InvalidInput(
            "X448 peer public key must be 56 bytes",
        ));
    }
    let key = x448_private_key(secret)?;
    let peer = PKey::public_key_from_raw_bytes(peer_public_key, Id::X448).map_err(|_| {
        ClassicalComponentError::InvalidInput("X448 peer public key rejected by provider")
    })?;
    let mut deriver = Deriver::new(&key)
        .map_err(|_| ClassicalComponentError::OperationFailed("X448 derive setup failed"))?;
    deriver
        .set_peer(&peer)
        .map_err(|_| ClassicalComponentError::OperationFailed("X448 derive setup failed"))?;
    let shared = Zeroizing::new(
        deriver
            .derive_to_vec()
            .map_err(|_| ClassicalComponentError::OperationFailed("X448 derivation failed"))?,
    );
    if shared.len() != X448_SHARED_SECRET_LENGTH {
        return Err(ClassicalComponentError::OperationFailed(
            "X448 derivation returned an unexpected shape",
        ));
    }
    if shared.iter().all(|byte| *byte == 0) {
        return Err(ClassicalComponentError::OperationFailed(
            "X448 derivation returned an all-zero shared secret",
        ));
    }
    Ok(shared)
}

fn ed25519_private_key(
    secret: &[u8],
) -> Result<PKey<openssl::pkey::Private>, ClassicalComponentError> {
    validate_component_secret(secret)?;
    PKey::private_key_from_raw_bytes(secret, Id::ED25519)
        .map_err(|_| ClassicalComponentError::InvalidInput("Ed25519 secret rejected by provider"))
}

fn ed448_private_key(
    secret: &[u8],
) -> Result<PKey<openssl::pkey::Private>, ClassicalComponentError> {
    validate_component_secret_shape(
        secret,
        ED448_SECRET_LENGTH,
        "Ed448 classical component secret must be 57 bytes",
    )?;
    PKey::private_key_from_raw_bytes(secret, Id::ED448)
        .map_err(|_| ClassicalComponentError::InvalidInput("Ed448 secret rejected by provider"))
}

fn x448_private_key(
    secret: &[u8],
) -> Result<PKey<openssl::pkey::Private>, ClassicalComponentError> {
    validate_component_secret_shape(
        secret,
        X448_SECRET_LENGTH,
        "X448 classical component secret must be 56 bytes",
    )?;
    PKey::private_key_from_raw_bytes(secret, Id::X448)
        .map_err(|_| ClassicalComponentError::InvalidInput("X448 secret rejected by provider"))
}

fn x25519_private_key(
    secret: &[u8],
) -> Result<PKey<openssl::pkey::Private>, ClassicalComponentError> {
    validate_component_secret(secret)?;
    PKey::private_key_from_raw_bytes(secret, Id::X25519)
        .map_err(|_| ClassicalComponentError::InvalidInput("X25519 secret rejected by provider"))
}

fn validate_component_secret(secret: &[u8]) -> Result<(), ClassicalComponentError> {
    validate_component_secret_shape(
        secret,
        CLASSICAL_COMPONENT_SECRET_LENGTH,
        "classical component secret must be 32 bytes",
    )
}

fn validate_component_secret_shape(
    secret: &[u8],
    expected_length: usize,
    length_message: &'static str,
) -> Result<(), ClassicalComponentError> {
    if secret.len() != expected_length {
        return Err(ClassicalComponentError::InvalidInput(length_message));
    }
    if secret.iter().all(|byte| *byte == 0) {
        return Err(ClassicalComponentError::InvalidInput(
            "classical component secret must not be all zeros",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_component_round_trip_signs_and_derives_public() {
        let (secret, public) = generate_ed25519_component().expect("generate");
        assert_eq!(ed25519_public_key(&secret).expect("public"), public);
        let signature = ed25519_sign(&secret, b"0123456789abcdef0123456789abcdef").expect("sign");
        assert_eq!(signature.len(), ED25519_SIGNATURE_LENGTH);
    }

    #[test]
    fn x25519_components_agree_on_shared_secret() {
        let (secret_a, public_a) = generate_x25519_component().expect("generate a");
        let (secret_b, public_b) = generate_x25519_component().expect("generate b");
        let shared_ab = x25519_shared_secret(&secret_a, &public_b).expect("derive ab");
        let shared_ba = x25519_shared_secret(&secret_b, &public_a).expect("derive ba");
        assert_eq!(shared_ab.as_slice(), shared_ba.as_slice());
    }

    #[test]
    fn component_secret_validation_rejects_bad_shapes() {
        assert!(ed25519_sign(&[0u8; 32], b"digest").is_err());
        assert!(ed25519_sign(&[7u8; 16], b"digest").is_err());
        assert!(x25519_shared_secret(&[7u8; 32], &[1u8; 16]).is_err());
    }

    #[test]
    fn ed448_component_round_trip_signs_and_derives_public() {
        let (secret, public) = generate_ed448_component().expect("generate");
        assert_eq!(secret.len(), ED448_SECRET_LENGTH);
        assert_eq!(ed448_public_key(&secret).expect("public"), public);
        let signature = ed448_sign(&secret, b"0123456789abcdef0123456789abcdef").expect("sign");
        assert_eq!(signature.len(), ED448_SIGNATURE_LENGTH);
    }

    #[test]
    fn x448_components_agree_on_shared_secret() {
        let (secret_a, public_a) = generate_x448_component().expect("generate a");
        let (secret_b, public_b) = generate_x448_component().expect("generate b");
        assert_eq!(secret_a.len(), X448_SECRET_LENGTH);
        let shared_ab = x448_shared_secret(&secret_a, &public_b).expect("derive ab");
        let shared_ba = x448_shared_secret(&secret_b, &public_a).expect("derive ba");
        assert_eq!(shared_ab.as_slice(), shared_ba.as_slice());
        assert_eq!(shared_ab.len(), X448_SHARED_SECRET_LENGTH);
    }

    #[test]
    fn ed448_x448_secret_validation_rejects_bad_shapes() {
        // All-zero and wrong-length secrets must be rejected for both curves.
        assert!(ed448_sign(&[0u8; ED448_SECRET_LENGTH], b"digest").is_err());
        assert!(ed448_sign(&[7u8; 32], b"digest").is_err());
        assert!(x448_shared_secret(&[7u8; X448_SECRET_LENGTH], &[1u8; 16]).is_err());
        assert!(x448_shared_secret(&[7u8; 32], &[1u8; X448_PUBLIC_KEY_LENGTH]).is_err());
    }
}
