//! The OpenPGP engine of CypherAir, on Sequoia, exposed to Swift through UniFFI.
//!
//! The engine has no state, no logging and no expiry policy of its own. For the
//! times inside a key it reads no clock: the caller gives them. Every input may
//! be armored or binary; certificates it writes are binary. Lists of
//! certificates keep the caller's order, and results point into them by
//! position. Times are Unix seconds.
//!
//! Every exported function runs its body through `error::contained`, so that a
//! panic anywhere below it becomes `EngineError::Internal`. That needs panics
//! to unwind, in every profile and for every target.

#[cfg(panic = "abort")]
compile_error!(
    "the engine needs `panic = \"unwind\"`: every exported function contains its panics"
);

use sequoia_openpgp::policy::StandardPolicy;

uniffi::setup_scaffolding!();

mod bounded_walk;
mod custody;
mod error;
mod key;
mod message;
mod unlock_stretch;

pub use error::EngineError;
pub use key::{
    DeviceKey, DeviceKeyError, PrivateKey, armor, device_key_slots, generate_device_key,
    generate_portable_key, inspect_certificate,
};
pub use message::{decrypt, encrypt, outgoing_format};
pub use unlock_stretch::stretch_unlock_passphrase;

/// The one policy every operation judges keys, signatures and algorithms by.
pub(crate) static POLICY: StandardPolicy<'static> = StandardPolicy::new();

/// The certificate shapes this app makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyShape {
    /// Portable Legacy.
    V4Curve25519,
    /// Device-Bound Legacy.
    V4P256,
    /// Portable Modern.
    V6Curve25519,
    /// Device-Bound Modern.
    V6P256,
    /// Portable Modern · High.
    V6Curve448,
    /// Both Post-Quantum families.
    V6MlDsa65,
    /// Both Post-Quantum · High families.
    V6MlDsa87,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AlgorithmKind {
    Rsa,
    Dsa,
    ElGamal,
    EdDsaLegacy,
    Ecdsa,
    Ecdh,
    Ed25519,
    X25519,
    Ed448,
    X448,
    MlDsa65Ed25519,
    MlDsa87Ed448,
    MlKem768X25519,
    MlKem1024X448,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Curve {
    None,
    Ed25519,
    Curve25519,
    NistP256,
    NistP384,
    NistP521,
    BrainpoolP256,
    BrainpoolP384,
    BrainpoolP512,
    Unknown,
}

/// A key's real algorithm and size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct Algorithm {
    pub kind: AlgorithmKind,
    pub curve: Curve,
    /// The key size where the algorithm leaves it open (RSA, DSA, ElGamal);
    /// 0 where the algorithm or the curve already says it.
    pub bits: u32,
}

/// When a key expires: never, or a number of days after its stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Expiry {
    Never,
    After { days: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UserId {
    pub name: String,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyStatus {
    Valid,
    Expired,
    Revoked,
    /// The certificate is not valid under the engine's policy.
    Unusable,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CertificateInfo {
    /// Lowercase hex.
    pub fingerprint: String,
    /// 4 or 6.
    pub version: u8,
    pub primary: Algorithm,
    /// The key a message to this certificate is encrypted to.
    pub encryption: Option<Algorithm>,
    /// Only when the version, the primary key and every encryption key match
    /// one of the shapes this app makes.
    pub shape: Option<KeyShape>,
    /// Only from a User ID with a valid binding.
    pub name: Option<String>,
    pub email: Option<String>,
    pub created: u64,
    /// The latest creation time among the certificate's verified
    /// self-signatures, whatever their date; the key's creation time when it
    /// has none. A later stamp must be strictly later.
    pub newest_self_signature: u64,
    pub expires: Option<u64>,
    pub status: KeyStatus,
    /// `encrypt` accepts this certificate as a recipient now.
    pub can_encrypt: bool,
    /// A message to this certificate is quantum-safe: every key it is
    /// encrypted to is a post-quantum KEM.
    pub quantum_safe: bool,
    pub has_secret: bool,
}

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewKey {
    pub certificate: Vec<u8>,
    /// What the vault must seal: the secret key packets of a portable key,
    /// which `PrivateKey::portable` joins with the certificate; the classical
    /// halves of a device-bound post-quantum key; nothing for a device-bound
    /// P-256 key.
    pub secret: Option<Vec<u8>>,
    /// A revocation signature that states no specific reason, so that applying
    /// it is final.
    pub revocation: Vec<u8>,
}

impl std::fmt::Debug for NewKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewKey")
            .field(
                "certificate",
                &format_args!("{} bytes", self.certificate.len()),
            )
            .field("secret", &self.secret.as_ref().map(|_| "…"))
            .field(
                "revocation",
                &format_args!("{} bytes", self.revocation.len()),
            )
            .finish()
    }
}

/// The public keys that the device's two keys must have.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceKeySlots {
    pub signing_public_key: Vec<u8>,
    pub agreement_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ArmorKind {
    Certificate,
    Revocation,
}

/// The container an outgoing message will use.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutgoingFormat {
    /// The RFC 9580 container (SEIPDv2). Exactly when `held_back_by` is empty.
    pub modern: bool,
    /// Positions of the recipients that do not support the modern container.
    pub held_back_by: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Encrypted {
    /// Armored.
    pub message: Vec<u8>,
    pub quantum_safe: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Verdict {
    NotSigned,
    Verified,
    Invalid,
    SignerRevoked,
    SignerExpired,
    UnknownSigner,
    Unverifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct Signature {
    pub verdict: Verdict,
    /// Position in the caller's list of verifiers.
    pub signer: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct Decrypted {
    pub plaintext: Vec<u8>,
    pub signature: Signature,
    pub quantum_safe: bool,
}

impl std::fmt::Debug for Decrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decrypted")
            .field("plaintext", &format_args!("{} bytes", self.plaintext.len()))
            .field("signature", &self.signature)
            .field("quantum_safe", &self.quantum_safe)
            .finish()
    }
}
