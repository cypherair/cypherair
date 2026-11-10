//! The software stand-in for the Secure Enclave: one `DeviceKey` over software
//! keys, which can also cancel, refuse, fail and answer wrongly, and which
//! counts how often it was asked.
//!
//! P-256 runs on OpenSSL. The post-quantum keys are a Sequoia composite key,
//! of which the stand-in uses only the ML-DSA half, and an ML-KEM seed that
//! the `ossl` crate decapsulates with: the real FIPS 204 and FIPS 203
//! primitives. Like the Secure Enclave, it refuses a P-256 point that is not
//! on the curve.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cypher_engine::{
    DeviceKey, DeviceKeyError, Expiry, KeyShape, NewKey, PrivateKey, generate_device_key,
};
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::{KeyPair, Signer, mpi};
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::types::HashAlgorithm;
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use sequoia_openpgp as openpgp;

use super::keys;

/// How the stand-in answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    Answer,
    Cancel,
    NotAuthenticated,
    Fail,
    /// An answer of the right length with one bit flipped.
    AnswerWrongly,
    /// An answer one byte short.
    AnswerShort,
    /// An answer of the right length, all zeros.
    AnswerZeros,
}

pub struct SoftwareDevice {
    keys: Keys,
    behaviour: Mutex<Behaviour>,
    /// Calls still answered before the behaviour applies.
    answers_first: AtomicUsize,
    signs: AtomicUsize,
    agreements: AtomicUsize,
}

enum Keys {
    P256 {
        signing: EcKey<Private>,
        agreement: EcKey<Private>,
    },
    MlDsa(Box<PostQuantum>),
}

struct PostQuantum {
    /// A composite signing key; only its ML-DSA half is the device's.
    signing: Mutex<KeyPair>,
    mldsa_public: Vec<u8>,
    mlkem_seed: Vec<u8>,
    mlkem_public: Vec<u8>,
    high: bool,
}

impl SoftwareDevice {
    /// Fresh device keys for a device-bound shape.
    pub fn new(shape: KeyShape) -> Arc<Self> {
        let keys = match shape {
            KeyShape::V4P256 | KeyShape::V6P256 => {
                let group = p256();
                Keys::P256 {
                    signing: EcKey::generate(&group).unwrap(),
                    agreement: EcKey::generate(&group).unwrap(),
                }
            }
            KeyShape::V6MlDsa65 => post_quantum(CipherSuite::MLDSA65_Ed25519, false),
            KeyShape::V6MlDsa87 => post_quantum(CipherSuite::MLDSA87_Ed448, true),
            _ => panic!("{shape:?} is not device-bound"),
        };
        Arc::new(Self {
            keys,
            behaviour: Mutex::new(Behaviour::Answer),
            answers_first: AtomicUsize::new(0),
            signs: AtomicUsize::new(0),
            agreements: AtomicUsize::new(0),
        })
    }

    /// The public keys of the signing key and the key-agreement key, as the
    /// Secure Enclave states them.
    pub fn public_keys(&self) -> (Vec<u8>, Vec<u8>) {
        match &self.keys {
            Keys::P256 { signing, agreement } => (point(signing), point(agreement)),
            Keys::MlDsa(keys) => (keys.mldsa_public.clone(), keys.mlkem_public.clone()),
        }
    }

    pub fn behave(&self, behaviour: Behaviour) {
        self.behave_after(0, behaviour);
    }

    /// Answer the next `calls` calls, and behave so from then on.
    pub fn behave_after(&self, calls: usize, behaviour: Behaviour) {
        self.answers_first.store(calls, Ordering::SeqCst);
        *self.behaviour.lock().unwrap() = behaviour;
    }

    pub fn signs(&self) -> usize {
        self.signs.load(Ordering::SeqCst)
    }

    pub fn agreements(&self) -> usize {
        self.agreements.load(Ordering::SeqCst)
    }

    fn refusal(&self) -> Result<Behaviour, DeviceKeyError> {
        let answered =
            self.answers_first
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |calls| {
                    calls.checked_sub(1)
                });
        if answered.is_ok() {
            return Ok(Behaviour::Answer);
        }
        match *self.behaviour.lock().unwrap() {
            Behaviour::Cancel => Err(DeviceKeyError::Cancelled),
            Behaviour::NotAuthenticated => Err(DeviceKeyError::NotAuthenticated),
            Behaviour::Fail => Err(DeviceKeyError::Failed),
            behaviour => Ok(behaviour),
        }
    }
}

impl DeviceKey for SoftwareDevice {
    fn sign(&self, input: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        let behaviour = self.refusal()?;
        let answer = match &self.keys {
            Keys::P256 { signing, .. } => {
                let signature =
                    EcdsaSig::sign(&input, signing).map_err(|_| DeviceKeyError::Failed)?;
                let mut answer = signature.r().to_vec_padded(32).unwrap();
                answer.extend(signature.s().to_vec_padded(32).unwrap());
                answer
            }
            Keys::MlDsa(keys) => {
                match keys
                    .signing
                    .lock()
                    .unwrap()
                    .sign(HashAlgorithm::SHA512, &input)
                {
                    Ok(mpi::Signature::MLDSA65_Ed25519 { mldsa, .. }) => mldsa.to_vec(),
                    Ok(mpi::Signature::MLDSA87_Ed448 { mldsa, .. }) => mldsa.to_vec(),
                    _ => return Err(DeviceKeyError::Failed),
                }
            }
        };
        Ok(spoil(answer, behaviour))
    }

    fn agree(&self, input: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError> {
        self.agreements.fetch_add(1, Ordering::SeqCst);
        let behaviour = self.refusal()?;
        let answer = match &self.keys {
            Keys::P256 { agreement, .. } => {
                p256_agree(agreement, &input).ok_or(DeviceKeyError::Failed)?
            }
            Keys::MlDsa(keys) => {
                decapsulate(&keys.mlkem_seed, &input, keys.high).ok_or(DeviceKeyError::Failed)?
            }
        };
        Ok(spoil(answer, behaviour))
    }
}

fn spoil(mut answer: Vec<u8>, behaviour: Behaviour) -> Vec<u8> {
    match behaviour {
        Behaviour::AnswerWrongly => answer[0] ^= 0x01,
        Behaviour::AnswerShort => {
            answer.pop();
        }
        Behaviour::AnswerZeros => answer.fill(0),
        _ => {}
    }
    answer
}

fn p256() -> EcGroup {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()
}

fn point(key: &EcKey<Private>) -> Vec<u8> {
    let mut context = BigNumContext::new().unwrap();
    key.public_key()
        .to_bytes(&p256(), PointConversionForm::UNCOMPRESSED, &mut context)
        .unwrap()
}

/// The x-coordinate of the shared point, as the Secure Enclave returns it. A
/// point off the curve is refused.
fn p256_agree(key: &EcKey<Private>, peer: &[u8]) -> Option<Vec<u8>> {
    let group = p256();
    let mut context = BigNumContext::new().ok()?;
    let point = EcPoint::from_bytes(&group, peer, &mut context).ok()?;
    if !point.is_on_curve(&group, &mut context).ok()? {
        return None;
    }
    let peer = PKey::from_ec_key(EcKey::from_public_key(&group, &point).ok()?).ok()?;
    let key = PKey::from_ec_key(key.clone()).ok()?;
    let mut deriver = Deriver::new(&key).ok()?;
    deriver.set_peer(&peer).ok()?;
    deriver.derive_to_vec().ok()
}

fn post_quantum(suite: CipherSuite, high: bool) -> Keys {
    let (cert, _) = CertBuilder::new()
        .set_cipher_suite(suite)
        .set_profile(openpgp::Profile::RFC9580)
        .unwrap()
        .add_transport_encryption_subkey()
        .generate()
        .unwrap();
    let primary = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap();
    let mldsa_public = match primary.mpis() {
        mpi::PublicKey::MLDSA65_Ed25519 { mldsa, .. } => mldsa.to_vec(),
        mpi::PublicKey::MLDSA87_Ed448 { mldsa, .. } => mldsa.to_vec(),
        _ => unreachable!(),
    };
    let subkey = cert.keys().subkeys().next().unwrap().key().clone();
    let mlkem_public = match subkey.mpis() {
        mpi::PublicKey::MLKEM768_X25519 { mlkem, .. } => mlkem.to_vec(),
        mpi::PublicKey::MLKEM1024_X448 { mlkem, .. } => mlkem.to_vec(),
        _ => unreachable!(),
    };
    let mlkem_seed = match subkey.parts_into_secret().unwrap().secret() {
        SecretKeyMaterial::Unencrypted(secret) => secret.map(|secret| match secret {
            mpi::SecretKeyMaterial::MLKEM768_X25519 { mlkem, .. }
            | mpi::SecretKeyMaterial::MLKEM1024_X448 { mlkem, .. } => mlkem.to_vec(),
            _ => unreachable!(),
        }),
        SecretKeyMaterial::Encrypted(_) => unreachable!(),
    };
    Keys::MlDsa(Box::new(PostQuantum {
        signing: Mutex::new(primary.role_into_unspecified().into_keypair().unwrap()),
        mldsa_public,
        mlkem_seed,
        mlkem_public,
        high,
    }))
}

/// FIPS 203 decapsulation from the 64-byte seed.
fn decapsulate(seed: &[u8], ciphertext: &[u8], high: bool) -> Option<Vec<u8>> {
    use ossl::asymcipher::{EncOp, OsslAsymcipher};
    use ossl::pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
    use ossl::{OsslContext, OsslSecret};

    let context = OsslContext::new_lib_ctx_checked().ok()?;
    let kind = if high {
        EvpPkeyType::MlKem1024
    } else {
        EvpPkeyType::MlKem768
    };
    let mut key = EvpPkey::import(
        &context,
        kind,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .ok()?;
    let mut decapsulator =
        OsslAsymcipher::new(&context, EncOp::Decapsulate, &mut key, None).ok()?;
    decapsulator.decapsulate(ciphertext).ok()
}

/// A device-bound key made by the engine around a fresh stand-in, at the
/// harness's stamp.
pub fn device_key(shape: KeyShape, name: &str) -> (NewKey, Arc<SoftwareDevice>) {
    let device = SoftwareDevice::new(shape);
    let (signing, agreement) = device.public_keys();
    let key = generate_device_key(
        shape,
        keys::user(name),
        Expiry::Never,
        keys::STAMP,
        signing,
        agreement,
        device.clone(),
    )
    .expect("generate a device-bound key");
    (key, device)
}

/// The handle for a device-bound key made by the engine.
pub fn device_handle(key: &NewKey, device: &Arc<SoftwareDevice>) -> Arc<PrivateKey> {
    PrivateKey::device(
        key.certificate.clone(),
        key.secret.as_deref().unwrap_or_default(),
        device.clone(),
    )
    .expect("build the device handle")
}

/// The four device-bound shapes.
pub const SHAPES: [KeyShape; 4] = [
    KeyShape::V4P256,
    KeyShape::V6P256,
    KeyShape::V6MlDsa65,
    KeyShape::V6MlDsa87,
];

/// A Sequoia signer over a stand-in's P-256 signing key, for a signature the
/// engine does not make, such as a later self-signature.
pub struct StandInSigner {
    public: openpgp::packet::Key<
        openpgp::packet::key::PublicParts,
        openpgp::packet::key::UnspecifiedRole,
    >,
    device: Arc<SoftwareDevice>,
}

impl StandInSigner {
    pub fn new(cert: &openpgp::Cert, device: &Arc<SoftwareDevice>) -> Self {
        Self {
            public: cert.primary_key().key().clone().role_into_unspecified(),
            device: device.clone(),
        }
    }
}

impl Signer for StandInSigner {
    fn public(
        &self,
    ) -> &openpgp::packet::Key<
        openpgp::packet::key::PublicParts,
        openpgp::packet::key::UnspecifiedRole,
    > {
        &self.public
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &[HashAlgorithm::SHA256]
    }

    fn sign(&mut self, _: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        let answer = self.device.sign(digest.to_vec())?;
        Ok(mpi::Signature::ECDSA {
            r: mpi::MPI::new(&answer[..32]),
            s: mpi::MPI::new(&answer[32..]),
        })
    }
}
