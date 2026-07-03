//! Shared software split-custody composite test support for integration tests.
//!
//! Provides software stand-ins for the external ML-DSA-65 signing and
//! ML-KEM-768 decapsulation providers, plus `SoftwareCompositeMaterial`, which
//! drives the production `generate_secure_enclave_composite_public_certificate`
//! with software PQ component keys and retains everything an operation needs:
//! the ML-DSA/ML-KEM secrets behind the fake providers, and the classical
//! Ed25519/X25519 component secrets the production generator returned.
//!
//! The PQ component donor is a stock Sequoia `CertBuilder` composite
//! certificate — the same construction another RFC 9980 implementation (e.g.
//! `sq`) would use — so the fake providers exercise real FIPS 204/203
//! primitives: the signing fake signs with the full composite software key and
//! returns only the ML-DSA half; the decapsulation fake runs real ML-KEM-768
//! decapsulation through the `ossl` crate (the same OpenSSL wrapper Sequoia's
//! backend uses).
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::{mpi, Signer};
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::types::HashAlgorithm;
use ossl::asymcipher::{EncOp, OsslAsymcipher};
use ossl::pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
use ossl::{OsslContext, OsslSecret};
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{
    self, ExternalCompositeKeyAgreementError, ExternalCompositeKeyAgreementFailureCategory,
    ExternalCompositeSigningError, ExternalCompositeSigningFailureCategory,
    ExternalMlDsa65SigningProvider, ExternalMlKem768DecapsulationProvider,
    ExternalMlKem768DecapsulationRequest, MlDsa65Signature, MlKem768KeyShare,
    SecureEnclaveCompositePublicCertificateInput,
};
use sequoia_openpgp as openpgp;

pub const MLDSA65_PUBLIC_KEY_LENGTH: usize = 1952;
pub const MLKEM768_PUBLIC_KEY_LENGTH: usize = 1184;
pub const MLKEM768_SECRET_SEED_LENGTH: usize = 64;

/// A software ML-DSA-65 signing provider over a Sequoia composite `KeyPair`,
/// standing in for the Secure Enclave external signer. It signs with the full
/// composite key and returns only the ML-DSA half — exactly the Secure Enclave
/// primitive shape.
pub struct OracleMlDsa65SigningProvider {
    keypair: Arc<Mutex<openpgp::crypto::KeyPair>>,
}

impl OracleMlDsa65SigningProvider {
    pub fn new(keypair: Arc<Mutex<openpgp::crypto::KeyPair>>) -> Self {
        Self { keypair }
    }
}

impl ExternalMlDsa65SigningProvider for OracleMlDsa65SigningProvider {
    fn sign_mldsa65_digest(
        &self,
        digest: Vec<u8>,
    ) -> Result<MlDsa65Signature, ExternalCompositeSigningError> {
        let mut keypair = self.keypair.lock().map_err(|_| external_signing_failed())?;
        match keypair.sign(HashAlgorithm::SHA512, &digest) {
            Ok(mpi::Signature::MLDSA65_Ed25519 { mldsa, .. }) => Ok(MlDsa65Signature {
                raw: mldsa.to_vec(),
            }),
            _ => Err(external_signing_failed()),
        }
    }
}

fn external_signing_failed() -> ExternalCompositeSigningError {
    ExternalCompositeSigningError::Failed {
        category: ExternalCompositeSigningFailureCategory::ExternalOperationFailed,
    }
}

/// A software ML-KEM-768 decapsulation provider over the 64-byte FIPS 203
/// secret seed, standing in for the Secure Enclave external provider. Uses the
/// `ossl` crate — the same OpenSSL wrapper Sequoia's backend uses — so the key
/// share is byte-identical to the native decapsulation path.
pub struct SoftwareMlKem768DecapsulationProvider {
    secret_seed: Vec<u8>,
}

impl SoftwareMlKem768DecapsulationProvider {
    pub fn new(secret_seed: Vec<u8>) -> Self {
        Self { secret_seed }
    }
}

impl ExternalMlKem768DecapsulationProvider for SoftwareMlKem768DecapsulationProvider {
    fn decapsulate_mlkem768(
        &self,
        request: ExternalMlKem768DecapsulationRequest,
    ) -> Result<MlKem768KeyShare, ExternalCompositeKeyAgreementError> {
        decapsulate_mlkem768_with_ossl(&self.secret_seed, &request.mlkem_ciphertext)
            .map(|raw| MlKem768KeyShare { raw })
            .map_err(|_| ExternalCompositeKeyAgreementError::Failed {
                category: ExternalCompositeKeyAgreementFailureCategory::ExternalOperationFailed,
            })
    }
}

/// Real FIPS 203 ML-KEM-768 decapsulation from the 64-byte secret seed.
pub fn decapsulate_mlkem768_with_ossl(
    secret_seed: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ossl::Error> {
    let ctx = OsslContext::new_lib_ctx();
    let mut key = EvpPkey::import(
        &ctx,
        EvpPkeyType::MlKem768,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(secret_seed)),
        }),
    )?;
    let mut decapsulator = OsslAsymcipher::new(&ctx, EncOp::Decapsulate, &mut key, None)?;
    decapsulator.decapsulate(ciphertext)
}

/// Software-held composite material whose PQ public halves back a
/// production-built Device-Bound Post-Quantum-shaped certificate, and whose PQ
/// secret halves drive the external signing/decapsulation providers. The
/// classical component secrets are the ones the production generator returned.
pub struct SoftwareCompositeMaterial {
    pub public_key_data: Vec<u8>,
    pub revocation_cert: Vec<u8>,
    pub fingerprint: String,
    pub signing_key_fingerprint: String,
    pub key_agreement_subkey_fingerprint: String,
    pub classical_eddsa_secret: Vec<u8>,
    pub classical_ecdh_secret: Vec<u8>,
    pub mldsa65_signing_public_key: Vec<u8>,
    pub mlkem768_key_agreement_public_key: Vec<u8>,
    signing_keypair: Arc<Mutex<openpgp::crypto::KeyPair>>,
    mlkem_secret_seed: Vec<u8>,
}

impl SoftwareCompositeMaterial {
    /// Generate software composite PQ donor keys and build the production
    /// split-custody-shaped public certificate around their PQ public halves,
    /// self-signed through the software external signer.
    pub fn generate(expiry_seconds: Option<u64>) -> Result<Self, PgpError> {
        Self::generate_with_identity(
            "Software Composite",
            Some("software-composite@example.test"),
            expiry_seconds,
        )
    }

    pub fn generate_with_identity(
        name: &str,
        email: Option<&str>,
        expiry_seconds: Option<u64>,
    ) -> Result<Self, PgpError> {
        let (donor, _rev) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
            .set_profile(openpgp::Profile::RFC9580)
            .expect("set RFC 9580 profile")
            .add_userid("PQ Component Donor <donor@composite.test>")
            .add_transport_encryption_subkey()
            .generate()
            .expect("generate software composite donor");

        let primary = donor.primary_key().key().clone();
        let mldsa65_signing_public_key = match primary.mpis() {
            mpi::PublicKey::MLDSA65_Ed25519 { mldsa, .. } => mldsa.to_vec(),
            _ => panic!("expected composite primary key"),
        };
        let signing_keypair = Arc::new(Mutex::new(
            primary
                .parts_into_secret()
                .expect("donor primary secret parts")
                .role_into_unspecified()
                .into_keypair()
                .expect("donor signing keypair"),
        ));

        let ka_donor = donor
            .keys()
            .subkeys()
            .next()
            .expect("donor encryption subkey")
            .key()
            .clone();
        let mlkem768_key_agreement_public_key = match ka_donor.mpis() {
            mpi::PublicKey::MLKEM768_X25519 { mlkem, .. } => mlkem.to_vec(),
            _ => panic!("expected composite KA subkey"),
        };
        let mlkem_secret_seed = match ka_donor.optional_secret() {
            Some(SecretKeyMaterial::Unencrypted(secret)) => secret.map(|mpis| match mpis {
                mpi::SecretKeyMaterial::MLKEM768_X25519 { mlkem, .. } => mlkem.to_vec(),
                _ => panic!("expected composite KA secret material"),
            }),
            _ => panic!("expected unencrypted KA secret material"),
        };
        assert_eq!(mlkem_secret_seed.len(), MLKEM768_SECRET_SEED_LENGTH);

        let generated = keys::generate_secure_enclave_composite_public_certificate(
            SecureEnclaveCompositePublicCertificateInput {
                name: name.to_string(),
                email: email.map(str::to_string),
                expiry_seconds,
                mldsa65_signing_public_key: mldsa65_signing_public_key.clone(),
                mlkem768_key_agreement_public_key: mlkem768_key_agreement_public_key.clone(),
            },
            Arc::new(OracleMlDsa65SigningProvider {
                keypair: signing_keypair.clone(),
            }),
        )?;

        Ok(Self {
            public_key_data: generated.public_key_data,
            revocation_cert: generated.revocation_cert,
            fingerprint: generated.fingerprint,
            signing_key_fingerprint: generated.signing_key_fingerprint,
            key_agreement_subkey_fingerprint: generated.key_agreement_subkey_fingerprint,
            classical_eddsa_secret: generated.classical_eddsa_secret,
            classical_ecdh_secret: generated.classical_ecdh_secret,
            mldsa65_signing_public_key,
            mlkem768_key_agreement_public_key,
            signing_keypair,
            mlkem_secret_seed,
        })
    }

    /// A signing provider bound to this material's software ML-DSA-65 key.
    pub fn signing_provider(&self) -> Arc<dyn ExternalMlDsa65SigningProvider> {
        Arc::new(OracleMlDsa65SigningProvider {
            keypair: self.signing_keypair.clone(),
        })
    }

    /// A decapsulation provider bound to this material's software ML-KEM-768 seed.
    pub fn decapsulation_provider(&self) -> Arc<dyn ExternalMlKem768DecapsulationProvider> {
        Arc::new(SoftwareMlKem768DecapsulationProvider {
            secret_seed: self.mlkem_secret_seed.clone(),
        })
    }
}

/// A signing provider that always cancels — for cancellation-path tests.
pub struct CancellingMlDsa65SigningProvider;

impl ExternalMlDsa65SigningProvider for CancellingMlDsa65SigningProvider {
    fn sign_mldsa65_digest(
        &self,
        _digest: Vec<u8>,
    ) -> Result<MlDsa65Signature, ExternalCompositeSigningError> {
        Err(ExternalCompositeSigningError::OperationCancelled)
    }
}

/// A decapsulation provider that always cancels — for cancellation-path tests.
pub struct CancellingMlKem768DecapsulationProvider;

impl ExternalMlKem768DecapsulationProvider for CancellingMlKem768DecapsulationProvider {
    fn decapsulate_mlkem768(
        &self,
        _request: ExternalMlKem768DecapsulationRequest,
    ) -> Result<MlKem768KeyShare, ExternalCompositeKeyAgreementError> {
        Err(ExternalCompositeKeyAgreementError::OperationCancelled)
    }
}

/// A decapsulation provider returning a fixed (wrong) key share — for
/// fail-closed session-unwrap tests.
pub struct WrongShareMlKem768DecapsulationProvider;

impl ExternalMlKem768DecapsulationProvider for WrongShareMlKem768DecapsulationProvider {
    fn decapsulate_mlkem768(
        &self,
        _request: ExternalMlKem768DecapsulationRequest,
    ) -> Result<MlKem768KeyShare, ExternalCompositeKeyAgreementError> {
        Ok(MlKem768KeyShare {
            raw: vec![0x5Au8; 32],
        })
    }
}
