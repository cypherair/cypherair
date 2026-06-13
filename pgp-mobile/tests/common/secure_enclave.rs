//! Shared software-P256 Secure Enclave custody test support for integration tests.
//!
//! Provides software stand-ins for the external P-256 signing and key-agreement
//! providers, plus `SoftwareP256Material`, which drives the production
//! `generate_secure_enclave_public_certificate` with a software signing key and
//! retains both secret halves. Because the software lane holds the secrets, it can
//! also export a GnuPG-importable TSK whose fingerprints match the SE-shaped public
//! certificate — enabling full bidirectional GnuPG interop in CI with no hardware.
//!
//! This is the integration-test consolidation of the per-file `OracleSigningProvider`
//! / `RuntimeKeyAgreementProvider` helpers. The unit-test copies under
//! `src/**/tests.rs` are a separate compilation population (the unit/integration
//! boundary) and are intentionally not shared from here.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use openpgp::crypto::{mpi, Signer};
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::packet::{key, Key, Packet};
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::types::{Curve, HashAlgorithm};
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{
    self, ExternalP256KeyAgreementError, ExternalP256KeyAgreementFailureCategory,
    ExternalP256KeyAgreementProvider, ExternalP256KeyAgreementRequest, ExternalP256SigningError,
    ExternalP256SigningFailureCategory, ExternalP256SigningProvider, P256EcdsaSignature,
    P256RawSharedSecret, SecureEnclaveCertificateVersion, SecureEnclavePublicCertificateInput,
};
use sequoia_openpgp as openpgp;

const P256_SCALAR_LENGTH: usize = 32;

/// A software signing provider over a Sequoia P-256 `KeyPair`, standing in for the
/// Secure Enclave external signer so the production certificate-construction and
/// runtime-signing seams run with no hardware.
pub struct OracleSigningProvider {
    keypair: Arc<Mutex<openpgp::crypto::KeyPair>>,
}

impl OracleSigningProvider {
    pub fn new(keypair: Arc<Mutex<openpgp::crypto::KeyPair>>) -> Self {
        Self { keypair }
    }
}

impl ExternalP256SigningProvider for OracleSigningProvider {
    fn sign_sha256_digest(
        &self,
        digest: Vec<u8>,
    ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
        let mut keypair = self.keypair.lock().map_err(|_| external_signing_failed())?;
        match keypair.sign(HashAlgorithm::SHA256, &digest) {
            Ok(mpi::Signature::ECDSA { r, s }) => Ok(P256EcdsaSignature {
                r: r.value_padded(P256_SCALAR_LENGTH)
                    .map_err(|_| external_signing_failed())?
                    .into_owned(),
                s: s.value_padded(P256_SCALAR_LENGTH)
                    .map_err(|_| external_signing_failed())?
                    .into_owned(),
            }),
            _ => Err(external_signing_failed()),
        }
    }
}

fn external_signing_failed() -> ExternalP256SigningError {
    ExternalP256SigningError::Failed {
        category: ExternalP256SigningFailureCategory::ExternalOperationFailed,
    }
}

/// A software key-agreement provider performing P-256 ECDH with OpenSSL over a
/// software scalar, standing in for the Secure Enclave external key-agreement provider.
pub struct SoftwareKeyAgreementProvider {
    agreement_scalar: Vec<u8>,
}

impl SoftwareKeyAgreementProvider {
    pub fn new(agreement_scalar: Vec<u8>) -> Self {
        Self { agreement_scalar }
    }
}

impl ExternalP256KeyAgreementProvider for SoftwareKeyAgreementProvider {
    fn derive_shared_secret(
        &self,
        request: ExternalP256KeyAgreementRequest,
    ) -> Result<P256RawSharedSecret, ExternalP256KeyAgreementError> {
        derive_shared_secret_with_openssl(
            &self.agreement_scalar,
            &request.recipient_public_key,
            &request.ephemeral_public_key,
        )
        .map(|raw| P256RawSharedSecret { raw })
        .map_err(|_| ExternalP256KeyAgreementError::Failed {
            category: ExternalP256KeyAgreementFailureCategory::ExternalOperationFailed,
        })
    }
}

/// Software-held P-256 material whose public halves back a production-built
/// Secure Enclave-shaped certificate, and whose secret halves drive the external
/// signer/key-agreement providers and a GnuPG-importable TSK.
pub struct SoftwareP256Material {
    pub public_key_data: Vec<u8>,
    pub revocation_cert: Vec<u8>,
    pub signing_key_fingerprint: String,
    pub key_agreement_subkey_fingerprint: String,
    keypair: Arc<Mutex<openpgp::crypto::KeyPair>>,
    agreement_scalar: Vec<u8>,
    signing_secret_material: SecretKeyMaterial,
    agreement_secret_material: SecretKeyMaterial,
}

impl SoftwareP256Material {
    /// Generate two software P-256 keys (an ECDSA signing primary and an ECDH
    /// subkey) and build the production SE-shaped public certificate around their
    /// public halves, self-signed through the software external signer.
    pub fn generate(
        version: SecureEnclaveCertificateVersion,
        expiry_seconds: Option<u64>,
    ) -> Result<Self, PgpError> {
        let signing_key: Key<key::SecretParts, key::PrimaryRole> = match version {
            SecureEnclaveCertificateVersion::V4 => key::Key4::generate_ecc(true, Curve::NistP256)
                .expect("P-256 ECDSA key should generate")
                .into(),
            SecureEnclaveCertificateVersion::V6 => key::Key6::generate_ecc(true, Curve::NistP256)
                .expect("P-256 ECDSA key should generate")
                .into(),
        };
        let agreement_key: Key<key::SecretParts, key::SubordinateRole> = match version {
            SecureEnclaveCertificateVersion::V4 => key::Key4::generate_ecc(false, Curve::NistP256)
                .expect("P-256 ECDH key should generate")
                .into(),
            SecureEnclaveCertificateVersion::V6 => key::Key6::generate_ecc(false, Curve::NistP256)
                .expect("P-256 ECDH key should generate")
                .into(),
        };

        let signing_public_key_x963 =
            public_key_x963(&signing_key.parts_as_public().role_as_unspecified().clone());
        let key_agreement_public_key_x963 = public_key_x963(
            &agreement_key
                .parts_as_public()
                .role_as_unspecified()
                .clone(),
        );

        // Retain the secret halves before consuming the signing key into a keypair:
        // the secret material backs the GnuPG-importable TSK graft, the scalar backs
        // the OpenSSL ECDH provider.
        let signing_secret_material = signing_key.secret().clone();
        let agreement_secret_material = agreement_key.secret().clone();
        let agreement_scalar = extract_agreement_scalar(&agreement_key);

        let keypair = Arc::new(Mutex::new(
            signing_key
                .role_into_unspecified()
                .into_keypair()
                .expect("signing keypair should build"),
        ));

        let generated = keys::generate_secure_enclave_public_certificate(
            SecureEnclavePublicCertificateInput {
                name: "Software SE P-256".to_string(),
                email: Some("software-se-p256@example.test".to_string()),
                expiry_seconds,
                version,
                signing_public_key_x963,
                key_agreement_public_key_x963,
            },
            Arc::new(OracleSigningProvider {
                keypair: keypair.clone(),
            }),
        )?;

        Ok(Self {
            public_key_data: generated.public_key_data,
            revocation_cert: generated.revocation_cert,
            signing_key_fingerprint: generated.signing_key_fingerprint,
            key_agreement_subkey_fingerprint: generated.key_agreement_subkey_fingerprint,
            keypair,
            agreement_scalar,
            signing_secret_material,
            agreement_secret_material,
        })
    }

    /// A signing provider bound to this material's software signing key.
    pub fn signing_provider(&self) -> Arc<dyn ExternalP256SigningProvider> {
        Arc::new(OracleSigningProvider {
            keypair: self.keypair.clone(),
        })
    }

    /// A key-agreement provider bound to this material's software ECDH scalar.
    pub fn key_agreement_provider(&self) -> Arc<dyn ExternalP256KeyAgreementProvider> {
        Arc::new(SoftwareKeyAgreementProvider {
            agreement_scalar: self.agreement_scalar.clone(),
        })
    }

    /// Re-attach the software secret halves to the certificate's own public keys
    /// (so fingerprints match by construction, regardless of generator creation-time)
    /// and serialize a binary TSK that GnuPG can import as the secret side of the
    /// SE-shaped certificate.
    pub fn export_gpg_importable_tsk(&self) -> openpgp::Result<Vec<u8>> {
        let cert = openpgp::Cert::from_bytes(&self.public_key_data)?;
        let primary_public = cert.primary_key().key().clone();
        let (primary_secret, _) = primary_public.add_secret(self.signing_secret_material.clone());
        let subkey_public = cert
            .keys()
            .subkeys()
            .next()
            .ok_or_else(|| openpgp::anyhow::anyhow!("certificate is missing a subkey"))?
            .key()
            .clone();
        let (subkey_secret, _) = subkey_public.add_secret(self.agreement_secret_material.clone());
        let (tsk_cert, _) = cert.insert_packets(vec![
            Packet::from(primary_secret),
            Packet::from(subkey_secret),
        ])?;
        let mut tsk = Vec::new();
        tsk_cert.as_tsk().serialize(&mut tsk)?;
        Ok(tsk)
    }
}

fn public_key_x963(key: &Key<key::PublicParts, key::UnspecifiedRole>) -> Vec<u8> {
    match key.mpis() {
        mpi::PublicKey::ECDSA {
            curve: Curve::NistP256,
            q,
        }
        | mpi::PublicKey::ECDH {
            curve: Curve::NistP256,
            q,
            ..
        } => q.value().to_vec(),
        _ => panic!("expected P-256 public key"),
    }
}

fn extract_agreement_scalar(key: &Key<key::SecretParts, key::SubordinateRole>) -> Vec<u8> {
    match key.secret() {
        SecretKeyMaterial::Unencrypted(secret) => secret.map(|mpis| match mpis {
            mpi::SecretKeyMaterial::ECDH { scalar } => {
                scalar.value_padded(P256_SCALAR_LENGTH).as_ref().to_vec()
            }
            _ => panic!("expected ECDH secret material"),
        }),
        SecretKeyMaterial::Encrypted(_) => panic!("expected unencrypted ECDH secret material"),
    }
}

/// P-256 ECDH via OpenSSL: derive the raw shared secret from a software private
/// scalar (bound to `recipient_public_key`) and the peer `ephemeral_public_key`.
pub fn derive_shared_secret_with_openssl(
    private_scalar: &[u8],
    recipient_public_key: &[u8],
    ephemeral_public_key: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    let recipient_point = EcPoint::from_bytes(&group, recipient_public_key, &mut ctx)?;
    let ephemeral_point = EcPoint::from_bytes(&group, ephemeral_public_key, &mut ctx)?;
    let private_scalar = BigNum::from_slice(private_scalar)?;
    let private_key =
        EcKey::from_private_components(&group, private_scalar.as_ref(), recipient_point.as_ref())?;
    private_key.check_key()?;
    let peer_key = EcKey::from_public_key(&group, ephemeral_point.as_ref())?;
    peer_key.check_key()?;

    let private_key = PKey::from_ec_key(private_key)?;
    let peer_key = PKey::from_ec_key(peer_key)?;
    let mut deriver = Deriver::new(&private_key)?;
    deriver.set_peer(&peer_key)?;
    deriver.derive_to_vec()
}
