use super::*;

use std::{
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use openpgp::crypto::{mpi, Decryptor, SessionKey, Signer};
use openpgp::packet::{key, signature, Key, Packet, UserID};
use openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{
    Encryptor, LiteralWriter, Message, Recipient, Signer as StreamSigner,
};
use openpgp::serialize::Serialize;
use openpgp::types::{Curve, Features, HashAlgorithm, KeyFlags, SignatureType};
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use sequoia_openpgp as openpgp;

use crate::decrypt::{decrypt_with_helper, SignatureStatus};
use crate::encrypt;
use crate::error::PgpError;
use crate::external_signer::{ExternalP256Signature, ExternalP256Signer, ExternalP256SignerError};
use crate::keys::{
    self, ExternalP256KeyAgreementError, ExternalP256KeyAgreementFailureCategory,
    ExternalP256KeyAgreementProvider, P256RawSharedSecret,
};
use crate::signature_details::{LegacyFoldMode, SignatureCollector};
use crate::PgpEngine;

#[derive(Clone, Copy, Debug)]
enum CandidateVersion {
    V4,
    V6,
}

impl CandidateVersion {
    fn all() -> [CandidateVersion; 2] {
        [CandidateVersion::V4, CandidateVersion::V6]
    }

    fn label(self) -> &'static str {
        match self {
            CandidateVersion::V4 => "v4",
            CandidateVersion::V6 => "v6",
        }
    }

    fn expected_key_version(self) -> u8 {
        match self {
            CandidateVersion::V4 => 4,
            CandidateVersion::V6 => 6,
        }
    }
}

struct CandidateMaterial {
    public_cert: Vec<u8>,
    signing_public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    signing_keypair: openpgp::crypto::KeyPair,
    agreement_public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    agreement_scalar: Vec<u8>,
}

struct RuntimeKeyAgreementProvider {
    agreement_scalar: Vec<u8>,
    request_count: Arc<AtomicUsize>,
    captured_requests: Arc<Mutex<Vec<ExternalP256KeyAgreementRequest>>>,
}

impl RuntimeKeyAgreementProvider {
    fn new(agreement_scalar: Vec<u8>) -> Self {
        Self {
            agreement_scalar,
            request_count: Arc::new(AtomicUsize::new(0)),
            captured_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    fn captured_requests(&self) -> Vec<ExternalP256KeyAgreementRequest> {
        self.captured_requests.lock().unwrap().clone()
    }
}

impl ExternalP256KeyAgreementProvider for RuntimeKeyAgreementProvider {
    fn derive_shared_secret(
        &self,
        request: ExternalP256KeyAgreementRequest,
    ) -> Result<P256RawSharedSecret, ExternalP256KeyAgreementError> {
        self.request_count.fetch_add(1, Ordering::SeqCst);
        self.captured_requests.lock().unwrap().push(request.clone());
        derive_shared_secret_with_openssl(
            &self.agreement_scalar,
            request.recipient_public_key(),
            request.ephemeral_public_key(),
        )
        .map(|raw| P256RawSharedSecret { raw })
        .map_err(|_| ExternalP256KeyAgreementError::Failed {
            category: ExternalP256KeyAgreementFailureCategory::ExternalOperationFailed,
        })
    }
}

struct FixedRuntimeKeyAgreementProvider {
    response: Result<P256RawSharedSecret, ExternalP256KeyAgreementError>,
    request_count: Arc<AtomicUsize>,
}

impl FixedRuntimeKeyAgreementProvider {
    fn new(response: Result<P256RawSharedSecret, ExternalP256KeyAgreementError>) -> Self {
        Self {
            response,
            request_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }
}

impl ExternalP256KeyAgreementProvider for FixedRuntimeKeyAgreementProvider {
    fn derive_shared_secret(
        &self,
        _request: ExternalP256KeyAgreementRequest,
    ) -> Result<P256RawSharedSecret, ExternalP256KeyAgreementError> {
        self.request_count.fetch_add(1, Ordering::SeqCst);
        match &self.response {
            Ok(response) => Ok(response.clone()),
            Err(ExternalP256KeyAgreementError::Failed { category }) => {
                Err(ExternalP256KeyAgreementError::Failed {
                    category: *category,
                })
            }
            Err(ExternalP256KeyAgreementError::OperationCancelled) => {
                Err(ExternalP256KeyAgreementError::OperationCancelled)
            }
        }
    }
}

#[derive(Clone, Default)]
struct ExternalDecryptTelemetry {
    recovered_session_keys: Arc<AtomicUsize>,
    accepted_payload_keys: Arc<AtomicUsize>,
}

impl ExternalDecryptTelemetry {
    fn record_recovered_session_key(&self) {
        self.recovered_session_keys.fetch_add(1, Ordering::SeqCst);
    }

    fn record_accepted_payload_key(&self) {
        self.accepted_payload_keys.fetch_add(1, Ordering::SeqCst);
    }

    fn recovered_session_key_count(&self) -> usize {
        self.recovered_session_keys.load(Ordering::SeqCst)
    }

    fn accepted_payload_key_count(&self) -> usize {
        self.accepted_payload_keys.load(Ordering::SeqCst)
    }
}

struct ExternalDecryptHelper<F>
where
    F: FnMut(
        ExternalP256KeyAgreementRequest,
    ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>,
{
    recipient_certs: Vec<openpgp::Cert>,
    verifier_certs: Vec<openpgp::Cert>,
    key_agreement_operation: F,
    collector: SignatureCollector,
    telemetry: ExternalDecryptTelemetry,
}

impl<F> VerificationHelper for ExternalDecryptHelper<F>
where
    F: FnMut(
        ExternalP256KeyAgreementRequest,
    ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>,
{
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        let mut all_certs = self.verifier_certs.clone();
        all_certs.extend(self.recipient_certs.iter().cloned());
        Ok(all_certs)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        self.collector.observe_structure(structure);
        Ok(())
    }
}

impl<F> DecryptionHelper for ExternalDecryptHelper<F>
where
    F: FnMut(
            ExternalP256KeyAgreementRequest,
        ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>
        + Send
        + Sync,
{
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<openpgp::types::SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        let policy = StandardPolicy::new();

        for pkesk in pkesks {
            for cert in &self.recipient_certs {
                for ka in cert
                    .keys()
                    .with_policy(&policy, None)
                    .supported()
                    .key_handles(pkesk.recipient())
                    .for_transport_encryption()
                {
                    let mut decryptor = ExternalP256Decryptor::new(
                        ka.key().clone().role_into_unspecified(),
                        &mut self.key_agreement_operation,
                    )?;
                    let decrypted = pkesk.decrypt(&mut decryptor, sym_algo);
                    if let Some(error) = decryptor.take_last_error() {
                        return Err(error.into());
                    }
                    if let Some((algo, session_key)) = decrypted {
                        self.telemetry.record_recovered_session_key();
                        if decrypt(algo, &session_key) {
                            self.telemetry.record_accepted_payload_key();
                            return Ok(None);
                        }
                    }
                }
            }
        }

        Err(openpgp::anyhow::anyhow!("No key to decrypt message"))
    }
}

fn build_candidate(version: CandidateVersion) -> openpgp::Result<CandidateMaterial> {
    let primary: Key<key::SecretParts, key::PrimaryRole> = match version {
        CandidateVersion::V4 => key::Key4::generate_ecc(true, Curve::NistP256)?.into(),
        CandidateVersion::V6 => key::Key6::generate_ecc(true, Curve::NistP256)?.into(),
    };
    let agreement: Key<key::SecretParts, key::SubordinateRole> = match version {
        CandidateVersion::V4 => key::Key4::generate_ecc(false, Curve::NistP256)?.into(),
        CandidateVersion::V6 => key::Key6::generate_ecc(false, Curve::NistP256)?.into(),
    };

    let signing_public_key = primary.parts_as_public().role_as_unspecified().clone();
    let mut oracle = primary.role_into_unspecified().into_keypair()?;
    let agreement_public_key = agreement.parts_as_public().role_as_unspecified().clone();
    let agreement_scalar = extract_agreement_scalar(&agreement)?;

    let primary_public = signing_public_key.clone().role_into_primary();
    let mut cert = openpgp::Cert::try_from(vec![Packet::from(primary_public)])?;
    let user_id = UserID::from(format!(
        "SE {label} ECDH <se-{label}-ecdh@example.test>",
        label = version.label()
    ));
    let mut user_id_builder =
        signature::SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_hash_algo(HashAlgorithm::SHA256)
            .set_key_flags(KeyFlags::empty().set_certification().set_signing())?;
    if matches!(version, CandidateVersion::V4) {
        user_id_builder = user_id_builder.set_features(Features::empty().set_seipdv1())?;
    } else {
        user_id_builder = user_id_builder.set_features(Features::empty().set_seipdv2())?;
    }

    let user_id_binding = user_id.bind(
        &mut signer_for(&signing_public_key, &mut oracle)?,
        &cert,
        user_id_builder,
    )?;
    cert = cert
        .insert_packets(vec![Packet::from(user_id), user_id_binding.into()])?
        .0;

    let subkey_public = agreement_public_key.clone().role_into_subordinate();
    let subkey_binding = subkey_public.bind(
        &mut signer_for(&signing_public_key, &mut oracle)?,
        &cert,
        signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(HashAlgorithm::SHA256)
            .set_key_flags(KeyFlags::empty().set_transport_encryption())?,
    )?;
    cert = cert
        .insert_packets(vec![Packet::from(subkey_public), subkey_binding.into()])?
        .0;

    let mut public_cert = Vec::new();
    cert.serialize(&mut public_cert)?;

    Ok(CandidateMaterial {
        public_cert,
        signing_public_key,
        signing_keypair: oracle,
        agreement_public_key,
        agreement_scalar,
    })
}

fn extract_agreement_scalar(
    key: &Key<key::SecretParts, key::SubordinateRole>,
) -> openpgp::Result<Vec<u8>> {
    match key.secret() {
        openpgp::packet::key::SecretKeyMaterial::Unencrypted(secret) => {
            secret.map(|mpis| match mpis {
                mpi::SecretKeyMaterial::ECDH { scalar } => Ok(scalar
                    .value_padded(P256_SHARED_SECRET_LENGTH)
                    .as_ref()
                    .to_vec()),
                _ => Err(openpgp::Error::InvalidOperation(
                    "expected ECDH secret material".to_string(),
                )
                .into()),
            })
        }
        openpgp::packet::key::SecretKeyMaterial::Encrypted(_) => {
            Err(openpgp::Error::InvalidOperation(
                "expected unencrypted ECDH secret material".to_string(),
            )
            .into())
        }
    }
}

fn signer_for<'a>(
    public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    oracle: &'a mut openpgp::crypto::KeyPair,
) -> openpgp::Result<
    ExternalP256Signer<
        impl FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, ExternalP256SignerError>
            + Send
            + Sync
            + 'a,
    >,
> {
    ExternalP256Signer::new(public_key.clone(), move |hash_algo, digest| {
        match oracle.sign(hash_algo, digest) {
            Ok(mpi::Signature::ECDSA { r, s }) => Ok(ExternalP256Signature::new(
                r.value_padded(P256_SHARED_SECRET_LENGTH)
                    .map_err(|_| ExternalP256SignerError::external_operation_failed())?
                    .into_owned(),
                s.value_padded(P256_SHARED_SECRET_LENGTH)
                    .map_err(|_| ExternalP256SignerError::external_operation_failed())?
                    .into_owned(),
            )),
            Ok(_) | Err(_) => Err(ExternalP256SignerError::external_operation_failed()),
        }
    })
}

fn oracle_for(
    agreement_scalar: Vec<u8>,
) -> impl FnMut(
    ExternalP256KeyAgreementRequest,
) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError> {
    move |request| {
        derive_shared_secret_with_openssl(
            &agreement_scalar,
            request.recipient_public_key(),
            request.ephemeral_public_key(),
        )
        .map(ExternalP256SharedSecret::new)
        .map_err(|_| external_operation_failed())
    }
}

fn external_operation_failed() -> ExternalP256DecryptorError {
    ExternalP256DecryptorError::ExternalFailure(
        ExternalP256KeyAgreementFailureCategory::ExternalOperationFailed,
    )
}

fn derive_shared_secret_with_openssl(
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

fn public_point_for(key: &Key<key::PublicParts, key::UnspecifiedRole>) -> Vec<u8> {
    match key.mpis() {
        mpi::PublicKey::ECDH {
            curve: Curve::NistP256,
            q,
            ..
        } => q.value().to_vec(),
        _ => panic!("expected ECDH P-256 public key"),
    }
}

fn decrypt_with_external_oracle(
    ciphertext: &[u8],
    material: &CandidateMaterial,
    verification_certs: &[openpgp::Cert],
) -> Result<
    (
        Vec<u8>,
        ExternalDecryptHelper<
            impl FnMut(
                    ExternalP256KeyAgreementRequest,
                )
                    -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>
                + Send
                + Sync,
        >,
    ),
    PgpError,
> {
    decrypt_with_external_operation(
        ciphertext,
        material,
        verification_certs,
        oracle_for(material.agreement_scalar.clone()),
        ExternalDecryptTelemetry::default(),
    )
}

fn decrypt_with_external_operation<F>(
    ciphertext: &[u8],
    material: &CandidateMaterial,
    verification_certs: &[openpgp::Cert],
    key_agreement_operation: F,
    telemetry: ExternalDecryptTelemetry,
) -> Result<(Vec<u8>, ExternalDecryptHelper<F>), PgpError>
where
    F: FnMut(
            ExternalP256KeyAgreementRequest,
        ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>
        + Send
        + Sync,
{
    let policy = StandardPolicy::new();
    let recipient_cert =
        openpgp::Cert::from_bytes(&material.public_cert).map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Invalid public key: {e}"),
        })?;
    let helper = ExternalDecryptHelper {
        recipient_certs: vec![recipient_cert],
        verifier_certs: verification_certs.to_vec(),
        key_agreement_operation,
        collector: SignatureCollector::new(LegacyFoldMode::DecryptLike),
        telemetry,
    };

    decrypt_with_helper(ciphertext, &policy, helper)
}

fn encrypt_signed_binary(
    plaintext: &[u8],
    recipient_cert: &[u8],
    signer: impl openpgp::crypto::Signer + Send + Sync,
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let certs = encrypt::collect_recipients(&[recipient_cert.to_vec()], None, &policy)?;
    let recipient_keys = encrypt::build_recipients(&certs, &policy);
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;
    let message = StreamSigner::new(message, signer)
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Signer setup failed: {e}"),
        })?
        .build()
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Signer setup failed: {e}"),
        })?;
    let mut literal =
        LiteralWriter::new(message)
            .build()
            .map_err(|e| PgpError::EncryptionFailed {
                reason: format!("Literal writer setup failed: {e}"),
            })?;
    literal
        .write_all(plaintext)
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Write failed: {e}"),
        })?;
    literal.finalize().map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Finalize failed: {e}"),
    })?;

    Ok(sink)
}

fn build_rsa_recipient_cert() -> openpgp::Result<Vec<u8>> {
    let (cert, _revocation) = openpgp::cert::CertBuilder::new()
        .set_cipher_suite(openpgp::cert::CipherSuite::RSA2k)
        .add_userid("RSA Recipient <rsa-recipient@example.test>")
        .add_transport_encryption_subkey()
        .generate()?;
    let mut public_cert = Vec::new();
    cert.serialize(&mut public_cert)?;
    Ok(public_cert)
}

/// Encrypt to multiple recipients in order while hiding every recipient keyid
/// behind the wildcard id (GnuPG `--throw-keyids` / `--hidden-recipient` style).
/// PKESKs are emitted in `recipient_certs` order, so a non-matching packet can be
/// placed before the intended recipient's packet.
fn encrypt_hidden_recipients_binary(
    plaintext: &[u8],
    recipient_certs: &[&[u8]],
) -> Result<Vec<u8>, PgpError> {
    let policy = StandardPolicy::new();
    let certs: Vec<openpgp::Cert> = recipient_certs
        .iter()
        .map(|bytes| openpgp::Cert::from_bytes(bytes))
        .collect::<openpgp::Result<Vec<_>>>()
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Invalid recipient cert: {e}"),
        })?;

    let mut recipients: Vec<Recipient> = Vec::new();
    for cert in &certs {
        for ka in cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .for_transport_encryption()
        {
            let recipient: Recipient = ka.into();
            let hidden = recipient
                .set_key_handle(openpgp::KeyHandle::KeyID(openpgp::KeyID::wildcard()))
                .map_err(|e| PgpError::EncryptionFailed {
                    reason: format!("Failed to hide recipient keyid: {e}"),
                })?;
            recipients.push(hidden);
        }
    }

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Encryptor setup failed: {e}"),
        })?;
    let mut literal =
        LiteralWriter::new(message)
            .build()
            .map_err(|e| PgpError::EncryptionFailed {
                reason: format!("Literal writer setup failed: {e}"),
            })?;
    literal
        .write_all(plaintext)
        .map_err(|e| PgpError::EncryptionFailed {
            reason: format!("Write failed: {e}"),
        })?;
    literal.finalize().map_err(|e| PgpError::EncryptionFailed {
        reason: format!("Finalize failed: {e}"),
    })?;
    Ok(sink)
}

fn assert_valid_public_candidate(version: CandidateVersion, public_cert: &[u8]) {
    let parsed = openpgp::Cert::from_bytes(public_cert).expect("candidate should parse");
    assert!(
        !parsed.is_tsk(),
        "Secure Enclave-shaped candidate must not contain secret key material"
    );
    assert_eq!(
        parsed.primary_key().key().version(),
        version.expected_key_version()
    );

    let validation = keys::validate_public_certificate(public_cert)
        .expect("candidate public certificate should validate");
    assert_eq!(
        validation.key_info.key_version,
        version.expected_key_version()
    );
    assert!(validation.key_info.has_encryption_subkey);

    let selectors = keys::discover_certificate_selectors(public_cert)
        .expect("candidate selectors should be discoverable");
    assert_eq!(selectors.user_ids.len(), 1);
    assert_eq!(selectors.subkeys.len(), 1);
}

fn assert_message_format(version: CandidateVersion, ciphertext: &[u8]) {
    let mut has_v1 = false;
    let mut has_v2 = false;
    let mut ppr =
        openpgp::parse::PacketParser::from_bytes(ciphertext).expect("ciphertext should parse");
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        if let openpgp::Packet::SEIP(seip) = &pp.packet {
            has_v1 |= seip.version() == 1;
            has_v2 |= seip.version() == 2;
        }
        let (_, next) = pp.next().expect("packet parser should advance");
        ppr = next;
    }

    match version {
        CandidateVersion::V4 => {
            assert!(has_v1, "v4 candidate should receive SEIPDv1");
            assert!(!has_v2, "v4 candidate should not receive SEIPDv2");
        }
        CandidateVersion::V6 => {
            assert!(!has_v1, "v6 candidate should not receive SEIPDv1");
            assert!(has_v2, "v6 candidate should receive SEIPDv2");
        }
    }
}

fn tamper_near_payload_tail(ciphertext: &[u8]) -> Vec<u8> {
    assert!(
        ciphertext.len() > 16,
        "ciphertext should be long enough to tamper near payload tail"
    );
    let mut tampered = ciphertext.to_vec();
    let tamper_pos = tampered.len().saturating_sub(8);
    tampered[tamper_pos] ^= 0x01;
    tampered
}

#[test]
fn test_external_decryptor_builds_valid_public_only_p256_certificates() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        assert_valid_public_candidate(version, &material.public_cert);
    }
}

#[test]
fn test_external_decryptor_decrypts_v4_and_v6_messages() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let plaintext = format!("external decryptor {}", version.label()).into_bytes();
        let ciphertext =
            encrypt::encrypt_binary(&plaintext, &[material.public_cert.clone()], None, None)
                .expect("encryption to public-only candidate should succeed");
        assert_message_format(version, &ciphertext);

        let (decrypted, helper) = decrypt_with_external_oracle(&ciphertext, &material, &[])
            .expect("external decryptor should recover plaintext");
        assert_eq!(decrypted, plaintext);
        let (legacy_status, _, _, _, _) = helper.collector.into_parts();
        assert_eq!(legacy_status, SignatureStatus::NotSigned);
    }
}

#[test]
fn test_external_decryptor_signed_messages_preserve_signature_status() {
    for version in CandidateVersion::all() {
        let mut material = build_candidate(version).expect("candidate should build");
        let plaintext = format!("signed external decryptor {}", version.label()).into_bytes();
        let signer = signer_for(&material.signing_public_key, &mut material.signing_keypair)
            .expect("external signer should initialize");
        let ciphertext = encrypt_signed_binary(&plaintext, &material.public_cert, signer)
            .expect("signed encryption should succeed");
        let verifier_cert = openpgp::Cert::from_bytes(&material.public_cert)
            .expect("verification cert should parse");

        let (decrypted, helper) =
            decrypt_with_external_oracle(&ciphertext, &material, &[verifier_cert])
                .expect("external decryptor should recover signed plaintext");
        assert_eq!(decrypted, plaintext);
        let (legacy_status, _, _, _, _) = helper.collector.into_parts();
        assert_eq!(legacy_status, SignatureStatus::Valid);
    }
}

#[test]
fn test_runtime_external_key_agreement_api_decrypts_v4_and_v6_messages() {
    let engine = PgpEngine::new();
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let plaintext = format!("runtime external key agreement {}", version.label()).into_bytes();
        let ciphertext =
            encrypt::encrypt_binary(&plaintext, &[material.public_cert.clone()], None, None)
                .expect("encryption to public-only candidate should succeed");
        let provider = Arc::new(RuntimeKeyAgreementProvider::new(
            material.agreement_scalar.clone(),
        ));

        let result = engine
            .decrypt_detailed_with_external_p256_key_agreement(
                ciphertext,
                material.public_cert.clone(),
                material.agreement_public_key.fingerprint().to_hex(),
                provider.clone(),
                Vec::new(),
            )
            .expect("runtime external key agreement should decrypt");

        assert_eq!(result.plaintext, plaintext);
        assert_eq!(result.legacy_status, SignatureStatus::NotSigned);
        assert!(provider.request_count() > 0);
        let requests = provider.captured_requests();
        assert!(!requests.is_empty());
        assert_eq!(
            requests[0].recipient_public_key(),
            public_point_for(&material.agreement_public_key)
        );
        assert_eq!(
            requests[0].ephemeral_public_key().len(),
            P256_PUBLIC_KEY_LENGTH
        );
    }
}

#[test]
fn test_runtime_external_key_agreement_api_preserves_signature_status() {
    let engine = PgpEngine::new();
    for version in CandidateVersion::all() {
        let mut material = build_candidate(version).expect("candidate should build");
        let plaintext = format!("runtime signed decrypt {}", version.label()).into_bytes();
        let signer = signer_for(&material.signing_public_key, &mut material.signing_keypair)
            .expect("external signer should initialize");
        let ciphertext = encrypt_signed_binary(&plaintext, &material.public_cert, signer)
            .expect("signed encryption should succeed");
        let provider = Arc::new(RuntimeKeyAgreementProvider::new(
            material.agreement_scalar.clone(),
        ));

        let result = engine
            .decrypt_detailed_with_external_p256_key_agreement(
                ciphertext,
                material.public_cert.clone(),
                material.agreement_public_key.fingerprint().to_hex(),
                provider,
                vec![material.public_cert.clone()],
            )
            .expect("runtime external key agreement should decrypt signed message");

        assert_eq!(result.plaintext, plaintext);
        assert_eq!(result.legacy_status, SignatureStatus::Valid);
    }
}

#[test]
fn test_runtime_external_key_agreement_api_maps_callback_cancel_and_failure() {
    let engine = PgpEngine::new();
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let ciphertext = encrypt::encrypt_binary(
        b"callback error",
        &[material.public_cert.clone()],
        None,
        None,
    )
    .expect("encryption should succeed");
    let cancelled = Arc::new(FixedRuntimeKeyAgreementProvider::new(Err(
        ExternalP256KeyAgreementError::OperationCancelled,
    )));

    let result = engine.decrypt_detailed_with_external_p256_key_agreement(
        ciphertext.clone(),
        material.public_cert.clone(),
        material.agreement_public_key.fingerprint().to_hex(),
        cancelled.clone(),
        Vec::new(),
    );
    assert!(matches!(result, Err(PgpError::OperationCancelled)));
    assert!(cancelled.request_count() > 0);

    let failed = Arc::new(FixedRuntimeKeyAgreementProvider::new(Err(
        ExternalP256KeyAgreementError::Failed {
            category: ExternalP256KeyAgreementFailureCategory::LocalAuthenticationFailed,
        },
    )));
    let result = engine.decrypt_detailed_with_external_p256_key_agreement(
        ciphertext,
        material.public_cert.clone(),
        material.agreement_public_key.fingerprint().to_hex(),
        failed.clone(),
        Vec::new(),
    );
    assert!(matches!(
        result,
        Err(PgpError::ExternalP256KeyAgreementFailed {
            category: ExternalP256KeyAgreementFailureCategory::LocalAuthenticationFailed
        })
    ));
    assert!(failed.request_count() > 0);
}

#[test]
fn test_runtime_external_key_agreement_api_rejects_invalid_response_and_wrong_selector() {
    let engine = PgpEngine::new();
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let ciphertext = encrypt::encrypt_binary(
        b"invalid response",
        &[material.public_cert.clone()],
        None,
        None,
    )
    .expect("encryption should succeed");
    let zero_secret = Arc::new(FixedRuntimeKeyAgreementProvider::new(Ok(
        P256RawSharedSecret {
            raw: vec![0u8; P256_SHARED_SECRET_LENGTH],
        },
    )));

    let result = engine.decrypt_detailed_with_external_p256_key_agreement(
        ciphertext.clone(),
        material.public_cert.clone(),
        material.agreement_public_key.fingerprint().to_hex(),
        zero_secret.clone(),
        Vec::new(),
    );
    assert!(matches!(
        result,
        Err(PgpError::ExternalP256KeyAgreementFailed {
            category: ExternalP256KeyAgreementFailureCategory::ExternalOperationInvalidResponse
        })
    ));
    assert!(zero_secret.request_count() > 0);

    let unexpected = Arc::new(FixedRuntimeKeyAgreementProvider::new(Ok(
        P256RawSharedSecret {
            raw: vec![1u8; P256_SHARED_SECRET_LENGTH],
        },
    )));
    let result = engine.decrypt_detailed_with_external_p256_key_agreement(
        ciphertext,
        material.public_cert.clone(),
        material.signing_public_key.fingerprint().to_hex(),
        unexpected.clone(),
        Vec::new(),
    );
    assert!(matches!(result, Err(PgpError::NoMatchingKey)));
    assert_eq!(
        unexpected.request_count(),
        0,
        "wrong key-agreement selector must fail before callback"
    );
}

#[test]
fn test_external_key_agreement_boundary_errors_map_to_typed_categories() {
    let invalid_request = crate::decrypt::classify_decrypt_error(
        ExternalP256DecryptorError::InvalidRequest("bad request").into(),
    );
    assert!(matches!(
        invalid_request,
        PgpError::ExternalP256KeyAgreementFailed {
            category: ExternalP256KeyAgreementFailureCategory::ExternalOperationInvalidRequest
        }
    ));

    let invalid_response = crate::decrypt::classify_decrypt_error(
        ExternalP256DecryptorError::InvalidResponse("bad response").into(),
    );
    assert!(matches!(
        invalid_response,
        PgpError::ExternalP256KeyAgreementFailed {
            category: ExternalP256KeyAgreementFailureCategory::ExternalOperationInvalidResponse
        }
    ));
}

#[test]
fn test_runtime_external_key_agreement_api_hard_aborts_invalid_response_before_later_pkesk() {
    let first = build_candidate(CandidateVersion::V4).expect("first candidate should build");
    let second = build_candidate(CandidateVersion::V4).expect("second candidate should build");
    let ciphertext = encrypt::encrypt_binary(
        b"must not try later pkesk after invalid response",
        &[first.public_cert.clone(), second.public_cert.clone()],
        None,
        None,
    )
    .expect("encryption should succeed");
    let policy = StandardPolicy::new();
    let first_cert =
        openpgp::Cert::from_bytes(&first.public_cert).expect("first recipient cert should parse");
    let second_cert =
        openpgp::Cert::from_bytes(&second.public_cert).expect("second recipient cert should parse");
    let first_public = public_point_for(&first.agreement_public_key);
    let second_public = public_point_for(&second.agreement_public_key);
    let second_scalar = second.agreement_scalar.clone();
    let operation_calls = Arc::new(AtomicUsize::new(0));
    let operation_calls_for_assertion = Arc::clone(&operation_calls);

    let helper = ExternalDecryptHelper {
        recipient_certs: vec![first_cert, second_cert],
        verifier_certs: Vec::new(),
        key_agreement_operation: move |request: ExternalP256KeyAgreementRequest| {
            operation_calls.fetch_add(1, Ordering::SeqCst);
            if request.recipient_public_key() == first_public.as_slice() {
                return Ok(ExternalP256SharedSecret::new(vec![
                    0u8;
                    P256_SHARED_SECRET_LENGTH
                ]));
            }
            if request.recipient_public_key() == second_public.as_slice() {
                return derive_shared_secret_with_openssl(
                    &second_scalar,
                    request.recipient_public_key(),
                    request.ephemeral_public_key(),
                )
                .map(ExternalP256SharedSecret::new)
                .map_err(|_| external_operation_failed());
            }
            Err(ExternalP256DecryptorError::InvalidRequest(
                "unexpected recipient public key",
            ))
        },
        collector: SignatureCollector::new(LegacyFoldMode::DecryptLike),
        telemetry: ExternalDecryptTelemetry::default(),
    };

    let result = decrypt_with_helper(&ciphertext, &policy, helper);
    assert!(matches!(
        result,
        Err(PgpError::ExternalP256KeyAgreementFailed {
            category: ExternalP256KeyAgreementFailureCategory::ExternalOperationInvalidResponse
        })
    ));
    assert_eq!(
        operation_calls_for_assertion.load(Ordering::SeqCst),
        1,
        "invalid callback response must hard-abort before later PKESKs"
    );
}

#[test]
fn test_runtime_external_key_agreement_api_decrypts_hidden_recipient_message_skipping_non_ecdh_pkesk(
) {
    let engine = PgpEngine::new();
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let rsa_recipient = build_rsa_recipient_cert().expect("RSA recipient cert should build");
    let plaintext = b"hidden recipient mixed RSA and P-256".to_vec();
    // Hidden (wildcard) recipients; the non-ECDH RSA PKESK is emitted before the
    // P-256 ECDH PKESK. A wildcard recipient speculatively matches our key, so the
    // RSA packet reaches prepare_request and is rejected as a non-match: it must be
    // skipped, not treated as a definitive failure for the whole message.
    let ciphertext = encrypt_hidden_recipients_binary(
        &plaintext,
        &[rsa_recipient.as_slice(), material.public_cert.as_slice()],
    )
    .expect("hidden multi-recipient encryption should succeed");
    let provider = Arc::new(RuntimeKeyAgreementProvider::new(
        material.agreement_scalar.clone(),
    ));

    let result = engine
        .decrypt_detailed_with_external_p256_key_agreement(
            ciphertext,
            material.public_cert.clone(),
            material.agreement_public_key.fingerprint().to_hex(),
            provider.clone(),
            Vec::new(),
        )
        .expect("non-ECDH wildcard PKESK must be skipped and the P-256 PKESK decrypted");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.legacy_status, SignatureStatus::NotSigned);
    // The external operation runs only for the ECDH PKESK; the RSA PKESK is
    // rejected by prepare_request before the callback.
    assert!(provider.request_count() > 0);
}

#[test]
fn test_runtime_external_key_agreement_api_decrypts_hidden_recipient_message_with_other_ecdh_recipient_first(
) {
    let engine = PgpEngine::new();
    let other = build_candidate(CandidateVersion::V4).expect("other candidate should build");
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let plaintext = b"hidden recipient two ECDH recipients".to_vec();
    // Hidden (wildcard) recipients; a different P-256 recipient's PKESK is emitted
    // first. Its session-key unwrap fails for our key without recording a
    // definitive error, so decryption must continue to our own PKESK.
    let ciphertext = encrypt_hidden_recipients_binary(
        &plaintext,
        &[
            other.public_cert.as_slice(),
            material.public_cert.as_slice(),
        ],
    )
    .expect("hidden multi-recipient encryption should succeed");
    let provider = Arc::new(RuntimeKeyAgreementProvider::new(
        material.agreement_scalar.clone(),
    ));

    let result = engine
        .decrypt_detailed_with_external_p256_key_agreement(
            ciphertext,
            material.public_cert.clone(),
            material.agreement_public_key.fingerprint().to_hex(),
            provider,
            Vec::new(),
        )
        .expect("the other recipient's wildcard PKESK must be skipped and ours decrypted");

    assert_eq!(result.plaintext, plaintext);
}

#[test]
fn test_runtime_external_key_agreement_api_hidden_recipient_genuine_failure_hard_aborts() {
    let engine = PgpEngine::new();
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let plaintext = b"hidden recipient genuine failure".to_vec();
    let ciphertext =
        encrypt_hidden_recipients_binary(&plaintext, &[material.public_cert.as_slice()])
            .expect("hidden single-recipient encryption should succeed");
    let cancelled = Arc::new(FixedRuntimeKeyAgreementProvider::new(Err(
        ExternalP256KeyAgreementError::OperationCancelled,
    )));

    // Even though the recipient is hidden (a speculative match), a genuine external
    // operation failure must fail closed rather than be swallowed as no-matching-key.
    let result = engine.decrypt_detailed_with_external_p256_key_agreement(
        ciphertext,
        material.public_cert.clone(),
        material.agreement_public_key.fingerprint().to_hex(),
        cancelled.clone(),
        Vec::new(),
    );
    assert!(matches!(result, Err(PgpError::OperationCancelled)));
    assert!(cancelled.request_count() > 0);
}

#[test]
fn test_runtime_external_key_agreement_api_payload_authentication_hard_fails() {
    let engine = PgpEngine::new();
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let plaintext = format!("runtime payload hard fail {}", version.label())
            .repeat(600)
            .into_bytes();
        let ciphertext =
            encrypt::encrypt_binary(&plaintext, &[material.public_cert.clone()], None, None)
                .expect("encryption to public-only candidate should succeed");
        assert_message_format(version, &ciphertext);
        let tampered = tamper_near_payload_tail(&ciphertext);
        let provider = Arc::new(RuntimeKeyAgreementProvider::new(
            material.agreement_scalar.clone(),
        ));

        let result = engine.decrypt_detailed_with_external_p256_key_agreement(
            tampered,
            material.public_cert.clone(),
            material.agreement_public_key.fingerprint().to_hex(),
            provider.clone(),
            Vec::new(),
        );

        assert!(
            provider.request_count() > 0,
            "tampered {} payload should still exercise the external ECDH callback",
            version.label()
        );
        match result {
            Err(PgpError::AeadAuthenticationFailed)
            | Err(PgpError::IntegrityCheckFailed)
            | Err(PgpError::NoMatchingKey)
            | Err(PgpError::CorruptData { .. }) => {}
            Err(other) => panic!(
                "tampered {} payload should fail as payload authentication/corruption, got: {other:?}",
                version.label()
            ),
            Ok(_) => panic!(
                "tampered {} payload must not release plaintext through the runtime API",
                version.label()
            ),
        }
    }
}

#[test]
fn test_external_decryptor_request_binds_recipient_and_ephemeral_public_points() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let plaintext = b"request binding proof";
    let ciphertext =
        encrypt::encrypt_binary(plaintext, &[material.public_cert.clone()], None, None)
            .expect("encryption to public-only candidate should succeed");
    let expected_recipient = public_point_for(&material.agreement_public_key);
    let expected_recipient_for_operation = expected_recipient.clone();
    let captured_request = Arc::new(Mutex::new(None));
    let captured_request_for_operation = Arc::clone(&captured_request);
    let mut oracle = oracle_for(material.agreement_scalar.clone());

    let operation = move |request: ExternalP256KeyAgreementRequest| {
        assert_eq!(
            request.recipient_public_key(),
            expected_recipient_for_operation.as_slice()
        );
        assert_eq!(request.recipient_public_key().len(), P256_PUBLIC_KEY_LENGTH);
        assert_eq!(request.ephemeral_public_key().len(), P256_PUBLIC_KEY_LENGTH);
        assert_eq!(
            request.recipient_public_key().first().copied(),
            Some(P256_UNCOMPRESSED_POINT_TAG)
        );
        assert_eq!(
            request.ephemeral_public_key().first().copied(),
            Some(P256_UNCOMPRESSED_POINT_TAG)
        );
        assert_ne!(
            request.recipient_public_key(),
            request.ephemeral_public_key()
        );
        *captured_request_for_operation.lock().unwrap() = Some(request.clone());
        oracle(request)
    };

    let (decrypted, _) = decrypt_with_external_operation(
        &ciphertext,
        &material,
        &[],
        operation,
        ExternalDecryptTelemetry::default(),
    )
    .expect("external decryptor should recover plaintext");
    assert_eq!(decrypted, plaintext);

    let captured = captured_request
        .lock()
        .unwrap()
        .clone()
        .expect("external operation should receive a request");
    assert_eq!(captured.recipient_public_key(), expected_recipient);
}

#[test]
fn test_external_decryptor_failure_does_not_fallback_to_secret_certificate_decryption() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let ciphertext = encrypt::encrypt_binary(
        b"must not fallback",
        &[material.public_cert.clone()],
        None,
        None,
    )
    .expect("encryption should succeed");
    let policy = StandardPolicy::new();
    let recipient_cert =
        openpgp::Cert::from_bytes(&material.public_cert).expect("recipient cert should parse");
    let helper = ExternalDecryptHelper {
        recipient_certs: vec![recipient_cert],
        verifier_certs: Vec::new(),
        key_agreement_operation: |_request| Err(external_operation_failed()),
        collector: SignatureCollector::new(LegacyFoldMode::DecryptLike),
        telemetry: ExternalDecryptTelemetry::default(),
    };

    let result = decrypt_with_helper(&ciphertext, &policy, helper);
    assert!(matches!(
        result,
        Err(PgpError::ExternalP256KeyAgreementFailed {
            category: ExternalP256KeyAgreementFailureCategory::ExternalOperationFailed
        })
    ));
}

#[test]
fn test_external_decryptor_rejects_signing_role() {
    let signing_material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    assert!(
        ExternalP256Decryptor::new(signing_material.signing_public_key, |_request| Ok(
            ExternalP256SharedSecret::new(vec![1u8; P256_SHARED_SECRET_LENGTH])
        ),)
        .is_err()
    );
}

#[test]
fn test_external_decryptor_rejects_unsupported_keys_and_invalid_response_shape() {
    let x25519_agreement: Key<key::SecretParts, key::SubordinateRole> =
        key::Key4::generate_ecc(false, Curve::Cv25519)
            .expect("X25519 key should generate")
            .into();
    assert!(ExternalP256Decryptor::new(
        x25519_agreement
            .parts_as_public()
            .role_as_unspecified()
            .clone(),
        |_request| Ok(ExternalP256SharedSecret::new(vec![
            1u8;
            P256_SHARED_SECRET_LENGTH
        ])),
    )
    .is_err());

    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let mut decryptor =
        ExternalP256Decryptor::new(material.agreement_public_key.clone(), |_request| {
            Ok(ExternalP256SharedSecret::new(vec![
                1u8;
                P256_SHARED_SECRET_LENGTH
                    - 1
            ]))
        })
        .expect("valid decryptor should initialize");
    let rsa_ciphertext = mpi::Ciphertext::RSA {
        c: mpi::MPI::new(&[1u8; P256_SHARED_SECRET_LENGTH]),
    };
    assert!(decryptor.decrypt(&rsa_ciphertext, None).is_err());

    let mut decryptor = ExternalP256Decryptor::new(material.agreement_public_key, |_request| {
        Ok(ExternalP256SharedSecret::new(vec![
            1u8;
            P256_SHARED_SECRET_LENGTH
                - 1
        ]))
    })
    .expect("valid decryptor should initialize");
    let ciphertext = mpi::Ciphertext::ECDH {
        e: mpi::MPI::new(&[P256_UNCOMPRESSED_POINT_TAG; P256_PUBLIC_KEY_LENGTH]),
        key: vec![1u8; 40].into_boxed_slice(),
    };

    assert!(decryptor.decrypt(&ciphertext, None).is_err());
}

#[test]
fn test_external_decryptor_records_last_error_on_request_validation_failures() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");

    // Non-ECDH ciphertext: request validation must record the failure so the
    // helper loop can hard-abort (PKESK::decrypt turns the Err into None).
    let mut decryptor = ExternalP256Decryptor::new(
        material.agreement_public_key.clone(),
        |_request| -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError> {
            panic!("key-agreement callback must not run for an invalid request")
        },
    )
    .expect("valid decryptor should initialize");
    let rsa_ciphertext = mpi::Ciphertext::RSA {
        c: mpi::MPI::new(&[1u8; P256_SHARED_SECRET_LENGTH]),
    };
    assert!(decryptor.decrypt(&rsa_ciphertext, None).is_err());
    assert!(matches!(
        decryptor.take_last_error(),
        Some(ExternalP256DecryptorError::InvalidRequest(_))
    ));

    // Malformed ephemeral point (too short): same recording requirement.
    let mut decryptor = ExternalP256Decryptor::new(
        material.agreement_public_key,
        |_request| -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError> {
            panic!("key-agreement callback must not run for an invalid request")
        },
    )
    .expect("valid decryptor should initialize");
    let malformed_ephemeral = mpi::Ciphertext::ECDH {
        e: mpi::MPI::new(&[P256_UNCOMPRESSED_POINT_TAG; P256_PUBLIC_KEY_LENGTH - 1]),
        key: vec![1u8; 40].into_boxed_slice(),
    };
    assert!(decryptor.decrypt(&malformed_ephemeral, None).is_err());
    assert!(matches!(
        decryptor.take_last_error(),
        Some(ExternalP256DecryptorError::InvalidRequest(_))
    ));
}

#[test]
fn test_external_decryptor_wrong_public_binding_fails_closed() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let other = build_candidate(version).expect("other candidate should build");
        let plaintext = format!("wrong public binding {}", version.label()).into_bytes();
        let ciphertext =
            encrypt::encrypt_binary(&plaintext, &[material.public_cert.clone()], None, None)
                .expect("encryption to public-only candidate should succeed");
        let other_public = public_point_for(&other.agreement_public_key);
        let other_scalar = other.agreement_scalar.clone();
        let telemetry = ExternalDecryptTelemetry::default();
        let telemetry_for_assertion = telemetry.clone();
        let operation_calls = Arc::new(AtomicUsize::new(0));
        let operation_calls_for_assertion = Arc::clone(&operation_calls);

        let operation = move |request: ExternalP256KeyAgreementRequest| {
            operation_calls.fetch_add(1, Ordering::SeqCst);
            derive_shared_secret_with_openssl(
                &other_scalar,
                &other_public,
                request.ephemeral_public_key(),
            )
            .map(ExternalP256SharedSecret::new)
            .map_err(|_| external_operation_failed())
        };

        let result =
            decrypt_with_external_operation(&ciphertext, &material, &[], operation, telemetry);
        assert!(matches!(result, Err(PgpError::NoMatchingKey)));
        assert!(
            operation_calls_for_assertion.load(Ordering::SeqCst) > 0,
            "wrong public binding should exercise the external ECDH operation"
        );
        assert_eq!(
            telemetry_for_assertion.recovered_session_key_count(),
            0,
            "wrong public binding must not produce a usable OpenPGP session key"
        );
    }
}

#[test]
fn test_external_decryptor_session_key_validation_failure_fails_closed() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let plaintext = format!("session key validation {}", version.label()).into_bytes();
        let ciphertext =
            encrypt::encrypt_binary(&plaintext, &[material.public_cert.clone()], None, None)
                .expect("encryption to public-only candidate should succeed");
        let telemetry = ExternalDecryptTelemetry::default();
        let telemetry_for_assertion = telemetry.clone();
        let operation_calls = Arc::new(AtomicUsize::new(0));
        let operation_calls_for_assertion = Arc::clone(&operation_calls);

        let result = decrypt_with_external_operation(
            &ciphertext,
            &material,
            &[],
            move |_request| {
                operation_calls.fetch_add(1, Ordering::SeqCst);
                Ok(ExternalP256SharedSecret::new(vec![
                    0x42;
                    P256_SHARED_SECRET_LENGTH
                ]))
            },
            telemetry,
        );

        assert!(matches!(result, Err(PgpError::NoMatchingKey)));
        assert!(
            operation_calls_for_assertion.load(Ordering::SeqCst) > 0,
            "session-key validation failure should exercise the external ECDH operation"
        );
        assert_eq!(
            telemetry_for_assertion.recovered_session_key_count(),
            0,
            "shape-valid but wrong ECDH output must fail PKESK/session-key validation"
        );
    }
}

#[test]
fn test_external_decryptor_payload_authentication_hard_fails_after_session_key_acceptance() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let plaintext = format!("payload hard fail {}", version.label())
            .repeat(600)
            .into_bytes();
        let ciphertext =
            encrypt::encrypt_binary(&plaintext, &[material.public_cert.clone()], None, None)
                .expect("encryption to public-only candidate should succeed");
        assert_message_format(version, &ciphertext);

        let tampered = tamper_near_payload_tail(&ciphertext);
        let telemetry = ExternalDecryptTelemetry::default();
        let telemetry_for_assertion = telemetry.clone();
        let result = decrypt_with_external_operation(
            &tampered,
            &material,
            &[],
            oracle_for(material.agreement_scalar.clone()),
            telemetry,
        );

        assert!(
            telemetry_for_assertion.recovered_session_key_count() > 0,
            "tampered {} payload should reach accepted PKESK/session-key recovery",
            version.label()
        );
        assert!(
            telemetry_for_assertion.accepted_payload_key_count() > 0,
            "tampered {} payload should fail after payload decrypt starts",
            version.label()
        );
        match result {
                Err(PgpError::AeadAuthenticationFailed)
                | Err(PgpError::IntegrityCheckFailed)
                | Err(PgpError::NoMatchingKey)
                | Err(PgpError::CorruptData { .. }) => {}
                Err(other) => panic!(
                    "tampered {} payload should fail as payload authentication/corruption, got: {other:?}",
                    version.label()
                ),
                Ok((_decrypted, _)) => panic!(
                    "tampered {} payload must not release plaintext",
                    version.label()
                ),
            }
    }
}
