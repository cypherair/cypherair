use std::sync::{Arc, Mutex};

use openpgp::cert::prelude::*;
use openpgp::crypto::{mpi, Password, Signer};
use openpgp::packet::{key, Key, Packet};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::{Curve, HashAlgorithm};
use pgp_mobile::decrypt::SignatureStatus;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{
    self, ExternalP256SigningError, ExternalP256SigningFailureCategory,
    ExternalP256SigningProvider, P256EcdsaSignature, SecureEnclaveCertificateVersion,
    SecureEnclavePublicCertificateInput,
};
use pgp_mobile::password;
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::{armor, decrypt, encrypt, sign, streaming, verify};
use sequoia_openpgp as openpgp;
use tempfile::NamedTempFile;

const P256_SCALAR_LENGTH: usize = 32;

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

    fn secure_enclave_version(self) -> SecureEnclaveCertificateVersion {
        match self {
            CandidateVersion::V4 => SecureEnclaveCertificateVersion::V4,
            CandidateVersion::V6 => SecureEnclaveCertificateVersion::V6,
        }
    }
}

struct CandidateMaterial {
    public_cert: Vec<u8>,
    revocation_cert: Vec<u8>,
    signing_key_fingerprint: String,
    keypair: Arc<Mutex<openpgp::crypto::KeyPair>>,
}

impl CandidateMaterial {
    fn runtime_provider(&self) -> Arc<dyn ExternalP256SigningProvider> {
        Arc::new(OracleSigningProvider {
            keypair: self.keypair.clone(),
        })
    }
}

fn build_candidate(version: CandidateVersion) -> Result<CandidateMaterial, PgpError> {
    build_candidate_with_expiry(version, None)
}

fn build_candidate_with_expiry(
    version: CandidateVersion,
    expiry_seconds: Option<u64>,
) -> Result<CandidateMaterial, PgpError> {
    let signing_key: Key<key::SecretParts, key::PrimaryRole> = match version {
        CandidateVersion::V4 => key::Key4::generate_ecc(true, Curve::NistP256)
            .expect("P-256 ECDSA key should generate")
            .into(),
        CandidateVersion::V6 => key::Key6::generate_ecc(true, Curve::NistP256)
            .expect("P-256 ECDSA key should generate")
            .into(),
    };
    let agreement_key: Key<key::SecretParts, key::SubordinateRole> = match version {
        CandidateVersion::V4 => key::Key4::generate_ecc(false, Curve::NistP256)
            .expect("P-256 ECDH key should generate")
            .into(),
        CandidateVersion::V6 => key::Key6::generate_ecc(false, Curve::NistP256)
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
    let keypair = Arc::new(Mutex::new(
        signing_key
            .role_into_unspecified()
            .into_keypair()
            .expect("signing keypair should build"),
    ));
    let provider = Arc::new(OracleSigningProvider {
        keypair: keypair.clone(),
    });
    let generated = keys::generate_secure_enclave_public_certificate(
        SecureEnclavePublicCertificateInput {
            name: format!("SE {}", version.label()),
            email: Some(format!("se-{}@example.test", version.label())),
            expiry_seconds,
            version: version.secure_enclave_version(),
            signing_public_key_x963,
            key_agreement_public_key_x963,
        },
        provider,
    )?;

    Ok(CandidateMaterial {
        public_cert: generated.public_key_data,
        revocation_cert: generated.revocation_cert,
        signing_key_fingerprint: generated.signing_key_fingerprint,
        keypair,
    })
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

fn assert_valid_public_candidate(version: CandidateVersion, public_cert: &[u8]) {
    let parsed = openpgp::Cert::from_bytes(public_cert).expect("candidate should parse");
    assert!(
        !parsed.is_tsk(),
        "Secure Enclave-shaped candidate must not contain secret key material"
    );
    let primary = parsed.primary_key().key();
    assert_eq!(primary.version(), version.expected_key_version());
    assert!(matches!(
        primary.mpis(),
        mpi::PublicKey::ECDSA {
            curve: Curve::NistP256,
            ..
        }
    ));
    let subkey = parsed
        .keys()
        .subkeys()
        .next()
        .expect("candidate should have one key-agreement subkey")
        .key();
    assert_ne!(primary.fingerprint(), subkey.fingerprint());
    assert!(matches!(
        subkey.mpis(),
        mpi::PublicKey::ECDH {
            curve: Curve::NistP256,
            ..
        }
    ));
    assert!(parsed.with_policy(&StandardPolicy::new(), None).is_ok());

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

fn write_temp_data_file(data: &[u8]) -> NamedTempFile {
    let input = NamedTempFile::new().expect("temp input should be created");
    std::fs::write(input.path(), data).expect("temp input should be written");
    input
}

fn encrypt_streaming_file_with_external_p256_signer(
    plaintext: &[u8],
    recipient_certs: &[Vec<u8>],
    material: CandidateMaterial,
    encrypt_to_self: Option<&[u8]>,
    progress: Option<Arc<dyn streaming::ProgressReporter>>,
) -> NamedTempFile {
    let input = write_temp_data_file(plaintext);
    let output = NamedTempFile::new().expect("temp output should be created");
    streaming::encrypt_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        recipient_certs,
        &material.public_cert,
        &signing_key_fingerprint(&material),
        material.runtime_provider(),
        encrypt_to_self,
        progress,
    )
    .expect("runtime external streaming file encrypt-plus-sign should succeed");
    output
}

struct OracleSigningProvider {
    keypair: Arc<Mutex<openpgp::crypto::KeyPair>>,
}

impl ExternalP256SigningProvider for OracleSigningProvider {
    fn sign_sha256_digest(
        &self,
        digest: Vec<u8>,
    ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
        let mut keypair = self
            .keypair
            .lock()
            .map_err(|_| external_operation_failed())?;
        sign_digest_with_keypair(&mut keypair, &digest)
    }
}

struct FailingRuntimeSigningProvider {
    category: ExternalP256SigningFailureCategory,
}

impl ExternalP256SigningProvider for FailingRuntimeSigningProvider {
    fn sign_sha256_digest(
        &self,
        _digest: Vec<u8>,
    ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
        Err(ExternalP256SigningError::Failed {
            category: self.category,
        })
    }
}

struct CancelledRuntimeSigningProvider;

impl ExternalP256SigningProvider for CancelledRuntimeSigningProvider {
    fn sign_sha256_digest(
        &self,
        _digest: Vec<u8>,
    ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
        Err(ExternalP256SigningError::OperationCancelled)
    }
}

struct MalformedRuntimeSigningProvider {
    r: Vec<u8>,
    s: Vec<u8>,
}

impl ExternalP256SigningProvider for MalformedRuntimeSigningProvider {
    fn sign_sha256_digest(
        &self,
        _digest: Vec<u8>,
    ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
        Ok(P256EcdsaSignature {
            r: self.r.clone(),
            s: self.s.clone(),
        })
    }
}

struct WrongDigestRuntimeSigningProvider {
    keypair: Arc<Mutex<openpgp::crypto::KeyPair>>,
}

impl ExternalP256SigningProvider for WrongDigestRuntimeSigningProvider {
    fn sign_sha256_digest(
        &self,
        mut digest: Vec<u8>,
    ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
        digest[0] ^= 1;
        let mut keypair = self
            .keypair
            .lock()
            .map_err(|_| external_operation_failed())?;
        sign_digest_with_keypair(&mut keypair, &digest)
    }
}

struct UnexpectedRuntimeSigningProvider;

impl ExternalP256SigningProvider for UnexpectedRuntimeSigningProvider {
    fn sign_sha256_digest(
        &self,
        _digest: Vec<u8>,
    ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
        panic!("runtime signing provider should not be called")
    }
}

struct CancelledProgressReporter;

impl streaming::ProgressReporter for CancelledProgressReporter {
    fn on_progress(&self, _bytes_processed: u64, _total_bytes: u64) -> bool {
        false
    }
}

fn signing_key_fingerprint(material: &CandidateMaterial) -> String {
    material.signing_key_fingerprint.clone()
}

fn recipient_profile(version: CandidateVersion) -> keys::KeyProfile {
    match version {
        CandidateVersion::V4 => keys::KeyProfile::Universal,
        CandidateVersion::V6 => keys::KeyProfile::Advanced,
    }
}

fn dearmor_message(data: &[u8]) -> Vec<u8> {
    armor::decode_armor(data)
        .expect("message should dearmor cleanly")
        .0
}

fn detect_message_format(ciphertext: &[u8]) -> (bool, bool) {
    let mut has_v1 = false;
    let mut has_v2 = false;
    let mut ppr =
        openpgp::parse::PacketParser::from_bytes(ciphertext).expect("ciphertext should parse");
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        if let openpgp::Packet::SEIP(seip) = &pp.packet {
            if seip.version() == 1 {
                has_v1 = true;
            } else if seip.version() == 2 {
                has_v2 = true;
            }
        }
        let (_, next) = pp.next().expect("packet parser should advance");
        ppr = next;
    }
    (has_v1, has_v2)
}

fn assert_message_format(ciphertext: &[u8], expect_v1: bool, expect_v2: bool) {
    let binary = dearmor_message(ciphertext);
    assert_binary_message_format(&binary, expect_v1, expect_v2);
}

fn assert_binary_message_format(ciphertext: &[u8], expect_v1: bool, expect_v2: bool) {
    let (has_v1, has_v2) = detect_message_format(ciphertext);
    assert_eq!(has_v1, expect_v1, "unexpected SEIPDv1 presence");
    assert_eq!(has_v2, expect_v2, "unexpected SEIPDv2 presence");
}

fn assert_password_message_format(
    ciphertext: &[u8],
    format: password::PasswordMessageFormat,
    binary: bool,
) {
    let raw = if binary {
        ciphertext.to_vec()
    } else {
        dearmor_message(ciphertext)
    };
    let (has_v1, has_v2) = detect_message_format(&raw);
    match format {
        password::PasswordMessageFormat::Seipdv1 => {
            assert!(has_v1, "expected SEIPDv1 password message");
            assert!(!has_v2, "did not expect SEIPDv2 password message");
        }
        password::PasswordMessageFormat::Seipdv2 => {
            assert!(!has_v1, "did not expect SEIPDv1 password message");
            assert!(has_v2, "expected SEIPDv2 password message");
        }
    }
}

fn external_operation_failed() -> ExternalP256SigningError {
    ExternalP256SigningError::Failed {
        category: ExternalP256SigningFailureCategory::ExternalOperationFailed,
    }
}

fn sign_digest_with_keypair(
    keypair: &mut openpgp::crypto::KeyPair,
    digest: &[u8],
) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
    match keypair.sign(HashAlgorithm::SHA256, digest) {
        Ok(mpi::Signature::ECDSA { r, s }) => Ok(P256EcdsaSignature {
            r: r.value_padded(P256_SCALAR_LENGTH)
                .map_err(|_| external_operation_failed())?
                .into_owned(),
            s: s.value_padded(P256_SCALAR_LENGTH)
                .map_err(|_| external_operation_failed())?
                .into_owned(),
        }),
        _ => Err(external_operation_failed()),
    }
}

fn first_transport_subkey_expiry(public_cert: &[u8]) -> std::time::SystemTime {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(public_cert).expect("certificate should parse");
    cert.keys()
        .subkeys()
        .with_policy(&policy, None)
        .for_transport_encryption()
        .next()
        .expect("certificate should have a transport-encryption subkey")
        .key_expiration_time()
        .expect("transport-encryption subkey should have explicit expiry")
}

fn assert_transport_subkey_live_at(public_cert: &[u8], time: std::time::SystemTime) {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(public_cert).expect("certificate should parse");
    assert!(
        cert.keys()
            .subkeys()
            .with_policy(&policy, Some(time))
            .supported()
            .alive()
            .for_transport_encryption()
            .next()
            .is_some(),
        "transport-encryption subkey should remain live and policy-valid at the reference time"
    );
}

fn assert_primary_live_at(public_cert: &[u8], time: std::time::SystemTime) {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(public_cert).expect("certificate should parse");
    cert.with_policy(&policy, Some(time))
        .expect("certificate should have a policy-valid binding")
        .primary_key()
        .alive()
        .expect("primary key should be live at the reference time");
}

fn assert_primary_expired_now(public_cert: &[u8]) {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(public_cert).expect("certificate should parse");
    assert!(
        cert.with_policy(&policy, None)
            .expect("certificate should have a policy-valid binding")
            .primary_key()
            .alive()
            .is_err(),
        "primary key should be expired now"
    );
}

fn assert_no_transport_subkey_live_now(public_cert: &[u8]) {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(public_cert).expect("certificate should parse");
    assert!(
        cert.keys()
            .subkeys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .for_transport_encryption()
            .next()
            .is_none(),
        "transport-encryption subkey should be expired now"
    );
}

fn sleep_past(time: std::time::SystemTime) {
    let now = std::time::SystemTime::now();
    if let Ok(wait) = time.duration_since(now) {
        std::thread::sleep(wait + std::time::Duration::from_secs(1));
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ExpiryBindingSignatureHashes {
    direct_key: HashAlgorithm,
    user_ids: Vec<HashAlgorithm>,
    subkeys: Vec<HashAlgorithm>,
    backsigs: Vec<HashAlgorithm>,
}

fn expiry_binding_signature_hashes(cert_data: &[u8]) -> ExpiryBindingSignatureHashes {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(cert_data).expect("certificate should parse");
    let valid_cert = cert
        .with_policy(&policy, None)
        .expect("certificate should have a policy-valid binding");
    let direct_key = valid_cert
        .primary_key()
        .direct_key_signature()
        .expect("certificate should have a direct-key signature")
        .hash_algo();
    let user_ids = valid_cert
        .userids()
        .revoked(false)
        .map(|user_id| user_id.binding_signature().hash_algo())
        .collect();
    let mut subkeys = Vec::new();
    let mut backsigs = Vec::new();
    for subkey in valid_cert.keys().subkeys().revoked(false) {
        let binding = subkey.binding_signature();
        subkeys.push(binding.hash_algo());
        backsigs.extend(binding.embedded_signatures().map(|sig| sig.hash_algo()));
    }

    ExpiryBindingSignatureHashes {
        direct_key,
        user_ids,
        subkeys,
        backsigs,
    }
}

fn assert_expiry_binding_hashes(
    cert_data: &[u8],
    expected_hash: HashAlgorithm,
    expected_backsig_count: Option<usize>,
) {
    let hashes = expiry_binding_signature_hashes(cert_data);
    assert_eq!(hashes.direct_key, expected_hash);
    assert!(
        !hashes.user_ids.is_empty(),
        "certificate should have user ID binding signatures"
    );
    assert!(
        !hashes.subkeys.is_empty(),
        "certificate should have expiring subkey binding signatures"
    );
    assert!(
        hashes.user_ids.iter().all(|hash| *hash == expected_hash),
        "unexpected User ID binding hashes: {:?}",
        hashes.user_ids
    );
    assert!(
        hashes.subkeys.iter().all(|hash| *hash == expected_hash),
        "unexpected subkey binding hashes: {:?}",
        hashes.subkeys
    );
    if let Some(expected_backsig_count) = expected_backsig_count {
        assert_eq!(hashes.backsigs.len(), expected_backsig_count);
    }
    assert!(
        hashes.backsigs.iter().all(|hash| *hash == expected_hash),
        "unexpected backsig hashes: {:?}",
        hashes.backsigs
    );
}

fn software_signing_subkey_secret_cert() -> Vec<u8> {
    let (cert, _) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv25519)
        .set_profile(openpgp::Profile::RFC4880)
        .expect("profile should configure")
        .set_validity_period(Some(std::time::Duration::from_secs(60)))
        .add_userid("Software Signing Subkey <signing-subkey@example.test>")
        .add_signing_subkey()
        .generate()
        .expect("software signing-subkey cert should generate");
    let mut cert_data = Vec::new();
    cert.as_tsk()
        .serialize(&mut cert_data)
        .expect("secret cert should serialize");
    cert_data
}

fn insert_key_revocation(cert_data: &[u8], revocation_cert: &[u8]) -> Vec<u8> {
    let cert = openpgp::Cert::from_bytes(cert_data).expect("certificate should parse");
    let is_tsk = cert.is_tsk();
    let revocation = Packet::from_bytes(revocation_cert).expect("revocation packet should parse");
    let (revoked_cert, _) = cert
        .insert_packets(vec![revocation])
        .expect("revocation should insert");
    let mut output = Vec::new();
    if is_tsk {
        revoked_cert
            .as_tsk()
            .serialize(&mut output)
            .expect("revoked secret cert should serialize");
    } else {
        revoked_cert
            .serialize(&mut output)
            .expect("revoked public cert should serialize");
    }
    output
}

mod certificate;
mod cleartext;
mod detached_file;
mod expiry;
mod password_message;
mod revocation;
mod streaming_file_encrypt;
mod text_encrypt;
