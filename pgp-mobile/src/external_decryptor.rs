use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use openpgp::crypto::{ecdh, mem::Protected, mpi, Decryptor, SessionKey};
use openpgp::packet::{key, Key};
use openpgp::types::{Curve, PublicKeyAlgorithm};

const P256_PUBLIC_KEY_LENGTH: usize = 65;
const P256_SHARED_SECRET_LENGTH: usize = 32;
const P256_UNCOMPRESSED_POINT_TAG: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalP256KeyAgreementRequest {
    recipient_public_key: Vec<u8>,
    ephemeral_public_key: Vec<u8>,
}

impl ExternalP256KeyAgreementRequest {
    fn new(recipient_public_key: Vec<u8>, ephemeral_public_key: Vec<u8>) -> Self {
        Self {
            recipient_public_key,
            ephemeral_public_key,
        }
    }

    pub(crate) fn recipient_public_key(&self) -> &[u8] {
        &self.recipient_public_key
    }

    pub(crate) fn ephemeral_public_key(&self) -> &[u8] {
        &self.ephemeral_public_key
    }
}

#[derive(Debug)]
pub(crate) struct ExternalP256SharedSecret {
    raw: Zeroizing<Vec<u8>>,
}

impl ExternalP256SharedSecret {
    pub(crate) fn new(raw: Vec<u8>) -> Self {
        Self {
            raw: Zeroizing::new(raw),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalP256DecryptorError {
    InvalidRequest(&'static str),
    InvalidResponse(&'static str),
    ExternalFailure(&'static str),
}

impl ExternalP256DecryptorError {
    fn sanitized_reason(self) -> &'static str {
        match self {
            ExternalP256DecryptorError::InvalidRequest(reason)
            | ExternalP256DecryptorError::InvalidResponse(reason)
            | ExternalP256DecryptorError::ExternalFailure(reason) => reason,
        }
    }
}

pub(crate) struct ExternalP256Decryptor<F>
where
    F: FnMut(
        ExternalP256KeyAgreementRequest,
    ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    key_agreement_operation: F,
}

impl<F> ExternalP256Decryptor<F>
where
    F: FnMut(
        ExternalP256KeyAgreementRequest,
    ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>,
{
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        key_agreement_operation: F,
    ) -> openpgp::Result<Self> {
        Self::validate_public_key(&public_key).map_err(|error| {
            openpgp::Error::InvalidOperation(error.sanitized_reason().to_string())
        })?;

        Ok(Self {
            public_key,
            key_agreement_operation,
        })
    }

    fn validate_public_key(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Result<(), ExternalP256DecryptorError> {
        match (public_key.pk_algo(), public_key.mpis()) {
            (
                PublicKeyAlgorithm::ECDH,
                mpi::PublicKey::ECDH {
                    curve: Curve::NistP256,
                    q,
                    ..
                },
            ) => Self::validate_public_point(q.value()),
            _ => Err(ExternalP256DecryptorError::InvalidRequest(
                "external P-256 decryptor requires an ECDH P-256 public key",
            )),
        }
    }

    fn validate_public_point(bytes: &[u8]) -> Result<(), ExternalP256DecryptorError> {
        if bytes.len() != P256_PUBLIC_KEY_LENGTH
            || bytes.first().copied() != Some(P256_UNCOMPRESSED_POINT_TAG)
        {
            return Err(ExternalP256DecryptorError::InvalidRequest(
                "external P-256 decryptor received an invalid public point",
            ));
        }

        Ok(())
    }

    fn validate_shared_secret(
        shared_secret: &ExternalP256SharedSecret,
    ) -> Result<(), ExternalP256DecryptorError> {
        if shared_secret.raw.len() != P256_SHARED_SECRET_LENGTH {
            return Err(ExternalP256DecryptorError::InvalidResponse(
                "external P-256 decryptor returned an invalid shared secret shape",
            ));
        }

        if shared_secret.raw.iter().all(|byte| *byte == 0) {
            return Err(ExternalP256DecryptorError::InvalidResponse(
                "external P-256 decryptor returned an invalid zero shared secret",
            ));
        }

        Ok(())
    }
}

impl<F> Decryptor for ExternalP256Decryptor<F>
where
    F: FnMut(
            ExternalP256KeyAgreementRequest,
        ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>
        + Send
        + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        let ephemeral_public_key = match ciphertext {
            mpi::Ciphertext::ECDH { e, .. } => {
                Self::validate_public_point(e.value()).map_err(|error| {
                    openpgp::Error::InvalidOperation(error.sanitized_reason().to_string())
                })?;
                e.value().to_vec()
            }
            _ => {
                return Err(openpgp::Error::InvalidOperation(
                    "external P-256 decryptor supports ECDH ciphertext only".to_string(),
                )
                .into())
            }
        };

        let recipient_public_key = match self.public_key.mpis() {
            mpi::PublicKey::ECDH { q, .. } => q.value().to_vec(),
            _ => {
                return Err(openpgp::Error::InvalidOperation(
                    "external P-256 decryptor requires an ECDH public key".to_string(),
                )
                .into())
            }
        };

        let request =
            ExternalP256KeyAgreementRequest::new(recipient_public_key, ephemeral_public_key);
        let shared_secret = (self.key_agreement_operation)(request).map_err(|error| {
            openpgp::Error::InvalidOperation(error.sanitized_reason().to_string())
        })?;
        Self::validate_shared_secret(&shared_secret).map_err(|error| {
            openpgp::Error::InvalidOperation(error.sanitized_reason().to_string())
        })?;

        let shared_secret = Protected::from(shared_secret.raw.as_slice());
        ecdh::decrypt_unwrap(&self.public_key, &shared_secret, ciphertext, plaintext_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        io::Write,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use openpgp::crypto::{mpi, Signer};
    use openpgp::packet::{key, signature, Packet, UserID};
    use openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Signer as StreamSigner};
    use openpgp::serialize::Serialize;
    use openpgp::types::{Features, HashAlgorithm, KeyFlags, SignatureType};
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::derive::Deriver;
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;

    use crate::decrypt::{decrypt_with_helper, SignatureStatus};
    use crate::encrypt;
    use crate::error::PgpError;
    use crate::external_signer::{
        ExternalP256Signature, ExternalP256Signer, ExternalP256SignerError,
    };
    use crate::keys;
    use crate::signature_details::{LegacyFoldMode, SignatureCollector};

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
        fn get_certs(
            &mut self,
            _ids: &[openpgp::KeyHandle],
        ) -> openpgp::Result<Vec<openpgp::Cert>> {
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
            decrypt: &mut dyn FnMut(
                Option<openpgp::types::SymmetricAlgorithm>,
                &SessionKey,
            ) -> bool,
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
                        if let Some((algo, session_key)) = pkesk.decrypt(&mut decryptor, sym_algo) {
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
            impl FnMut(
                    HashAlgorithm,
                    &[u8],
                ) -> Result<ExternalP256Signature, ExternalP256SignerError>
                + Send
                + Sync
                + 'a,
        >,
    > {
        ExternalP256Signer::new(public_key.clone(), move |hash_algo, digest| {
            match oracle.sign(hash_algo, digest) {
                Ok(mpi::Signature::ECDSA { r, s }) => Ok(ExternalP256Signature::new(
                    r.value_padded(P256_SHARED_SECRET_LENGTH)
                        .map_err(|_| {
                            ExternalP256SignerError::ExternalFailure("external P-256 oracle failed")
                        })?
                        .into_owned(),
                    s.value_padded(P256_SHARED_SECRET_LENGTH)
                        .map_err(|_| {
                            ExternalP256SignerError::ExternalFailure("external P-256 oracle failed")
                        })?
                        .into_owned(),
                )),
                Ok(_) => Err(ExternalP256SignerError::ExternalFailure(
                    "external P-256 oracle returned a non-ECDSA signature",
                )),
                Err(_) => Err(ExternalP256SignerError::ExternalFailure(
                    "external P-256 oracle failed",
                )),
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
            .map_err(|_| {
                ExternalP256DecryptorError::ExternalFailure("external P-256 ECDH oracle failed")
            })
        }
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
        let private_key = EcKey::from_private_components(
            &group,
            private_scalar.as_ref(),
            recipient_point.as_ref(),
        )?;
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
        let recipient_cert = openpgp::Cert::from_bytes(&material.public_cert).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid public key: {e}"),
            }
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
            key_agreement_operation: |_request| {
                Err(ExternalP256DecryptorError::ExternalFailure(
                    "external P-256 ECDH oracle failed",
                ))
            },
            collector: SignatureCollector::new(LegacyFoldMode::DecryptLike),
            telemetry: ExternalDecryptTelemetry::default(),
        };

        let result = decrypt_with_helper(&ciphertext, &policy, helper);
        assert!(matches!(result, Err(PgpError::NoMatchingKey)));
    }

    #[test]
    fn test_external_decryptor_rejects_signing_role() {
        let signing_material =
            build_candidate(CandidateVersion::V4).expect("candidate should build");
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
                .map_err(|_| {
                    ExternalP256DecryptorError::ExternalFailure("external P-256 ECDH oracle failed")
                })
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
                Ok((decrypted, _)) => panic!(
                    "tampered {} payload must not release plaintext: {decrypted:?}",
                    version.label()
                ),
            }
        }
    }
}
