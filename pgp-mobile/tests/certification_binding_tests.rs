use openpgp::cert::prelude::*;
use openpgp::packet::signature;
use openpgp::packet::signature::subpacket::{Subpacket, SubpacketTag, SubpacketValue};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Marshal;
use openpgp::types::{KeyFlags, SignatureType};
use pgp_mobile::cert_signature::{self, CertificateSignatureStatus, CertificationKind};
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile, UserIdSelectorInput};
use sequoia_openpgp as openpgp;

fn generated_key(profile: KeyProfile, name: &str) -> keys::GeneratedKey {
    keys::generate_key_with_profile(
        name.to_string(),
        Some(format!("{}@example.com", name.to_lowercase())),
        None,
        profile,
    )
    .expect("key generation should succeed")
}

fn generated_key_with_identity(profile: KeyProfile, name: &str, email: &str) -> keys::GeneratedKey {
    keys::generate_key_with_profile(name.to_string(), Some(email.to_string()), None, profile)
        .expect("key generation should succeed")
}

fn parse_cert(cert_data: &[u8]) -> openpgp::Cert {
    openpgp::Cert::from_bytes(cert_data).expect("certificate should parse")
}

fn serialize_signature(signature: &openpgp::packet::Signature) -> Vec<u8> {
    let mut bytes = Vec::new();
    openpgp::Packet::from(signature.clone())
        .serialize(&mut bytes)
        .expect("signature serialization should succeed");
    bytes
}

fn first_user_id_bytes(cert_data: &[u8]) -> Vec<u8> {
    parse_cert(cert_data)
        .userids()
        .next()
        .expect("certificate should have a User ID")
        .userid()
        .value()
        .to_vec()
}

fn duplicate_userid(secret_cert: &[u8], duplicate_user_id: &str) -> Vec<u8> {
    let cert = parse_cert(secret_cert);
    let policy = StandardPolicy::new();
    let template: signature::SignatureBuilder = cert
        .with_policy(&policy, None)
        .expect("cert should validate")
        .primary_userid()
        .expect("primary user id should exist")
        .binding_signature()
        .clone()
        .into();

    let userid: openpgp::packet::UserID = duplicate_user_id.into();
    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .expect("primary key should have secret parts")
        .into_keypair()
        .expect("keypair conversion should succeed");
    let binding = userid
        .bind(
            &mut signer,
            &cert,
            template
                .set_primary_userid(false)
                .expect("signature builder update should succeed"),
        )
        .expect("userid binding should succeed");

    let mut userid_bytes = Vec::new();
    openpgp::Packet::from(userid)
        .serialize(&mut userid_bytes)
        .expect("userid packet should serialize");
    let mut binding_bytes = Vec::new();
    openpgp::Packet::from(binding)
        .serialize(&mut binding_bytes)
        .expect("binding packet should serialize");

    let raw_cert = openpgp::cert::raw::RawCert::from_bytes(secret_cert)
        .expect("raw secret cert should parse");
    let mut duplicated = Vec::new();
    let mut inserted = false;

    for packet in raw_cert.packets() {
        if !inserted
            && matches!(
                packet.tag(),
                openpgp::packet::Tag::PublicSubkey | openpgp::packet::Tag::SecretSubkey
            )
        {
            duplicated.extend_from_slice(&userid_bytes);
            duplicated.extend_from_slice(&binding_bytes);
            inserted = true;
        }

        duplicated.extend_from_slice(packet.as_bytes());
    }

    if !inserted {
        duplicated.extend_from_slice(&userid_bytes);
        duplicated.extend_from_slice(&binding_bytes);
    }

    duplicated
}

fn user_id_selector(user_id_data: &[u8], occurrence_index: u64) -> UserIdSelectorInput {
    UserIdSelectorInput {
        user_id_data: user_id_data.to_vec(),
        occurrence_index,
    }
}

fn direct_key_signature_bytes(cert_data: &[u8]) -> Vec<u8> {
    let cert = parse_cert(cert_data);
    let policy = StandardPolicy::new();
    let signature = cert
        .with_policy(&policy, None)
        .expect("certificate should validate")
        .direct_key_signature()
        .expect("certificate should have a direct-key signature")
        .clone();
    serialize_signature(&signature)
}

fn certification_subkey_signer() -> (openpgp::Cert, Vec<u8>, String) {
    let (cert, _) = CertBuilder::new()
        .set_primary_key_flags(KeyFlags::empty())
        .add_userid("Subkey Signer <subkey-signer@example.com>")
        .add_certification_subkey()
        .generate()
        .expect("certification-subkey signer should generate");

    let subkey_fingerprint = cert
        .keys()
        .subkeys()
        .next()
        .expect("certification subkey should exist")
        .key()
        .fingerprint()
        .to_hex()
        .to_lowercase();

    let mut stubbed = Vec::new();
    cert.as_tsk()
        .set_filter(|key| key.fingerprint() != cert.fingerprint())
        .emit_secret_key_stubs(true)
        .serialize(&mut stubbed)
        .expect("stubbed cert should serialize");

    (cert, stubbed, subkey_fingerprint)
}

fn signing_only_subkey_signer() -> (openpgp::Cert, Vec<u8>) {
    let (cert, _) = CertBuilder::new()
        .set_primary_key_flags(KeyFlags::empty())
        .add_userid("Signing Only <signing-only@example.com>")
        .add_signing_subkey()
        .generate()
        .expect("signing-only signer should generate");

    let mut public_bytes = Vec::new();
    cert.serialize(&mut public_bytes)
        .expect("public cert should serialize");

    (cert, public_bytes)
}

fn unusable_certification_signer() -> Vec<u8> {
    let (cert, _) = CertBuilder::new()
        .set_primary_key_flags(KeyFlags::empty())
        .add_userid("Unusable Signer <unusable-signer@example.com>")
        .add_signing_subkey()
        .generate()
        .expect("unusable signer should generate");

    let mut stubbed = Vec::new();
    cert.as_tsk()
        .set_filter(|key| key.fingerprint() != cert.fingerprint())
        .emit_secret_key_stubs(true)
        .serialize(&mut stubbed)
        .expect("stubbed cert should serialize");
    stubbed
}

fn strip_issuer_metadata(signature: &mut openpgp::packet::Signature) {
    for tag in [SubpacketTag::Issuer, SubpacketTag::IssuerFingerprint] {
        signature.hashed_area_mut().remove_all(tag);
        signature.unhashed_area_mut().remove_all(tag);
    }

    assert!(
        signature.get_issuers().is_empty(),
        "signature should not advertise issuer information"
    );
}

fn positive_certification_without_issuer(
    signer_cert: &openpgp::Cert,
    target_cert: &openpgp::Cert,
) -> Vec<u8> {
    let certification_subkey = signer_cert
        .keys()
        .subkeys()
        .next()
        .expect("certification subkey should exist");
    let mut signer = certification_subkey
        .key()
        .clone()
        .parts_into_secret()
        .expect("subkey should have secret material")
        .into_keypair()
        .expect("subkey should convert into keypair");

    let user_id = target_cert
        .userids()
        .next()
        .expect("target cert should have a User ID")
        .userid();

    let builder = signature::SignatureBuilder::new(SignatureType::PositiveCertification);
    let mut builder = builder;
    builder
        .unhashed_area_mut()
        .add(
            Subpacket::new(SubpacketValue::Issuer(signer.public().keyid()), false)
                .expect("issuer subpacket should build"),
        )
        .expect("issuer subpacket should add");
    let mut signature = user_id
        .bind(&mut signer, target_cert, builder)
        .expect("certification should sign");
    strip_issuer_metadata(&mut signature);
    serialize_signature(&signature)
}

fn positive_certification_from_signing_only_subkey(
    signer_cert: &openpgp::Cert,
    target_cert: &openpgp::Cert,
    remove_issuer_metadata: bool,
) -> Vec<u8> {
    let signing_subkey = signer_cert
        .keys()
        .subkeys()
        .next()
        .expect("signing subkey should exist");
    let mut signer = signing_subkey
        .key()
        .clone()
        .parts_into_secret()
        .expect("subkey should have secret material")
        .into_keypair()
        .expect("subkey should convert into keypair");

    let user_id = target_cert
        .userids()
        .next()
        .expect("target cert should have a User ID")
        .userid();
    let mut signature = user_id
        .bind(
            &mut signer,
            target_cert,
            signature::SignatureBuilder::new(SignatureType::PositiveCertification),
        )
        .expect("certification should sign");

    if remove_issuer_metadata {
        strip_issuer_metadata(&mut signature);
    } else {
        assert!(
            !signature.get_issuers().is_empty(),
            "signature should advertise issuer information"
        );
    }

    serialize_signature(&signature)
}

fn direct_key_signature_from_signing_only_subkey(
    signer_cert: &openpgp::Cert,
    target_cert: &openpgp::Cert,
    remove_issuer_metadata: bool,
) -> Vec<u8> {
    let signing_subkey = signer_cert
        .keys()
        .subkeys()
        .next()
        .expect("signing subkey should exist");
    let mut signer = signing_subkey
        .key()
        .clone()
        .parts_into_secret()
        .expect("subkey should have secret material")
        .into_keypair()
        .expect("subkey should convert into keypair");

    let mut signature = signature::SignatureBuilder::new(SignatureType::DirectKey)
        .sign_direct_key(&mut signer, Some(target_cert.primary_key().key()))
        .expect("direct-key signature should sign");

    if remove_issuer_metadata {
        strip_issuer_metadata(&mut signature);
    } else {
        assert!(
            !signature.get_issuers().is_empty(),
            "signature should advertise issuer information"
        );
    }

    serialize_signature(&signature)
}

#[test]
fn test_verify_direct_key_signature_valid_profile_a_and_b() {
    for profile in [KeyProfile::Universal, KeyProfile::Advanced] {
        let generated = generated_key(profile, "DirectValid");
        let signature = direct_key_signature_bytes(&generated.public_key_data);

        let result = cert_signature::verify_direct_key_signature(
            &signature,
            &generated.public_key_data,
            &[generated.public_key_data.clone()],
        )
        .expect("direct-key verification should succeed");

        assert_eq!(result.status, CertificateSignatureStatus::Valid);
        assert_eq!(result.certification_kind, None);
        assert_eq!(
            result.signer_primary_fingerprint,
            Some(generated.fingerprint.clone())
        );
        assert_eq!(result.signing_key_fingerprint, None);
    }
}

#[test]
fn test_verify_direct_key_signature_invalid_returns_invalid() {
    let signer = generated_key(KeyProfile::Universal, "DirectSigner");
    let other_target = generated_key(KeyProfile::Universal, "OtherTarget");
    let signature = direct_key_signature_bytes(&signer.public_key_data);

    let result = cert_signature::verify_direct_key_signature(
        &signature,
        &other_target.public_key_data,
        &[signer.public_key_data.clone()],
    )
    .expect("invalid direct-key verification should still return a result");

    assert_eq!(result.status, CertificateSignatureStatus::Invalid);
    assert_eq!(result.certification_kind, None);
    assert_eq!(result.signer_primary_fingerprint, None);
    assert_eq!(result.signing_key_fingerprint, None);
}

#[test]
fn test_verify_direct_key_signature_signer_missing_empty_candidates() {
    let generated = generated_key(KeyProfile::Universal, "DirectMissing");
    let signature = direct_key_signature_bytes(&generated.public_key_data);

    let result =
        cert_signature::verify_direct_key_signature(&signature, &generated.public_key_data, &[])
            .expect("signer-missing direct-key verification should return a result");

    assert_eq!(result.status, CertificateSignatureStatus::SignerMissing);
    assert_eq!(result.certification_kind, None);
    assert_eq!(result.signer_primary_fingerprint, None);
    assert_eq!(result.signing_key_fingerprint, None);
}

#[test]
fn test_verify_user_id_binding_signature_signer_missing_empty_candidates() {
    let signer = generated_key(KeyProfile::Universal, "MissingSigner");
    let target = generated_key(KeyProfile::Universal, "MissingTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &selector,
        &[],
    )
    .expect("signer-missing User ID verification should return a result");

    assert_eq!(result.status, CertificateSignatureStatus::SignerMissing);
    assert_eq!(result.certification_kind, Some(CertificationKind::Positive));
    assert_eq!(result.signer_primary_fingerprint, None);
    assert_eq!(result.signing_key_fingerprint, None);
}

#[test]
fn test_verify_user_id_binding_signature_invalid_matching_user_id_returns_invalid() {
    let signer = generated_key(KeyProfile::Universal, "InvalidSigner");
    let target = generated_key_with_identity(
        KeyProfile::Universal,
        "Shared Identity",
        "shared-identity@example.com",
    );
    let wrong_target = generated_key_with_identity(
        KeyProfile::Universal,
        "Shared Identity",
        "shared-identity@example.com",
    );
    let user_id_data = first_user_id_bytes(&target.public_key_data);

    assert_eq!(
        user_id_data,
        first_user_id_bytes(&wrong_target.public_key_data)
    );

    let target_selector = user_id_selector(&user_id_data, 0);
    let wrong_target_selector =
        user_id_selector(&first_user_id_bytes(&wrong_target.public_key_data), 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &target_selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &wrong_target.public_key_data,
        &wrong_target_selector,
        &[signer.public_key_data.clone()],
    )
    .expect("invalid User ID verification should still return a result");

    assert_eq!(result.status, CertificateSignatureStatus::Invalid);
    assert_eq!(result.certification_kind, Some(CertificationKind::Positive));
    assert_eq!(result.signer_primary_fingerprint, None);
    assert_eq!(result.signing_key_fingerprint, None);
}

#[test]
fn test_generate_and_verify_user_id_certification_preserves_kind_for_all_profiles() {
    for profile in [KeyProfile::Universal, KeyProfile::Advanced] {
        for kind in [
            CertificationKind::Generic,
            CertificationKind::Persona,
            CertificationKind::Casual,
            CertificationKind::Positive,
        ] {
            let signer = generated_key(profile, "KindSigner");
            let target = generated_key(profile, "KindTarget");
            let user_id_data = first_user_id_bytes(&target.public_key_data);
            let selector = user_id_selector(&user_id_data, 0);

            let signature = cert_signature::generate_user_id_certification_by_selector(
                &signer.cert_data,
                &target.public_key_data,
                &selector,
                kind,
            )
            .expect("certification generation should succeed");

            let parsed = openpgp::Packet::from_bytes(&signature).expect("signature should parse");
            let parsed = match parsed {
                openpgp::Packet::Signature(signature) => signature,
                other => panic!("expected signature packet, found {other:?}"),
            };
            assert_eq!(parsed.typ(), kind.signature_type());

            let result = cert_signature::verify_user_id_binding_signature_by_selector(
                &signature,
                &target.public_key_data,
                &selector,
                &[signer.public_key_data.clone()],
            )
            .expect("User ID verification should succeed");

            assert_eq!(result.status, CertificateSignatureStatus::Valid);
            assert_eq!(result.certification_kind, Some(kind));
            assert_eq!(
                result.signer_primary_fingerprint,
                Some(signer.fingerprint.clone())
            );
            assert_eq!(result.signing_key_fingerprint, None);
        }
    }
}

#[test]
fn test_generate_and_verify_user_id_certification_by_selector_accepts_duplicate_occurrence_selector()
{
    let signer = generated_key(KeyProfile::Advanced, "SelectorKindSigner");
    let target = generated_key(KeyProfile::Advanced, "SelectorKindTarget");
    let duplicated = duplicate_userid(
        &target.cert_data,
        "SelectorKindTarget <selectorkindtarget@example.com>",
    );
    let user_id_data = first_user_id_bytes(&duplicated);

    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &duplicated,
        &user_id_selector(&user_id_data, 1),
        CertificationKind::Persona,
    )
    .expect("selector-based certification generation should succeed");

    let second_result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &duplicated,
        &user_id_selector(&user_id_data, 1),
        &[signer.public_key_data.clone()],
    )
    .expect("selected occurrence verification should succeed");
    let first_result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &duplicated,
        &user_id_selector(&user_id_data, 0),
        &[signer.public_key_data.clone()],
    )
    .expect("non-selected occurrence verification should return a result");

    assert_eq!(second_result.status, CertificateSignatureStatus::Valid);
    assert_eq!(
        second_result.certification_kind,
        Some(CertificationKind::Persona)
    );
    assert_eq!(first_result.status, CertificateSignatureStatus::Valid);
}

#[test]
fn test_verify_user_id_binding_signature_missing_issuer_fallback_succeeds_with_subkey_signer() {
    let (signer_cert, signer_secret_bytes, subkey_fingerprint) = certification_subkey_signer();
    let target = generated_key(KeyProfile::Universal, "FallbackTarget");
    let target_cert = parse_cert(&target.public_key_data);
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature = positive_certification_without_issuer(&signer_cert, &target_cert);

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &selector,
        &[signer_secret_bytes],
    )
    .expect("fallback verification should succeed");

    assert_eq!(result.status, CertificateSignatureStatus::Valid);
    assert_eq!(result.certification_kind, Some(CertificationKind::Positive));
    assert_eq!(
        result.signer_primary_fingerprint,
        Some(signer_cert.fingerprint().to_hex().to_lowercase())
    );
    assert_eq!(result.signing_key_fingerprint, Some(subkey_fingerprint));
}

#[test]
fn test_verify_user_id_binding_signature_issuer_guided_rejects_signing_only_subkey() {
    let (signer_cert, signer_public_bytes) = signing_only_subkey_signer();
    let target = generated_key(KeyProfile::Universal, "IssuerGuidedUserIdTarget");
    let target_cert = parse_cert(&target.public_key_data);
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature_with_issuer =
        positive_certification_from_signing_only_subkey(&signer_cert, &target_cert, false);
    let signature_without_issuer =
        positive_certification_from_signing_only_subkey(&signer_cert, &target_cert, true);

    let with_issuer_result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature_with_issuer,
        &target.public_key_data,
        &selector,
        &[signer_public_bytes.clone()],
    )
    .expect("issuer-guided verification should return a result");
    let without_issuer_result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature_without_issuer,
        &target.public_key_data,
        &selector,
        &[signer_public_bytes],
    )
    .expect("fallback verification should return a result");

    assert_eq!(
        with_issuer_result.status,
        CertificateSignatureStatus::Invalid
    );
    assert_eq!(
        with_issuer_result.certification_kind,
        Some(CertificationKind::Positive)
    );
    assert_eq!(with_issuer_result.signer_primary_fingerprint, None);
    assert_eq!(with_issuer_result.signing_key_fingerprint, None);

    assert_eq!(
        without_issuer_result.status,
        CertificateSignatureStatus::Invalid
    );
    assert_eq!(
        without_issuer_result.certification_kind,
        Some(CertificationKind::Positive)
    );
    assert_eq!(without_issuer_result.signer_primary_fingerprint, None);
    assert_eq!(without_issuer_result.signing_key_fingerprint, None);
}

#[test]
fn test_verify_direct_key_signature_issuer_guided_rejects_signing_only_subkey() {
    let (signer_cert, signer_public_bytes) = signing_only_subkey_signer();
    let target = generated_key(KeyProfile::Universal, "IssuerGuidedDirectTarget");
    let target_cert = parse_cert(&target.public_key_data);
    let signature_with_issuer =
        direct_key_signature_from_signing_only_subkey(&signer_cert, &target_cert, false);
    let signature_without_issuer =
        direct_key_signature_from_signing_only_subkey(&signer_cert, &target_cert, true);

    let with_issuer_result = cert_signature::verify_direct_key_signature(
        &signature_with_issuer,
        &target.public_key_data,
        &[signer_public_bytes.clone()],
    )
    .expect("issuer-guided verification should return a result");
    let without_issuer_result = cert_signature::verify_direct_key_signature(
        &signature_without_issuer,
        &target.public_key_data,
        &[signer_public_bytes],
    )
    .expect("fallback verification should return a result");

    assert_eq!(
        with_issuer_result.status,
        CertificateSignatureStatus::Invalid
    );
    assert_eq!(with_issuer_result.certification_kind, None);
    assert_eq!(with_issuer_result.signer_primary_fingerprint, None);
    assert_eq!(with_issuer_result.signing_key_fingerprint, None);

    assert_eq!(
        without_issuer_result.status,
        CertificateSignatureStatus::Invalid
    );
    assert_eq!(without_issuer_result.certification_kind, None);
    assert_eq!(without_issuer_result.signer_primary_fingerprint, None);
    assert_eq!(without_issuer_result.signing_key_fingerprint, None);
}

#[test]
fn test_generate_user_id_certification_prefers_primary_over_certification_subkey() {
    let (signer_cert, _) = CertBuilder::new()
        .add_userid("Primary Preferred <primary-preferred@example.com>")
        .add_certification_subkey()
        .generate()
        .expect("signer should generate");
    let target = generated_key(KeyProfile::Universal, "PrimaryTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let mut signer_secret_bytes = Vec::new();
    signer_cert
        .as_tsk()
        .serialize(&mut signer_secret_bytes)
        .expect("secret cert should serialize");
    let mut signer_public_bytes = Vec::new();
    signer_cert
        .serialize(&mut signer_public_bytes)
        .expect("public cert should serialize");

    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer_secret_bytes,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("primary signer should generate certification");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &selector,
        &[signer_public_bytes],
    )
    .expect("verification should succeed");

    assert_eq!(result.status, CertificateSignatureStatus::Valid);
    assert_eq!(
        result.signer_primary_fingerprint,
        Some(signer_cert.fingerprint().to_hex().to_lowercase())
    );
    assert_eq!(result.signing_key_fingerprint, None);
}

#[test]
fn test_generate_user_id_certification_public_only_input_rejected() {
    let signer = generated_key(KeyProfile::Universal, "PublicOnlySigner");
    let target = generated_key(KeyProfile::Universal, "PublicOnlyTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let result = cert_signature::generate_user_id_certification_by_selector(
        &signer.public_key_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}

#[test]
fn test_generate_user_id_certification_by_selector_mismatch_returns_invalid_key_data() {
    let signer = generated_key(KeyProfile::Universal, "SelectorMismatchSigner");
    let target = generated_key(KeyProfile::Universal, "SelectorMismatchTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let mismatched = [user_id_data.clone(), b"-mismatch".to_vec()].concat();

    let result = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &user_id_selector(&mismatched, 0),
        CertificationKind::Positive,
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}

#[test]
fn test_generate_user_id_certification_by_selector_out_of_range_returns_invalid_key_data() {
    let signer = generated_key(KeyProfile::Universal, "SelectorRangeGenerateSigner");
    let target = generated_key(KeyProfile::Universal, "SelectorRangeGenerateTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);

    let result = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &user_id_selector(&user_id_data, 99),
        CertificationKind::Positive,
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}

#[test]
fn test_generate_user_id_certification_without_usable_certifier_returns_signing_failed() {
    let signer = unusable_certification_signer();
    let target = generated_key(KeyProfile::Universal, "UnusableTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let result = cert_signature::generate_user_id_certification_by_selector(
        &signer,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_verify_direct_key_signature_wrong_signature_type_returns_err() {
    let signer = generated_key(KeyProfile::Universal, "WrongTypeSigner");
    let target = generated_key(KeyProfile::Universal, "WrongTypeTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_direct_key_signature(
        &signature,
        &target.public_key_data,
        &[signer.public_key_data.clone()],
    );

    assert!(matches!(result, Err(PgpError::CorruptData { .. })));
}

#[test]
fn test_verify_user_id_binding_signature_wrong_signature_type_returns_err() {
    let generated = generated_key(KeyProfile::Universal, "WrongTypeDirect");
    let signature = direct_key_signature_bytes(&generated.public_key_data);
    let user_id_data = first_user_id_bytes(&generated.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &generated.public_key_data,
        &selector,
        &[generated.public_key_data.clone()],
    );

    assert!(matches!(result, Err(PgpError::CorruptData { .. })));
}

#[test]
fn test_verify_user_id_binding_signature_malformed_signature_returns_err() {
    let generated = generated_key(KeyProfile::Universal, "MalformedSig");
    let user_id_data = first_user_id_bytes(&generated.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        b"not a signature packet",
        &generated.public_key_data,
        &selector,
        &[generated.public_key_data.clone()],
    );

    assert!(matches!(result, Err(PgpError::CorruptData { .. })));
}

#[test]
fn test_verify_user_id_binding_signature_by_selector_out_of_range_returns_invalid_key_data() {
    let signer = generated_key(KeyProfile::Universal, "SelectorRangeSigner");
    let target = generated_key(KeyProfile::Universal, "SelectorRangeTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &user_id_selector(&user_id_data, 99),
        &[signer.public_key_data],
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}

#[test]
fn test_verify_user_id_binding_signature_by_selector_mismatch_returns_invalid_key_data() {
    let signer = generated_key(KeyProfile::Universal, "SelectorVerifyMismatchSigner");
    let target = generated_key(KeyProfile::Universal, "SelectorVerifyMismatchTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let mismatched = [user_id_data.clone(), b"-mismatch".to_vec()].concat();
    let selector = user_id_selector(&user_id_data, 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &user_id_selector(&mismatched, 0),
        &[signer.public_key_data],
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}
