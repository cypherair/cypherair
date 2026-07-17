use super::*;

pub(super) fn generated_key(profile: KeySuite, name: &str) -> keys::GeneratedKey {
    keys::generate_key_with_suite(
        name.to_string(),
        Some(format!("{}@example.com", name.to_lowercase())),
        None,
        profile,
    )
    .expect("key generation should succeed")
}

pub(super) fn generated_key_with_identity(
    profile: KeySuite,
    name: &str,
    email: &str,
) -> keys::GeneratedKey {
    keys::generate_key_with_suite(name.to_string(), Some(email.to_string()), None, profile)
        .expect("key generation should succeed")
}

pub(super) fn parse_cert(cert_data: &[u8]) -> openpgp::Cert {
    openpgp::Cert::from_bytes(cert_data).expect("certificate should parse")
}

pub(super) fn serialize_signature(signature: &openpgp::packet::Signature) -> Vec<u8> {
    let mut bytes = Vec::new();
    openpgp::Packet::from(signature.clone())
        .serialize(&mut bytes)
        .expect("signature serialization should succeed");
    bytes
}

pub(super) fn first_user_id_bytes(cert_data: &[u8]) -> Vec<u8> {
    parse_cert(cert_data)
        .userids()
        .next()
        .expect("certificate should have a User ID")
        .userid()
        .value()
        .to_vec()
}

pub(super) fn duplicate_userid(secret_cert: &[u8], duplicate_user_id: &str) -> Vec<u8> {
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

    let raw_cert =
        openpgp::cert::raw::RawCert::from_bytes(secret_cert).expect("raw secret cert should parse");
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

pub(super) fn user_id_selector(user_id_data: &[u8], occurrence_index: u64) -> UserIdSelectorInput {
    UserIdSelectorInput {
        user_id_data: user_id_data.to_vec(),
        occurrence_index,
    }
}

pub(super) fn direct_key_signature_bytes(cert_data: &[u8]) -> Vec<u8> {
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

pub(super) fn certification_subkey_signer() -> (openpgp::Cert, Vec<u8>, String) {
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

pub(super) fn signing_only_subkey_signer() -> (openpgp::Cert, Vec<u8>) {
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

pub(super) fn unusable_certification_signer() -> Vec<u8> {
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

pub(super) fn strip_issuer_metadata(signature: &mut openpgp::packet::Signature) {
    for tag in [SubpacketTag::Issuer, SubpacketTag::IssuerFingerprint] {
        signature.hashed_area_mut().remove_all(tag);
        signature.unhashed_area_mut().remove_all(tag);
    }

    assert!(
        signature.get_issuers().is_empty(),
        "signature should not advertise issuer information"
    );
}

pub(super) fn positive_certification_without_issuer(
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

pub(super) fn positive_certification_from_signing_only_subkey(
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

pub(super) fn direct_key_signature_from_signing_only_subkey(
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
