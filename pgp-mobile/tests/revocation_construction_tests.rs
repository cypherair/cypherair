use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile, UserIdSelectorInput};
use sequoia_openpgp as openpgp;

use openpgp::packet::signature;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::{RevocationStatus, SignatureType};
use openpgp::Packet;

fn generate_key(profile: KeyProfile, name: &str) -> keys::GeneratedKey {
    keys::generate_key_with_profile(
        name.to_string(),
        Some(format!("{}@example.com", name.to_lowercase())),
        None,
        profile,
    )
    .expect("key generation should succeed")
}

fn serialize_secret_cert(cert: &openpgp::Cert) -> Vec<u8> {
    let mut bytes = Vec::new();
    cert.as_tsk()
        .serialize(&mut bytes)
        .expect("secret cert serialization should succeed");
    bytes
}

fn add_userid(secret_cert: &[u8], new_user_id: &str) -> Vec<u8> {
    let cert = openpgp::Cert::from_bytes(secret_cert).expect("secret cert should parse");
    let policy = StandardPolicy::new();
    let template: signature::SignatureBuilder = cert
        .with_policy(&policy, None)
        .expect("cert should validate")
        .primary_userid()
        .expect("primary user id should exist")
        .binding_signature()
        .clone()
        .into();

    let userid: UserID = new_user_id.into();
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

    let (updated_cert, _) = cert
        .insert_packets(vec![Packet::from(userid), binding.into()])
        .expect("userid packets should insert");
    serialize_secret_cert(&updated_cert)
}

fn duplicate_userid(secret_cert: &[u8], duplicate_user_id: &str) -> Vec<u8> {
    let cert = openpgp::Cert::from_bytes(secret_cert).expect("secret cert should parse");
    let policy = StandardPolicy::new();
    let template: signature::SignatureBuilder = cert
        .with_policy(&policy, None)
        .expect("cert should validate")
        .primary_userid()
        .expect("primary user id should exist")
        .binding_signature()
        .clone()
        .into();

    let userid: UserID = duplicate_user_id.into();
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
    Packet::from(userid)
        .serialize(&mut userid_bytes)
        .expect("userid packet should serialize");
    let mut binding_bytes = Vec::new();
    Packet::from(binding)
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

fn first_user_id_bytes(cert_data: &[u8]) -> Vec<u8> {
    openpgp::Cert::from_bytes(cert_data)
        .expect("certificate should parse")
        .userids()
        .next()
        .expect("certificate should have a user id")
        .userid()
        .value()
        .to_vec()
}

fn assert_invalid_key_data(result: Result<Vec<u8>, PgpError>) {
    match result {
        Err(PgpError::InvalidKeyData { .. }) => {}
        Err(other) => panic!("expected InvalidKeyData, got: {other:?}"),
        Ok(_) => panic!("expected InvalidKeyData, got success"),
    }
}

#[test]
fn test_generate_key_revocation_profile_a_validates_against_source_cert() {
    let generated = generate_key(KeyProfile::Universal, "RevocationA");
    let revocation =
        keys::generate_key_revocation(&generated.cert_data).expect("revocation should generate");

    let result = keys::parse_revocation_cert(&revocation, &generated.public_key_data)
        .expect("revocation should validate");
    assert!(result.contains("revocation"));
}

#[test]
fn test_generate_key_revocation_profile_b_validates_against_source_cert() {
    let generated = generate_key(KeyProfile::Advanced, "RevocationB");
    let revocation =
        keys::generate_key_revocation(&generated.cert_data).expect("revocation should generate");

    let result = keys::parse_revocation_cert(&revocation, &generated.public_key_data)
        .expect("revocation should validate");
    assert!(result.contains("revocation"));
}

#[test]
fn test_generate_key_revocation_wrong_certificate_fails_validation() {
    let key_a = generate_key(KeyProfile::Universal, "KeyA");
    let key_b = generate_key(KeyProfile::Universal, "KeyB");

    let revocation =
        keys::generate_key_revocation(&key_a.cert_data).expect("revocation should generate");
    let result = keys::parse_revocation_cert(&revocation, &key_b.public_key_data);
    assert!(
        result.is_err(),
        "revocation should not validate against another certificate"
    );
}

#[test]
fn test_generate_key_revocation_public_only_input_rejected() {
    let generated = generate_key(KeyProfile::Universal, "PublicOnlyKey");
    assert_invalid_key_data(keys::generate_key_revocation(&generated.public_key_data));
}

#[test]
fn test_generate_subkey_revocation_public_only_input_rejected() {
    let generated = generate_key(KeyProfile::Universal, "PublicOnlySubkey");
    let cert = openpgp::Cert::from_bytes(&generated.public_key_data).expect("cert should parse");
    let fingerprint = cert
        .keys()
        .subkeys()
        .next()
        .expect("subkey should exist")
        .key()
        .fingerprint()
        .to_hex()
        .to_lowercase();

    assert_invalid_key_data(keys::generate_subkey_revocation(
        &generated.public_key_data,
        &fingerprint,
    ));
}

#[test]
fn test_generate_user_id_revocation_public_only_input_rejected() {
    let generated = generate_key(KeyProfile::Universal, "PublicOnlyUserid");
    let cert = openpgp::Cert::from_bytes(&generated.public_key_data).expect("cert should parse");
    let user_id = cert
        .userids()
        .next()
        .expect("user id should exist")
        .userid()
        .value()
        .to_vec();

    assert_invalid_key_data(keys::generate_user_id_revocation_by_selector(
        &generated.public_key_data,
        &user_id_selector(&user_id, 0),
    ));
}

#[test]
fn test_generate_key_revocation_encrypted_secret_input_rejected() {
    let generated = generate_key(KeyProfile::Advanced, "EncryptedSecret");
    let armored = keys::export_secret_key(&generated.cert_data, "passphrase", KeyProfile::Advanced)
        .expect("secret key export should succeed");
    let (encrypted_secret, _) =
        pgp_mobile::armor::decode_armor(&armored).expect("armored secret key should dearmor");

    assert_invalid_key_data(keys::generate_key_revocation(&encrypted_secret));
}

#[test]
fn test_generate_subkey_revocation_revokes_selected_subkey() {
    let generated = generate_key(KeyProfile::Universal, "SubkeyTarget");
    let cert = openpgp::Cert::from_bytes(&generated.cert_data).expect("secret cert should parse");
    let fingerprint = cert
        .keys()
        .subkeys()
        .next()
        .expect("subkey should exist")
        .key()
        .fingerprint()
        .to_hex()
        .to_lowercase();

    let revocation = keys::generate_subkey_revocation(&generated.cert_data, &fingerprint)
        .expect("subkey revocation should generate");
    let packet = Packet::from_bytes(&revocation).expect("revocation packet should parse");
    let (revoked_cert, _) = cert
        .insert_packets(vec![packet])
        .expect("revocation packet should insert");

    let policy = StandardPolicy::new();
    let subkey = revoked_cert
        .keys()
        .subkeys()
        .next()
        .expect("subkey should still exist");
    assert!(
        matches!(
            subkey.revocation_status(&policy, None),
            RevocationStatus::Revoked(_)
        ),
        "subkey should be revoked after inserting revocation signature"
    );
}

#[test]
fn test_generate_subkey_revocation_uppercase_fingerprint_succeeds() {
    let generated = generate_key(KeyProfile::Universal, "UppercaseSubkey");
    let cert = openpgp::Cert::from_bytes(&generated.cert_data).expect("secret cert should parse");
    let fingerprint = cert
        .keys()
        .subkeys()
        .next()
        .expect("subkey should exist")
        .key()
        .fingerprint()
        .to_hex()
        .to_uppercase();

    let revocation = keys::generate_subkey_revocation(&generated.cert_data, &fingerprint)
        .expect("uppercase subkey fingerprint should normalize and match");

    assert!(!revocation.is_empty());
}

#[test]
fn test_generate_subkey_revocation_selector_miss_returns_invalid_key_data() {
    let generated = generate_key(KeyProfile::Universal, "MissingSubkey");
    assert_invalid_key_data(keys::generate_subkey_revocation(
        &generated.cert_data,
        "0000000000000000000000000000000000000000",
    ));
}

#[test]
fn test_generate_user_id_revocation_revokes_selected_user_id_only() {
    let generated = generate_key(KeyProfile::Universal, "UseridTarget");
    let secret_with_extra_userid = add_userid(&generated.cert_data, "secondary@example.com");
    let cert =
        openpgp::Cert::from_bytes(&secret_with_extra_userid).expect("secret cert should parse");
    let primary_user_id = cert
        .userids()
        .next()
        .expect("primary user id should exist")
        .userid()
        .value()
        .to_vec();

    let revocation = keys::generate_user_id_revocation_by_selector(
        &secret_with_extra_userid,
        &user_id_selector(&primary_user_id, 0),
    )
    .expect("user id revocation should generate");
    let packet = Packet::from_bytes(&revocation).expect("revocation packet should parse");
    let (revoked_cert, _) = cert
        .insert_packets(vec![packet])
        .expect("revocation packet should insert");

    let policy = StandardPolicy::new();
    let statuses: Vec<(Vec<u8>, bool)> = revoked_cert
        .userids()
        .map(|ua| {
            (
                ua.userid().value().to_vec(),
                matches!(
                    ua.revocation_status(&policy, None),
                    RevocationStatus::Revoked(_)
                ),
            )
        })
        .collect();

    assert_eq!(statuses.len(), 2, "test cert should contain two user IDs");
    assert!(
        statuses
            .iter()
            .any(|(bytes, revoked)| bytes == &primary_user_id && *revoked),
        "selected user ID should be revoked"
    );
    assert!(
        statuses
            .iter()
            .any(|(bytes, revoked)| bytes != &primary_user_id && !*revoked),
        "non-selected user ID should remain valid"
    );
}

#[test]
fn test_generate_user_id_revocation_by_selector_accepts_duplicate_occurrence_selector() {
    let generated = generate_key(KeyProfile::Universal, "SelectorDuplicateUserid");
    let duplicated = duplicate_userid(
        &generated.cert_data,
        "SelectorDuplicateUserid <selectorduplicateuserid@example.com>",
    );
    let discovered = keys::discover_certificate_selectors(&duplicated)
        .expect("selector discovery should succeed");
    let selector = &discovered.user_ids[1];

    let revocation = keys::generate_user_id_revocation_by_selector(
        &duplicated,
        &user_id_selector(&selector.user_id_data, selector.occurrence_index),
    )
    .expect("selector-based user id revocation should generate");

    assert!(!revocation.is_empty());
}

#[test]
fn test_generate_user_id_revocation_by_selector_occurrence_index_out_of_range_returns_invalid_key_data()
{
    let generated = generate_key(KeyProfile::Universal, "OutOfRangeUserid");
    let user_id_data = first_user_id_bytes(&generated.cert_data);

    assert_invalid_key_data(keys::generate_user_id_revocation_by_selector(
        &generated.cert_data,
        &user_id_selector(&user_id_data, 99),
    ));
}

#[test]
fn test_generate_user_id_revocation_by_selector_bytes_mismatch_returns_invalid_key_data() {
    let generated = generate_key(KeyProfile::Universal, "MismatchUserid");
    let first_user_id = first_user_id_bytes(&generated.cert_data);
    let mismatched = [first_user_id.clone(), b"-mismatch".to_vec()].concat();

    assert_invalid_key_data(keys::generate_user_id_revocation_by_selector(
        &generated.cert_data,
        &user_id_selector(&mismatched, 0),
    ));
}

#[test]
fn test_generate_subkey_and_user_id_revocations_are_signature_packets() {
    let generated = generate_key(KeyProfile::Advanced, "SignatureTypes");
    let cert = openpgp::Cert::from_bytes(&generated.cert_data).expect("secret cert should parse");
    let subkey_fingerprint = cert
        .keys()
        .subkeys()
        .next()
        .expect("subkey should exist")
        .key()
        .fingerprint()
        .to_hex()
        .to_lowercase();
    let user_id = cert
        .userids()
        .next()
        .expect("user id should exist")
        .userid()
        .value()
        .to_vec();

    let subkey_revocation =
        keys::generate_subkey_revocation(&generated.cert_data, &subkey_fingerprint)
            .expect("subkey revocation should generate");
    let user_id_revocation = keys::generate_user_id_revocation_by_selector(
        &generated.cert_data,
        &user_id_selector(&user_id, 0),
    )
    .expect("user id revocation should generate");

    let subkey_packet = Packet::from_bytes(&subkey_revocation).expect("subkey packet should parse");
    let user_id_packet =
        Packet::from_bytes(&user_id_revocation).expect("user id packet should parse");

    match subkey_packet {
        Packet::Signature(sig) => assert_eq!(sig.typ(), SignatureType::SubkeyRevocation),
        other => panic!("expected subkey revocation signature, got: {other:?}"),
    }

    match user_id_packet {
        Packet::Signature(sig) => assert_eq!(sig.typ(), SignatureType::CertificationRevocation),
        other => panic!("expected user ID revocation signature, got: {other:?}"),
    }
}
