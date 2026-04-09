use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, CertificateMergeOutcome, KeyProfile};
use sequoia_openpgp as openpgp;

use openpgp::Packet;
use openpgp::packet::UserID;
use openpgp::packet::key;
use openpgp::packet::signature;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::{KeyFlags, SignatureType};

fn generate_key(profile: KeyProfile, name: &str) -> keys::GeneratedKey {
    keys::generate_key_with_profile(
        name.to_string(),
        Some(format!("{}@example.com", name.to_lowercase())),
        None,
        profile,
    )
    .expect("key generation should succeed")
}

fn serialize_public_cert(cert: &openpgp::Cert) -> Vec<u8> {
    let mut bytes = Vec::new();
    cert.serialize(&mut bytes)
        .expect("public cert serialization should succeed");
    bytes
}

fn make_revocation_update(generated: &keys::GeneratedKey) -> Vec<u8> {
    let cert = openpgp::Cert::from_bytes(&generated.public_key_data)
        .expect("public certificate should parse");
    let revocation = Packet::from_bytes(&generated.revocation_cert)
        .expect("revocation packet should parse");
    let (revoked_cert, _) = cert.insert_packets(vec![revocation])
        .expect("revocation should insert");
    serialize_public_cert(&revoked_cert)
}

fn make_userid_update(secret_cert: &[u8], new_user_id: &str) -> Vec<u8> {
    let cert = openpgp::Cert::from_bytes(secret_cert)
        .expect("secret cert should parse");
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

    let (updated_cert, _) = cert.insert_packets(vec![Packet::from(userid), binding.into()])
        .expect("userid packets should insert");
    serialize_public_cert(&updated_cert.strip_secret_key_material())
}

fn make_subkey_update(secret_cert: &[u8]) -> Vec<u8> {
    let cert = openpgp::Cert::from_bytes(secret_cert)
        .expect("secret cert should parse");
    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .expect("primary key should have secret parts")
        .into_keypair()
        .expect("keypair conversion should succeed");

    let subkey: openpgp::packet::Key<key::SecretParts, key::SubordinateRole> =
        match cert.primary_key().key().version() {
        4 => key::Key4::generate_x25519()
            .expect("v4 subkey generation should succeed")
            .into(),
        6 => key::Key6::generate_x448()
            .expect("v6 subkey generation should succeed")
            .into(),
        version => panic!("unexpected key version: {version}"),
    };

    let binding = subkey
        .bind(
            &mut signer,
            &cert,
            signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_key_flags(
                    KeyFlags::empty()
                        .set_transport_encryption(),
                )
                .expect("subkey binding flags should be valid"),
        )
        .expect("subkey binding should succeed");

    let (updated_cert, _) = cert.insert_packets(vec![Packet::from(subkey), binding.into()])
        .expect("subkey packets should insert");
    serialize_public_cert(&updated_cert.strip_secret_key_material())
}

#[test]
fn test_merge_public_certificate_duplicate_no_op_profile_a() {
    let generated = generate_key(KeyProfile::Universal, "DuplicateA");

    let result = keys::merge_public_certificate_update(
        &generated.public_key_data,
        &generated.public_key_data,
    )
    .expect("duplicate merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::NoOp);
    let info = keys::parse_key_info(&result.merged_cert_data)
        .expect("merged cert should parse");
    assert_eq!(info.fingerprint, generated.fingerprint);
}

#[test]
fn test_merge_public_certificate_duplicate_no_op_profile_b() {
    let generated = generate_key(KeyProfile::Advanced, "DuplicateB");

    let result = keys::merge_public_certificate_update(
        &generated.public_key_data,
        &generated.public_key_data,
    )
    .expect("duplicate merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::NoOp);
    let info = keys::parse_key_info(&result.merged_cert_data)
        .expect("merged cert should parse");
    assert_eq!(info.fingerprint, generated.fingerprint);
    assert_eq!(info.profile, KeyProfile::Advanced);
}

#[test]
fn test_merge_public_certificate_expiry_refresh_profile_a() {
    let generated = generate_key(KeyProfile::Universal, "ExpiryA");
    let refreshed = keys::modify_expiry(&generated.cert_data, Some(60 * 60 * 24 * 365))
        .expect("expiry refresh should succeed");

    let result = keys::merge_public_certificate_update(
        &generated.public_key_data,
        &refreshed.public_key_data,
    )
    .expect("expiry merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);
    let info = keys::parse_key_info(&result.merged_cert_data)
        .expect("merged cert should parse");
    assert_eq!(info.fingerprint, generated.fingerprint);
    assert_eq!(info.expiry_timestamp, refreshed.key_info.expiry_timestamp);
}

#[test]
fn test_merge_public_certificate_expiry_refresh_profile_b() {
    let generated = generate_key(KeyProfile::Advanced, "ExpiryB");
    let refreshed = keys::modify_expiry(&generated.cert_data, Some(60 * 60 * 24 * 365))
        .expect("expiry refresh should succeed");

    let result = keys::merge_public_certificate_update(
        &generated.public_key_data,
        &refreshed.public_key_data,
    )
    .expect("expiry merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);
    let info = keys::parse_key_info(&result.merged_cert_data)
        .expect("merged cert should parse");
    assert_eq!(info.fingerprint, generated.fingerprint);
    assert_eq!(info.profile, KeyProfile::Advanced);
    assert_eq!(info.expiry_timestamp, refreshed.key_info.expiry_timestamp);
}

#[test]
fn test_merge_public_certificate_absorbs_revocation_update() {
    let generated = generate_key(KeyProfile::Universal, "Revocation");
    let revocation_update = make_revocation_update(&generated);

    let result = keys::merge_public_certificate_update(
        &generated.public_key_data,
        &revocation_update,
    )
    .expect("revocation merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);
    let info = keys::parse_key_info(&result.merged_cert_data)
        .expect("merged cert should parse");
    assert!(info.is_revoked, "merged cert should be revoked");
}

#[test]
fn test_merge_public_certificate_absorbs_new_user_id() {
    let generated = generate_key(KeyProfile::Universal, "Userid");
    let new_user_id = "Userid Secondary <secondary@example.com>";
    let userid_update = make_userid_update(&generated.cert_data, new_user_id);

    let result = keys::merge_public_certificate_update(
        &generated.public_key_data,
        &userid_update,
    )
    .expect("userid merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);
    let merged_cert = openpgp::Cert::from_bytes(&result.merged_cert_data)
        .expect("merged cert should parse");
    assert!(
        merged_cert.userids().any(|userid| userid.userid().value() == new_user_id.as_bytes()),
        "merged cert should contain the new user id"
    );
}

#[test]
fn test_merge_public_certificate_absorbs_new_subkey() {
    let generated = generate_key(KeyProfile::Universal, "Subkey");
    let subkey_update = make_subkey_update(&generated.cert_data);
    let existing_cert = openpgp::Cert::from_bytes(&generated.public_key_data)
        .expect("existing cert should parse");

    let result = keys::merge_public_certificate_update(
        &generated.public_key_data,
        &subkey_update,
    )
    .expect("subkey merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);
    let merged_cert = openpgp::Cert::from_bytes(&result.merged_cert_data)
        .expect("merged cert should parse");
    assert_eq!(
        merged_cert.keys().subkeys().count(),
        existing_cert.keys().subkeys().count() + 1,
        "merged cert should contain one additional subkey"
    );
}

#[test]
fn test_merge_public_certificate_rejects_fingerprint_mismatch() {
    let alice = generate_key(KeyProfile::Universal, "MismatchAlice");
    let bob = generate_key(KeyProfile::Universal, "MismatchBob");

    let error = keys::merge_public_certificate_update(
        &alice.public_key_data,
        &bob.public_key_data,
    )
    .expect_err("mismatched fingerprints must be rejected");

    assert!(
        matches!(error, PgpError::InvalidKeyData { .. }),
        "expected InvalidKeyData, got {error:?}"
    );
}

#[test]
fn test_merge_public_certificate_rejects_secret_bearing_input() {
    let generated = generate_key(KeyProfile::Universal, "SecretReject");

    let error = keys::merge_public_certificate_update(
        &generated.public_key_data,
        &generated.cert_data,
    )
    .expect_err("secret-bearing input must be rejected");

    assert!(
        matches!(error, PgpError::InvalidKeyData { .. }),
        "expected InvalidKeyData, got {error:?}"
    );
}
