use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, CertificateMergeOutcome, KeyProfile};
use sequoia_openpgp as openpgp;
use std::fs;
use std::path::PathBuf;

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

fn load_fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    fs::read(&path).unwrap_or_else(|error| {
        panic!("Failed to load fixture {}: {}", path.display(), error)
    })
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
fn test_parse_key_info_prefers_primary_user_id_after_merge_fixture() {
    let base = load_fixture("merge_primary_uid_base.gpg");
    let update = load_fixture("merge_primary_uid_update.gpg");

    let result = keys::merge_public_certificate_update(&base, &update)
        .expect("primary user id merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);

    let merged_cert = openpgp::Cert::from_bytes(&result.merged_cert_data)
        .expect("merged cert should parse");
    let policy = StandardPolicy::new();
    assert_eq!(
        merged_cert.userids().next().unwrap().userid().value(),
        b"aaaaa",
        "raw user id order should keep the original user id first"
    );
    assert_eq!(
        merged_cert.with_policy(&policy, None)
            .expect("merged cert should validate")
            .primary_userid()
            .expect("merged cert should have a primary user id")
            .userid()
            .value(),
        b"bbbbb",
        "Sequoia should pick the newer primary identity"
    );

    let info = keys::parse_key_info(&result.merged_cert_data)
        .expect("merged cert should parse via parse_key_info");
    assert_eq!(info.user_id.as_deref(), Some("bbbbb"));
}

#[test]
fn test_parse_key_info_revoked_cert_uses_relaxed_display_user_id_fallback() {
    let generated = keys::generate_key_with_profile(
        "Expired Display".to_string(),
        Some("expired-display@example.com".to_string()),
        Some(1),
        KeyProfile::Universal,
    )
    .expect("short-lived key generation should succeed");
    std::thread::sleep(std::time::Duration::from_secs(2));

    let info = keys::parse_key_info(&generated.public_key_data)
        .expect("expired cert should still parse for display");
    assert_eq!(
        info.user_id.as_deref(),
        Some("Expired Display <expired-display@example.com>")
    );
    assert!(info.is_expired);
}

#[test]
fn test_merge_public_certificate_absorbs_revocation_update_profile_a_fixture() {
    let base = load_fixture("merge_revocation_profile_a_base.gpg");
    let update = load_fixture("merge_revocation_profile_a_update.gpg");

    let result = keys::merge_public_certificate_update(&base, &update)
        .expect("profile A revocation merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);
    let info = keys::parse_key_info(&result.merged_cert_data)
        .expect("merged profile A revocation cert should parse");
    assert!(info.is_revoked);
    assert_eq!(info.profile, KeyProfile::Universal);
}

#[test]
fn test_merge_public_certificate_absorbs_revocation_update_profile_b_fixture() {
    let base = load_fixture("merge_revocation_profile_b_base.gpg");
    let update = load_fixture("merge_revocation_profile_b_update.gpg");

    let result = keys::merge_public_certificate_update(&base, &update)
        .expect("profile B revocation merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);
    let info = keys::parse_key_info(&result.merged_cert_data)
        .expect("merged profile B revocation cert should parse");
    assert!(info.is_revoked);
    assert_eq!(info.profile, KeyProfile::Advanced);
}

#[test]
fn test_merge_public_certificate_adds_encryption_subkey_profile_a_fixture() {
    let base = load_fixture("merge_add_encryption_subkey_profile_a_base.gpg");
    let update = load_fixture("merge_add_encryption_subkey_profile_a_update.gpg");

    let base_info = keys::parse_key_info(&base).expect("profile A base cert should parse");
    assert!(!base_info.has_encryption_subkey);

    let result = keys::merge_public_certificate_update(&base, &update)
        .expect("profile A subkey merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);
    let merged_info = keys::parse_key_info(&result.merged_cert_data)
        .expect("profile A merged cert should parse");
    assert!(merged_info.has_encryption_subkey);
    assert_eq!(merged_info.profile, KeyProfile::Universal);
}

#[test]
fn test_merge_public_certificate_adds_encryption_subkey_profile_b_fixture() {
    let base = load_fixture("merge_add_encryption_subkey_profile_b_base.gpg");
    let update = load_fixture("merge_add_encryption_subkey_profile_b_update.gpg");

    let base_info = keys::parse_key_info(&base).expect("profile B base cert should parse");
    assert!(!base_info.has_encryption_subkey);

    let result = keys::merge_public_certificate_update(&base, &update)
        .expect("profile B subkey merge should succeed");

    assert_eq!(result.outcome, CertificateMergeOutcome::Updated);
    let merged_info = keys::parse_key_info(&result.merged_cert_data)
        .expect("profile B merged cert should parse");
    assert!(merged_info.has_encryption_subkey);
    assert_eq!(merged_info.profile, KeyProfile::Advanced);
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
