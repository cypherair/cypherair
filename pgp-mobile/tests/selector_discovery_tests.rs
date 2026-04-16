use pgp_mobile::armor;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile};
use sequoia_openpgp as openpgp;

use openpgp::cert::prelude::*;
use openpgp::packet::signature;
use openpgp::packet::Tag;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::ReasonForRevocation;
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

fn serialize_public_cert(cert: &openpgp::Cert) -> Vec<u8> {
    let mut bytes = Vec::new();
    cert.serialize(&mut bytes)
        .expect("public cert serialization should succeed");
    bytes
}

fn serialize_secret_cert(cert: &openpgp::Cert) -> Vec<u8> {
    let mut bytes = Vec::new();
    cert.as_tsk()
        .serialize(&mut bytes)
        .expect("secret cert serialization should succeed");
    bytes
}

fn duplicate_userid_raw(secret_cert: &[u8], duplicate_user_id: &str) -> Vec<u8> {
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
        if !inserted && matches!(packet.tag(), Tag::PublicSubkey | Tag::SecretSubkey) {
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

fn revoke_userid_occurrence(secret_cert: &[u8], occurrence_index: usize) -> Vec<u8> {
    let cert = openpgp::Cert::from_bytes(secret_cert).expect("secret cert should parse");
    let raw_cert = openpgp::cert::raw::RawCert::from_bytes(secret_cert)
        .expect("raw secret cert should parse");
    let user_id = raw_cert
        .packets()
        .filter(|packet| packet.tag() == Tag::UserID)
        .nth(occurrence_index)
        .map(|packet| Packet::from_bytes(packet.as_bytes()).expect("userid packet should parse"))
        .and_then(|packet| match packet {
            Packet::UserID(user_id) => Some(user_id),
            _ => None,
        })
        .expect("requested User ID occurrence should exist");
    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .expect("primary key should have secret parts")
        .into_keypair()
        .expect("keypair conversion should succeed");
    let revocation = UserIDRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")
        .expect("revocation reason should configure")
        .build(&mut signer, &cert, &user_id, None)
        .expect("User ID revocation should build");
    let mut revocation_bytes = Vec::new();
    Packet::from(revocation)
        .serialize(&mut revocation_bytes)
        .expect("revocation packet should serialize");

    let raw_cert = openpgp::cert::raw::RawCert::from_bytes(secret_cert)
        .expect("raw secret cert should parse");
    let mut revoked = Vec::new();
    let mut seen_user_ids = 0usize;
    let mut target_open = false;
    let mut inserted = false;

    for packet in raw_cert.packets() {
        if target_open && packet.tag() != Tag::Signature && !inserted {
            revoked.extend_from_slice(&revocation_bytes);
            inserted = true;
            target_open = false;
        }

        if packet.tag() == Tag::UserID {
            if target_open && !inserted {
                revoked.extend_from_slice(&revocation_bytes);
                inserted = true;
            }

            target_open = seen_user_ids == occurrence_index;
            seen_user_ids += 1;
        }

        revoked.extend_from_slice(packet.as_bytes());
    }

    if target_open && !inserted {
        revoked.extend_from_slice(&revocation_bytes);
    }

    revoked
}

fn assert_invalid_key_data<T>(result: Result<T, PgpError>) {
    match result {
        Err(PgpError::InvalidKeyData { .. }) => {}
        Err(other) => panic!("expected InvalidKeyData, got: {other:?}"),
        Ok(_) => panic!("expected InvalidKeyData, got success"),
    }
}

fn first_user_id_text(cert_data: &[u8]) -> String {
    String::from_utf8(
        openpgp::Cert::from_bytes(cert_data)
            .expect("certificate should parse")
            .userids()
            .next()
            .expect("certificate should have a User ID")
            .userid()
            .value()
            .to_vec(),
    )
    .expect("User ID should be valid UTF-8 in test fixture")
}

#[test]
fn test_discover_certificate_selectors_profile_a_generated_cert_exposes_selectors() {
    let generated = generate_key(KeyProfile::Universal, "SelectorA");

    let discovered = keys::discover_certificate_selectors(&generated.public_key_data)
        .expect("selector discovery should succeed");

    assert_eq!(discovered.certificate_fingerprint, generated.fingerprint);
    assert_eq!(discovered.user_ids.len(), 1, "generated cert should expose one User ID");
    assert_eq!(discovered.user_ids[0].occurrence_index, 0);
    assert_eq!(
        discovered.user_ids[0].display_text,
        "SelectorA <selectora@example.com>"
    );
    assert_eq!(
        discovered.user_ids[0].user_id_data,
        b"SelectorA <selectora@example.com>"
    );
    assert!(
        discovered.user_ids[0].is_currently_primary,
        "generated primary User ID should be marked primary"
    );
    assert!(!discovered.user_ids[0].is_currently_revoked);

    assert!(
        !discovered.subkeys.is_empty(),
        "generated cert should expose at least one discovered subkey"
    );
    assert_eq!(
        discovered.subkeys[0].fingerprint,
        discovered.subkeys[0].fingerprint.to_lowercase(),
        "subkey fingerprint must be canonical lowercase hex"
    );
    assert!(
        discovered
            .subkeys
            .iter()
            .any(|subkey| subkey.is_currently_transport_encryption_capable),
        "generated cert should expose at least one currently transport-capable subkey"
    );
    assert!(discovered.subkeys.iter().all(|subkey| !subkey.is_currently_revoked));
    assert!(discovered.subkeys.iter().all(|subkey| !subkey.is_currently_expired));
}

#[test]
fn test_discover_certificate_selectors_profile_b_public_and_secret_match() {
    let generated = generate_key(KeyProfile::Advanced, "SelectorB");

    let from_public = keys::discover_certificate_selectors(&generated.public_key_data)
        .expect("public selector discovery should succeed");
    let from_secret = keys::discover_certificate_selectors(&generated.cert_data)
        .expect("secret selector discovery should succeed");

    assert_eq!(from_public, from_secret);
    assert_eq!(from_public.certificate_fingerprint, generated.fingerprint);
}

#[test]
fn test_discover_certificate_selectors_duplicate_user_ids_preserve_order_and_occurrence_indexes() {
    let generated = generate_key(KeyProfile::Universal, "Duplicate User");
    let secret_cert = duplicate_userid_raw(
        &generated.cert_data,
        "Duplicate User <duplicate user@example.com>",
    );
    let discovered = keys::discover_certificate_selectors(&secret_cert)
        .expect("selector discovery should succeed");

    assert_eq!(discovered.user_ids.len(), 2);
    assert_eq!(discovered.user_ids[0].occurrence_index, 0);
    assert_eq!(discovered.user_ids[1].occurrence_index, 1);
    assert_eq!(discovered.user_ids[0].user_id_data, discovered.user_ids[1].user_id_data);
    assert_eq!(discovered.user_ids[0].display_text, discovered.user_ids[1].display_text);
}

#[test]
fn test_discover_certificate_selectors_duplicate_user_ids_preserve_per_occurrence_primary_state() {
    let generated = generate_key(KeyProfile::Universal, "Duplicate Primary");
    let original_user_id = first_user_id_text(&generated.cert_data);
    let secret_cert = duplicate_userid_raw(&generated.cert_data, &original_user_id);

    let discovered = keys::discover_certificate_selectors(&secret_cert)
        .expect("selector discovery should succeed");

    assert_eq!(discovered.user_ids.len(), 2);
    assert_eq!(discovered.user_ids[0].user_id_data, discovered.user_ids[1].user_id_data);
    assert!(
        discovered.user_ids[0].is_currently_primary,
        "original occurrence should remain primary"
    );
    assert!(
        !discovered.user_ids[1].is_currently_primary,
        "duplicate occurrence should preserve its non-primary state"
    );
}

#[test]
fn test_discover_certificate_selectors_duplicate_user_ids_preserve_per_occurrence_revocation_state()
{
    let generated = generate_key(KeyProfile::Universal, "Duplicate Revoked");
    let original_user_id = first_user_id_text(&generated.cert_data);
    let duplicated = duplicate_userid_raw(&generated.cert_data, &original_user_id);
    let revoked = revoke_userid_occurrence(&duplicated, 1);

    let discovered =
        keys::discover_certificate_selectors(&revoked).expect("selector discovery should succeed");

    assert_eq!(discovered.user_ids.len(), 2);
    assert_eq!(discovered.user_ids[0].user_id_data, discovered.user_ids[1].user_id_data);
    assert!(
        !discovered.user_ids[0].is_currently_revoked,
        "first occurrence should remain valid"
    );
    assert!(
        discovered.user_ids[1].is_currently_revoked,
        "second occurrence should preserve its revoked state"
    );
}

#[test]
fn test_discover_certificate_selectors_multiple_subkeys_preserve_native_order() {
    let (cert, _) = CertBuilder::new()
        .add_userid("Multi Subkey <multi-subkey@example.com>")
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .expect("cert should generate");
    let public_cert = serialize_public_cert(&cert);
    let policy = StandardPolicy::new();
    let transport_capable_fingerprints: std::collections::HashSet<String> = cert
        .keys()
        .subkeys()
        .with_policy(&policy, None)
        .supported()
        .for_transport_encryption()
        .map(|subkey| subkey.key().fingerprint().to_hex().to_lowercase())
        .collect();
    let expected_order: Vec<String> = cert
        .keys()
        .subkeys()
        .map(|subkey| subkey.key().fingerprint().to_hex().to_lowercase())
        .collect();

    let discovered = keys::discover_certificate_selectors(&public_cert)
        .expect("selector discovery should succeed");

    assert_eq!(
        discovered
            .subkeys
            .iter()
            .map(|subkey| subkey.fingerprint.clone())
            .collect::<Vec<_>>(),
        expected_order
    );
    assert_eq!(discovered.subkeys.len(), 2);
    assert_eq!(
        discovered
            .subkeys
            .iter()
            .map(|subkey| transport_capable_fingerprints.contains(&subkey.fingerprint))
            .collect::<Vec<_>>(),
        discovered
            .subkeys
            .iter()
            .map(|subkey| subkey.is_currently_transport_encryption_capable)
            .collect::<Vec<_>>(),
        "transport-encryption capability should align with the cert's native subkey order"
    );
}

#[test]
fn test_discover_certificate_selectors_catalog_selectors_drive_existing_revocation_apis() {
    let generated = generate_key(KeyProfile::Universal, "SelectorRevocations");
    let discovered = keys::discover_certificate_selectors(&generated.public_key_data)
        .expect("selector discovery should succeed");

    let subkey_revocation = keys::generate_subkey_revocation(
        &generated.cert_data,
        &discovered.subkeys[0].fingerprint,
    )
    .expect("subkey revocation should accept discovered subkey fingerprint");
    let user_id_revocation = keys::generate_user_id_revocation(
        &generated.cert_data,
        &discovered.user_ids[0].user_id_data,
    )
    .expect("user ID revocation should accept discovered user ID bytes");

    assert!(!subkey_revocation.is_empty());
    assert!(!user_id_revocation.is_empty());
}

#[test]
fn test_discover_certificate_selectors_binary_only_armored_input_rejected() {
    let generated = generate_key(KeyProfile::Universal, "SelectorArmor");
    let armored = armor::armor_public_key(&generated.public_key_data)
        .expect("armoring public cert should succeed");

    assert_invalid_key_data(keys::discover_certificate_selectors(&armored));
}

#[test]
fn test_discover_certificate_selectors_malformed_input_rejected() {
    assert_invalid_key_data(keys::discover_certificate_selectors(b"not a cert"));
}

#[test]
fn test_discover_certificate_selectors_secret_and_public_builder_outputs_match() {
    let (cert, _) = CertBuilder::new()
        .add_userid("Builder Match <builder-match@example.com>")
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .expect("cert should generate");
    let public_cert = serialize_public_cert(&cert);
    let secret_cert = serialize_secret_cert(&cert);

    let from_public = keys::discover_certificate_selectors(&public_cert)
        .expect("public selector discovery should succeed");
    let from_secret = keys::discover_certificate_selectors(&secret_cert)
        .expect("secret selector discovery should succeed");

    assert_eq!(from_public, from_secret);
}
