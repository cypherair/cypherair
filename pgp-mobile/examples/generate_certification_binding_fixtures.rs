use std::fs;
use std::path::PathBuf;

use openpgp::cert::prelude::*;
use openpgp::packet::signature;
use openpgp::packet::signature::subpacket::{Subpacket, SubpacketTag, SubpacketValue};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Marshal;
use openpgp::types::{KeyFlags, SignatureType};
use pgp_mobile::keys::{self, KeyProfile};
use sequoia_openpgp as openpgp;

fn strip_issuer_metadata(signature: &mut openpgp::packet::Signature) {
    for tag in [SubpacketTag::Issuer, SubpacketTag::IssuerFingerprint] {
        signature.hashed_area_mut().remove_all(tag);
        signature.unhashed_area_mut().remove_all(tag);
    }

    assert!(signature.get_issuers().is_empty());
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("Tests")
        .join("Fixtures");
    fs::create_dir_all(&fixtures_dir)?;

    let (signer_cert, _) = CertBuilder::new()
        .set_primary_key_flags(KeyFlags::empty())
        .add_userid("FFI Subkey Signer <ffi-subkey-signer@example.com>")
        .add_certification_subkey()
        .generate()?;

    let target = keys::generate_key_with_profile(
        "FFI Fallback Target".to_string(),
        Some("ffi-fallback-target@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )?;
    let target_cert = openpgp::Cert::from_bytes(&target.public_key_data)?;

    let mut signer_secret_bytes = Vec::new();
    signer_cert
        .as_tsk()
        .set_filter(|key| key.fingerprint() != signer_cert.fingerprint())
        .emit_secret_key_stubs(true)
        .serialize(&mut signer_secret_bytes)?;

    let certification_subkey = signer_cert
        .keys()
        .subkeys()
        .next()
        .expect("certification subkey should exist");
    let certification_subkey_fingerprint = certification_subkey
        .key()
        .fingerprint()
        .to_hex()
        .to_lowercase();
    let mut signer = certification_subkey
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;

    let user_id = target_cert
        .userids()
        .next()
        .expect("target cert should have a user id")
        .userid();

    let mut builder = signature::SignatureBuilder::new(SignatureType::PositiveCertification);
    builder.unhashed_area_mut().add(Subpacket::new(
        SubpacketValue::Issuer(signer.public().keyid()),
        false,
    )?)?;
    let mut signature = user_id.bind(&mut signer, &target_cert, builder)?;
    strip_issuer_metadata(&mut signature);

    let mut signature_bytes = Vec::new();
    openpgp::Packet::from(signature).serialize(&mut signature_bytes)?;

    let direct_key = keys::generate_key_with_profile(
        "FFI Direct Key".to_string(),
        Some("ffi-direct@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )?;
    let direct_key_cert = openpgp::Cert::from_bytes(&direct_key.public_key_data)?;
    let direct_key_signature = direct_key_cert
        .with_policy(&StandardPolicy::new(), None)?
        .direct_key_signature()?
        .clone();
    let mut direct_key_signature_bytes = Vec::new();
    openpgp::Packet::from(direct_key_signature).serialize(&mut direct_key_signature_bytes)?;

    fs::write(
        fixtures_dir.join("ffi_cert_binding_subkey_signer.gpg"),
        signer_secret_bytes,
    )?;
    fs::write(
        fixtures_dir.join("ffi_cert_binding_target.gpg"),
        target.public_key_data,
    )?;
    fs::write(
        fixtures_dir.join("ffi_cert_binding_missing_issuer_positive.sig"),
        signature_bytes,
    )?;
    fs::write(
        fixtures_dir.join("ffi_cert_binding_subkey_fingerprint.txt"),
        certification_subkey_fingerprint,
    )?;
    fs::write(
        fixtures_dir.join("ffi_direct_key_target.gpg"),
        direct_key.public_key_data,
    )?;
    fs::write(
        fixtures_dir.join("ffi_direct_key_signature.sig"),
        direct_key_signature_bytes,
    )?;

    Ok(())
}
