//! Generates richer-signature-result fixtures for Swift FFI and service-layer tests.
//!
//! Includes:
//! - multi-signer cleartext and detached fixtures,
//! - repeated-signer detached fixtures,
//! - encrypted multi-signer fixtures,
//! - verify-family mixed-fold detached fixtures for `expired + unknown` and `expired + bad`.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use openpgp::packet::signature::subpacket::SubpacketTag;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};
use openpgp::types::SignatureType;
use pgp_mobile::armor::{self, ArmorKind};
use pgp_mobile::decrypt::SignatureStatus;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::signature_details::DetailedSignatureStatus;
use pgp_mobile::verify;
use sequoia_openpgp as openpgp;

fn extract_signing_keypair(cert_data: &[u8]) -> openpgp::crypto::KeyPair {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(cert_data).expect("signer cert should parse");
    cert.keys()
        .with_policy(&policy, None)
        .supported()
        .secret()
        .for_signing()
        .next()
        .expect("signing key should exist")
        .key()
        .clone()
        .into_keypair()
        .expect("keypair extraction should succeed")
}

fn sign_cleartext_multi(text: &[u8], signer_certs: &[&[u8]]) -> Vec<u8> {
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let first = extract_signing_keypair(signer_certs[0]);
    let mut signer = Signer::with_template(
        message,
        first,
        openpgp::packet::signature::SignatureBuilder::new(SignatureType::Text),
    )
    .expect("cleartext signer should initialize");
    for cert in signer_certs.iter().skip(1) {
        signer = signer
            .add_signer(extract_signing_keypair(cert))
            .expect("additional signer should be added");
    }
    let mut signer = signer
        .cleartext()
        .build()
        .expect("cleartext signer should build");
    signer
        .write_all(text)
        .expect("cleartext signer should accept plaintext");
    signer.finalize().expect("cleartext signer should finalize");
    sink
}

fn sign_detached_multi(data: &[u8], signer_certs: &[&[u8]]) -> Vec<u8> {
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Signature)
        .build()
        .expect("armorer should build");
    let first = extract_signing_keypair(signer_certs[0]);
    let mut signer = Signer::new(message, first).expect("detached signer should initialize");
    for cert in signer_certs.iter().skip(1) {
        signer = signer
            .add_signer(extract_signing_keypair(cert))
            .expect("additional signer should be added");
    }
    let mut signer = signer
        .detached()
        .build()
        .expect("detached signer should build");
    signer
        .write_all(data)
        .expect("detached signer should accept data");
    signer.finalize().expect("detached signer should finalize");
    sink
}

fn sign_detached_multi_binary(data: &[u8], signer_certs: &[&[u8]]) -> Vec<u8> {
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let first = extract_signing_keypair(signer_certs[0]);
    let mut signer = Signer::new(message, first).expect("detached signer should initialize");
    for cert in signer_certs.iter().skip(1) {
        signer = signer
            .add_signer(extract_signing_keypair(cert))
            .expect("additional signer should be added");
    }
    let mut signer = signer
        .detached()
        .build()
        .expect("detached signer should build");
    signer
        .write_all(data)
        .expect("detached signer should accept data");
    signer.finalize().expect("detached signer should finalize");
    sink
}

fn serialize_packet_pile(pile: &openpgp::PacketPile) -> Vec<u8> {
    let mut serialized = Vec::new();
    pile.serialize(&mut serialized)
        .expect("mutated pile should serialize");
    serialized
}

fn invalidate_second_signature(binary_signature: &[u8]) -> Vec<u8> {
    let mut pile =
        openpgp::PacketPile::from_bytes(binary_signature).expect("signature should parse cleanly");
    match pile.path_ref_mut(&[1]) {
        Some(openpgp::Packet::Signature(signature)) => {
            signature
                .hashed_area_mut()
                .remove_all(SubpacketTag::SignatureCreationTime);
        }
        other => panic!("expected second packet to be a signature, got {other:?}"),
    }

    serialize_packet_pile(&pile)
}

fn encrypt_multi_signed(
    plaintext: &[u8],
    recipient_cert_data: &[u8],
    signer_certs: &[&[u8]],
) -> Vec<u8> {
    let policy = StandardPolicy::new();
    let recipient_cert =
        openpgp::Cert::from_bytes(recipient_cert_data).expect("recipient cert should parse");
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let recipients = recipient_cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .for_transport_encryption();
    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .expect("encryptor should build");
    let first = extract_signing_keypair(signer_certs[0]);
    let mut signer = Signer::new(message, first).expect("message signer should initialize");
    for cert in signer_certs.iter().skip(1) {
        signer = signer
            .add_signer(extract_signing_keypair(cert))
            .expect("additional signer should be added");
    }
    let message = signer.build().expect("message signer should build");
    let mut literal = LiteralWriter::new(message)
        .build()
        .expect("literal writer should build");
    literal
        .write_all(plaintext)
        .expect("literal writer should accept plaintext");
    literal.finalize().expect("literal writer should finalize");
    sink
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("Tests")
        .join("Fixtures");
    fs::create_dir_all(&fixtures_dir)?;

    let signer_a = keys::generate_key_with_profile(
        "FFI Detailed Signer A".to_string(),
        Some("ffi-detailed-a@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )?;
    let signer_b = keys::generate_key_with_profile(
        "FFI Detailed Signer B".to_string(),
        Some("ffi-detailed-b@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )?;
    let recipient = keys::generate_key_with_profile(
        "FFI Detailed Recipient".to_string(),
        Some("ffi-detailed-recipient@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )?;
    let expired_signer = keys::generate_key_with_profile(
        "FFI Detailed Expired Signer".to_string(),
        Some("ffi-detailed-expired@example.com".to_string()),
        Some(1),
        KeyProfile::Universal,
    )?;
    let bad_signer = keys::generate_key_with_profile(
        "FFI Detailed Bad Signer".to_string(),
        Some("ffi-detailed-bad@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )?;
    let unknown_signer = keys::generate_key_with_profile(
        "FFI Detailed Unknown Signer".to_string(),
        Some("ffi-detailed-unknown@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )?;

    let cleartext = sign_cleartext_multi(
        b"FFI detailed multi-signer cleartext",
        &[&signer_a.cert_data, &signer_b.cert_data],
    );
    let detached_data = b"FFI detailed multi-signer detached".to_vec();
    let detached_multisig =
        sign_detached_multi(&detached_data, &[&signer_a.cert_data, &signer_b.cert_data]);
    let detached_repeated =
        sign_detached_multi(&detached_data, &[&signer_a.cert_data, &signer_a.cert_data]);
    let encrypted = encrypt_multi_signed(
        b"FFI detailed encrypted payload",
        &recipient.public_key_data,
        &[&signer_a.cert_data, &signer_b.cert_data],
    );
    let encrypted_repeated = encrypt_multi_signed(
        b"FFI detailed repeated encrypted payload",
        &recipient.public_key_data,
        &[&signer_a.cert_data, &signer_a.cert_data],
    );
    let mixedfold_data = b"FFI detailed verify mixed fold".to_vec();
    let expired_unknown_binary = sign_detached_multi_binary(
        &mixedfold_data,
        &[&expired_signer.cert_data, &unknown_signer.cert_data],
    );
    let expired_bad_binary = invalidate_second_signature(&sign_detached_multi_binary(
        &mixedfold_data,
        &[&bad_signer.cert_data, &expired_signer.cert_data],
    ));

    std::thread::sleep(Duration::from_secs(2));

    let expired_unknown = armor::encode_armor(&expired_unknown_binary, ArmorKind::Signature)?;
    let expired_bad = armor::encode_armor(&expired_bad_binary, ArmorKind::Signature)?;

    let expired_unknown_verify = verify::verify_detached_detailed(
        &mixedfold_data,
        &expired_unknown,
        &[expired_signer.public_key_data.clone()],
    )?;
    assert_eq!(expired_unknown_verify.legacy_status, SignatureStatus::Expired);
    assert_eq!(expired_unknown_verify.signatures.len(), 2);
    assert_eq!(
        expired_unknown_verify.signatures[0].status,
        DetailedSignatureStatus::UnknownSigner
    );
    assert_eq!(
        expired_unknown_verify.signatures[1].status,
        DetailedSignatureStatus::Expired
    );

    let expired_bad_verify = verify::verify_detached_detailed(
        &mixedfold_data,
        &expired_bad,
        &[
            expired_signer.public_key_data.clone(),
            bad_signer.public_key_data.clone(),
        ],
    )?;
    assert_eq!(expired_bad_verify.legacy_status, SignatureStatus::Expired);
    assert_eq!(expired_bad_verify.signatures.len(), 2);
    assert_eq!(
        expired_bad_verify.signatures[0].status,
        DetailedSignatureStatus::Expired
    );
    assert_eq!(
        expired_bad_verify.signatures[1].status,
        DetailedSignatureStatus::Bad
    );

    fs::write(
        fixtures_dir.join("ffi_detailed_signer_a.gpg"),
        signer_a.public_key_data,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_signer_b.gpg"),
        signer_b.public_key_data,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_recipient_secret.gpg"),
        recipient.cert_data,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_multisig_cleartext.asc"),
        cleartext,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_detached_data.txt"),
        detached_data,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_multisig_detached.sig"),
        detached_multisig,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_repeated_detached.sig"),
        detached_repeated,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_multisig_encrypted.gpg"),
        encrypted,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_repeated_encrypted.gpg"),
        encrypted_repeated,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_mixedfold_data.txt"),
        mixedfold_data,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_mixedfold_expired_signer.gpg"),
        expired_signer.public_key_data,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_mixedfold_bad_signer.gpg"),
        bad_signer.public_key_data,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_mixedfold_expired_unknown.sig"),
        expired_unknown,
    )?;
    fs::write(
        fixtures_dir.join("ffi_detailed_mixedfold_expired_bad.sig"),
        expired_bad,
    )?;

    Ok(())
}
