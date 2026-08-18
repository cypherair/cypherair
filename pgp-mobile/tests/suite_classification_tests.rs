//! Refusable suite classification: a certificate is placed only when its
//! primary-key algorithm, curve, and certificate version agree with exactly
//! one suite, and everything else is reported as unplaceable rather than
//! approximated. Positive classifications per suite live beside their
//! lifecycle tests; this file owns the refusals.

use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeySuite};
use sequoia_openpgp as openpgp;

use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::serialize::SerializeInto;

fn public_cert(cipher_suite: CipherSuite) -> Vec<u8> {
    let (cert, _rev) = CertBuilder::general_purpose(Some("Probe <probe@example.test>"))
        .set_cipher_suite(cipher_suite)
        .generate()
        .expect("cert should generate");
    cert.to_vec().expect("cert should serialize")
}

/// An algorithm outside the vocabulary (RSA) is unplaceable — the old
/// classifier silently labelled it a classical suite.
#[test]
fn test_rsa_certificate_is_unplaceable() {
    let cert = public_cert(CipherSuite::RSA2k);
    assert_eq!(keys::detect_suite(&cert).expect("parse"), None);

    let info = keys::parse_key_info(&cert).expect("parse_key_info");
    assert_eq!(info.suite, None, "refusal is a report, not a parse failure");
    assert_eq!(info.key_version, 4, "the rest of the parse stands");
}

/// A recognised algorithm id on a curve the suite vocabulary does not pin
/// (ECDSA over P-384) is unplaceable, never approximated to the P-256 suite.
#[test]
fn test_ecdsa_p384_certificate_is_unplaceable() {
    let cert = public_cert(CipherSuite::P384);
    assert_eq!(keys::detect_suite(&cert).expect("parse"), None);
}

/// Contact import refuses an unplaceable certificate with the algorithm's
/// name, instead of storing it under a suite it does not have.
#[test]
fn test_validate_public_certificate_refuses_unplaceable() {
    let cert = public_cert(CipherSuite::RSA2k);
    match keys::validate_public_certificate(&cert) {
        Err(PgpError::UnsupportedAlgorithm { algo }) => {
            assert!(algo.contains("RSA"), "algo should name RSA, got {algo:?}");
        }
        other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
    }
}

/// The P-256 suites are Secure Enclave custody certificate shapes; software
/// generation refuses them.
#[test]
fn test_software_generation_refuses_p256_suites() {
    for suite in [
        KeySuite::EcdsaNistP256EcdhNistP256V4,
        KeySuite::EcdsaNistP256EcdhNistP256,
    ] {
        match keys::generate_key_with_suite("P256 Probe".to_string(), None, None, suite) {
            Err(PgpError::KeyGenerationFailed { .. }) => {}
            Err(other) => panic!("expected KeyGenerationFailed for {suite:?}, got {other:?}"),
            Ok(_) => panic!("expected KeyGenerationFailed for {suite:?}, got a generated key"),
        }
    }
}
