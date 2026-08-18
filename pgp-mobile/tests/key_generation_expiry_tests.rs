//! What every generation path writes into the certificate's Key Expiration Time
//! subpackets.
//!
//! These read the expirations back off the binding signatures rather than
//! trusting the value handed in, because the defect this guards against lived
//! entirely inside the wrapper: `Never` used to arrive as an absent
//! `Option<u64>` and each generation path substituted a validity of its own, so
//! a caller asking for a perpetual key got one that stopped working in two
//! years. Asserting at the call boundary would have seen nothing wrong.
//!
//! Coverage is every path that can mint a certificate: the five software
//! suites, both P-256 device-bound certificate versions, and both
//! composite-custody tiers. The device-bound paths run through the software
//! signing-provider doubles in `tests/common/`, so no Secure Enclave is needed.

mod common;

use std::time::Duration;

use common::composite::{SoftwareCompositeHighMaterial, SoftwareCompositeMaterial};
use common::secure_enclave::SoftwareP256Material;

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use pgp_mobile::keys::{self, KeySuite, KeyValidity, SecureEnclaveCertificateVersion};
use sequoia_openpgp as openpgp;

/// The validity period the certificate states for its primary key and for every
/// subkey, each relative to that key's own creation time — `None` where no Key
/// Expiration Time subpacket is present, which is what "never expires" is.
fn stated_validity_periods(cert_data: &[u8]) -> Vec<Option<Duration>> {
    let cert = openpgp::Cert::from_bytes(cert_data).expect("certificate should parse");
    let policy = StandardPolicy::new();
    let valid = cert
        .with_policy(&policy, None)
        .expect("certificate should be policy-valid");

    let period_since_creation = |creation, expiration: Option<std::time::SystemTime>| {
        expiration.map(|expiration| {
            expiration
                .duration_since(creation)
                .expect("expiration should follow creation")
        })
    };

    let mut periods = vec![period_since_creation(
        valid.primary_key().key().creation_time(),
        valid.primary_key().key_expiration_time(),
    )];
    for subkey in valid.keys().subkeys() {
        periods.push(period_since_creation(
            subkey.key().creation_time(),
            subkey.key_expiration_time(),
        ));
    }
    periods
}

/// Every key in the certificate carries exactly the validity the caller stated —
/// no key silently longer or shorter than another, and no key expiring at all
/// when `Never` was asked for.
fn assert_certificate_states(validity: KeyValidity, cert_data: &[u8], path: &str) {
    let expected = match validity {
        KeyValidity::Never => None,
        KeyValidity::ExpiresIn { seconds } => Some(Duration::from_secs(seconds)),
    };
    let periods = stated_validity_periods(cert_data);
    assert!(
        periods.len() >= 2,
        "{path}: expected a primary key and at least one subkey, got {} keys",
        periods.len()
    );
    for period in &periods {
        assert_eq!(
            *period, expected,
            "{path}: certificate states {periods:?}, caller asked for {validity:?}"
        );
    }
}

const SOFTWARE_SUITES: [KeySuite; 5] = [
    KeySuite::Ed25519LegacyCurve25519Legacy,
    KeySuite::Ed25519X25519,
    KeySuite::Ed448X448,
    KeySuite::MlDsa65Ed25519MlKem768X25519,
    KeySuite::MlDsa87Ed448MlKem1024X448,
];

const A_STATED_TERM: KeyValidity = KeyValidity::ExpiresIn {
    seconds: 3 * 365 * 24 * 60 * 60,
};

#[test]
fn software_suites_carry_back_the_stated_validity() {
    for suite in SOFTWARE_SUITES {
        for validity in [KeyValidity::Never, A_STATED_TERM] {
            let generated = keys::generate_key_with_suite(
                "Validity Probe".to_string(),
                Some("validity@example.test".to_string()),
                validity,
                suite,
            )
            .expect("software key should generate");
            assert_certificate_states(
                validity,
                &generated.public_key_data,
                &format!("software suite {suite:?}"),
            );
        }
    }
}

#[test]
fn p256_device_bound_certificates_carry_back_the_stated_validity() {
    for version in [
        SecureEnclaveCertificateVersion::V4,
        SecureEnclaveCertificateVersion::V6,
    ] {
        for validity in [KeyValidity::Never, A_STATED_TERM] {
            let material = SoftwareP256Material::generate(version, validity)
                .expect("device-bound certificate should generate");
            assert_certificate_states(
                validity,
                &material.public_key_data,
                &format!("P-256 device-bound {version:?}"),
            );
        }
    }
}

#[test]
fn composite_custody_certificates_carry_back_the_stated_validity() {
    for validity in [KeyValidity::Never, A_STATED_TERM] {
        let material = SoftwareCompositeMaterial::generate(validity)
            .expect("composite custody certificate should generate");
        assert_certificate_states(validity, &material.public_key_data, "composite custody");
    }
}

#[test]
fn composite_custody_high_certificates_carry_back_the_stated_validity() {
    for validity in [KeyValidity::Never, A_STATED_TERM] {
        let material = SoftwareCompositeHighMaterial::generate(validity)
            .expect("composite custody high certificate should generate");
        assert_certificate_states(validity, &material.public_key_data, "composite custody high");
    }
}
