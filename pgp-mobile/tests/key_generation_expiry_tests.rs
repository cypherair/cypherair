//! Every generation path states exactly the validity its caller asked for,
//! `Never` included.
//!
//! Sequoia's contract is that a validity period of `None` removes the Key
//! Expiration Time subpacket, so a certificate built from `KeyValidity::Never`
//! never expires. These tests read the expirations off the binding signatures
//! themselves — the primary key's and every subkey's — because a validity the
//! wrapper substitutes for its caller's surfaces there and nowhere else.

mod common;

use std::time::Duration;

use common::composite::{SoftwareCompositeHighMaterial, SoftwareCompositeMaterial};
use common::secure_enclave::SoftwareP256Material;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use pgp_mobile::keys::{self, KeySuite, KeyValidity, SecureEnclaveCertificateVersion};
use sequoia_openpgp as openpgp;

const STATED_TERM_SECONDS: u64 = 365 * 24 * 60 * 60;

/// Every key expiration the certificate states: the primary key's, then one per
/// subkey, as their binding signatures carry them.
fn stated_validity_periods(public_key_data: &[u8]) -> Vec<Option<Duration>> {
    let cert = openpgp::Cert::from_bytes(public_key_data).expect("certificate parses");
    let policy = StandardPolicy::new();
    let valid_cert = cert
        .with_policy(&policy, None)
        .expect("certificate is policy-valid");

    std::iter::once(
        valid_cert
            .primary_key()
            .binding_signature()
            .key_validity_period(),
    )
    .chain(
        valid_cert
            .keys()
            .subkeys()
            .map(|subkey| subkey.binding_signature().key_validity_period()),
    )
    .collect()
}

fn assert_states_validity(label: &str, public_key_data: &[u8], expected: Option<Duration>) {
    let periods = stated_validity_periods(public_key_data);
    assert!(
        periods.len() > 1,
        "{label}: expected a primary key and at least one subkey to read"
    );
    for period in &periods {
        assert_eq!(
            *period, expected,
            "{label} must state {expected:?} on every binding, got {periods:?}"
        );
    }
}

/// Generate twice through `generate` — once declining an expiry, once stating a
/// term — and require the certificate to carry back what was asked for.
fn assert_generation_honours_its_caller(label: &str, generate: impl Fn(KeyValidity) -> Vec<u8>) {
    assert_states_validity(label, &generate(KeyValidity::Never), None);
    assert_states_validity(
        label,
        &generate(KeyValidity::ExpiresIn {
            seconds: STATED_TERM_SECONDS,
        }),
        Some(Duration::from_secs(STATED_TERM_SECONDS)),
    );
}

#[test]
fn software_generation_honours_its_stated_validity() {
    for suite in [
        KeySuite::Ed25519LegacyCurve25519Legacy,
        KeySuite::Ed25519X25519,
        KeySuite::Ed448X448,
        KeySuite::MlDsa65Ed25519MlKem768X25519,
        KeySuite::MlDsa87Ed448MlKem1024X448,
    ] {
        assert_generation_honours_its_caller(&format!("{suite:?}"), |validity| {
            keys::generate_key_with_suite("Alice".to_string(), None, validity, suite)
                .expect("key generation succeeds")
                .public_key_data
        });
    }
}

#[test]
fn device_bound_p256_generation_honours_its_stated_validity() {
    for version in [
        SecureEnclaveCertificateVersion::V4,
        SecureEnclaveCertificateVersion::V6,
    ] {
        assert_generation_honours_its_caller(
            &format!("Device-Bound P-256 {version:?}"),
            |validity| {
                SoftwareP256Material::generate(version, validity)
                    .expect("device-bound material builds")
                    .public_key_data
            },
        );
    }
}

#[test]
fn device_bound_composite_generation_honours_its_stated_validity() {
    assert_generation_honours_its_caller("Device-Bound Post-Quantum", |validity| {
        SoftwareCompositeMaterial::generate(validity)
            .expect("composite material builds")
            .public_key_data
    });
}

#[test]
fn device_bound_composite_high_generation_honours_its_stated_validity() {
    assert_generation_honours_its_caller("Device-Bound Post-Quantum · High", |validity| {
        SoftwareCompositeHighMaterial::generate(validity)
            .expect("composite high material builds")
            .public_key_data
    });
}
