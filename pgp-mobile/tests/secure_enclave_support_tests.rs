//! Smoke tests for the shared software-P256 Secure Enclave custody support
//! (`tests/common/secure_enclave.rs`). These exercise `SoftwareP256Material`
//! without GnuPG so the gpg-importable-TSK graft is verified independently before
//! the interop lanes depend on it.

mod common;

use common::secure_enclave::SoftwareP256Material;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use pgp_mobile::keys::SecureEnclaveCertificateVersion;
use sequoia_openpgp as openpgp;

#[test]
fn software_material_exports_gpg_importable_tsk_matching_public_cert() {
    for version in [
        SecureEnclaveCertificateVersion::V4,
        SecureEnclaveCertificateVersion::V6,
    ] {
        let material =
            SoftwareP256Material::generate(version, Some(3600)).expect("material should build");

        // The SE-shaped public certificate is public-only.
        let public = openpgp::Cert::from_bytes(&material.public_key_data)
            .expect("public certificate should parse");
        assert!(
            !public.is_tsk(),
            "public_key_data must not carry secret key material"
        );

        // The exported TSK is the SAME certificate (identical fingerprints and
        // self-signatures) now carrying secret material on both keys, so GnuPG
        // imports it as the secret side of the public certificate.
        let tsk_bytes = material
            .export_gpg_importable_tsk()
            .expect("TSK export should succeed");
        let tsk = openpgp::Cert::from_bytes(&tsk_bytes).expect("TSK should parse");

        assert!(tsk.is_tsk(), "exported TSK must carry secret key material");
        assert_eq!(
            tsk.fingerprint(),
            public.fingerprint(),
            "TSK primary fingerprint must match the SE-shaped public certificate"
        );
        assert_eq!(
            tsk.keys().secret().count(),
            2,
            "primary signing key and ECDH subkey must both carry secret material"
        );
        assert!(
            tsk.with_policy(&StandardPolicy::new(), None).is_ok(),
            "grafting secret material must preserve a policy-valid certificate"
        );

        // The fingerprints the generator recorded match the certificate's keys.
        assert_eq!(
            material.signing_key_fingerprint,
            public.fingerprint().to_hex().to_lowercase()
        );
        let subkey_fingerprint = public
            .keys()
            .subkeys()
            .next()
            .expect("public certificate should have a subkey")
            .key()
            .fingerprint()
            .to_hex()
            .to_lowercase();
        assert_eq!(
            material.key_agreement_subkey_fingerprint,
            subkey_fingerprint
        );
    }
}
