//! Post-quantum test key helpers (RFC 9980).

use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::serialize::{Serialize, SerializeInto};
use sequoia_openpgp as openpgp;

/// Generate a foreign RFC 9980 certificate the way another Sequoia-based
/// implementation (e.g. `sq`) would — deliberately NOT through the
/// engine's profile path, to simulate an imported contact certificate.
/// Returns (binary TSK, armored public cert).
#[allow(dead_code)]
pub fn generate_foreign_pq() -> (Vec<u8>, Vec<u8>) {
    let (cert, _rev) = CertBuilder::general_purpose(Some("Foreign PQ <pq@interop.example>"))
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        .set_profile(openpgp::Profile::RFC9580)
        .expect("set RFC 9580 profile")
        .generate()
        .expect("generate foreign PQ cert");
    let mut tsk = Vec::new();
    cert.as_tsk().serialize(&mut tsk).expect("serialize TSK");
    let pub_armored = cert.armored().to_vec().expect("armor public cert");
    (tsk, pub_armored)
}
