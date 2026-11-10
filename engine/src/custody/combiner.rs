//! The RFC 9980 KEM combiner and the session-key unwrap of a composite
//! recipient packet, for device custody, where the two key shares come from
//! two places.
//!
//! The combiner is a byte-exact port of `multi_key_combine` in sequoia-openpgp
//! 2.4.2 (`src/crypto/asymmetric.rs`), which is private there. A known-answer
//! test pins it to the vectors of RFC 9980, appendix A.

use openpgp::crypto::{SessionKey, ecdh};
use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp as openpgp;

/// The length of an ML-KEM key share, for every FIPS 203 parameter set.
pub(crate) const MLKEM_KEY_SHARE_LENGTH: usize = 32;

/// RFC 9980 section 4.2.1:
///
/// ```text
/// KEK = SHA3-256(mlkemKeyShare || ecdhKeyShare || ecdhCipherText ||
///                ecdhPublicKey || algId || domSep || len(domSep))
/// ```
pub(crate) fn combine(
    mlkem_key_share: &[u8],
    ecdh_key_share: &[u8],
    ecdh_ciphertext: &[u8],
    ecdh_public_key: &[u8],
    algorithm: PublicKeyAlgorithm,
) -> openpgp::Result<SessionKey> {
    let mut hash = HashAlgorithm::SHA3_256.context()?.for_digest();
    hash.update(mlkem_key_share);
    hash.update(ecdh_key_share);
    hash.update(ecdh_ciphertext);
    hash.update(ecdh_public_key);
    hash.update(&[algorithm.into()]);
    hash.update(b"OpenPGPCompositeKDFv1\x15");
    let mut kek = SessionKey::from(vec![0; 32]);
    hash.digest(&mut kek)?;
    Ok(kek)
}

/// Unwrap the session key with the combined KEK. RFC 9980 fixes the key wrap
/// at AES-256, whatever the message's cipher.
pub(crate) fn unwrap_session_key(kek: &SessionKey, wrapped: &[u8]) -> openpgp::Result<SessionKey> {
    Ok(ecdh::aes_key_unwrap(SymmetricAlgorithm::AES256, kek.as_protected(), wrapped)?.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9980, appendix A.3.3 (ML-KEM-768+X25519) and A.4.3
    /// (ML-KEM-1024+X448): the key shares, KEK and session key the RFC prints;
    /// the ECDH ciphertext and the wrapped key from the message's recipient
    /// packet, and the ECDH public key from the subkey of the certificate in
    /// A.3.2 and A.4.2.
    #[test]
    fn e16_combiner_gives_the_answer_of_the_rfc_vectors() {
        let vectors = [
            (
                PublicKeyAlgorithm::MLKEM768_X25519,
                "0987fe72ad5ea58e73344f9a2a543f4131d9fdb7cf07474f501430a20f705b4d",
                "88f3e9a8de1917127b4b758f6e83bd4ce00faaae01bd8b6e412a43a710b26012",
                "bbc0e8a3ee3a57ac02d60f621bbb8430d5bd38cee4f93c843dd889ad32e95600",
                "8d197729ba24950ba78dfa3eacfcbb25fda4f745cb58615ac3934659c143ea5d",
                "0fd45f800114a4bb783c475261cfa0139ca4ef076dc1efe81f0921d2e4e094359c52429b12991f4a",
                "a4904982f7caa9c9de690afd772d8bfe027a1ad6a5bbda00db68963fe303ae8e",
                "adee68618b302d4bfd7ae3d432bc63a1c1ad7f5fd6e7fd7bdedbb0d0b14a5c9a",
            ),
            (
                PublicKeyAlgorithm::MLKEM1024_X448,
                "f18f161e617b8ce5968f109aadea1e7e1511d10165768d36127ba913c00637d2",
                "732860c8114ae84a964664b1f607785d11bc7d24d5324510adad89bd52db7ee0\
                 df9982ad0d1669bdd05556330c86f2dae9e2edea42e05bc5",
                "fb52fcd81db4cd5840a0ced2953d05c36613a34d6e21adcf90388c5d0c841bc8\
                 cc732ddda9a37168f04bd36c6a3bbfc85ed2fa99151550cf",
                "b1fe20c8bf842e52f97eff0971e1e2df8eb955272e901e06619f7f272de6027b\
                 e216b30019b5180d375e1aa6a0ac4cf8a8a72af6c27fc569",
                "f692baf9a5b0936fa707916fe8f9755b9b23f0b3c5ea0338bd54094df57ea545662ae8657eee94cb",
                "ef1e32906f67d39bc800d90cabb0033c77ca6dce8ffca3e96d9c7348e2e8c16e",
                "0588ce40b038aac353d1cf8c67a674b412985105794821013ef154f786c4d89d",
            ),
        ];
        for (algorithm, mlkem, ecdh, ciphertext, public, wrapped, kek, session_key) in vectors {
            let combined = combine(
                &hex(mlkem),
                &hex(ecdh),
                &hex(ciphertext),
                &hex(public),
                algorithm,
            )
            .unwrap();
            assert_eq!(&combined[..], &hex(kek)[..], "{algorithm:?}");
            let unwrapped = unwrap_session_key(&combined, &hex(wrapped)).unwrap();
            assert_eq!(&unwrapped[..], &hex(session_key)[..], "{algorithm:?}");
        }
    }
}
