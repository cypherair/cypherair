//! The verdict on a message's signatures.
//!
//! Sequoia reports each signature as good or as one of several errors. Where
//! it rejected the signer's key before checking the signature, the engine
//! checks the signature itself, so that a bad signature is never reported as
//! something milder; and it asks the signer's key, not an error message,
//! whether the key is revoked or expired.

use openpgp::cert::prelude::*;
use openpgp::packet::Signature as Sig;
use openpgp::parse::stream::{
    MessageLayer, MessageStructure, VerificationError, VerificationResult,
};
use openpgp::policy::{HashAlgoSecurity, Policy as _};
use openpgp::types::RevocationStatus;
use sequoia_openpgp as openpgp;

use crate::{POLICY, Signature, Verdict};

/// The summary of every signature in the message: `Verified`, naming the
/// signer, if any signature verifies; else the first verdict that applies of
/// `Invalid`, `SignerRevoked`, `SignerExpired`, `UnknownSigner`,
/// `Unverifiable`; `NotSigned` when there is none.
pub(crate) fn grade(structure: MessageStructure, verifiers: &[Option<Cert>]) -> Signature {
    let graded: Vec<Signature> = structure
        .into_iter()
        .filter_map(|layer| match layer {
            MessageLayer::SignatureGroup { results } => Some(results),
            _ => None,
        })
        .flatten()
        .map(|result| grade_one(&result, verifiers))
        .collect();

    const PRECEDENCE: [Verdict; 6] = [
        Verdict::Verified,
        Verdict::Invalid,
        Verdict::SignerRevoked,
        Verdict::SignerExpired,
        Verdict::UnknownSigner,
        Verdict::Unverifiable,
    ];
    PRECEDENCE
        .iter()
        .find_map(|verdict| {
            graded
                .iter()
                .find(|signature| signature.verdict == *verdict)
        })
        .copied()
        .unwrap_or(Signature {
            verdict: Verdict::NotSigned,
            signer: None,
        })
}

fn grade_one(result: &VerificationResult, verifiers: &[Option<Cert>]) -> Signature {
    let (verdict, signer) = match result {
        Ok(good) => (Verdict::Verified, Some(good.ka.cert())),
        Err(VerificationError::MissingKey { .. }) => (Verdict::UnknownSigner, None),
        Err(VerificationError::BadSignature { sig, ka, .. }) => {
            let verdict = if checkable(sig) {
                Verdict::Invalid
            } else {
                Verdict::Unverifiable
            };
            (verdict, Some(ka.cert()))
        }
        Err(VerificationError::BadKey { sig, ka, .. }) => {
            let revoked = matches!(
                ka.valid_cert().revocation_status(),
                RevocationStatus::Revoked(_)
            ) || matches!(ka.revocation_status(), RevocationStatus::Revoked(_));
            let expired = ka.valid_cert().alive().is_err() || ka.alive().is_err();
            let verdict = if checkable(sig) && sig.verify_document(ka.key()).is_err() {
                Verdict::Invalid
            } else if revoked {
                Verdict::SignerRevoked
            } else if expired {
                Verdict::SignerExpired
            } else {
                // A key that is not allowed to sign.
                Verdict::Invalid
            };
            (verdict, Some(ka.cert()))
        }
        Err(VerificationError::UnboundKey { sig, cert, .. }) => {
            // The key was not bound to the certificate when the signature was
            // made. That says nothing about the signature unless it is bad.
            let bad = checkable(sig)
                && cert
                    .keys()
                    .key_handles(sig.get_issuers())
                    .all(|key| sig.verify_document(key.key()).is_err());
            let verdict = if bad {
                Verdict::Invalid
            } else {
                Verdict::Unverifiable
            };
            (verdict, Some(*cert))
        }
        Err(_) => (Verdict::Unverifiable, None),
    };
    Signature {
        verdict,
        signer: signer.and_then(|cert| position(cert, verifiers)),
    }
}

/// Whether the engine can check this signature at all: the backend supports
/// its hash and the policy accepts it.
fn checkable(sig: &Sig) -> bool {
    sig.hash_algo().is_supported()
        && POLICY
            .signature(sig, HashAlgoSecurity::CollisionResistance)
            .is_ok()
}

fn position(cert: &Cert, verifiers: &[Option<Cert>]) -> Option<u32> {
    let fingerprint = cert.fingerprint();
    (0u32..)
        .zip(verifiers)
        .find(|(_, verifier)| {
            verifier
                .as_ref()
                .is_some_and(|verifier| verifier.fingerprint() == fingerprint)
        })
        .map(|(position, _)| position)
}
