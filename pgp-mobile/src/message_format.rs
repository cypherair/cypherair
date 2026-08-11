//! Where the outgoing message format is decided.
//!
//! Sequoia picks the symmetric container when the `Encryptor` is built: AEAD
//! exactly when the recipient list is non-empty and every recipient certificate
//! advertises SEIPDv2 in its Features subpacket. The key version is never
//! consulted — see `Encryptor::build` in sequoia-openpgp's
//! `serialize/stream.rs`, reading `Recipient::features`, which is
//! `ValidCert::features().unwrap_or(Features::empty())`.
//!
//! `crate::encrypt` passes no format, so a produced message simply *is* whatever
//! Sequoia chose. Anything that must state the format before the message exists
//! — a pre-send preview, say — asks here, with the same arguments it would hand
//! `encrypt`, and gets an answer built from the same recipient resolution and
//! the same predicate. Restating the rule anywhere else is how a preview comes
//! to contradict the message it previews.
//!
//! Nothing about a certificate is cached or carried over from import: an answer
//! describes the certificates as they are when it is asked, which is the only
//! way it can describe the message the next `encrypt` call would produce.

use openpgp::cert::prelude::*;
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;

use crate::encrypt::collect_recipients;
use crate::error::PgpError;

/// The symmetrically-encrypted container an outgoing public-key message carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OutgoingMessageFormat {
    /// RFC 4880 SEIPDv1 — integrity by MDC, no AEAD.
    SeipdV1,
    /// RFC 9580 SEIPDv2 — AEAD (OCB).
    SeipdV2,
}

/// What the format rule answers for one outgoing message.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutgoingFormatDecision {
    /// The container this recipient set produces.
    pub format: OutgoingMessageFormat,
    /// The format is SEIPDv1 while a recipient advertises SEIPDv2: AEAD is being
    /// given up, not merely unavailable. False when no recipient could have
    /// received AEAD in the first place — SEIPDv1 costs those nothing.
    pub withholds_aead: bool,
    /// Fingerprints, lowercase hex, of the recipients that hold the message at
    /// SEIPDv1 while another recipient advertises SEIPDv2: dropping all of them
    /// restores AEAD. Non-empty exactly when `withholds_aead` is set, and
    /// includes the encrypt-to-self copy when that is what costs the message its
    /// AEAD.
    pub seipd_v1_forcing_fingerprints: Vec<String>,
}

/// The container format an encrypt of these arguments will produce, and which
/// recipients decide it.
///
/// Takes what `crate::encrypt::encrypt` takes, minus the plaintext and the
/// signing key — signing adds no recipient and does not move the format — and
/// resolves recipients through that same `collect_recipients`, so the answer
/// describes the message that call would produce rather than a neighbouring one.
/// A selection `encrypt` would refuse (no recipients, a revoked certificate, one
/// with no usable encryption subkey) is refused here with the same error: there
/// is no message to describe.
pub fn decide_outgoing_message_format(
    recipient_certs: &[Vec<u8>],
    encrypt_to_self: Option<&[u8]>,
) -> Result<OutgoingFormatDecision, PgpError> {
    let policy = StandardPolicy::new();
    let certs = collect_recipients(recipient_certs, encrypt_to_self, &policy)?;

    // Sequoia folds over one recipient per encryption-capable subkey, each
    // carrying its certificate's features, and `collect_recipients` has already
    // guaranteed every certificate contributes at least one. Folding per
    // certificate is therefore the same fold over the same values.
    let mut forcing_fingerprints = Vec::new();
    let mut any_advertises_aead = false;
    for cert in &certs {
        if advertises_seipd_v2(cert, &policy) {
            any_advertises_aead = true;
        } else {
            forcing_fingerprints.push(cert.fingerprint().to_hex().to_lowercase());
        }
    }

    let withholds_aead = !forcing_fingerprints.is_empty() && any_advertises_aead;
    Ok(OutgoingFormatDecision {
        format: if forcing_fingerprints.is_empty() {
            OutgoingMessageFormat::SeipdV2
        } else {
            OutgoingMessageFormat::SeipdV1
        },
        withholds_aead,
        // A set no certificate could have had AEAD on flags nobody: SEIPDv1 is
        // what those keys support, and no other recipient is paying for them.
        seipd_v1_forcing_fingerprints: if withholds_aead {
            forcing_fingerprints
        } else {
            Vec::new()
        },
    })
}

/// The SEIPDv2 capability the encryptor will read off this certificate, at the
/// same instant and under the same policy `collect_recipients` just used.
fn advertises_seipd_v2(cert: &openpgp::Cert, policy: &StandardPolicy) -> bool {
    cert.with_policy(policy, None)
        .ok()
        .and_then(|valid_cert| valid_cert.features())
        .is_some_and(|features| features.supports_seipdv2())
}
