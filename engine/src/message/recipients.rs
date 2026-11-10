//! Recipients and the outgoing format. `encrypt` and `outgoing_format` both
//! resolve recipients here, so that the preview cannot disagree with the
//! message.

use std::collections::HashSet;
use std::time::SystemTime;

use openpgp::cert::prelude::*;
use openpgp::packet::key::PublicParts;
use openpgp::types::RevocationStatus;
use sequoia_openpgp as openpgp;

use crate::error::contained;
use crate::{EngineError, OutgoingFormat, POLICY, key};

/// The recipients of one message, checked.
pub(crate) struct Recipients {
    /// One per distinct certificate, in the caller's order.
    pub(crate) certs: Vec<Cert>,
    /// Positions of the recipients without the modern container.
    held_back_by: Vec<u32>,
}

impl Recipients {
    /// Sequoia writes SEIPDv2 exactly when every recipient advertises it in its
    /// Features, which it reads from the same `ValidCert` as here.
    pub(crate) fn modern(&self) -> bool {
        self.held_back_by.is_empty()
    }
}

/// Check every recipient. One that does not parse, is not valid under the
/// policy, is expired or revoked, or has no usable encryption key is
/// `RecipientUnusable` with its position. An empty list is `Internal`.
pub(crate) fn resolve(recipients: &[Vec<u8>], now: SystemTime) -> Result<Recipients, EngineError> {
    if recipients.is_empty() {
        return Err(EngineError::Internal);
    }
    let mut certs = Vec::new();
    let mut held_back_by = Vec::new();
    let mut seen = HashSet::new();
    for (position, bytes) in (0u32..).zip(recipients) {
        let unusable = EngineError::RecipientUnusable { position };
        let cert = key::certificate(bytes).map_err(|_| unusable)?;
        let valid = cert.with_policy(&POLICY, now).map_err(|_| unusable)?;
        if !accepts(&valid) {
            return Err(unusable);
        }
        let modern = valid
            .features()
            .is_some_and(|features| features.supports_seipdv2());
        if !modern {
            held_back_by.push(position);
        }
        if seen.insert(cert.fingerprint()) {
            certs.push(cert);
        }
    }
    Ok(Recipients {
        certs,
        held_back_by,
    })
}

/// Whether `encrypt` takes this certificate as a recipient.
pub(crate) fn accepts(valid: &ValidCert) -> bool {
    !matches!(valid.revocation_status(), RevocationStatus::Revoked(_))
        && valid.alive().is_ok()
        && encryption_keys(valid).next().is_some()
}

/// The keys a message to this certificate is encrypted to.
pub(crate) fn encryption_keys<'a>(
    valid: &'a ValidCert<'a>,
) -> impl Iterator<Item = ValidErasedKeyAmalgamation<'a, PublicParts>> + 'a {
    valid
        .keys()
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
}

/// The container a message to these recipients will use, and which recipients
/// hold it back. Refuses what `encrypt` refuses.
#[uniffi::export]
pub fn outgoing_format(recipients: Vec<Vec<u8>>) -> Result<OutgoingFormat, EngineError> {
    contained(|| {
        let resolved = resolve(&recipients, SystemTime::now())?;
        Ok(OutgoingFormat {
            modern: resolved.modern(),
            held_back_by: resolved.held_back_by,
        })
    })
}
