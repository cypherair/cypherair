//! A message's header: its session-key packets and its container, read by the
//! bounded header walk before anything is decrypted.

use openpgp::Packet;
use openpgp::packet::{PKESK, SEIP};
use openpgp::policy::Policy as _;
use openpgp::types::{AEADAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp as openpgp;

use crate::bounded_walk::{self, PrefixEnd};
use crate::{EngineError, POLICY};

pub(crate) struct Header {
    /// The public-key algorithm of each session-key packet for a key, `None`
    /// for one of a version Sequoia does not read.
    recipients: Vec<Option<PublicKeyAlgorithm>>,
    /// Session-key packets for a password.
    passwords: usize,
    container: Container,
}

enum Container {
    /// SEIPDv1: integrity by MDC. Its cipher is inside the session-key packet.
    V1,
    /// SEIPDv2: AEAD.
    V2 {
        cipher: SymmetricAlgorithm,
        aead: AEADAlgorithm,
    },
}

/// Read an encrypted message's header.
///
/// A message cut off before its container is `Malformed`; OpenPGP that is not
/// an encrypted message is `WrongKind`.
pub(crate) fn read(message: &[u8]) -> Result<Header, EngineError> {
    let mut recipients = Vec::new();
    let mut passwords = 0;
    let mut container = None;
    let end = bounded_walk::walk_message_prefix(message, |packet| match packet {
        Packet::PKESK(PKESK::V3(pkesk)) => recipients.push(Some(pkesk.pk_algo())),
        Packet::PKESK(PKESK::V6(pkesk)) => recipients.push(Some(pkesk.pk_algo())),
        Packet::SKESK(_) => passwords += 1,
        Packet::SEIP(SEIP::V1(_)) => container = Some(Container::V1),
        Packet::SEIP(SEIP::V2(seip)) => {
            container = Some(Container::V2 {
                cipher: seip.symmetric_algo(),
                aead: seip.aead(),
            })
        }
        _ => recipients.push(None),
    })?;
    let seen_any_key_packet = !recipients.is_empty() || passwords > 0;
    match (end, container) {
        (PrefixEnd::Container, Some(container)) => Ok(Header {
            recipients,
            passwords,
            container,
        }),
        (PrefixEnd::Other, _) if !seen_any_key_packet => Err(EngineError::WrongKind),
        _ => Err(EngineError::Malformed),
    }
}

impl Header {
    /// Whether the engine can open this container: `Unsupported` for a cipher
    /// or AEAD mode that the backend lacks or the policy refuses. The cipher
    /// of a SEIPDv1 container is checked once a session key reveals it.
    pub(crate) fn check_container(&self) -> Result<(), EngineError> {
        if let Container::V2 { cipher, aead } = self.container
            && (!cipher.is_supported()
                || !aead.is_supported()
                || POLICY.symmetric_algorithm(cipher).is_err()
                || POLICY.aead_algorithm(aead).is_err())
        {
            return Err(EngineError::Unsupported);
        }
        Ok(())
    }

    /// Every session-key packet is for a post-quantum KEM, and the container
    /// is AES-256: no recipient's copy of the session key, and not the cipher,
    /// falls to a quantum computer.
    pub(crate) fn quantum_safe(&self) -> bool {
        let post_quantum = |algorithm: &Option<PublicKeyAlgorithm>| {
            matches!(
                algorithm,
                Some(PublicKeyAlgorithm::MLKEM768_X25519 | PublicKeyAlgorithm::MLKEM1024_X448)
            )
        };
        !self.recipients.is_empty()
            && self.recipients.iter().all(post_quantum)
            && self.passwords == 0
            && matches!(
                self.container,
                Container::V2 {
                    cipher: SymmetricAlgorithm::AES256,
                    ..
                }
            )
    }
}
