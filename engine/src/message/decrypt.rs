//! Decrypting text with a private key, and grading its signatures.
//!
//! Which error a failed decryption gives is decided by where it failed; see
//! `error::failed_decryption`. Plaintext is returned only after the whole
//! message was read and authenticated.

use std::io::Read;
use std::rc::Rc;
use std::sync::Arc;
use std::time::SystemTime;

use openpgp::crypto::SessionKey;
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::Parse as _;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::policy::Policy as _;
use openpgp::types::SymmetricAlgorithm;
use openpgp::{Cert, KeyHandle};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use super::{header, verdict};
use crate::bounded_walk::{self, BoundedHelper};
use crate::error::{self, DecryptionFailure, DecryptionProgress, contained};
use crate::key::{self, PrivateKey};
use crate::{Decrypted, EngineError, POLICY, Signature, Verdict};

/// The most plaintext a message decrypted into memory may have.
const MAX_PLAINTEXT_BYTES: usize = 256 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Decrypt a message with `key`, and grade its signatures against `verifiers`.
///
/// Expiry and revocation of `key` do not matter, so that old messages stay
/// readable. A verifier that does not parse vouches for nothing: a signature by
/// it is graded as by an unknown signer.
#[uniffi::export]
pub fn decrypt(
    message: Vec<u8>,
    key: Arc<PrivateKey>,
    verifiers: Vec<Vec<u8>>,
) -> Result<Decrypted, EngineError> {
    contained(|| {
        let now = SystemTime::now();
        let header = header::read(&message)?;
        header.check_container()?;
        let verifiers: Vec<Option<Cert>> = verifiers
            .iter()
            .map(|verifier| key::certificate(verifier).ok())
            .collect();

        let progress = Rc::new(DecryptionProgress::new(header.old_container()));
        let helper = Helper {
            key: &key,
            verifiers: &verifiers,
            now,
            progress: Rc::clone(&progress),
            signature: None,
        };
        let failed = |error: openpgp::anyhow::Error| {
            error::failed_decryption(DecryptionFailure::Sequoia(&error), &progress)
        };

        let mut decryptor = DecryptorBuilder::from_bytes(&message)
            .map_err(|_| EngineError::Malformed)?
            .buffer_size(bounded_walk::SETUP_BUFFER_BYTES)
            // No time: Sequoia then reads the clock itself and allows a
            // signature dated up to 30 minutes ahead. Given a time, it allows
            // none, and a sender's clock a second fast would grade as forged.
            .with_policy(
                &POLICY,
                None,
                BoundedHelper::new(helper, message.len() as u64),
            )
            .map_err(failed)?;

        let mut plaintext = Zeroizing::new(Vec::new());
        let mut chunk = Zeroizing::new(vec![0u8; READ_CHUNK_BYTES]);
        loop {
            let read = decryptor
                .read(&mut chunk)
                .map_err(|error| failed(error.into()))?;
            if read == 0 {
                break;
            }
            if read > MAX_PLAINTEXT_BYTES - plaintext.len() {
                return Err(error::failed_decryption(
                    DecryptionFailure::Ceiling,
                    &progress,
                ));
            }
            append_erasing(&mut plaintext, &chunk[..read]);
        }

        let helper = decryptor.into_helper().into_inner();
        Ok(Decrypted {
            plaintext: std::mem::take(&mut *plaintext),
            signature: helper.signature.unwrap_or(Signature {
                verdict: Verdict::NotSigned,
                signer: None,
            }),
            quantum_safe: header.quantum_safe(),
        })
    })
}

/// Append to a buffer of secret bytes without leaving a copy behind: where
/// `Vec` would reallocate and free the old allocation as it is, the bytes move
/// into a larger buffer and the old one is erased as it drops.
fn append_erasing(buffer: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    let needed = buffer.len() + bytes.len();
    if needed > buffer.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(2 * buffer.capacity())));
        grown.extend_from_slice(buffer);
        *buffer = grown;
    }
    buffer.extend_from_slice(bytes);
}

struct Helper<'a> {
    key: &'a PrivateKey,
    verifiers: &'a [Option<Cert>],
    now: SystemTime,
    progress: Rc<DecryptionProgress>,
    signature: Option<Signature>,
}

impl Helper<'_> {
    fn refuse(&self, refusal: EngineError) -> openpgp::Result<Option<Cert>> {
        self.progress.refusal.set(Some(refusal));
        Err(openpgp::anyhow::anyhow!("refused"))
    }
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.verifiers.iter().flatten().cloned().collect())
    }

    /// Grades the signatures. It never fails: the verdict travels beside the
    /// plaintext.
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        self.signature = Some(verdict::grade(structure, self.verifiers));
        Ok(())
    }
}

impl DecryptionHelper for Helper<'_> {
    /// Tries every session-key packet that names one of the key's encryption
    /// keys, then the hidden ones against every encryption key, until one opens
    /// the message. If none does: a packet that names the key and unwrapped to
    /// a cipher the engine refuses makes the failure `Unsupported`, else one
    /// that did not unwrap makes it `Tampered`. A hidden packet that does not
    /// open the message, also for a refused cipher, is someone else's and is
    /// skipped.
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        let mut decryptors = self.key.decryptors(self.now);
        let (named, hidden): (Vec<_>, Vec<_>) =
            pkesks.iter().partition(|pkesk| recipient(pkesk).is_some());

        // Packets that name the key and did not open the message: one that
        // unwrapped to a refused cipher, or one that did not unwrap. Neither
        // stops the next packet from being tried.
        let mut named_refused = false;
        let mut named_failed = false;
        for pkesk in named {
            let handle = recipient(pkesk).expect("partitioned on the recipient");
            for decryptor in decryptors
                .iter_mut()
                .filter(|decryptor| handle.aliases(decryptor.public().key_handle()))
            {
                match unwrap(pkesk, decryptor.as_mut(), sym_algo) {
                    Some((algorithm, _)) if refused(algorithm) => named_refused = true,
                    Some((algorithm, session_key)) if decrypt(algorithm, &session_key) => {
                        self.progress.unwrapped.set(true);
                        return Ok(None);
                    }
                    _ => named_failed = true,
                }
            }
        }
        for pkesk in hidden {
            for decryptor in &mut decryptors {
                if let Some((algorithm, session_key)) = unwrap(pkesk, decryptor.as_mut(), sym_algo)
                    && !refused(algorithm)
                    && decrypt(algorithm, &session_key)
                {
                    self.progress.unwrapped.set(true);
                    return Ok(None);
                }
            }
        }
        self.refuse(if named_refused {
            EngineError::Unsupported
        } else if named_failed {
            EngineError::Tampered
        } else {
            EngineError::NoMatchingKey
        })
    }
}

/// The key a session-key packet names, or `None` for a hidden recipient.
fn recipient(pkesk: &PKESK) -> Option<KeyHandle> {
    pkesk.recipient().filter(|handle| match handle {
        KeyHandle::KeyID(id) => !id.is_wildcard(),
        KeyHandle::Fingerprint(_) => true,
    })
}

fn unwrap(
    pkesk: &PKESK,
    decryptor: &mut dyn openpgp::crypto::Decryptor,
    sym_algo: Option<SymmetricAlgorithm>,
) -> Option<(Option<SymmetricAlgorithm>, SessionKey)> {
    pkesk.decrypt(decryptor, sym_algo)
}

/// A known cipher that the backend lacks or the policy refuses, which a v3
/// session-key packet reveals only once it is unwrapped. A value no sender
/// writes is a failed unwrap, not an old cipher.
fn refused(algorithm: Option<SymmetricAlgorithm>) -> bool {
    match algorithm {
        Some(
            SymmetricAlgorithm::Unencrypted
            | SymmetricAlgorithm::Unknown(_)
            | SymmetricAlgorithm::Private(_),
        )
        | None => false,
        Some(algorithm) => {
            !algorithm.is_supported() || POLICY.symmetric_algorithm(algorithm).is_err()
        }
    }
}
