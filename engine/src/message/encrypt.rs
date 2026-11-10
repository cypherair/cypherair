//! Encrypting text to recipients, optionally signed.

use std::io::Write as _;
use std::sync::Arc;
use std::time::SystemTime;

use openpgp::armor;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Recipient, Signer};
use openpgp::types::{AEADAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp as openpgp;

use super::{header, recipients};
use crate::error::{self, contained};
use crate::{Encrypted, EngineError, POLICY, PrivateKey};

/// Encrypt to every recipient, and sign with `signer` when given. The message
/// is armored, never compressed, AES-256, and uses SEIPDv2 only if every
/// recipient supports it. Encrypt-to-self is the caller adding its own
/// certificate to `recipients`.
#[uniffi::export]
pub fn encrypt(
    plaintext: &[u8],
    recipients: Vec<Vec<u8>>,
    signer: Option<Arc<PrivateKey>>,
) -> Result<Encrypted, EngineError> {
    contained(|| {
        let now = SystemTime::now();
        let resolved = recipients::resolve(&recipients, now)?;
        let signer = signer.map(|key| key.signer(now)).transpose()?;

        let valid = resolved
            .certs
            .iter()
            .map(|cert| cert.with_policy(&POLICY, now))
            .collect::<Result<Vec<_>, _>>()
            .map_err(EngineError::internal)?;
        let keys: Vec<Recipient> = valid
            .iter()
            .flat_map(|valid| recipients::encryption_keys(valid).map(Recipient::from))
            .collect();

        let mut sink = Vec::new();
        let message = Armorer::new(Message::new(&mut sink))
            .kind(armor::Kind::Message)
            .build()
            .map_err(EngineError::internal)?;
        let mut encryptor =
            Encryptor::for_recipients(message, keys).symmetric_algo(SymmetricAlgorithm::AES256);
        if resolved.modern() {
            encryptor = encryptor.aead_algo(AEADAlgorithm::OCB);
        }
        // A device signs as the stream ends; its failure is told apart here.
        let failed = |error: openpgp::anyhow::Error| error::failed_operation(&error);
        let mut message = encryptor.build().map_err(failed)?;
        if let Some(signer) = signer {
            message = Signer::new(message, signer)
                .map_err(failed)?
                .build()
                .map_err(failed)?;
        }
        let mut literal = LiteralWriter::new(message).build().map_err(failed)?;
        literal
            .write_all(plaintext)
            .map_err(|error| failed(error.into()))?;
        literal.finalize().map_err(failed)?;

        let quantum_safe = header::read(&sink)?.quantum_safe();
        Ok(Encrypted {
            message: sink,
            quantum_safe,
        })
    })
}
