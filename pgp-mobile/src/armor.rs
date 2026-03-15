use openpgp::armor;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;

/// Armor binary OpenPGP data into ASCII format.
pub fn encode_armor(data: &[u8], kind: ArmorKind) -> Result<Vec<u8>, PgpError> {
    let armor_kind = match kind {
        ArmorKind::PublicKey => armor::Kind::PublicKey,
        ArmorKind::SecretKey => armor::Kind::SecretKey,
        ArmorKind::Message => armor::Kind::Message,
        ArmorKind::Signature => armor::Kind::Signature,
        ArmorKind::Unknown => {
            return Err(PgpError::ArmorError {
                reason: "Cannot encode armor with Unknown kind".to_string(),
            });
        }
    };

    let mut output = Vec::new();
    let mut writer = armor::Writer::new(&mut output, armor_kind)
        .map_err(|e| PgpError::ArmorError {
            reason: e.to_string(),
        })?;

    std::io::Write::write_all(&mut writer, data).map_err(|e| PgpError::ArmorError {
        reason: e.to_string(),
    })?;

    writer.finalize().map_err(|e| PgpError::ArmorError {
        reason: e.to_string(),
    })?;

    Ok(output)
}

/// Dearmor ASCII-armored OpenPGP data into binary format.
pub fn decode_armor(armored: &[u8]) -> Result<(Vec<u8>, ArmorKind), PgpError> {
    let mut reader =
        armor::Reader::from_bytes(armored, armor::ReaderMode::Tolerant(None));

    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut data).map_err(|e| PgpError::ArmorError {
        reason: e.to_string(),
    })?;

    let kind = match reader.kind() {
        Some(armor::Kind::PublicKey) => ArmorKind::PublicKey,
        Some(armor::Kind::SecretKey) => ArmorKind::SecretKey,
        Some(armor::Kind::Message) => ArmorKind::Message,
        Some(armor::Kind::Signature) => ArmorKind::Signature,
        _ => ArmorKind::Unknown,
    };

    Ok((data, kind))
}

/// Armor kind for the FFI boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ArmorKind {
    PublicKey,
    SecretKey,
    Message,
    Signature,
    /// Unrecognized armor type. The data was dearmored successfully
    /// but the armor kind header was not one of the known types.
    Unknown,
}

/// Create an armor writer for use in other modules.
pub(crate) fn armor_writer<'a, W: std::io::Write + Send + Sync + 'a>(
    sink: &'a mut W,
    kind: armor::Kind,
) -> Result<armor::Writer<&'a mut W>, PgpError> {
    armor::Writer::new(sink, kind).map_err(|e| PgpError::ArmorError {
        reason: e.to_string(),
    })
}

/// Armor a public key certificate.
pub fn armor_public_key(cert_data: &[u8]) -> Result<Vec<u8>, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    let mut output = Vec::new();
    let mut writer = armor::Writer::new(&mut output, armor::Kind::PublicKey)
        .map_err(|e| PgpError::ArmorError {
            reason: e.to_string(),
        })?;

    cert.serialize(&mut writer)
        .map_err(|e| PgpError::ArmorError {
            reason: e.to_string(),
        })?;

    writer.finalize().map_err(|e| PgpError::ArmorError {
        reason: e.to_string(),
    })?;

    Ok(output)
}
