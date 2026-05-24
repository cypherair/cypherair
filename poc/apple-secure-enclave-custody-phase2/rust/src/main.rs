use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use openpgp::cert::prelude::*;
use openpgp::crypto::mpi;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::{
    Curve, Features, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SymmetricAlgorithm,
};
use openpgp::{packet, Packet};
use sequoia_openpgp as openpgp;
use serde::Deserialize;
use serde_json::{json, Value};

type ProbeResult<T> = Result<T, String>;

#[derive(Clone, Copy)]
enum Mode {
    SoftwareControl,
    SecureEnclavePublics,
    ArtifactMap,
    Mismatch,
    CapabilityResolver,
}

struct Arguments {
    mode: Mode,
    fixture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SwiftFixture {
    #[allow(dead_code)]
    schema: String,
    #[serde(rename = "secureEnclaveAvailable")]
    secure_enclave_available: bool,
    keys: Vec<SwiftFixtureKey>,
}

#[derive(Debug, Deserialize)]
struct SwiftFixtureKey {
    role: String,
    algorithm: String,
    curve: String,
    #[serde(rename = "publicKeyEncoding")]
    public_key_encoding: String,
    #[serde(rename = "publicKeyX963Hex")]
    public_key_x963_hex: String,
    #[serde(rename = "publicKeyX963Length")]
    public_key_x963_length: usize,
}

#[derive(Clone)]
struct BoundPublics {
    signing_x963: Vec<u8>,
    agreement_x963: Vec<u8>,
}

fn main() {
    match run() {
        Ok(report) => {
            let status = report["status"].as_str().unwrap_or("unknown");
            let mode = report["mode"].as_str().unwrap_or("unknown");
            println!("Phase 2 OpenPGP certificate probe: {mode} {status}");
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("report should serialize")
            );
            if status == "failed" {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("Phase2OpenPGPCertProbe failed: {error}");
            std::process::exit(1);
        }
    }
}

fn run() -> ProbeResult<Value> {
    let args = parse_arguments()?;
    match args.mode {
        Mode::SoftwareControl => software_control(),
        Mode::SecureEnclavePublics => {
            let fixture = args
                .fixture
                .ok_or_else(|| "--fixture <json> is required".to_string())?;
            secure_enclave_publics(&fixture)
        }
        Mode::ArtifactMap => Ok(artifact_map()),
        Mode::Mismatch => mismatch(),
        Mode::CapabilityResolver => Ok(capability_resolver()),
    }
}

fn parse_arguments() -> ProbeResult<Arguments> {
    let mut mode = None;
    let mut fixture = None;
    let mut iter = env::args().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--mode" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --mode".to_string())?;
                mode = Some(match value.as_str() {
                    "software-control" => Mode::SoftwareControl,
                    "secure-enclave-publics" => Mode::SecureEnclavePublics,
                    "artifact-map" => Mode::ArtifactMap,
                    "mismatch" => Mode::Mismatch,
                    "capability-resolver" => Mode::CapabilityResolver,
                    other => return Err(format!("unsupported mode: {other}")),
                });
            }
            "--fixture" => {
                fixture = Some(
                    iter.next()
                        .ok_or_else(|| "missing value for --fixture".to_string())?,
                );
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }

    Ok(Arguments {
        mode: mode.ok_or_else(|| "missing --mode".to_string())?,
        fixture,
    })
}

fn software_control() -> ProbeResult<Value> {
    let candidates = vec![
        control_candidate(4, openpgp::Profile::RFC4880)?,
        control_candidate(6, openpgp::Profile::RFC9580)?,
    ];

    let status = if candidates.iter().all(|c| {
        c["validPublicCertificate"].as_bool() == Some(true)
            && c["transportRecipientSelection"].as_bool() == Some(true)
            && c["cypherAirPublicParse"].as_bool() == Some(true)
    }) {
        "passed"
    } else {
        "failed"
    };

    Ok(json!({
        "phase": "phase2",
        "mode": "software-control",
        "status": status,
        "materialsPrinted": false,
        "candidateCount": candidates.len(),
        "candidates": candidates,
        "summary": "Software P-256 control certificates prove Sequoia can build, parse, validate, and select v4/v6 P-256 public certificates when the signing private key is available."
    }))
}

fn control_candidate(version: u8, profile: openpgp::Profile) -> ProbeResult<Value> {
    let user_id = format!("Phase 2 P-256 Control v{version} <phase2-v{version}@cypherair.local>");
    let mut builder = CertBuilder::new()
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .set_creation_time(fixed_creation_time())
        .set_cipher_suite(CipherSuite::P256)
        .set_profile(profile)
        .map_err(sanitize_error)?
        .add_userid(user_id)
        .add_transport_encryption_subkey();

    if version == 4 {
        builder = builder
            .set_features(Features::empty().set_seipdv1())
            .map_err(sanitize_error)?;
    }

    let (cert, revocation) = builder.generate().map_err(sanitize_error)?;
    let mut secret_cert_data = Vec::new();
    cert.as_tsk()
        .serialize(&mut secret_cert_data)
        .map_err(sanitize_error)?;

    let mut public_cert_data = Vec::new();
    cert.serialize(&mut public_cert_data)
        .map_err(sanitize_error)?;

    let key_info = pgp_mobile::keys::parse_key_info(&public_cert_data).map_err(sanitize_error)?;
    let validation =
        pgp_mobile::keys::validate_public_certificate(&public_cert_data).map_err(sanitize_error)?;
    let selectors = pgp_mobile::keys::discover_certificate_selectors(&public_cert_data)
        .map_err(sanitize_error)?;
    let ciphertext = pgp_mobile::encrypt::encrypt_binary(
        b"phase2 recipient selection",
        &[public_cert_data.clone()],
        None,
        None,
    )
    .map_err(sanitize_error)?;
    let matched = pgp_mobile::decrypt::match_recipients(&ciphertext, &[public_cert_data.clone()])
        .map_err(sanitize_error)?;

    let mut revocation_bytes = Vec::new();
    Packet::from(revocation)
        .serialize(&mut revocation_bytes)
        .map_err(sanitize_error)?;
    let generated_key_revocation =
        pgp_mobile::keys::generate_key_revocation(&secret_cert_data).map_err(sanitize_error)?;

    let first_subkey_fingerprint = cert
        .keys()
        .subkeys()
        .next()
        .ok_or_else(|| "missing encryption subkey".to_string())?
        .key()
        .fingerprint()
        .to_hex()
        .to_lowercase();
    let subkey_revocation =
        pgp_mobile::keys::generate_subkey_revocation(&secret_cert_data, &first_subkey_fingerprint)
            .map_err(sanitize_error)?;

    let user_id_data = cert
        .userids()
        .next()
        .ok_or_else(|| "missing user id".to_string())?
        .userid()
        .value()
        .to_vec();
    let user_id_selector = pgp_mobile::keys::UserIdSelectorInput {
        user_id_data,
        occurrence_index: 0,
    };
    let user_id_revocation = pgp_mobile::keys::generate_user_id_revocation_by_selector(
        &secret_cert_data,
        &user_id_selector,
    )
    .map_err(sanitize_error)?;

    Ok(json!({
        "candidate": format!("p256-v{version}-software-control"),
        "keyVersion": key_info.key_version,
        "cypherAirDetectedProfile": format!("{:?}", key_info.profile),
        "primaryAlgorithm": key_info.primary_algo,
        "subkeyAlgorithm": key_info.subkey_algo,
        "validPublicCertificate": true,
        "cypherAirPublicParse": validation.public_cert_data == public_cert_data,
        "transportRecipientSelection": matched.len() == 1,
        "publicCertificateByteLength": public_cert_data.len(),
        "fingerprintHexLength": key_info.fingerprint.len(),
        "userIdCount": selectors.user_ids.len(),
        "subkeyCount": selectors.subkeys.len(),
        "revocationArtifactByteLengths": {
            "certBuilderKeyRevocation": revocation_bytes.len(),
            "generatedKeyRevocation": generated_key_revocation.len(),
            "subkeyRevocation": subkey_revocation.len(),
            "userIdRevocation": user_id_revocation.len()
        },
        "rawMaterialsPrinted": false
    }))
}

fn secure_enclave_publics(path: &str) -> ProbeResult<Value> {
    let fixture_data = fs::read_to_string(path).map_err(|e| format!("fixtureRead:{e}"))?;
    let fixture: SwiftFixture =
        serde_json::from_str(&fixture_data).map_err(|e| format!("fixtureJson:{e}"))?;

    if !fixture.secure_enclave_available {
        return Ok(json!({
            "phase": "phase2",
            "mode": "secure-enclave-publics",
            "status": "skipped",
            "secureEnclaveAvailable": false,
            "materialsPrinted": false,
            "summary": "Fixture reports Secure Enclave unavailable; no software fallback attempted."
        }));
    }

    let bound = bound_publics_from_fixture(&fixture)?;
    validate_bound_publics(&bound, &bound, "signing", "keyAgreement")?;

    let candidates = vec![
        se_public_candidate(4, &bound)?,
        se_public_candidate(6, &bound)?,
    ];
    let status = if candidates
        .iter()
        .all(|c| c["packetEncoding"].as_bool() == Some(true))
    {
        "passed"
    } else {
        "failed"
    };

    Ok(json!({
        "phase": "phase2",
        "mode": "secure-enclave-publics",
        "status": status,
        "secureEnclaveAvailable": true,
        "materialsPrinted": false,
        "privateMaterialAvailable": false,
        "fixturePublicKeyLengths": {
            "signingX963": bound.signing_x963.len(),
            "keyAgreementX963": bound.agreement_x963.len()
        },
        "fixturePublicKeysDistinct": bound.signing_x963 != bound.agreement_x963,
        "candidates": candidates,
        "summary": "Secure Enclave public keys can be encoded as P-256 OpenPGP public key packets. Full public-certificate validation and recipient selection remain pending until Phase 3 produces valid SE-backed binding signatures."
    }))
}

fn se_public_candidate(version: u8, bound: &BoundPublics) -> ProbeResult<Value> {
    let primary = public_signing_key(version, &bound.signing_x963)?;
    let subkey = public_agreement_key(version, &bound.agreement_x963)?;
    let user_id: packet::UserID = format!(
        "Phase 2 Secure Enclave Candidate v{version} <phase2-se-v{version}@cypherair.local>"
    )
    .into();

    let packets = vec![
        Packet::from(primary),
        Packet::from(user_id),
        Packet::from(subkey),
    ];

    let mut packet_bytes = Vec::new();
    for packet in packets.clone() {
        packet
            .serialize(&mut packet_bytes)
            .map_err(sanitize_error)?;
    }

    let bare_cert_result = openpgp::Cert::from_packets(packets.into_iter());
    let (
        bare_cert_parsed,
        cypherair_public_parse,
        selector_discovery,
        user_id_count,
        subkey_count,
        transport_selected,
        parse_error_class,
    ) = match bare_cert_result {
        Ok(cert) => {
            let mut cert_bytes = Vec::new();
            let serialized = cert.serialize(&mut cert_bytes).is_ok();
            let cypherair =
                serialized && pgp_mobile::keys::validate_public_certificate(&cert_bytes).is_ok();
            let (selector_discovery, user_id_count, subkey_count) = if serialized {
                match pgp_mobile::keys::discover_certificate_selectors(&cert_bytes) {
                    Ok(selectors) => (true, selectors.user_ids.len(), selectors.subkeys.len()),
                    Err(_) => (false, 0, 0),
                }
            } else {
                (false, 0, 0)
            };
            let policy = StandardPolicy::new();
            let transport = cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .for_transport_encryption()
                .next()
                .is_some();
            (
                true,
                cypherair,
                selector_discovery,
                user_id_count,
                subkey_count,
                transport,
                Value::Null,
            )
        }
        Err(error) => (
            false,
            false,
            false,
            0,
            0,
            false,
            Value::String(classify_error(&error.to_string())),
        ),
    };

    Ok(json!({
        "candidate": format!("p256-v{version}-secure-enclave-publics"),
        "keyVersion": version,
        "primaryAlgorithm": "ECDSA",
        "subkeyAlgorithm": "ECDH",
        "curve": "NIST P-256",
        "packetEncoding": true,
        "packetByteLength": packet_bytes.len(),
        "bareCertParsed": bare_cert_parsed,
        "cypherAirPublicParse": cypherair_public_parse,
        "selectorDiscovery": selector_discovery,
        "userIdCount": user_id_count,
        "subkeyCount": subkey_count,
        "policyUsableForTransportEncryption": transport_selected,
        "transportRecipientSelection": transport_selected,
        "parseErrorClass": parse_error_class,
        "requiredBeforeFullValidation": [
            "User ID self-certification signed by Secure Enclave signing key",
            "ECDH subkey binding signature signed by Secure Enclave signing key"
        ],
        "rawMaterialsPrinted": false
    }))
}

fn artifact_map() -> Value {
    json!({
        "phase": "phase2",
        "mode": "artifact-map",
        "status": "passed",
        "materialsPrinted": false,
        "candidateShape": {
            "primary": "P-256 ECDSA certification/signing public key",
            "subkey": "distinct P-256 ECDH transport-encryption public subkey",
            "versionsCompared": [4, 6]
        },
        "artifacts": [
            {
                "name": "User ID self-certification",
                "signatureType": "Generic/Positive Certification",
                "issuer": "primary P-256 ECDSA key",
                "requiresSecureEnclaveSigningKey": true,
                "validationPhase": "Phase 3"
            },
            {
                "name": "ECDH subkey binding",
                "signatureType": "Subkey Binding",
                "issuer": "primary P-256 ECDSA key",
                "requiresSecureEnclaveSigningKey": true,
                "validationPhase": "Phase 3"
            },
            {
                "name": "Key revocation artifact",
                "signatureType": "Key Revocation",
                "issuer": "primary P-256 ECDSA key",
                "requiresSecureEnclaveSigningKey": true,
                "validationPhase": "Phase 3 or lifecycle follow-up"
            },
            {
                "name": "Subkey revocation artifact",
                "signatureType": "Subkey Revocation",
                "issuer": "primary P-256 ECDSA key",
                "requiresSecureEnclaveSigningKey": true,
                "validationPhase": "later lifecycle validation"
            },
            {
                "name": "User ID revocation artifact",
                "signatureType": "Certification Revocation",
                "issuer": "primary P-256 ECDSA key",
                "requiresSecureEnclaveSigningKey": true,
                "validationPhase": "later lifecycle validation"
            }
        ],
        "summary": "All durable certificate and revocation artifacts for this custody shape ultimately require Secure Enclave ECDSA signatures from the primary signing key."
    })
}

fn mismatch() -> ProbeResult<Value> {
    let signing_key: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole> =
        packet::key::Key4::generate_ecc(true, Curve::NistP256)
            .map_err(sanitize_error)?
            .into();
    let agreement_key: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole> =
        packet::key::Key4::generate_ecc(false, Curve::NistP256)
            .map_err(sanitize_error)?
            .into();

    let fixture = BoundPublics {
        signing_x963: x963_from_key(signing_key.parts_as_public())?,
        agreement_x963: x963_from_key(agreement_key.parts_as_public())?,
    };

    let cases = vec![
        mismatch_case(
            "swappedPublics",
            &fixture,
            &BoundPublics {
                signing_x963: fixture.agreement_x963.clone(),
                agreement_x963: fixture.signing_x963.clone(),
            },
            "signing",
            "keyAgreement",
        ),
        mismatch_case(
            "duplicatePublics",
            &fixture,
            &BoundPublics {
                signing_x963: fixture.signing_x963.clone(),
                agreement_x963: fixture.signing_x963.clone(),
            },
            "signing",
            "keyAgreement",
        ),
        mismatch_case(
            "wrongSigningRoleMetadata",
            &fixture,
            &fixture,
            "keyAgreement",
            "keyAgreement",
        ),
        mismatch_case(
            "wrongAgreementRoleMetadata",
            &fixture,
            &fixture,
            "signing",
            "signing",
        ),
    ];

    let status = if cases
        .iter()
        .all(|case| case["rejected"].as_bool() == Some(true))
    {
        "passed"
    } else {
        "failed"
    };

    Ok(json!({
        "phase": "phase2",
        "mode": "mismatch",
        "status": status,
        "materialsPrinted": false,
        "cases": cases,
        "summary": "The disposable binder rejects role swaps, duplicate public keys, public-certificate mismatch, and wrong role metadata before Sequoia parsing or CryptoKit role reconstruction is trusted."
    }))
}

fn mismatch_case(
    name: &str,
    fixture: &BoundPublics,
    candidate: &BoundPublics,
    signing_role: &'static str,
    agreement_role: &'static str,
) -> Value {
    let result = validate_bound_publics(fixture, candidate, signing_role, agreement_role);
    json!({
        "name": name,
        "rejected": result.is_err(),
        "errorClass": result.err().map(|e| classify_error(&e)),
        "materialsPrinted": false
    })
}

fn capability_resolver() -> Value {
    json!({
        "phase": "phase2",
        "mode": "capability-resolver",
        "status": "passed",
        "materialsPrinted": false,
        "dimensions": {
            "algorithmProfile": ["Profile A software v4 Ed25519/X25519", "Profile B software v6 Ed448/X448", "P-256 OpenPGP candidate v4", "P-256 OpenPGP candidate v6"],
            "custody": ["softwareSecretCertificate", "appleSecureEnclaveCustody"]
        },
        "rules": [
            {
                "algorithmProfile": "Profile A",
                "custody": "softwareSecretCertificate",
                "selectableToday": true,
                "reason": "current shipped software-key profile"
            },
            {
                "algorithmProfile": "Profile B",
                "custody": "softwareSecretCertificate",
                "selectableToday": true,
                "reason": "current shipped software-key profile"
            },
            {
                "algorithmProfile": "Profile A",
                "custody": "appleSecureEnclaveCustody",
                "selectableToday": false,
                "reason": "Secure Enclave supports P-256 only, not Ed25519/X25519"
            },
            {
                "algorithmProfile": "Profile B",
                "custody": "appleSecureEnclaveCustody",
                "selectableToday": false,
                "reason": "Secure Enclave supports P-256 only, not Ed448/X448"
            },
            {
                "algorithmProfile": "P-256 OpenPGP v4 candidate",
                "custody": "appleSecureEnclaveCustody",
                "selectableToday": false,
                "phase2Candidate": true,
                "reason": "candidate only; requires Phase 3 SE-backed binding signatures and later decrypt evidence"
            },
            {
                "algorithmProfile": "P-256 OpenPGP v6 candidate",
                "custody": "appleSecureEnclaveCustody",
                "selectableToday": false,
                "phase2Candidate": true,
                "reason": "candidate only; requires Phase 3 SE-backed binding signatures and later decrypt evidence"
            }
        ],
        "summary": "Algorithm/profile and custody are modeled as separate dimensions; the disposable resolver keeps Apple SE custody unavailable to product UI until later phases pass."
    })
}

fn bound_publics_from_fixture(fixture: &SwiftFixture) -> ProbeResult<BoundPublics> {
    let signing = fixture_key(fixture, "signing")?;
    let agreement = fixture_key(fixture, "keyAgreement")?;
    validate_fixture_key(signing, "ECDSA")?;
    validate_fixture_key(agreement, "ECDH")?;

    Ok(BoundPublics {
        signing_x963: hex_decode(&signing.public_key_x963_hex)?,
        agreement_x963: hex_decode(&agreement.public_key_x963_hex)?,
    })
}

fn fixture_key<'a>(fixture: &'a SwiftFixture, role: &str) -> ProbeResult<&'a SwiftFixtureKey> {
    fixture
        .keys
        .iter()
        .find(|key| key.role == role)
        .ok_or_else(|| format!("missingFixtureRole:{role}"))
}

fn validate_fixture_key(key: &SwiftFixtureKey, expected_algorithm: &str) -> ProbeResult<()> {
    if key.algorithm != expected_algorithm {
        return Err(format!("unexpectedAlgorithm:{}", key.role));
    }
    if key.curve != "NIST P-256" {
        return Err(format!("unexpectedCurve:{}", key.role));
    }
    if key.public_key_encoding != "x963-uncompressed" {
        return Err(format!("unexpectedEncoding:{}", key.role));
    }
    if key.public_key_x963_length != 65 {
        return Err(format!("unexpectedPublicKeyLength:{}", key.role));
    }
    Ok(())
}

fn validate_bound_publics(
    fixture: &BoundPublics,
    candidate: &BoundPublics,
    signing_role: &str,
    agreement_role: &str,
) -> ProbeResult<()> {
    if signing_role != "signing" {
        return Err("roleBinding:signing".to_string());
    }
    if agreement_role != "keyAgreement" {
        return Err("roleBinding:keyAgreement".to_string());
    }
    validate_x963_public(&candidate.signing_x963, "candidateSigning")?;
    validate_x963_public(&candidate.agreement_x963, "candidateAgreement")?;
    if candidate.signing_x963 == candidate.agreement_x963 {
        return Err("publicKeyBinding:duplicatePublicKeys".to_string());
    }
    if candidate.signing_x963 != fixture.signing_x963 {
        return Err("publicKeyBinding:signingMismatch".to_string());
    }
    if candidate.agreement_x963 != fixture.agreement_x963 {
        return Err("publicKeyBinding:agreementMismatch".to_string());
    }
    Ok(())
}

fn validate_x963_public(bytes: &[u8], name: &str) -> ProbeResult<()> {
    if bytes.len() != 65 {
        return Err(format!("publicKeyFormat:{name}:length"));
    }
    if bytes.first().copied() != Some(0x04) {
        return Err(format!("publicKeyFormat:{name}:prefix"));
    }
    Ok(())
}

fn public_signing_key(
    version: u8,
    x963: &[u8],
) -> ProbeResult<packet::Key<packet::key::PublicParts, packet::key::PrimaryRole>> {
    let mpis = p256_ecdsa_public_mpis(x963)?;
    let creation_time = fixed_creation_time();
    match version {
        4 => {
            let key: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> =
                packet::key::Key4::<packet::key::PublicParts, packet::key::UnspecifiedRole>::new(
                    creation_time,
                    PublicKeyAlgorithm::ECDSA,
                    mpis,
                )
                .map_err(sanitize_error)?
                .into();
            Ok(key.role_into_primary())
        }
        6 => {
            let key: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> =
                packet::key::Key6::<packet::key::PublicParts, packet::key::UnspecifiedRole>::new(
                    creation_time,
                    PublicKeyAlgorithm::ECDSA,
                    mpis,
                )
                .map_err(sanitize_error)?
                .into();
            Ok(key.role_into_primary())
        }
        _ => Err(format!("unsupportedKeyVersion:{version}")),
    }
}

fn public_agreement_key(
    version: u8,
    x963: &[u8],
) -> ProbeResult<packet::Key<packet::key::PublicParts, packet::key::SubordinateRole>> {
    let mpis = p256_ecdh_public_mpis(x963)?;
    let creation_time = fixed_creation_time();
    match version {
        4 => {
            let key: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> =
                packet::key::Key4::<packet::key::PublicParts, packet::key::UnspecifiedRole>::new(
                    creation_time,
                    PublicKeyAlgorithm::ECDH,
                    mpis,
                )
                .map_err(sanitize_error)?
                .into();
            Ok(key.role_into_subordinate())
        }
        6 => {
            let key: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> =
                packet::key::Key6::<packet::key::PublicParts, packet::key::UnspecifiedRole>::new(
                    creation_time,
                    PublicKeyAlgorithm::ECDH,
                    mpis,
                )
                .map_err(sanitize_error)?
                .into();
            Ok(key.role_into_subordinate())
        }
        _ => Err(format!("unsupportedKeyVersion:{version}")),
    }
}

fn p256_ecdsa_public_mpis(x963: &[u8]) -> ProbeResult<mpi::PublicKey> {
    validate_x963_public(x963, "ecdsa")?;
    Ok(mpi::PublicKey::ECDSA {
        curve: Curve::NistP256,
        q: mpi::MPI::new_point(&x963[1..33], &x963[33..65], 256),
    })
}

fn p256_ecdh_public_mpis(x963: &[u8]) -> ProbeResult<mpi::PublicKey> {
    validate_x963_public(x963, "ecdh")?;
    Ok(mpi::PublicKey::ECDH {
        curve: Curve::NistP256,
        q: mpi::MPI::new_point(&x963[1..33], &x963[33..65], 256),
        hash: HashAlgorithm::SHA256,
        sym: SymmetricAlgorithm::AES256,
    })
}

fn x963_from_key(
    key: &packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole>,
) -> ProbeResult<Vec<u8>> {
    match key.mpis() {
        mpi::PublicKey::ECDSA {
            curve: Curve::NistP256,
            q,
        }
        | mpi::PublicKey::ECDH {
            curve: Curve::NistP256,
            q,
            ..
        } => Ok(q.value().to_vec()),
        _ => Err("unexpectedP256PublicKeyShape".to_string()),
    }
}

fn fixed_creation_time() -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_secs(1_735_689_600)
}

fn hex_decode(input: &str) -> ProbeResult<Vec<u8>> {
    if input.len() % 2 != 0 {
        return Err("hexDecode:oddLength".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks(2) {
        let hi = hex_value(chunk[0])?;
        let lo = hex_value(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> ProbeResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hexDecode:invalidCharacter".to_string()),
    }
}

fn sanitize_error(error: impl ToString) -> String {
    classify_error(&error.to_string())
}

fn classify_error(message: &str) -> String {
    let lower = message.to_lowercase();
    if lower.contains("malformed") {
        "malformedData".to_string()
    } else if lower.contains("unsupported") {
        "unsupported".to_string()
    } else if lower.contains("no binding signature") || lower.contains("self signature") {
        "missingBindingSignature".to_string()
    } else if lower.contains("invalid") {
        "invalidData".to_string()
    } else if lower.contains("mismatch") {
        "mismatch".to_string()
    } else if lower.contains("duplicate") {
        "duplicate".to_string()
    } else if lower.contains("role") {
        "roleBinding".to_string()
    } else {
        "operationFailed".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_control_reports_valid_candidates() {
        let report = software_control().expect("software control should run");
        assert_eq!(report["status"], "passed");
        assert_eq!(report["candidateCount"], 2);
    }

    #[test]
    fn mismatch_cases_are_rejected() {
        let report = mismatch().expect("mismatch should run");
        assert_eq!(report["status"], "passed");
    }

    #[test]
    fn capability_resolver_keeps_secure_enclave_candidates_unselectable() {
        let report = capability_resolver();
        assert_eq!(report["status"], "passed");
        let rules = report["rules"]
            .as_array()
            .expect("rules should be an array");
        assert!(rules.iter().any(|rule| {
            rule["custody"] == "appleSecureEnclaveCustody"
                && rule["phase2Candidate"] == true
                && rule["selectableToday"] == false
        }));
    }
}
