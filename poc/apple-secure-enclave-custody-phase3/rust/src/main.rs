use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openpgp::cert::prelude::*;
use openpgp::crypto::{mpi, Signer};
use openpgp::packet::signature::SignatureBuilder;
use openpgp::parse::stream::{MessageLayer, MessageStructure, VerificationHelper, VerifierBuilder};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{LiteralWriter, Message, Signer as StreamSigner};
use openpgp::serialize::Serialize;
use openpgp::types::{
    Curve, Features, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm,
};
use openpgp::{packet, Packet};
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize as SerdeSerialize};
use serde_json::{json, Value};

type ProbeResult<T> = Result<T, String>;

const RUST_REQUEST_SCHEMA: &str = "cypherair.se-custody.phase3.rust-request.v1";
const SWIFT_SIGNING_REQUEST_SCHEMA: &str = "cypherair.se-custody.phase3.signing-request.v1";
const SWIFT_SIGNING_RESPONSE_SCHEMA: &str = "cypherair.se-custody.phase3.signing-response.v1";
const SWIFT_STATE_SCHEMA: &str = "cypherair.se-custody.phase3.signing-state.v1";

#[derive(Clone, Copy)]
enum Mode {
    ExternalSignerControl,
    SecureEnclaveBindings,
    MessageSignatures,
    Failure,
}

struct Arguments {
    mode: Mode,
    request: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
struct RustRequest {
    schema: String,
    #[serde(rename = "statePath")]
    state_path: Option<PathBuf>,
    #[serde(rename = "bridgeExecutablePath")]
    bridge_executable_path: Option<PathBuf>,
    #[serde(rename = "bridgePath")]
    bridge_path_alias: Option<PathBuf>,
    #[serde(rename = "tempDirectory")]
    temp_directory: Option<PathBuf>,
    #[serde(rename = "tempDir")]
    temp_dir_alias: Option<PathBuf>,
    #[serde(rename = "resultPath")]
    result_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct SwiftState {
    schema: String,
    #[serde(rename = "secureEnclaveAvailable")]
    secure_enclave_available: bool,
    keys: Vec<SwiftStateKey>,
}

#[derive(Clone, Debug, Deserialize)]
struct SwiftStateKey {
    role: String,
    #[serde(rename = "publicKeyX963Hex")]
    public_key_x963_hex: String,
    #[serde(rename = "publicKeyX963Length")]
    public_key_x963_length: usize,
    #[serde(rename = "keyType")]
    key_type: String,
    #[serde(rename = "keySizeBits")]
    key_size_bits: usize,
    #[serde(rename = "tokenID")]
    token_id: String,
}

#[derive(Clone)]
struct BoundPublics {
    signing_x963: Vec<u8>,
    agreement_x963: Vec<u8>,
}

#[derive(Clone)]
struct BridgeConfig {
    state_path: PathBuf,
    bridge_path: PathBuf,
    temp_dir: PathBuf,
}

#[derive(SerdeSerialize)]
struct SwiftSigningRequest<'a> {
    schema: &'a str,
    #[serde(rename = "statePath")]
    state_path: &'a str,
    #[serde(rename = "hashAlgorithm")]
    hash_algorithm: &'a str,
    #[serde(rename = "digestHex")]
    digest_hex: String,
    #[serde(rename = "responsePath")]
    response_path: &'a str,
}

#[derive(Debug, Deserialize)]
struct SwiftSigningResponse {
    schema: String,
    status: String,
    #[serde(rename = "hashAlgorithm")]
    hash_algorithm: String,
    #[serde(rename = "digestByteLength")]
    digest_byte_length: usize,
    #[serde(rename = "rHex")]
    r_hex: String,
    #[serde(rename = "sHex")]
    s_hex: String,
    #[serde(rename = "rByteLength")]
    r_byte_length: usize,
    #[serde(rename = "sByteLength")]
    s_byte_length: usize,
    #[serde(rename = "publicKeyRevalidated")]
    public_key_revalidated: bool,
}

#[derive(Clone)]
struct ExternalSecKeySigner {
    public: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole>,
    bridge: BridgeConfig,
    serial: u64,
}

#[derive(Clone)]
struct SoftwareExternalSigner {
    public: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole>,
    keypair: openpgp::crypto::KeyPair,
}

struct CandidateArtifacts {
    cert: openpgp::Cert,
    public_cert_bytes: Vec<u8>,
    direct_sig_bytes: usize,
    user_id_sig_bytes: usize,
    subkey_sig_bytes: usize,
    bridge_signatures: usize,
}

struct BinaryVerifyHelper {
    certs: Vec<openpgp::Cert>,
    good_signatures: usize,
}

fn main() {
    match run() {
        Ok(report) => {
            let status = report["status"].as_str().unwrap_or("unknown");
            let mode = report["mode"].as_str().unwrap_or("unknown");
            println!("Phase 3 OpenPGP external signer probe: {mode} {status}");
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("report should serialize")
            );
            if status == "failed" {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!(
                "Phase3OpenPGPExternalSignerProbe failed: {}",
                classify_error(&error)
            );
            std::process::exit(1);
        }
    }
}

fn run() -> ProbeResult<Value> {
    let args = parse_arguments()?;
    match args.mode {
        Mode::ExternalSignerControl => external_signer_control(),
        Mode::SecureEnclaveBindings => {
            let request = args.request.ok_or_else(|| "missingRequest".to_string())?;
            secure_enclave_bindings(&request)
        }
        Mode::MessageSignatures => {
            let request = args.request.ok_or_else(|| "missingRequest".to_string())?;
            message_signatures(&request)
        }
        Mode::Failure => {
            let request = args.request.ok_or_else(|| "missingRequest".to_string())?;
            failure(&request)
        }
    }
}

fn parse_arguments() -> ProbeResult<Arguments> {
    let mut mode = None;
    let mut request = None;
    let mut iter = env::args().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--mode" => {
                let value = iter.next().ok_or_else(|| "missingModeValue".to_string())?;
                mode = Some(match value.as_str() {
                    "external-signer-control" => Mode::ExternalSignerControl,
                    "secure-enclave-bindings" => Mode::SecureEnclaveBindings,
                    "message-signatures" => Mode::MessageSignatures,
                    "failure" => Mode::Failure,
                    _ => return Err("unsupportedMode".to_string()),
                });
            }
            "--request" => {
                request = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "missingRequestValue".to_string())?,
                ));
            }
            _ => return Err("unexpectedArgument".to_string()),
        }
    }

    Ok(Arguments {
        mode: mode.ok_or_else(|| "missingMode".to_string())?,
        request,
    })
}

fn external_signer_control() -> ProbeResult<Value> {
    let candidates = vec![software_candidate(4)?, software_candidate(6)?];
    let status = if candidates.iter().all(|c| {
        c["certValid"].as_bool() == Some(true)
            && c["detachedVerified"].as_bool() == Some(true)
            && c["binaryMessageVerified"].as_bool() == Some(true)
    }) {
        "passed"
    } else {
        "failed"
    };

    Ok(json!({
        "phase": "phase3",
        "mode": "external-signer-control",
        "status": status,
        "materialsPrinted": false,
        "candidateCount": candidates.len(),
        "candidates": candidates,
        "summary": "Software P-256 external signer wrapper exercised the same Sequoia Signer trait path used by the Secure Enclave bridge."
    }))
}

fn software_candidate(version: u8) -> ProbeResult<Value> {
    let (primary, subkey, mut signer) =
        software_materials(version).map_err(|e| format!("softwareMaterials:{e}"))?;
    let artifacts = build_candidate_cert(
        version,
        &primary,
        &subkey,
        &mut signer,
        &format!("Phase 3 Software External Signer v{version} <phase3-control-v{version}@cypherair.local>"),
    )
    .map_err(|e| format!("candidateCert:{e}"))?;
    let cert_report =
        validate_candidate_cert(version, &artifacts).map_err(|e| format!("certValidate:{e}"))?;
    let message_report =
        sign_and_verify_messages(&artifacts.cert, &artifacts.public_cert_bytes, signer)
            .map_err(|e| format!("messageSignatures:{e}"))?;

    Ok(json!({
        "candidate": format!("p256-v{version}-software-external-signer"),
        "keyVersion": version,
        "certValid": cert_report["certValid"],
        "cypherAirPublicParse": cert_report["cypherAirPublicParse"],
        "selectorDiscovery": cert_report["selectorDiscovery"],
        "transportRecipientSelection": cert_report["transportRecipientSelection"],
        "recipientMatching": cert_report["recipientMatching"],
        "directKeySignatureByteLength": artifacts.direct_sig_bytes,
        "userIdBindingSignatureByteLength": artifacts.user_id_sig_bytes,
        "subkeyBindingSignatureByteLength": artifacts.subkey_sig_bytes,
        "detachedVerified": message_report["detachedVerified"],
        "cleartextVerified": message_report["cleartextVerified"],
        "binaryMessageVerified": message_report["binaryMessageVerified"],
        "hashAlgorithms": ["SHA256", "SHA384", "SHA512"],
        "materialsPrinted": false
    }))
}

fn secure_enclave_bindings(request_path: &Path) -> ProbeResult<Value> {
    let request = read_rust_request(request_path)?;
    let (bridge, bound) = bridge_materials(&request)?;

    let candidates = vec![
        secure_enclave_candidate(4, &bridge, &bound, false)?,
        secure_enclave_candidate(6, &bridge, &bound, false)?,
    ];
    let status = if candidates.iter().all(|c| {
        c["certValid"].as_bool() == Some(true)
            && c["cypherAirPublicParse"].as_bool() == Some(true)
            && c["recipientMatching"].as_bool() == Some(true)
            && c["bridgeSignatures"].as_u64().unwrap_or(0) >= 3
    }) {
        "passed"
    } else {
        "failed"
    };

    maybe_write_result(
        &request,
        &json!({
            "mode": "secure-enclave-bindings",
            "candidateCount": candidates.len(),
            "status": status
        }),
    )?;

    Ok(json!({
        "phase": "phase3",
        "mode": "secure-enclave-bindings",
        "status": status,
        "secureEnclaveAvailable": true,
        "materialsPrinted": false,
        "stateRequestResponseRestricted": true,
        "perSignaturePublicKeyRevalidation": true,
        "candidates": candidates,
        "summary": "Secure Enclave public keys produced v4/v6 P-256 certificates with direct-key, User ID, and ECDH subkey binding signatures accepted by Sequoia and CypherAir public-certificate paths."
    }))
}

fn secure_enclave_candidate(
    version: u8,
    bridge: &BridgeConfig,
    bound: &BoundPublics,
    include_messages: bool,
) -> ProbeResult<Value> {
    validate_bound_publics(bound, bound, "signing", "keyAgreement")?;
    let primary = public_signing_key(version, &bound.signing_x963)?;
    let subkey = public_agreement_key(version, &bound.agreement_x963)?;
    let mut signer = ExternalSecKeySigner::new(primary.clone(), bridge.clone());
    let artifacts = build_candidate_cert(
        version,
        &primary,
        &subkey,
        &mut signer,
        &format!(
            "Phase 3 Secure Enclave Candidate v{version} <phase3-se-v{version}@cypherair.local>"
        ),
    )?;
    let cert_report = validate_candidate_cert(version, &artifacts)?;
    let message_report = if include_messages {
        Some(sign_and_verify_messages(
            &artifacts.cert,
            &artifacts.public_cert_bytes,
            ExternalSecKeySigner::new(primary.clone(), bridge.clone()),
        )?)
    } else {
        None
    };

    Ok(json!({
        "candidate": format!("p256-v{version}-secure-enclave-external-signer"),
        "keyVersion": version,
        "primaryAlgorithm": "ECDSA",
        "subkeyAlgorithm": "ECDH",
        "curve": "NIST P-256",
        "certValid": cert_report["certValid"],
        "cypherAirPublicParse": cert_report["cypherAirPublicParse"],
        "selectorDiscovery": cert_report["selectorDiscovery"],
        "transportRecipientSelection": cert_report["transportRecipientSelection"],
        "recipientMatching": cert_report["recipientMatching"],
        "directKeySignatureByteLength": artifacts.direct_sig_bytes,
        "userIdBindingSignatureByteLength": artifacts.user_id_sig_bytes,
        "subkeyBindingSignatureByteLength": artifacts.subkey_sig_bytes,
        "publicCertificateByteLength": artifacts.public_cert_bytes.len(),
        "bridgeSignatures": artifacts.bridge_signatures,
        "messageSignatures": message_report,
        "hashAlgorithms": ["SHA256", "SHA384", "SHA512"],
        "materialsPrinted": false
    }))
}

fn message_signatures(request_path: &Path) -> ProbeResult<Value> {
    let request = read_rust_request(request_path)?;
    let (bridge, bound) = bridge_materials(&request)?;

    let mut candidates = Vec::new();
    for version in [4_u8, 6_u8] {
        candidates.push(secure_enclave_candidate(version, &bridge, &bound, true)?);
    }

    let status = if candidates.iter().all(|candidate| {
        let messages = &candidate["messageSignatures"];
        messages["detachedVerified"].as_bool() == Some(true)
            && messages["cleartextVerified"].as_bool() == Some(true)
            && messages["binaryMessageVerified"].as_bool() == Some(true)
    }) {
        "passed"
    } else {
        "failed"
    };

    maybe_write_result(
        &request,
        &json!({
            "mode": "message-signatures",
            "candidateCount": candidates.len(),
            "status": status
        }),
    )?;

    Ok(json!({
        "phase": "phase3",
        "mode": "message-signatures",
        "status": status,
        "secureEnclaveAvailable": true,
        "materialsPrinted": false,
        "candidates": candidates,
        "summary": "Secure Enclave backed Sequoia Signer produced detached, cleartext, and binary signed-message shapes that verified without exposing private material."
    }))
}

fn failure(request_path: &Path) -> ProbeResult<Value> {
    let request = read_rust_request(request_path)?;
    let (bridge, bound) = bridge_materials(&request)?;
    let primary = public_signing_key(4, &bound.signing_x963)?;
    let mut passed = 0_u64;
    let mut failed = 0_u64;

    expect_failure(&mut passed, &mut failed, || {
        validate_bound_publics(
            &bound,
            &BoundPublics {
                signing_x963: bound.agreement_x963.clone(),
                agreement_x963: bound.signing_x963.clone(),
            },
            "signing",
            "keyAgreement",
        )
    });
    expect_failure(&mut passed, &mut failed, || {
        validate_bound_publics(
            &bound,
            &BoundPublics {
                signing_x963: bound.signing_x963.clone(),
                agreement_x963: bound.signing_x963.clone(),
            },
            "signing",
            "keyAgreement",
        )
    });
    expect_failure(&mut passed, &mut failed, || {
        let mut signer = ExternalSecKeySigner::new(primary.clone(), bridge.clone());
        signer
            .sign(HashAlgorithm::SHA1, &[0_u8; 20])
            .map(|_| ())
            .map_err(sanitize_error)
    });
    expect_failure(&mut passed, &mut failed, || {
        let mut signer = ExternalSecKeySigner::new(primary.clone(), bridge.clone());
        signer
            .sign(HashAlgorithm::SHA256, &[0_u8; 12])
            .map(|_| ())
            .map_err(sanitize_error)
    });
    expect_failure(&mut passed, &mut failed, || {
        parse_bridge_response(br#"{"schema":"cypherair.se-custody.phase3.signing-response.v1","status":"passed","hashAlgorithm":"sha256","digestByteLength":32,"rHex":"00","sHex":"00","rByteLength":1,"sByteLength":1,"publicKeyRevalidated":true}"#)
            .map(|_| ())
    });
    expect_failure(&mut passed, &mut failed, || {
        let symlink = bridge
            .temp_dir
            .join(format!("phase3-rust-symlink-{}", std::process::id()));
        let target = bridge
            .temp_dir
            .join(format!("phase3-rust-symlink-target-{}", std::process::id()));
        let _ = fs::remove_file(&symlink);
        let _ = fs::remove_file(&target);
        write_private_json(&target, &json!({"schema": RUST_REQUEST_SCHEMA}))?;
        std::os::unix::fs::symlink(&target, &symlink).map_err(|_| "symlinkCreate".to_string())?;
        let result = read_secure_file(&symlink).map(|_| ());
        let _ = fs::remove_file(&symlink);
        let _ = fs::remove_file(&target);
        result
    });
    expect_failure(&mut passed, &mut failed, || {
        let mut bad_bridge = bridge.clone();
        bad_bridge.bridge_path = bridge.temp_dir.join("missing-bridge-executable");
        let mut signer = ExternalSecKeySigner::new(primary.clone(), bad_bridge);
        signer
            .sign(HashAlgorithm::SHA256, &[0_u8; 32])
            .map(|_| ())
            .map_err(sanitize_error)
    });

    let status = if failed == 0 { "passed" } else { "failed" };
    maybe_write_result(
        &request,
        &json!({
            "mode": "failure",
            "checksPassed": passed,
            "checksFailed": failed,
            "status": status
        }),
    )?;

    Ok(json!({
        "phase": "phase3",
        "mode": "failure",
        "status": status,
        "materialsPrinted": false,
        "checksPassed": passed,
        "checksFailed": failed,
        "cases": [
            "wrongPublicKeyBinding",
            "duplicatePublicKeys",
            "unsupportedHash",
            "wrongDigestLength",
            "corruptedResponseSignatureCoordinates",
            "symlinkedRequestFile",
            "bridgeFailureWithoutSoftwareFallback"
        ],
        "summary": "Failure coverage rejected role/public mismatches, unsupported hashes, invalid digest/response shapes, symlinks, and bridge failure without software fallback."
    }))
}

fn software_materials(
    version: u8,
) -> ProbeResult<(
    packet::Key<packet::key::PublicParts, packet::key::PrimaryRole>,
    packet::Key<packet::key::PublicParts, packet::key::SubordinateRole>,
    SoftwareExternalSigner,
)> {
    let signing: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole> = match version
    {
        4 => packet::key::Key4::generate_ecc(true, Curve::NistP256)
            .map_err(sanitize_error)?
            .into(),
        6 => packet::key::Key6::generate_ecc(true, Curve::NistP256)
            .map_err(sanitize_error)?
            .into(),
        _ => return Err("unsupportedKeyVersion".to_string()),
    };
    let agreement: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole> =
        match version {
            4 => packet::key::Key4::generate_ecc(false, Curve::NistP256)
                .map_err(sanitize_error)?
                .into(),
            6 => packet::key::Key6::generate_ecc(false, Curve::NistP256)
                .map_err(sanitize_error)?
                .into(),
            _ => return Err("unsupportedKeyVersion".to_string()),
        };
    let public = signing.parts_as_public().clone().role_into_unspecified();
    let keypair = signing.clone().into_keypair().map_err(sanitize_error)?;
    let primary = signing.parts_as_public().clone().role_into_primary();
    let agreement_x963 = x963_from_key(agreement.parts_as_public())?;
    let subkey = public_agreement_key(version, &agreement_x963)?;
    Ok((primary, subkey, SoftwareExternalSigner { public, keypair }))
}

fn build_candidate_cert(
    _version: u8,
    primary: &packet::Key<packet::key::PublicParts, packet::key::PrimaryRole>,
    subkey: &packet::Key<packet::key::PublicParts, packet::key::SubordinateRole>,
    signer: &mut dyn Signer,
    user_id_text: &str,
) -> ProbeResult<CandidateArtifacts> {
    let user_id: packet::UserID = user_id_text.into();
    let direct_sig = direct_key_signature_builder()?
        .sign_direct_key(signer, Some(primary))
        .map_err(sanitize_error)?;
    let user_id_sig = certification_signature_builder()?
        .sign_userid_binding(signer, Some(primary), &user_id)
        .map_err(sanitize_error)?;
    let subkey_sig = subkey_binding_signature_builder()?
        .sign_subkey_binding(signer, Some(primary), subkey)
        .map_err(sanitize_error)?;

    let direct_sig_bytes = serialized_packet_len(Packet::from(direct_sig.clone()))?;
    let user_id_sig_bytes = serialized_packet_len(Packet::from(user_id_sig.clone()))?;
    let subkey_sig_bytes = serialized_packet_len(Packet::from(subkey_sig.clone()))?;

    let cert = openpgp::Cert::from_packets(
        vec![
            Packet::from(primary.clone()),
            Packet::from(direct_sig),
            Packet::from(user_id),
            Packet::from(user_id_sig),
            Packet::from(subkey.clone()),
            Packet::from(subkey_sig),
        ]
        .into_iter(),
    )
    .map_err(sanitize_error)?;

    let mut public_cert_bytes = Vec::new();
    cert.serialize(&mut public_cert_bytes)
        .map_err(sanitize_error)?;

    Ok(CandidateArtifacts {
        cert,
        public_cert_bytes,
        direct_sig_bytes,
        user_id_sig_bytes,
        subkey_sig_bytes,
        bridge_signatures: 3,
    })
}

fn direct_key_signature_builder() -> ProbeResult<SignatureBuilder> {
    SignatureBuilder::new(SignatureType::DirectKey)
        .set_hash_algo(HashAlgorithm::SHA256)
        .set_key_flags(KeyFlags::empty().set_certification().set_signing())
        .map_err(sanitize_error)?
        .set_features(Features::empty().set_seipdv1())
        .map_err(sanitize_error)
}

fn certification_signature_builder() -> ProbeResult<SignatureBuilder> {
    SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_hash_algo(HashAlgorithm::SHA256)
        .set_key_flags(KeyFlags::empty().set_certification().set_signing())
        .map_err(sanitize_error)?
        .set_features(Features::empty().set_seipdv1())
        .map_err(sanitize_error)?
        .set_preferred_hash_algorithms(vec![
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ])
        .map_err(sanitize_error)?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])
        .map_err(sanitize_error)
}

fn subkey_binding_signature_builder() -> ProbeResult<SignatureBuilder> {
    SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_hash_algo(HashAlgorithm::SHA256)
        .set_key_flags(KeyFlags::empty().set_transport_encryption())
        .map_err(sanitize_error)
}

fn serialized_packet_len(packet: Packet) -> ProbeResult<usize> {
    let mut bytes = Vec::new();
    packet.serialize(&mut bytes).map_err(sanitize_error)?;
    Ok(bytes.len())
}

fn validate_candidate_cert(version: u8, artifacts: &CandidateArtifacts) -> ProbeResult<Value> {
    let policy = StandardPolicy::new();
    let cert_valid = artifacts.cert.with_policy(&policy, None).is_ok();
    let validation = pgp_mobile::keys::validate_public_certificate(&artifacts.public_cert_bytes)
        .map_err(|e| format!("validatePublicCertificate:{}", sanitize_error(e)))?;
    let selectors = pgp_mobile::keys::discover_certificate_selectors(&artifacts.public_cert_bytes)
        .map_err(|e| format!("discoverSelectors:{}", sanitize_error(e)))?;
    let key_info = pgp_mobile::keys::parse_key_info(&artifacts.public_cert_bytes)
        .map_err(|e| format!("parseKeyInfo:{}", sanitize_error(e)))?;
    let transport_count = artifacts
        .cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .for_transport_encryption()
        .count();
    if transport_count == 0 {
        let reason = artifacts
            .cert
            .keys()
            .subkeys()
            .next()
            .map(|ka| match ka.with_policy(&policy, None) {
                Ok(valid) => format!(
                    "validNoTransportFlags:{:?}",
                    valid
                        .key_flags()
                        .map(|flags| flags.for_transport_encryption())
                ),
                Err(_) => "subkeyPolicyRejected".to_string(),
            })
            .unwrap_or_else(|| "missingSubkey".to_string());
        return Err(format!("transportSelectionDebug:{reason}"));
    }
    let ciphertext = pgp_mobile::encrypt::encrypt_binary(
        b"phase3 recipient selection",
        &[artifacts.public_cert_bytes.clone()],
        None,
        None,
    )
    .map_err(|e| format!("encryptBinary:{}", sanitize_error(e)))?;
    let matched =
        pgp_mobile::decrypt::match_recipients(&ciphertext, &[artifacts.public_cert_bytes.clone()])
            .map_err(|e| format!("matchRecipients:{}", sanitize_error(e)))?;

    Ok(json!({
        "keyVersion": version,
        "reportedKeyVersion": key_info.key_version,
        "certValid": cert_valid,
        "cypherAirPublicParse": validation.public_cert_data == artifacts.public_cert_bytes,
        "selectorDiscovery": !selectors.user_ids.is_empty() && !selectors.subkeys.is_empty(),
        "userIdCount": selectors.user_ids.len(),
        "subkeyCount": selectors.subkeys.len(),
        "transportRecipientSelection": true,
        "recipientMatching": matched.len() == 1,
        "primaryAlgorithm": key_info.primary_algo,
        "subkeyAlgorithm": key_info.subkey_algo,
        "materialsPrinted": false
    }))
}

fn sign_and_verify_messages<S>(
    cert: &openpgp::Cert,
    public_cert_bytes: &[u8],
    signer: S,
) -> ProbeResult<Value>
where
    S: Signer + Send + Sync + Clone + 'static,
{
    let data = b"phase3 external signer message";
    let mut detached_signer = signer.clone();
    let detached_sig = SignatureBuilder::new(SignatureType::Binary)
        .set_hash_algo(HashAlgorithm::SHA384)
        .sign_message(&mut detached_signer, data)
        .map_err(sanitize_error)?;
    detached_sig
        .verify_message(detached_signer.public(), data)
        .map_err(sanitize_error)?;
    let mut detached_packet = Vec::new();
    Packet::from(detached_sig)
        .serialize(&mut detached_packet)
        .map_err(sanitize_error)?;
    let detached_result = pgp_mobile::verify::verify_detached_detailed(
        data,
        &detached_packet,
        &[public_cert_bytes.to_vec()],
    )
    .map_err(sanitize_error)?;

    let cleartext = sign_cleartext_external(data, signer.clone())?;
    let cleartext_result =
        pgp_mobile::verify::verify_cleartext_detailed(&cleartext, &[public_cert_bytes.to_vec()])
            .map_err(sanitize_error)?;

    let binary_message = sign_binary_message_external(data, signer)?;
    let binary_verified = verify_binary_message(&binary_message, cert)?;

    Ok(json!({
        "detachedSignatureByteLength": detached_packet.len(),
        "cleartextSignedMessageByteLength": cleartext.len(),
        "binarySignedMessageByteLength": binary_message.len(),
        "detachedVerified": format!("{:?}", detached_result.legacy_status) == "Valid",
        "cleartextVerified": format!("{:?}", cleartext_result.legacy_status) == "Valid",
        "binaryMessageVerified": binary_verified,
        "hashAlgorithmsUsed": ["SHA384", "SHA512", "SHA256"],
        "materialsPrinted": false
    }))
}

fn sign_cleartext_external<S>(data: &[u8], signer: S) -> ProbeResult<Vec<u8>>
where
    S: Signer + Send + Sync + 'static,
{
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let mut cleartext = StreamSigner::with_template(
        message,
        signer,
        SignatureBuilder::new(SignatureType::Text).set_hash_algo(HashAlgorithm::SHA512),
    )
    .map_err(sanitize_error)?
    .cleartext()
    .build()
    .map_err(sanitize_error)?;
    cleartext.write_all(data).map_err(sanitize_error)?;
    cleartext.finalize().map_err(sanitize_error)?;
    Ok(sink)
}

fn sign_binary_message_external<S>(data: &[u8], signer: S) -> ProbeResult<Vec<u8>>
where
    S: Signer + Send + Sync + 'static,
{
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = StreamSigner::with_template(
        message,
        signer,
        SignatureBuilder::new(SignatureType::Binary).set_hash_algo(HashAlgorithm::SHA256),
    )
    .map_err(sanitize_error)?
    .build()
    .map_err(sanitize_error)?;
    let mut literal = LiteralWriter::new(message)
        .build()
        .map_err(sanitize_error)?;
    literal.write_all(data).map_err(sanitize_error)?;
    literal.finalize().map_err(sanitize_error)?;
    Ok(sink)
}

fn verify_binary_message(message: &[u8], cert: &openpgp::Cert) -> ProbeResult<bool> {
    let policy = StandardPolicy::new();
    let helper = BinaryVerifyHelper {
        certs: vec![cert.clone()],
        good_signatures: 0,
    };
    let mut verifier = VerifierBuilder::from_bytes(message)
        .map_err(sanitize_error)?
        .with_policy(&policy, None, helper)
        .map_err(sanitize_error)?;
    let mut content = Vec::new();
    verifier.read_to_end(&mut content).map_err(sanitize_error)?;
    let helper = verifier.into_helper();
    Ok(helper.good_signatures > 0 && content == b"phase3 external signer message")
}

impl VerificationHelper for BinaryVerifyHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                self.good_signatures += results.iter().filter(|result| result.is_ok()).count();
            }
        }
        Ok(())
    }
}

impl ExternalSecKeySigner {
    fn new(
        public: packet::Key<packet::key::PublicParts, packet::key::PrimaryRole>,
        bridge: BridgeConfig,
    ) -> Self {
        Self {
            public: public.role_into_unspecified(),
            bridge,
            serial: 0,
        }
    }
}

impl Signer for ExternalSecKeySigner {
    fn public(&self) -> &packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> {
        &self.public
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        static HASHES: [HashAlgorithm; 3] = [
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ];
        &HASHES
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        let signature = self
            .bridge_sign(hash_algo, digest)
            .map_err(openpgp::Error::InvalidArgument)?;
        Ok(signature)
    }
}

impl ExternalSecKeySigner {
    fn bridge_sign(
        &mut self,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> ProbeResult<mpi::Signature> {
        let (hash_name, expected_len) = match hash_algo {
            HashAlgorithm::SHA256 => ("sha256", 32),
            HashAlgorithm::SHA384 => ("sha384", 48),
            HashAlgorithm::SHA512 => ("sha512", 64),
            _ => return Err("unsupportedHash".to_string()),
        };
        if digest.len() != expected_len {
            return Err("wrongDigestLength".to_string());
        }
        validate_private_directory(&self.bridge.temp_dir)?;
        validate_executable(&self.bridge.bridge_path)?;
        let state_path = self.bridge.state_path.to_string_lossy().to_string();
        let request_name = format!(
            "phase3-bridge-request-{}-{}.json",
            std::process::id(),
            self.serial
        );
        let response_name = format!(
            "phase3-bridge-response-{}-{}.json",
            std::process::id(),
            self.serial
        );
        self.serial += 1;
        let request_path = self.bridge.temp_dir.join(request_name);
        let response_path = self.bridge.temp_dir.join(response_name);
        let response_path_string = response_path.to_string_lossy().to_string();
        let request = SwiftSigningRequest {
            schema: SWIFT_SIGNING_REQUEST_SCHEMA,
            state_path: &state_path,
            hash_algorithm: hash_name,
            digest_hex: hex_encode(digest),
            response_path: &response_path_string,
        };
        write_private_json(&request_path, &request)?;

        let output = Command::new(&self.bridge.bridge_path)
            .arg("--mode")
            .arg("sign-digest")
            .arg("--request")
            .arg(&request_path)
            .output()
            .map_err(|_| "bridgeInvokeFailed".to_string());

        let _ = remove_secure_file(&request_path);
        let output = output?;
        if !output.status.success() {
            let _ = remove_secure_file(&response_path);
            return Err("bridgeRejected".to_string());
        }

        let response_bytes = read_secure_file(&response_path)?;
        let _ = remove_secure_file(&response_path);
        let response = parse_bridge_response(&response_bytes)?;
        if response.hash_algorithm != hash_name
            || response.digest_byte_length != expected_len
            || !response.public_key_revalidated
        {
            return Err("bridgeResponseMismatch".to_string());
        }
        let r = hex_decode(&response.r_hex)?;
        let s = hex_decode(&response.s_hex)?;
        if r.len() != 32
            || s.len() != 32
            || response.r_byte_length != 32
            || response.s_byte_length != 32
        {
            return Err("bridgeResponseCoordinateLength".to_string());
        }
        Ok(mpi::Signature::ECDSA {
            r: mpi::MPI::new(&r),
            s: mpi::MPI::new(&s),
        })
    }
}

impl Signer for SoftwareExternalSigner {
    fn public(&self) -> &packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> {
        &self.public
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        static HASHES: [HashAlgorithm; 3] = [
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ];
        &HASHES
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        match hash_algo {
            HashAlgorithm::SHA256 if digest.len() == 32 => {}
            HashAlgorithm::SHA384 if digest.len() == 48 => {}
            HashAlgorithm::SHA512 if digest.len() == 64 => {}
            _ => {
                return Err(
                    openpgp::Error::InvalidArgument("unsupportedHashOrDigest".into()).into(),
                )
            }
        }
        self.keypair.sign(hash_algo, digest)
    }
}

fn read_rust_request(path: &Path) -> ProbeResult<RustRequest> {
    let data = read_secure_file(path)?;
    let request: RustRequest =
        serde_json::from_slice(&data).map_err(|_| "requestJson".to_string())?;
    if request.schema != RUST_REQUEST_SCHEMA {
        return Err("requestSchema".to_string());
    }
    Ok(request)
}

fn bridge_materials(request: &RustRequest) -> ProbeResult<(BridgeConfig, BoundPublics)> {
    let state_path = request
        .state_path
        .clone()
        .ok_or_else(|| "missingStatePath".to_string())?;
    let bridge_path = request
        .bridge_executable_path
        .clone()
        .or_else(|| request.bridge_path_alias.clone())
        .ok_or_else(|| "missingBridgePath".to_string())?;
    let temp_dir = request
        .temp_directory
        .clone()
        .or_else(|| request.temp_dir_alias.clone())
        .ok_or_else(|| "missingTempDir".to_string())?;
    validate_private_directory(&temp_dir)?;
    validate_executable(&bridge_path)?;
    let state: SwiftState = serde_json::from_slice(&read_secure_file(&state_path)?)
        .map_err(|_| "stateJson".to_string())?;
    let bound = bound_publics_from_state(&state)?;
    validate_bound_publics(&bound, &bound, "signing", "keyAgreement")?;
    Ok((
        BridgeConfig {
            state_path,
            bridge_path,
            temp_dir,
        },
        bound,
    ))
}

fn bound_publics_from_state(state: &SwiftState) -> ProbeResult<BoundPublics> {
    if state.schema != SWIFT_STATE_SCHEMA {
        return Err("stateSchema".to_string());
    }
    if !state.secure_enclave_available {
        return Err("secureEnclaveUnavailable".to_string());
    }
    let signing = state_key(state, "signing")?;
    let agreement = state_key(state, "keyAgreement")?;
    validate_state_key(signing, "SecureEnclave.P256.Signing.PrivateKey")?;
    validate_state_key(agreement, "SecureEnclave.P256.KeyAgreement.PrivateKey")?;
    Ok(BoundPublics {
        signing_x963: hex_decode(&signing.public_key_x963_hex)?,
        agreement_x963: hex_decode(&agreement.public_key_x963_hex)?,
    })
}

fn state_key<'a>(state: &'a SwiftState, role: &str) -> ProbeResult<&'a SwiftStateKey> {
    state
        .keys
        .iter()
        .find(|key| key.role == role)
        .ok_or_else(|| format!("missingStateRole:{role}"))
}

fn validate_state_key(key: &SwiftStateKey, expected_type: &str) -> ProbeResult<()> {
    if key.key_type != expected_type {
        return Err("stateKeyType".to_string());
    }
    if key.key_size_bits != 256 || key.token_id != "SecureEnclave" {
        return Err("stateKeyAttributes".to_string());
    }
    if key.public_key_x963_length != 65 {
        return Err("statePublicKeyLength".to_string());
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
        _ => Err("unsupportedKeyVersion".to_string()),
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
        _ => Err("unsupportedKeyVersion".to_string()),
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

fn parse_bridge_response(data: &[u8]) -> ProbeResult<SwiftSigningResponse> {
    let response: SwiftSigningResponse =
        serde_json::from_slice(data).map_err(|_| "bridgeResponseJson".to_string())?;
    if response.schema != SWIFT_SIGNING_RESPONSE_SCHEMA || response.status != "passed" {
        return Err("bridgeResponseStatus".to_string());
    }
    let r = hex_decode(&response.r_hex)?;
    let s = hex_decode(&response.s_hex)?;
    if r.len() != 32 || s.len() != 32 {
        return Err("bridgeResponseCoordinateLength".to_string());
    }
    Ok(response)
}

fn maybe_write_result(request: &RustRequest, value: &Value) -> ProbeResult<()> {
    if let Some(path) = &request.result_path {
        write_private_json(path, value)?;
    }
    Ok(())
}

fn expect_failure<F>(passed: &mut u64, failed: &mut u64, body: F)
where
    F: FnOnce() -> ProbeResult<()>,
{
    match body() {
        Ok(()) => *failed += 1,
        Err(_) => *passed += 1,
    }
}

fn read_secure_file(path: &Path) -> ProbeResult<Vec<u8>> {
    validate_private_parent_directory(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "secureOpen".to_string())?;
    validate_open_file(&file)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|_| "secureRead".to_string())?;
    Ok(data)
}

fn write_private_json<T: ?Sized + serde::Serialize>(path: &Path, value: &T) -> ProbeResult<()> {
    let data = serde_json::to_vec(value).map_err(|_| "jsonEncode".to_string())?;
    write_private_bytes(path, &data)
}

fn write_private_bytes(path: &Path, data: &[u8]) -> ProbeResult<()> {
    validate_private_parent_directory(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "secureCreate".to_string())?;
    file.write_all(data)
        .map_err(|_| "secureWrite".to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "secureChmod".to_string())?;
    Ok(())
}

fn remove_secure_file(path: &Path) -> ProbeResult<()> {
    if path.exists() {
        let _ = secure_file_metadata(path)?;
        fs::remove_file(path).map_err(|_| "secureRemove".to_string())?;
    }
    Ok(())
}

fn secure_file_metadata(path: &Path) -> ProbeResult<fs::Metadata> {
    validate_private_parent_directory(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "secureOpen".to_string())?;
    validate_open_file(&file)?;
    file.metadata().map_err(|_| "secureMetadata".to_string())
}

fn validate_private_parent_directory(path: &Path) -> ProbeResult<()> {
    let parent = path.parent().ok_or_else(|| "missingParent".to_string())?;
    validate_private_directory(parent)
}

fn validate_private_directory(path: &Path) -> ProbeResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "directoryMetadata".to_string())?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err("directoryType".to_string());
    }
    if metadata.uid() != unsafe { libc::getuid() } {
        return Err("directoryOwner".to_string());
    }
    if metadata.mode() & 0o777 != 0o700 {
        return Err("directoryMode".to_string());
    }
    Ok(())
}

fn validate_open_file(file: &File) -> ProbeResult<()> {
    let metadata = file.metadata().map_err(|_| "fileMetadata".to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("fileType".to_string());
    }
    if metadata.uid() != unsafe { libc::getuid() } {
        return Err("fileOwner".to_string());
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err("fileMode".to_string());
    }
    Ok(())
}

fn validate_executable(path: &Path) -> ProbeResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "bridgeMetadata".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("bridgeType".to_string());
    }
    if metadata.mode() & 0o111 == 0 {
        return Err("bridgeNotExecutable".to_string());
    }
    Ok(())
}

fn fixed_creation_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_735_689_600)
}

fn hex_encode(input: &[u8]) -> String {
    input.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(input: &str) -> ProbeResult<Vec<u8>> {
    if input.len() % 2 != 0 {
        return Err("hexDecodeOddLength".to_string());
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
        _ => Err("hexDecodeInvalidCharacter".to_string()),
    }
}

fn sanitize_error(error: impl ToString) -> String {
    classify_error(&error.to_string())
}

fn classify_error(message: &str) -> String {
    let lower = message.to_lowercase();
    if lower.contains("unsupported") || lower.contains("sha1") {
        "unsupported".to_string()
    } else if lower.contains("digest") || lower.contains("coordinate") {
        "invalidSignatureShape".to_string()
    } else if lower.contains("symlink")
        || lower.contains("mode")
        || lower.contains("owner")
        || lower.contains("secure")
        || lower.contains("permission")
    {
        "restrictedFileRejected".to_string()
    } else if lower.contains("bridge") {
        "bridgeFailure".to_string()
    } else if lower.contains("binding") || lower.contains("mismatch") || lower.contains("duplicate")
    {
        "publicKeyBinding".to_string()
    } else if lower.contains("certificate") || lower.contains("cert") {
        "certificateValidation".to_string()
    } else {
        "operationFailed".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_external_signer_control_passes() {
        let report = external_signer_control().expect("software control should run");
        assert_eq!(report["status"], "passed");
        assert_eq!(report["candidateCount"], 2);
    }

    #[test]
    fn bound_publics_reject_duplicate_keys() {
        let public = vec![0x04; 65];
        let bound = BoundPublics {
            signing_x963: public.clone(),
            agreement_x963: public,
        };
        assert!(validate_bound_publics(&bound, &bound, "signing", "keyAgreement").is_err());
    }

    #[test]
    fn bridge_response_rejects_short_coordinates() {
        let response = br#"{"schema":"cypherair.se-custody.phase3.signing-response.v1","status":"passed","hashAlgorithm":"sha256","digestByteLength":32,"rHex":"00","sHex":"00","rByteLength":1,"sByteLength":1,"publicKeyRevalidated":true}"#;
        assert!(parse_bridge_response(response).is_err());
    }
}
