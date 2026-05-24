use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use openpgp::crypto::{mpi, KeyPair, Signer as CryptoSigner};
use openpgp::parse::stream::{
    MessageLayer, MessageStructure, VerificationHelper, VerifierBuilder,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{LiteralWriter, Message, Signer as StreamSigner};
use openpgp::serialize::Serialize;
use openpgp::types::{
    Curve, Features, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType,
    SymmetricAlgorithm,
};
use openpgp::{packet, Packet};
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize as SerdeSerialize};
use serde_json::{json, Value};

type ProbeResult<T> = Result<T, String>;

static SHA256_ONLY: [HashAlgorithm; 1] = [HashAlgorithm::SHA256];

#[derive(Clone, Copy)]
enum Mode {
    MockControl,
    SecureEnclaveBindings,
    MessageShapes,
    Failure,
    CapabilityResolver,
}

struct Arguments {
    mode: Mode,
    request: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProbeRequest {
    schema: Option<String>,
    #[serde(rename = "fixturePath")]
    fixture_path: Option<String>,
    #[serde(rename = "signerApp")]
    signer_app: Option<String>,
    #[serde(rename = "bridgeStatePath")]
    bridge_state_path: Option<String>,
    #[serde(rename = "workDirectory")]
    work_directory: Option<String>,
    #[serde(rename = "resultPath")]
    result_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublicFixture {
    schema: String,
    #[serde(rename = "runId")]
    run_id: String,
    #[serde(rename = "secureEnclaveAvailable")]
    secure_enclave_available: bool,
    keys: Vec<PublicFixtureKey>,
    #[serde(rename = "privateMaterialCaptured")]
    private_material_captured: bool,
    #[serde(rename = "keychainLocatorsCaptured")]
    keychain_locators_captured: bool,
}

#[derive(Debug, Deserialize)]
struct PublicFixtureKey {
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

#[derive(Clone)]
struct BridgeConfig {
    signer_app: PathBuf,
    state_path: PathBuf,
    work_directory: PathBuf,
    expected_signing_public_hex: String,
}

#[derive(SerdeSerialize)]
struct BridgeSignRequest<'a> {
    schema: &'a str,
    #[serde(rename = "statePath")]
    state_path: &'a str,
    #[serde(rename = "responsePath")]
    response_path: &'a str,
    #[serde(rename = "hashAlgorithm")]
    hash_algorithm: &'a str,
    #[serde(rename = "digestHex")]
    digest_hex: String,
    #[serde(rename = "expectedSigningPublicKeyX963Hex")]
    expected_signing_public_key_x963_hex: &'a str,
}

#[derive(Debug, Deserialize)]
struct BridgeSignResponse {
    schema: String,
    status: String,
    #[serde(rename = "hashAlgorithm")]
    hash_algorithm: String,
    #[serde(rename = "signatureEncoding")]
    signature_encoding: String,
    #[serde(rename = "rHex")]
    r_hex: String,
    #[serde(rename = "sHex")]
    s_hex: String,
    #[serde(rename = "rLength")]
    r_length: usize,
    #[serde(rename = "sLength")]
    s_length: usize,
    #[serde(rename = "rawSignatureLength")]
    raw_signature_length: usize,
}

struct SecureEnclaveAppSigner {
    public_key: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole>,
    bridge: BridgeConfig,
}

struct MockExternalSigner {
    public_key: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole>,
    inner: KeyPair,
}

struct CertEvidence {
    version: u8,
    cert_bytes: Vec<u8>,
    report: Value,
}

struct VerifyHelper {
    certs: Vec<openpgp::Cert>,
    good_signature: bool,
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
        Mode::MockControl => mock_control(),
        Mode::SecureEnclaveBindings => {
            let request = read_probe_request(required_request(args.request)?)?;
            secure_enclave_bindings(&request)
        }
        Mode::MessageShapes => {
            let request = read_probe_request(required_request(args.request)?)?;
            message_shapes(&request)
        }
        Mode::Failure => {
            let request = read_probe_request(required_request(args.request)?)?;
            failure(&request)
        }
        Mode::CapabilityResolver => Ok(capability_resolver()),
    }
}

fn parse_arguments() -> ProbeResult<Arguments> {
    let mut mode = None;
    let mut request = None;
    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--mode" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missingModeValue".to_string())?;
                mode = Some(match value.as_str() {
                    "mock-control" => Mode::MockControl,
                    "secure-enclave-bindings" => Mode::SecureEnclaveBindings,
                    "message-shapes" => Mode::MessageShapes,
                    "failure" => Mode::Failure,
                    "capability-resolver" => Mode::CapabilityResolver,
                    other => return Err(format!("unsupportedMode:{other}")),
                });
            }
            "--request" => {
                request = Some(
                    iter.next()
                        .ok_or_else(|| "missingRequestValue".to_string())?,
                );
            }
            other => return Err(format!("unexpectedArgument:{other}")),
        }
    }
    Ok(Arguments {
        mode: mode.ok_or_else(|| "missingMode".to_string())?,
        request,
    })
}

fn required_request(request: Option<String>) -> ProbeResult<String> {
    request.ok_or_else(|| "missingRequest".to_string())
}

fn mock_control() -> ProbeResult<Value> {
    let candidates = vec![mock_candidate(4)?, mock_candidate(6)?];
    let message = mock_message_shapes()?;
    let status = if candidates.iter().all(candidate_passed) && report_passed(&message) {
        "passed"
    } else {
        "failed"
    };
    Ok(json!({
        "phase": "phase3",
        "mode": "mock-control",
        "status": status,
        "hashAlgorithm": "SHA256",
        "candidateCount": candidates.len(),
        "candidates": candidates,
        "messageShapes": message,
        "materialsPrinted": false,
        "summary": "Software external signer control exercises the same Sequoia Signer seam and SHA-256 digest path without Secure Enclave hardware."
    }))
}

fn mock_candidate(version: u8) -> ProbeResult<Value> {
    let (bound, mut signer) = software_signer_and_bound(version)?;
    build_candidate(version, &bound, &mut signer).map(|evidence| evidence.report)
}

fn mock_message_shapes() -> ProbeResult<Value> {
    build_mock_message_shapes()
}

fn secure_enclave_bindings(request: &ProbeRequest) -> ProbeResult<Value> {
    let (fixture, bound, bridge) = load_se_request(request)?;
    if !fixture.secure_enclave_available {
        return Ok(json!({
            "phase": "phase3",
            "mode": "secure-enclave-bindings",
            "status": "skipped",
            "secureEnclaveAvailable": false,
            "materialsPrinted": false,
            "summary": "Fixture reports Secure Enclave unavailable; no software fallback attempted."
        }));
    }

    let mut candidates = Vec::new();
    for version in [4_u8, 6_u8] {
        let public = public_signing_key(version, &bound.signing_x963)?.role_into_unspecified();
        let mut signer = SecureEnclaveAppSigner {
            public_key: public,
            bridge: bridge.clone(),
        };
        candidates.push(build_candidate(version, &bound, &mut signer)?.report);
    }
    let status = if candidates.iter().all(candidate_passed) {
        "passed"
    } else {
        "failed"
    };
    let report = json!({
        "phase": "phase3",
        "mode": "secure-enclave-bindings",
        "status": status,
        "secureEnclaveAvailable": true,
        "hashAlgorithm": "SHA256",
        "candidateCount": candidates.len(),
        "candidates": candidates,
        "materialsPrinted": false,
        "summary": "Secure Enclave backed Sequoia Signer produced User ID self-certification and ECDH subkey binding signatures for v4/v6 P-256 candidates."
    });
    write_optional_result(request, &report)?;
    Ok(report)
}

fn message_shapes(request: &ProbeRequest) -> ProbeResult<Value> {
    let (_fixture, bound, bridge) = load_se_request(request)?;
    let mut build_signer = SecureEnclaveAppSigner {
        public_key: public_signing_key(4, &bound.signing_x963)?.role_into_unspecified(),
        bridge: bridge.clone(),
    };
    let cert = build_candidate(4, &bound, &mut build_signer)?;
    let signing_x963 = bound.signing_x963.clone();
    let shapes = build_message_shapes(cert.cert_bytes, || {
        Ok(SecureEnclaveAppSigner {
            public_key: public_signing_key(4, &signing_x963)?.role_into_unspecified(),
            bridge: bridge.clone(),
        })
    })?;
    let status = if report_passed(&shapes) { "passed" } else { "failed" };
    let report = json!({
        "phase": "phase3",
        "mode": "message-shapes",
        "status": status,
        "hashAlgorithm": "SHA256",
        "messageShapes": shapes,
        "materialsPrinted": false,
        "summary": "Secure Enclave backed signer produced detached, cleartext, and binary signed-message shapes accepted by verification paths."
    });
    write_optional_result(request, &report)?;
    Ok(report)
}

fn failure(request: &ProbeRequest) -> ProbeResult<Value> {
    let (_fixture, bound, bridge) = load_se_request(request)?;
    let mut cases = Vec::new();
    cases.push(failure_case("duplicatePublics", || {
        let duplicate = BoundPublics {
            signing_x963: bound.signing_x963.clone(),
            agreement_x963: bound.signing_x963.clone(),
        };
        validate_bound_publics(&bound, &duplicate, signingRole(), key_agreement_role())
    }));
    cases.push(failure_case("swappedPublics", || {
        let swapped = BoundPublics {
            signing_x963: bound.agreement_x963.clone(),
            agreement_x963: bound.signing_x963.clone(),
        };
        validate_bound_publics(&bound, &swapped, signingRole(), key_agreement_role())
    }));
    cases.push(failure_case("wrongRoleMetadata", || {
        validate_bound_publics(&bound, &bound, key_agreement_role(), key_agreement_role())
    }));
    cases.push(failure_case("unsupportedHash", || {
        let mut signer = SecureEnclaveAppSigner {
            public_key: public_signing_key(4, &bound.signing_x963)?.role_into_unspecified(),
            bridge: bridge.clone(),
        };
        signer
            .sign(HashAlgorithm::SHA512, &[0_u8; 64])
            .map(|_| ())
            .map_err(sanitize_error)
    }));
    cases.push(failure_case("wrongDigestLength", || {
        let mut signer = SecureEnclaveAppSigner {
            public_key: public_signing_key(4, &bound.signing_x963)?.role_into_unspecified(),
            bridge: bridge.clone(),
        };
        signer
            .sign(HashAlgorithm::SHA256, &[0_u8; 31])
            .map(|_| ())
            .map_err(sanitize_error)
    }));
    cases.push(failure_case("bridgeFailureNoFallback", || {
        let mut bad_bridge = bridge.clone();
        bad_bridge.signer_app = PathBuf::from("/missing/SecureEnclaveCustodyProbe");
        let mut signer = SecureEnclaveAppSigner {
            public_key: public_signing_key(4, &bound.signing_x963)?.role_into_unspecified(),
            bridge: bad_bridge,
        };
        signer
            .sign(HashAlgorithm::SHA256, &[0_u8; 32])
            .map(|_| ())
            .map_err(sanitize_error)
    }));
    cases.push(failure_case("corruptedSignatureResponse", || {
        let response = BridgeSignResponse {
            schema: response_schema().to_string(),
            status: "passed".to_string(),
            hash_algorithm: "SHA256".to_string(),
            signature_encoding: "ecdsa-rfc4754-raw".to_string(),
            r_hex: "00".to_string(),
            s_hex: "00".to_string(),
            r_length: 1,
            s_length: 1,
            raw_signature_length: 2,
        };
        response_to_signature(response).map(|_| ())
    }));
    cases.push(failure_case("symlinkedRequestFile", || {
        let target = unique_path(&bridge.work_directory, "target", "json");
        let link = unique_path(&bridge.work_directory, "link", "json");
        write_exclusive_0600(&target, b"{}")?;
        std::os::unix::fs::symlink(&target, &link).map_err(|_| "symlink".to_string())?;
        let result = read_strict_file(&link).map(|_| ());
        let _ = fs::remove_file(target);
        let _ = fs::remove_file(link);
        result
    }));

    let status = if cases
        .iter()
        .all(|case| case["rejected"].as_bool() == Some(true))
    {
        "passed"
    } else {
        "failed"
    };
    let report = json!({
        "phase": "phase3",
        "mode": "failure",
        "status": status,
        "caseCount": cases.len(),
        "cases": cases,
        "materialsPrinted": false,
        "summary": "Rust-side bridge and binder reject role/public mismatches, unsupported SHA choices, malformed signatures, unsafe files, and bridge failures without software fallback."
    });
    write_optional_result(request, &report)?;
    Ok(report)
}

fn capability_resolver() -> Value {
    json!({
        "phase": "phase3",
        "mode": "capability-resolver",
        "status": "passed",
        "materialsPrinted": false,
        "rules": [
            {
                "custody": "softwareSecretCertificate",
                "profileASelectableToday": true,
                "profileBSelectableToday": true
            },
            {
                "custody": "appleSecureEnclaveP256",
                "phase3SigningEvidence": true,
                "selectableToday": false,
                "blockedBy": "Phase 4 ECDH session-key recovery and decrypt hard-fail evidence"
            }
        ],
        "summary": "Phase 3 signing evidence does not make Apple Secure Enclave custody product-selectable until Phase 4 decrypt evidence passes."
    })
}

fn load_se_request(request: &ProbeRequest) -> ProbeResult<(PublicFixture, BoundPublics, BridgeConfig)> {
    validate_request_schema(request.schema.as_deref())?;
    let fixture_path = request
        .fixture_path
        .as_ref()
        .ok_or_else(|| "missingFixturePath".to_string())?;
    let signer_app = request
        .signer_app
        .as_ref()
        .ok_or_else(|| "missingSignerApp".to_string())?;
    let state_path = request
        .bridge_state_path
        .as_ref()
        .ok_or_else(|| "missingBridgeStatePath".to_string())?;
    let work_directory = request
        .work_directory
        .as_ref()
        .ok_or_else(|| "missingWorkDirectory".to_string())?;
    validate_owned_dir(Path::new(work_directory), 0o700)?;
    validate_owned_file(Path::new(fixture_path), 0o600)?;
    validate_owned_file(Path::new(state_path), 0o600)?;
    if !Path::new(signer_app).is_file() {
        return Err("signerAppMissing".to_string());
    }

    let fixture: PublicFixture = serde_json::from_slice(&read_strict_file(Path::new(fixture_path))?)
        .map_err(|_| "fixtureJson".to_string())?;
    if fixture.private_material_captured || fixture.keychain_locators_captured {
        return Err("fixtureMaterialPolicy".to_string());
    }
    if !fixture.schema.contains("phase3.fixture") {
        return Err("fixtureSchema".to_string());
    }
    let bound = bound_publics_from_fixture(&fixture)?;
    validate_bound_publics(&bound, &bound, signingRole(), key_agreement_role())?;
    let bridge = BridgeConfig {
        signer_app: PathBuf::from(signer_app),
        state_path: PathBuf::from(state_path),
        work_directory: PathBuf::from(work_directory),
        expected_signing_public_hex: hex_encode(&bound.signing_x963),
    };
    Ok((fixture, bound, bridge))
}

fn build_candidate(
    version: u8,
    bound: &BoundPublics,
    signer: &mut dyn openpgp::crypto::Signer,
) -> ProbeResult<CertEvidence> {
    let primary = public_signing_key(version, &bound.signing_x963)?;
    let subkey = public_agreement_key(version, &bound.agreement_x963)?;
    let user_id: packet::UserID = format!(
        "Phase 3 Secure Enclave Candidate v{version} <phase3-se-v{version}@cypherair.local>"
    )
    .into();
    let features = if version == 4 {
        Features::empty().set_seipdv1()
    } else {
        Features::empty().set_seipdv2()
    };
    let uid_sig = openpgp::packet::signature::SignatureBuilder::new(
        SignatureType::PositiveCertification,
    )
    .set_hash_algo(HashAlgorithm::SHA256)
    .set_signature_creation_time(fixed_creation_time())
    .map_err(sanitize_error)?
    .set_key_flags(KeyFlags::empty().set_certification().set_signing())
    .map_err(sanitize_error)?
    .set_features(features)
    .map_err(sanitize_error)?
    .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA256])
    .map_err(sanitize_error)?
    .set_preferred_symmetric_algorithms(vec![SymmetricAlgorithm::AES256])
    .map_err(sanitize_error)?
    .sign_userid_binding(signer, Some(&primary), &user_id)
    .map_err(sanitize_error)?;
    let subkey_sig =
        openpgp::packet::signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(HashAlgorithm::SHA256)
            .set_signature_creation_time(fixed_creation_time())
            .map_err(sanitize_error)?
            .set_key_flags(KeyFlags::empty().set_transport_encryption())
            .map_err(sanitize_error)?
            .sign_subkey_binding(signer, Some(&primary), &subkey)
            .map_err(sanitize_error)?;

    let cert = openpgp::Cert::from_packets(
        vec![
            Packet::from(primary.clone()),
            Packet::from(user_id.clone()),
            Packet::from(uid_sig),
            Packet::from(subkey.clone()),
            Packet::from(subkey_sig),
        ]
        .into_iter(),
    )
    .map_err(sanitize_error)?;
    let mut cert_bytes = Vec::new();
    cert.serialize(&mut cert_bytes).map_err(sanitize_error)?;
    let validation =
        pgp_mobile::keys::validate_public_certificate(&cert_bytes).map_err(sanitize_error)?;
    let selectors = pgp_mobile::keys::discover_certificate_selectors(&cert_bytes)
        .map_err(sanitize_error)?;
    let policy = StandardPolicy::new();
    let transport_usable = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .for_transport_encryption()
        .next()
        .is_some();
    let ciphertext = pgp_mobile::encrypt::encrypt_binary(
        b"phase3 recipient selection",
        &[cert_bytes.clone()],
        None,
        None,
    )
    .map_err(sanitize_error)?;
    let matched = pgp_mobile::decrypt::match_recipients(&ciphertext, &[cert_bytes.clone()])
        .map_err(sanitize_error)?;
    let report = json!({
        "candidate": format!("p256-v{version}-secure-enclave-signing"),
        "keyVersion": version,
        "hashAlgorithm": "SHA256",
        "primaryAlgorithm": "ECDSA",
        "subkeyAlgorithm": "ECDH",
        "curve": "NIST P-256",
        "userIdSelfCertification": true,
        "ecdhSubkeyBinding": true,
        "validPublicCertificate": validation.public_cert_data == cert_bytes,
        "selectorDiscovery": !selectors.user_ids.is_empty() && !selectors.subkeys.is_empty(),
        "policyUsableForTransportEncryption": transport_usable,
        "transportRecipientSelection": matched.len() == 1,
        "publicCertificateByteLength": cert_bytes.len(),
        "userIdCount": selectors.user_ids.len(),
        "subkeyCount": selectors.subkeys.len(),
        "materialsPrinted": false
    });
    Ok(CertEvidence {
        version,
        cert_bytes,
        report,
    })
}

fn build_message_shapes<F, S>(cert_bytes: Vec<u8>, mut signer_factory: F) -> ProbeResult<Value>
where
    F: FnMut() -> ProbeResult<S>,
    S: openpgp::crypto::Signer + Send + Sync + 'static,
{
    let data = b"phase3 message signing";
    let detached = detached_signature(data, signer_factory()?)?;
    let detached_verified =
        pgp_mobile::verify::verify_detached_detailed(data, &detached, &[cert_bytes.clone()])
            .map_err(sanitize_error)?;

    let cleartext = cleartext_signature(data, signer_factory()?)?;
    let cleartext_verified =
        pgp_mobile::verify::verify_cleartext_detailed(&cleartext, &[cert_bytes.clone()])
            .map_err(sanitize_error)?;
    let binary = binary_signed_message(data, signer_factory()?)?;
    let binary_verified = verify_binary_message(&binary, cert_bytes.clone())?;

    Ok(json!({
        "detached": {
            "produced": true,
            "verified": detached_verified.legacy_status == pgp_mobile::decrypt::SignatureStatus::Valid,
            "signatureByteLength": detached.len()
        },
        "cleartext": {
            "produced": true,
            "verified": cleartext_verified.legacy_status == pgp_mobile::decrypt::SignatureStatus::Valid,
            "signedMessageByteLength": cleartext.len()
        },
        "binary": {
            "produced": true,
            "verified": binary_verified,
            "signedMessageByteLength": binary.len()
        },
        "materialsPrinted": false
    }))
}

fn build_mock_message_shapes() -> ProbeResult<Value> {
    let data = b"phase3 message signing";

    let (detached_cert, detached) = mock_signed_shape(data, detached_signature)?;
    let detached_verified =
        pgp_mobile::verify::verify_detached_detailed(data, &detached, &[detached_cert])
            .map_err(sanitize_error)?;

    let (cleartext_cert, cleartext) = mock_signed_shape(data, cleartext_signature)?;
    let cleartext_verified =
        pgp_mobile::verify::verify_cleartext_detailed(&cleartext, &[cleartext_cert])
            .map_err(sanitize_error)?;

    let (binary_cert, binary) = mock_signed_shape(data, binary_signed_message)?;
    let binary_verified = verify_binary_message(&binary, binary_cert)?;

    Ok(json!({
        "detached": {
            "produced": true,
            "verified": detached_verified.legacy_status == pgp_mobile::decrypt::SignatureStatus::Valid,
            "signatureByteLength": detached.len()
        },
        "cleartext": {
            "produced": true,
            "verified": cleartext_verified.legacy_status == pgp_mobile::decrypt::SignatureStatus::Valid,
            "signedMessageByteLength": cleartext.len()
        },
        "binary": {
            "produced": true,
            "verified": binary_verified,
            "signedMessageByteLength": binary.len()
        },
        "materialsPrinted": false
    }))
}

fn mock_signed_shape<F>(data: &[u8], sign: F) -> ProbeResult<(Vec<u8>, Vec<u8>)>
where
    F: FnOnce(&[u8], MockExternalSigner) -> ProbeResult<Vec<u8>>,
{
    let (bound, mut signer) = software_signer_and_bound(4)?;
    let evidence = build_candidate(4, &bound, &mut signer)?;
    let signed = sign(data, signer)?;
    Ok((evidence.cert_bytes, signed))
}

fn detached_signature<S>(data: &[u8], signer: S) -> ProbeResult<Vec<u8>>
where
    S: openpgp::crypto::Signer + Send + Sync + 'static,
{
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let mut stream = StreamSigner::new(message, signer)
        .map_err(sanitize_error)?
        .hash_algo(HashAlgorithm::SHA256)
        .map_err(sanitize_error)?
        .detached()
        .build()
        .map_err(sanitize_error)?;
    stream.write_all(data).map_err(sanitize_error)?;
    stream.finalize().map_err(sanitize_error)?;
    Ok(sink)
}

fn cleartext_signature<S>(data: &[u8], signer: S) -> ProbeResult<Vec<u8>>
where
    S: openpgp::crypto::Signer + Send + Sync + 'static,
{
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let mut stream = StreamSigner::with_template(
        message,
        signer,
        openpgp::packet::signature::SignatureBuilder::new(SignatureType::Text),
    )
    .map_err(sanitize_error)?
    .hash_algo(HashAlgorithm::SHA256)
    .map_err(sanitize_error)?
    .cleartext()
    .build()
    .map_err(sanitize_error)?;
    stream.write_all(data).map_err(sanitize_error)?;
    stream.finalize().map_err(sanitize_error)?;
    Ok(sink)
}

fn binary_signed_message<S>(data: &[u8], signer: S) -> ProbeResult<Vec<u8>>
where
    S: openpgp::crypto::Signer + Send + Sync + 'static,
{
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = StreamSigner::new(message, signer)
        .map_err(sanitize_error)?
        .hash_algo(HashAlgorithm::SHA256)
        .map_err(sanitize_error)?
        .build()
        .map_err(sanitize_error)?;
    let mut literal = LiteralWriter::new(message).build().map_err(sanitize_error)?;
    literal.write_all(data).map_err(sanitize_error)?;
    literal.finalize().map_err(sanitize_error)?;
    Ok(sink)
}

fn verify_binary_message(signed: &[u8], cert_bytes: Vec<u8>) -> ProbeResult<bool> {
    let cert = openpgp::Cert::from_bytes(&cert_bytes).map_err(sanitize_error)?;
    let helper = VerifyHelper {
        certs: vec![cert],
        good_signature: false,
    };
    let policy = StandardPolicy::new();
    let mut verifier = VerifierBuilder::from_bytes(signed)
        .map_err(sanitize_error)?
        .with_policy(&policy, None, helper)
        .map_err(sanitize_error)?;
    let mut content = Vec::new();
    verifier.read_to_end(&mut content).map_err(sanitize_error)?;
    Ok(verifier.into_helper().good_signature)
}

impl openpgp::crypto::Signer for SecureEnclaveAppSigner {
    fn public(&self) -> &packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> {
        &self.public_key
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &SHA256_ONLY
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        if hash_algo != HashAlgorithm::SHA256 {
            return Err(openpgp::Error::InvalidOperation(
                "phase3UnsupportedHash".to_string(),
            )
            .into());
        }
        if digest.len() != 32 {
            return Err(openpgp::Error::InvalidOperation(
                "phase3WrongDigestLength".to_string(),
            )
            .into());
        }
        bridge_sign(&self.bridge, digest)
            .map_err(|e| openpgp::Error::InvalidOperation(e).into())
    }
}

impl openpgp::crypto::Signer for MockExternalSigner {
    fn public(&self) -> &packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> {
        &self.public_key
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &SHA256_ONLY
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        if hash_algo != HashAlgorithm::SHA256 {
            return Err(openpgp::Error::InvalidOperation(
                "phase3UnsupportedHash".to_string(),
            )
            .into());
        }
        self.inner.sign(hash_algo, digest)
    }
}

impl VerificationHelper for VerifyHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                self.good_signature = results.iter().any(|result| result.is_ok());
            }
        }
        Ok(())
    }
}

fn bridge_sign(bridge: &BridgeConfig, digest: &[u8]) -> ProbeResult<mpi::Signature> {
    validate_owned_dir(&bridge.work_directory, 0o700)?;
    validate_owned_file(&bridge.state_path, 0o600)?;
    let request_path = unique_path(&bridge.work_directory, "sign-request", "json");
    let response_path = unique_path(&bridge.work_directory, "sign-response", "json");
    let state_path = path_string(&bridge.state_path)?;
    let response = path_string(&response_path)?;
    let request = BridgeSignRequest {
        schema: request_schema(),
        state_path: &state_path,
        response_path: &response,
        hash_algorithm: "SHA256",
        digest_hex: hex_encode(digest),
        expected_signing_public_key_x963_hex: &bridge.expected_signing_public_hex,
    };
    let request_bytes = serde_json::to_vec_pretty(&request).map_err(|_| "requestJson".to_string())?;
    write_exclusive_0600(&request_path, &request_bytes)?;
    let output = Command::new(&bridge.signer_app)
        .arg("--mode")
        .arg("sign-digest")
        .arg("--request")
        .arg(&request_path)
        .output()
        .map_err(|_| "bridgeLaunch".to_string());
    let _ = fs::remove_file(&request_path);
    let output = output?;
    if !output.status.success() {
        let _ = fs::remove_file(&response_path);
        return Err("bridgeFailure".to_string());
    }
    let response: BridgeSignResponse =
        serde_json::from_slice(&read_strict_file(&response_path)?)
            .map_err(|_| "bridgeResponseJson".to_string())?;
    let _ = fs::remove_file(&response_path);
    response_to_signature(response)
}

fn response_to_signature(response: BridgeSignResponse) -> ProbeResult<mpi::Signature> {
    if response.schema != response_schema()
        || response.status != "passed"
        || response.hash_algorithm != "SHA256"
        || response.r_length != 32
        || response.s_length != 32
        || response.raw_signature_length != 64
    {
        return Err("bridgeResponseShape".to_string());
    }
    match response.signature_encoding.as_str() {
        "ecdsa-rfc4754-raw" | "ecdsa-x962-der" => {}
        _ => return Err("bridgeSignatureEncoding".to_string()),
    }
    let r = hex_decode(&response.r_hex)?;
    let s = hex_decode(&response.s_hex)?;
    if r.len() != 32 || s.len() != 32 {
        return Err("bridgeSignatureLength".to_string());
    }
    Ok(mpi::Signature::ECDSA {
        r: mpi::MPI::new(&r),
        s: mpi::MPI::new(&s),
    })
}

fn software_signer_and_bound(version: u8) -> ProbeResult<(BoundPublics, MockExternalSigner)> {
    let signing: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole> = match version
    {
        4 => packet::key::Key4::generate_ecc(true, Curve::NistP256)
            .map_err(sanitize_error)?
            .into(),
        6 => packet::key::Key6::generate_ecc(true, Curve::NistP256)
            .map_err(sanitize_error)?
            .into(),
        _ => return Err(format!("unsupportedKeyVersion:{version}")),
    };
    let agreement: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole> =
        match version {
            4 => packet::key::Key4::generate_ecc(false, Curve::NistP256)
                .map_err(sanitize_error)?
                .into(),
            6 => packet::key::Key6::generate_ecc(false, Curve::NistP256)
                .map_err(sanitize_error)?
                .into(),
            _ => return Err(format!("unsupportedKeyVersion:{version}")),
        };
    let bound = BoundPublics {
        signing_x963: x963_from_key(signing.parts_as_public())?,
        agreement_x963: x963_from_key(agreement.parts_as_public())?,
    };
    let public_key = public_signing_key(version, &bound.signing_x963)?.role_into_unspecified();
    let signer = MockExternalSigner {
        public_key,
        inner: signing.into_keypair().map_err(sanitize_error)?,
    };
    Ok((bound, signer))
}

fn bound_publics_from_fixture(fixture: &PublicFixture) -> ProbeResult<BoundPublics> {
    let signing = fixture_key(fixture, signingRole())?;
    let agreement = fixture_key(fixture, key_agreement_role())?;
    validate_fixture_key(signing, "ECDSA")?;
    validate_fixture_key(agreement, "ECDH")?;
    Ok(BoundPublics {
        signing_x963: hex_decode(&signing.public_key_x963_hex)?,
        agreement_x963: hex_decode(&agreement.public_key_x963_hex)?,
    })
}

fn fixture_key<'a>(fixture: &'a PublicFixture, role: &str) -> ProbeResult<&'a PublicFixtureKey> {
    fixture
        .keys
        .iter()
        .find(|key| key.role == role)
        .ok_or_else(|| format!("missingFixtureRole:{role}"))
}

fn validate_fixture_key(key: &PublicFixtureKey, expected_algorithm: &str) -> ProbeResult<()> {
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
    if signing_role != signingRole() {
        return Err("roleBinding:signing".to_string());
    }
    if agreement_role != key_agreement_role() {
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

fn validate_x963_public(bytes: &[u8], name: &str) -> ProbeResult<()> {
    if bytes.len() != 65 {
        return Err(format!("publicKeyFormat:{name}:length"));
    }
    if bytes.first().copied() != Some(0x04) {
        return Err(format!("publicKeyFormat:{name}:prefix"));
    }
    Ok(())
}

fn read_probe_request(path: String) -> ProbeResult<ProbeRequest> {
    let path = Path::new(&path);
    validate_owned_file(path, 0o600)?;
    let request: ProbeRequest =
        serde_json::from_slice(&read_strict_file(path)?).map_err(|_| "requestJson".to_string())?;
    validate_request_schema(request.schema.as_deref())?;
    Ok(request)
}

fn validate_request_schema(schema: Option<&str>) -> ProbeResult<()> {
    match schema {
        None | Some("com.cypherair.poc.secure-enclave-custody.phase3.request.v1") => Ok(()),
        _ => Err("requestSchema".to_string()),
    }
}

fn write_optional_result(request: &ProbeRequest, report: &Value) -> ProbeResult<()> {
    if let Some(path) = &request.result_path {
        write_exclusive_0600(
            Path::new(path),
            serde_json::to_vec_pretty(report)
                .map_err(|_| "resultJson".to_string())?
                .as_slice(),
        )?;
    }
    Ok(())
}

fn validate_owned_dir(path: &Path, mode: u32) -> ProbeResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "filePolicy".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err("filePolicy".to_string());
    }
    validate_owner_mode(&metadata, mode)
}

fn validate_owned_file(path: &Path, mode: u32) -> ProbeResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "filePolicy".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("filePolicy".to_string());
    }
    validate_owner_mode(&metadata, mode)
}

fn validate_owner_mode(metadata: &fs::Metadata, mode: u32) -> ProbeResult<()> {
    if metadata.uid() != unsafe { libc_getuid() } {
        return Err("filePolicy".to_string());
    }
    if metadata.permissions().mode() & 0o777 != mode {
        return Err("filePolicy".to_string());
    }
    Ok(())
}

unsafe fn libc_getuid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    getuid()
}

fn read_strict_file(path: &Path) -> ProbeResult<Vec<u8>> {
    validate_owned_file(path, 0o600)?;
    fs::read(path).map_err(|_| "fileRead".to_string())
}

fn write_exclusive_0600(path: &Path, bytes: &[u8]) -> ProbeResult<()> {
    let parent = path.parent().ok_or_else(|| "filePolicy".to_string())?;
    validate_owned_dir(parent, 0o700)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "filePolicy".to_string())?;
    file.write_all(bytes).map_err(|_| "fileWrite".to_string())?;
    Ok(())
}

fn unique_path(directory: &Path, prefix: &str, ext: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    directory.join(format!("{prefix}-{}-{nanos}.{ext}", std::process::id()))
}

fn path_string(path: &Path) -> ProbeResult<String> {
    path.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "pathEncoding".to_string())
}

fn failure_case<F>(name: &str, operation: F) -> Value
where
    F: FnOnce() -> ProbeResult<()>,
{
    match operation() {
        Ok(()) => json!({
            "name": name,
            "rejected": false,
            "errorClass": "notRejected",
            "materialsPrinted": false
        }),
        Err(error) => json!({
            "name": name,
            "rejected": true,
            "errorClass": classify_error(&error),
            "materialsPrinted": false
        }),
    }
}

fn candidate_passed(candidate: &Value) -> bool {
    candidate["validPublicCertificate"].as_bool() == Some(true)
        && candidate["selectorDiscovery"].as_bool() == Some(true)
        && candidate["policyUsableForTransportEncryption"].as_bool() == Some(true)
        && candidate["transportRecipientSelection"].as_bool() == Some(true)
}

fn report_passed(report: &Value) -> bool {
    report["detached"]["verified"].as_bool() == Some(true)
        && report["cleartext"]["verified"].as_bool() == Some(true)
        && report["binary"]["verified"].as_bool() == Some(true)
}

fn fixed_creation_time() -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_secs(1_735_689_600)
}

fn hex_decode(input: &str) -> ProbeResult<Vec<u8>> {
    if input.len() % 2 != 0 {
        return Err("hexLength".to_string());
    }
    let mut bytes = Vec::with_capacity(input.len() / 2);
    let mut chars = input.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(value: u8) -> ProbeResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("hexCharacter".to_string()),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sanitize_error<E: std::fmt::Display>(error: E) -> String {
    classify_error(&error.to_string())
}

fn classify_error(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("file") || lower.contains("permission") || lower.contains("symlink") {
        "filePolicy".to_string()
    } else if lower.contains("hash") {
        "hashPolicy".to_string()
    } else if lower.contains("digest") {
        "digestPolicy".to_string()
    } else if lower.contains("role") || lower.contains("binding") || lower.contains("public") {
        "bindingPolicy".to_string()
    } else if lower.contains("bridge") || lower.contains("signer") {
        "bridgeFailure".to_string()
    } else if lower.contains("signature") {
        "signatureShape".to_string()
    } else if lower.contains("key") {
        "keyMaterialPolicy".to_string()
    } else {
        "operationFailed".to_string()
    }
}

fn request_schema() -> &'static str {
    "com.cypherair.poc.secure-enclave-custody.phase3.request.v1"
}

fn response_schema() -> &'static str {
    "com.cypherair.poc.secure-enclave-custody.phase3.response.v1"
}

#[allow(non_snake_case)]
fn signingRole() -> &'static str {
    "signing"
}

fn key_agreement_role() -> &'static str {
    "keyAgreement"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_response_requires_fixed_width_rs() {
        let response = BridgeSignResponse {
            schema: response_schema().to_string(),
            status: "passed".to_string(),
            hash_algorithm: "SHA256".to_string(),
            signature_encoding: "ecdsa-rfc4754-raw".to_string(),
            r_hex: "11".repeat(32),
            s_hex: "22".repeat(32),
            r_length: 32,
            s_length: 32,
            raw_signature_length: 64,
        };
        assert!(response_to_signature(response).is_ok());
    }

    #[test]
    fn binder_rejects_duplicate_publics() {
        let public = vec![4_u8; 65];
        let fixture = BoundPublics {
            signing_x963: public.clone(),
            agreement_x963: public.clone(),
        };
        assert!(validate_bound_publics(&fixture, &fixture, signingRole(), key_agreement_role())
            .is_err());
    }
}
