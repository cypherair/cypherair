use std::env;
use std::ffi::OsStr;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use openpgp::cert::Preferences;
use openpgp::crypto::mem::Protected;
use openpgp::crypto::{
    mpi, Decryptor as CryptoDecryptor, KeyPair, SessionKey, Signer as CryptoSigner,
};
use openpgp::packet::Tag;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Signer as StreamSigner};
use openpgp::serialize::Serialize;
use openpgp::types::{
    Curve, Features, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm,
};
use openpgp::{packet, Packet};
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize as SerdeSerialize};
use serde_json::{json, Value};
use zeroize::Zeroize;

type ProbeResult<T> = Result<T, String>;

static SHA256_ONLY: [HashAlgorithm; 1] = [HashAlgorithm::SHA256];

#[derive(Clone, Copy)]
enum Mode {
    MockControl,
    SecureEnclaveDecrypt,
    Failure,
    CapabilityResolver,
    GnuPGMockControl,
    GnuPGInterop,
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
    expected_agreement_public_hex: String,
    shared_secret_lengths: Arc<Mutex<Vec<usize>>>,
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

#[derive(SerdeSerialize)]
struct BridgeDeriveRequest<'a> {
    schema: &'a str,
    #[serde(rename = "statePath")]
    state_path: &'a str,
    #[serde(rename = "responsePath")]
    response_path: &'a str,
    #[serde(rename = "peerPublicKeyX963Hex")]
    peer_public_key_x963_hex: String,
    #[serde(rename = "expectedAgreementPublicKeyX963Hex")]
    expected_agreement_public_key_x963_hex: &'a str,
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

#[derive(Debug, Deserialize)]
struct BridgeDeriveResponse {
    schema: String,
    status: String,
    #[serde(rename = "keyAgreementAlgorithm")]
    key_agreement_algorithm: String,
    #[serde(rename = "sharedSecretHex")]
    shared_secret_hex: String,
    #[serde(rename = "sharedSecretLength")]
    shared_secret_length: usize,
}

struct SecureEnclaveAppSigner {
    public_key: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole>,
    bridge: BridgeConfig,
}

struct MockExternalSigner {
    public_key: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole>,
    inner: KeyPair,
}

struct SecureEnclaveAppDecryptor {
    public_key: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole>,
    bridge: BridgeConfig,
}

#[derive(Clone)]
enum DecryptorSource {
    SecureEnclave(BridgeConfig),
    Mock(KeyPair),
}

struct ExternalDecryptHelper<'a> {
    policy: &'a StandardPolicy<'a>,
    cert: openpgp::Cert,
    verifier_certs: Vec<openpgp::Cert>,
    source: DecryptorSource,
    good_signature: bool,
    session_key_recovered: bool,
}

struct CertEvidence {
    cert_bytes: Vec<u8>,
}

struct GnuPGHarness {
    gpg: PathBuf,
    root: PathBuf,
    home: PathBuf,
    version: String,
}

struct GnuPGImportEvidence {
    processed: usize,
    imported: usize,
}

struct GnuPGStatusEvidence {
    good_sig: bool,
    valid_sig: bool,
    trust_undefined: bool,
    decryption_okay: bool,
}

struct GnuPGKeyEvidence {
    primary_algo_19: bool,
    subkey_algo_18: bool,
    curve_nistp256: bool,
    fingerprint_matched: bool,
}

struct PacketShapeEvidence {
    pkesk_v3_ecdh: bool,
    seipdv1_mdc: bool,
    unexpected_aead: bool,
    pkesk_count: usize,
    seip_version: Option<u8>,
}

struct GnuPGGeneratedKey {
    fingerprint: String,
    public_cert: Vec<u8>,
    key_evidence: GnuPGKeyEvidence,
}

struct GnuPGDecryptResult {
    plaintext: Vec<u8>,
    status: GnuPGStatusEvidence,
}

fn main() {
    match run() {
        Ok(report) => {
            let status = report["status"].as_str().unwrap_or("unknown");
            let mode = report["mode"].as_str().unwrap_or("unknown");
            println!("Phase 4 OpenPGP external decryptor probe: {mode} {status}");
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
                "Phase4OpenPGPExternalDecryptorProbe failed: {}",
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
        Mode::SecureEnclaveDecrypt => {
            let request = read_probe_request(required_request(args.request)?)?;
            secure_enclave_decrypt(&request)
        }
        Mode::Failure => {
            let request = read_probe_request(required_request(args.request)?)?;
            failure(&request)
        }
        Mode::CapabilityResolver => Ok(capability_resolver()),
        Mode::GnuPGMockControl => gnupg_mock_control(),
        Mode::GnuPGInterop => {
            let request = read_probe_request(required_request(args.request)?)?;
            gnupg_interop(&request)
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
                    "mock-control" => Mode::MockControl,
                    "secure-enclave-decrypt" => Mode::SecureEnclaveDecrypt,
                    "failure" => Mode::Failure,
                    "capability-resolver" => Mode::CapabilityResolver,
                    "gnupg-mock-control" => Mode::GnuPGMockControl,
                    "gnupg-interop" => Mode::GnuPGInterop,
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
    let mut candidates = Vec::new();
    for version in [4_u8, 6_u8] {
        let material =
            software_material(version).map_err(|e| format!("mockMaterial:v{version}:{e}"))?;
        let mut cert_signer = material
            .signer()
            .map_err(|e| format!("mockCertSigner:v{version}:{e}"))?;
        let cert = build_candidate_from_keys(
            version,
            material.primary_public(),
            material.agreement_public(),
            &mut cert_signer,
        )
        .map_err(|e| format!("mockBuildCandidate:v{version}:{e}"))?;
        let ciphertext = encrypt_signed_binary(
            &cert.cert_bytes,
            b"phase4 mock decrypt plaintext",
            material
                .signer()
                .map_err(|e| format!("mockMessageSigner:v{version}:{e}"))?,
        )
        .map_err(|e| format!("mockEncrypt:v{version}:{e}"))?;
        let report = decrypt_candidate(
            version,
            &cert.cert_bytes,
            ciphertext,
            b"phase4 mock decrypt plaintext",
            DecryptorSource::Mock(
                material
                    .agreement_keypair()
                    .map_err(|e| format!("mockAgreementKeypair:v{version}:{e}"))?,
            ),
        )
        .map_err(|e| format!("mockDecrypt:v{version}:{e}"))?;
        candidates.push(report);
    }
    let status = if candidates.iter().all(decrypt_candidate_passed) {
        "passed"
    } else {
        "failed"
    };
    Ok(json!({
        "phase": "phase4",
        "mode": "mock-control",
        "status": status,
        "candidateCount": candidates.len(),
        "candidates": candidates,
        "materialsPrinted": false,
        "summary": "Software external decryptor control exercises Sequoia Decryptor plumbing without Secure Enclave hardware."
    }))
}

fn secure_enclave_decrypt(request: &ProbeRequest) -> ProbeResult<Value> {
    let (fixture, bound, bridge) = load_se_request(request)?;
    if !fixture.secure_enclave_available {
        return Ok(json!({
            "phase": "phase4",
            "mode": "secure-enclave-decrypt",
            "status": "skipped",
            "secureEnclaveAvailable": false,
            "materialsPrinted": false,
            "summary": "Fixture reports Secure Enclave unavailable; no software fallback attempted."
        }));
    }

    let plaintext = b"phase4 secure enclave decrypt plaintext";
    let mut candidates = Vec::new();
    for version in [4_u8, 6_u8] {
        let primary = public_signing_key(version, &bound.signing_x963)
            .map_err(|e| format!("seSigningPublic:v{version}:{e}"))?;
        let subkey = public_agreement_key(version, &bound.agreement_x963)
            .map_err(|e| format!("seAgreementPublic:v{version}:{e}"))?;
        let mut cert_signer = SecureEnclaveAppSigner {
            public_key: primary.clone().role_into_unspecified(),
            bridge: bridge.clone(),
        };
        let cert = build_candidate_from_keys(version, primary.clone(), subkey, &mut cert_signer)
            .map_err(|e| format!("seBuildCandidate:v{version}:{e}"))?;
        let ciphertext = encrypt_signed_binary(
            &cert.cert_bytes,
            plaintext,
            SecureEnclaveAppSigner {
                public_key: primary.role_into_unspecified(),
                bridge: bridge.clone(),
            },
        )
        .map_err(|e| format!("seEncrypt:v{version}:{e}"))?;
        let report = decrypt_candidate(
            version,
            &cert.cert_bytes,
            ciphertext,
            plaintext,
            DecryptorSource::SecureEnclave(bridge.clone()),
        )
        .map_err(|e| format!("seDecrypt:v{version}:{e}"))?;
        candidates.push(report);
    }
    let lengths = bridge.shared_secret_lengths();
    let status = if candidates.iter().all(decrypt_candidate_passed)
        && lengths.iter().all(|length| *length == 32)
        && !lengths.is_empty()
    {
        "passed"
    } else {
        "failed"
    };
    let report = json!({
        "phase": "phase4",
        "mode": "secure-enclave-decrypt",
        "status": status,
        "secureEnclaveAvailable": true,
        "keyAgreementAlgorithm": "ecdhKeyExchangeStandard",
        "rawSharedSecretLengths": lengths,
        "candidateCount": candidates.len(),
        "candidates": candidates,
        "materialsPrinted": false,
        "summary": "Secure Enclave backed Sequoia Decryptor recovered OpenPGP session keys and decrypted v4/v6 encrypted messages."
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
        validate_bound_publics(&bound, &duplicate, signing_role(), key_agreement_role())
    }));
    cases.push(failure_case("swappedPublics", || {
        let swapped = BoundPublics {
            signing_x963: bound.agreement_x963.clone(),
            agreement_x963: bound.signing_x963.clone(),
        };
        validate_bound_publics(&bound, &swapped, signing_role(), key_agreement_role())
    }));
    cases.push(failure_case("wrongAgreementPublic", || {
        let mut bad = bridge.clone();
        bad.expected_agreement_public_hex = hex_encode(&bound.signing_x963);
        bridge_derive(&bad, &bound.signing_x963).map(|_| ())
    }));
    cases.push(failure_case("badEphemeralPoint", || {
        bridge_derive(&bridge, &[0_u8; 65]).map(|_| ())
    }));
    cases.push(failure_case("bridgeFailureNoFallback", || {
        let mut bad = bridge.clone();
        bad.signer_app = PathBuf::from("/missing/SecureEnclaveCustodyProbe");
        bridge_derive(&bad, &bound.signing_x963).map(|_| ())
    }));
    cases.push(failure_case("corruptedSharedSecretResponse", || {
        let response = BridgeDeriveResponse {
            schema: derive_response_schema().to_string(),
            status: "passed".to_string(),
            key_agreement_algorithm: "ecdhKeyExchangeStandard".to_string(),
            shared_secret_hex: "00".to_string(),
            shared_secret_length: 1,
        };
        response_to_shared_secret(response).map(|_| ())
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
    cases.push(failure_case("invalidRequestPermissions", || {
        let path = unique_path(&bridge.work_directory, "bad-mode", "json");
        fs::write(&path, b"{}").map_err(|_| "fileWrite".to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .map_err(|_| "filePolicy".to_string())?;
        let result = read_strict_file(&path).map(|_| ());
        let _ = fs::remove_file(path);
        result
    }));

    for version in [4_u8, 6_u8] {
        let primary = public_signing_key(version, &bound.signing_x963)?;
        let subkey = public_agreement_key(version, &bound.agreement_x963)?;
        let mut cert_signer = SecureEnclaveAppSigner {
            public_key: primary.clone().role_into_unspecified(),
            bridge: bridge.clone(),
        };
        let cert = build_candidate_from_keys(version, primary.clone(), subkey, &mut cert_signer)?;
        let ciphertext = encrypt_signed_binary(
            &cert.cert_bytes,
            b"phase4 tamper target",
            SecureEnclaveAppSigner {
                public_key: primary.role_into_unspecified(),
                bridge: bridge.clone(),
            },
        )?;
        cases.push(failure_case(&format!("tamperedSeipdV{version}"), || {
            let tampered = tamper_last_byte(&ciphertext)?;
            decrypt_candidate(
                version,
                &cert.cert_bytes,
                tampered,
                b"phase4 tamper target",
                DecryptorSource::SecureEnclave(bridge.clone()),
            )
            .map(|_| ())
        }));
        cases.push(failure_case(
            &format!("tamperedPkeskMaterialV{version}"),
            || {
                let corrupted = tamper_pkesk_byte(&ciphertext)?;
                decrypt_candidate(
                    version,
                    &cert.cert_bytes,
                    corrupted,
                    b"phase4 tamper target",
                    DecryptorSource::SecureEnclave(bridge.clone()),
                )
                .map(|_| ())
            },
        ));
    }

    let status = if cases
        .iter()
        .all(|case| case["rejected"].as_bool() == Some(true))
    {
        "passed"
    } else {
        "failed"
    };
    let report = json!({
        "phase": "phase4",
        "mode": "failure",
        "status": status,
        "caseCount": cases.len(),
        "cases": cases,
        "materialsPrinted": false,
        "summary": "Rust-side decryptor probe rejects unsafe files, role/public mismatches, bridge failures, tampered PKESK material, and tampered payloads without fallback."
    });
    write_optional_result(request, &report)?;
    Ok(report)
}

fn capability_resolver() -> Value {
    json!({
        "phase": "phase4",
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
                "phase4DecryptEvidenceRequired": true,
                "selectableAfterPhase4": false,
                "blockedBy": "Phase 5 app architecture and lifecycle integration feasibility"
            }
        ],
        "summary": "Phase 4 decrypt evidence is necessary but still not sufficient for product selection until Phase 5 integration evidence exists."
    })
}

fn gnupg_mock_control() -> ProbeResult<Value> {
    let material = software_material(4).map_err(|e| format!("gnupgMockMaterial:{e}"))?;
    let mut cert_signer = material
        .signer()
        .map_err(|e| format!("gnupgMockCertSigner:{e}"))?;
    let cert = build_candidate_from_keys(
        4,
        material.primary_public(),
        material.agreement_public(),
        &mut cert_signer,
    )
    .map_err(|e| format!("gnupgMockBuildCandidate:{e}"))?;
    let cert_shape = phase45_v4_cert_evidence(&cert.cert_bytes)?;
    let cert_fpr = cert_fingerprint_hex(&cert.cert_bytes)?;
    let harness = GnuPGHarness::new(false)?;

    let import = harness.import_public(&cert.cert_bytes)?;
    let listed = harness.list_key_evidence(&cert_fpr)?;

    let plaintext = b"phase4.5 gnupg mock interop plaintext";
    let signature = sign_detached_binary(
        plaintext,
        material
            .signer()
            .map_err(|e| format!("gnupgMockDetachedSigner:{e}"))?,
    )?;
    let verify = harness.verify_detached(&signature, plaintext)?;
    let mut tampered_plaintext = plaintext.to_vec();
    tampered_plaintext[0] ^= 0x01;
    let tampered_verify = harness.verify_detached(&signature, &tampered_plaintext)?;

    let ciphertext = harness.encrypt_to_recipient(&cert_fpr, plaintext)?;
    let packet_shape = packet_shape_evidence(&ciphertext)?;
    assert_gnupg_sev4_packet_shape(&packet_shape)?;
    let decrypt_report = decrypt_candidate(
        4,
        &cert.cert_bytes,
        ciphertext.clone(),
        plaintext,
        DecryptorSource::Mock(
            material
                .agreement_keypair()
                .map_err(|e| format!("gnupgMockAgreement:{e}"))?,
        ),
    )
    .map_err(|e| format!("gnupgMockDecrypt:{e}"))?;
    let tampered_decrypt_rejected = decrypt_candidate(
        4,
        &cert.cert_bytes,
        tamper_last_byte(&ciphertext)?,
        plaintext,
        DecryptorSource::Mock(
            material
                .agreement_keypair()
                .map_err(|e| format!("gnupgMockTamperAgreement:{e}"))?,
        ),
    )
    .is_err();

    let status = if cert_shape["passed"].as_bool() == Some(true)
        && import.imported_or_processed()
        && listed.passed()
        && verify.good_sig
        && verify.valid_sig
        && !tampered_verify.valid_sig
        && decrypt_candidate_plaintext_passed(&decrypt_report)
        && tampered_decrypt_rejected
    {
        "passed"
    } else {
        "failed"
    };

    Ok(json!({
        "phase": "phase4.5",
        "mode": "gnupg-mock-control",
        "status": status,
        "gpgVersion": harness.version.clone(),
        "isolatedGnuPGHome": true,
        "publicCertImport": {
            "processedCount": import.processed,
            "importedCount": import.imported,
            "fingerprintMatched": listed.fingerprint_matched,
            "primaryAlgo19": listed.primary_algo_19,
            "subkeyAlgo18": listed.subkey_algo_18,
            "curveNistp256": listed.curve_nistp256
        },
        "v4PublicCert": cert_shape,
        "seSignGpgVerify": {
            "goodSig": verify.good_sig,
            "validSig": verify.valid_sig,
            "trustUndefinedAccepted": verify.trust_undefined
        },
        "negativeSignatureTamperRejected": !tampered_verify.valid_sig,
        "gpgEncryptSeDecrypt": {
            "packetShape": packet_shape.to_json(),
            "recipientMatched": decrypt_report["recipientMatched"],
            "sessionKeyRecovered": decrypt_report["sessionKeyRecovered"],
            "plaintextMatched": decrypt_report["plaintextMatched"],
            "signatureVerified": decrypt_report["signatureVerified"]
        },
        "negativeCiphertextTamperRejected": tampered_decrypt_rejected,
        "materialsPrinted": false,
        "summary": "Software P-256 v4 control verifies GnuPG import, SE-shaped ECDSA verification, GnuPG v3 ECDH PKESK + SEIPDv1/MDC encryption, and tamper rejection without Secure Enclave hardware."
    }))
}

fn gnupg_interop(request: &ProbeRequest) -> ProbeResult<Value> {
    let (fixture, bound, bridge) = load_se_request(request)?;
    if !fixture.secure_enclave_available {
        let report = json!({
            "phase": "phase4.5",
            "mode": "gnupg-interop",
            "status": "skipped",
            "secureEnclaveAvailable": false,
            "materialsPrinted": false,
            "summary": "Fixture reports Secure Enclave unavailable; no software fallback attempted."
        });
        write_optional_result(request, &report)?;
        return Ok(report);
    }

    let primary = public_signing_key(4, &bound.signing_x963)?;
    let subkey = public_agreement_key(4, &bound.agreement_x963)?;
    let mut cert_signer = SecureEnclaveAppSigner {
        public_key: primary.clone().role_into_unspecified(),
        bridge: bridge.clone(),
    };
    let se_cert = build_candidate_from_keys(4, primary.clone(), subkey, &mut cert_signer)?;
    let cert_shape = phase45_v4_cert_evidence(&se_cert.cert_bytes)?;
    let se_fpr = cert_fingerprint_hex(&se_cert.cert_bytes)?;
    let harness = GnuPGHarness::new(true)?;

    let import = harness.import_public(&se_cert.cert_bytes)?;
    let listed = harness.list_key_evidence(&se_fpr)?;
    let plaintext = b"phase4.5 secure enclave gnupg interop plaintext";

    let signature = sign_detached_binary(
        plaintext,
        SecureEnclaveAppSigner {
            public_key: primary.clone().role_into_unspecified(),
            bridge: bridge.clone(),
        },
    )?;
    let verify = harness.verify_detached(&signature, plaintext)?;
    let mut tampered_plaintext = plaintext.to_vec();
    tampered_plaintext[0] ^= 0x01;
    let tampered_verify = harness.verify_detached(&signature, &tampered_plaintext)?;

    let gpg_to_se = harness.encrypt_to_recipient(&se_fpr, plaintext)?;
    let gpg_to_se_shape = packet_shape_evidence(&gpg_to_se)?;
    assert_gnupg_sev4_packet_shape(&gpg_to_se_shape)?;
    let gpg_to_se_decrypt = decrypt_candidate(
        4,
        &se_cert.cert_bytes,
        gpg_to_se.clone(),
        plaintext,
        DecryptorSource::SecureEnclave(bridge.clone()),
    )?;
    let tampered_gpg_to_se_rejected = decrypt_candidate(
        4,
        &se_cert.cert_bytes,
        tamper_last_byte(&gpg_to_se)?,
        plaintext,
        DecryptorSource::SecureEnclave(bridge.clone()),
    )
    .is_err();

    let gpg_key = harness.generate_p256_key_no_aead()?;
    let se_to_gpg = encrypt_signed_binary(
        &gpg_key.public_cert,
        plaintext,
        SecureEnclaveAppSigner {
            public_key: primary.clone().role_into_unspecified(),
            bridge: bridge.clone(),
        },
    )?;
    let se_to_gpg_shape = packet_shape_evidence(&se_to_gpg)?;
    assert_gnupg_sev4_packet_shape(&se_to_gpg_shape)?;
    let se_to_gpg_decrypt = harness.decrypt_message(&se_to_gpg)?;
    let se_to_gpg_plaintext_matched = se_to_gpg_decrypt.plaintext.as_slice() == plaintext;

    let gpg_signed_to_se =
        harness.sign_encrypt_to_recipient(&gpg_key.fingerprint, &se_fpr, plaintext)?;
    let gpg_signed_to_se_shape = packet_shape_evidence(&gpg_signed_to_se)?;
    assert_gnupg_sev4_packet_shape(&gpg_signed_to_se_shape)?;
    let gpg_signed_to_se_decrypt = decrypt_candidate_with_verifiers(
        4,
        &se_cert.cert_bytes,
        &[gpg_key.public_cert.clone()],
        gpg_signed_to_se,
        plaintext,
        DecryptorSource::SecureEnclave(bridge.clone()),
    )?;

    let lengths = bridge.shared_secret_lengths();
    let status = if cert_shape["passed"].as_bool() == Some(true)
        && import.imported_or_processed()
        && listed.passed()
        && gpg_key.key_evidence.passed()
        && verify.good_sig
        && verify.valid_sig
        && !tampered_verify.valid_sig
        && decrypt_candidate_plaintext_passed(&gpg_to_se_decrypt)
        && tampered_gpg_to_se_rejected
        && se_to_gpg_plaintext_matched
        && se_to_gpg_decrypt.status.good_sig
        && se_to_gpg_decrypt.status.valid_sig
        && se_to_gpg_decrypt.status.decryption_okay
        && decrypt_candidate_passed(&gpg_signed_to_se_decrypt)
        && lengths.iter().all(|length| *length == 32)
        && !lengths.is_empty()
    {
        "passed"
    } else {
        "failed"
    };

    let report = json!({
        "phase": "phase4.5",
        "mode": "gnupg-interop",
        "status": status,
        "secureEnclaveAvailable": true,
        "gpgVersion": harness.version.clone(),
        "isolatedGnuPGHome": true,
        "publicCertImport": {
            "processedCount": import.processed,
            "importedCount": import.imported,
            "fingerprintMatched": listed.fingerprint_matched,
            "primaryAlgo19": listed.primary_algo_19,
            "subkeyAlgo18": listed.subkey_algo_18,
            "curveNistp256": listed.curve_nistp256
        },
        "v4PublicCert": cert_shape,
        "seSignGpgVerify": {
            "goodSig": verify.good_sig,
            "validSig": verify.valid_sig,
            "trustUndefinedAccepted": verify.trust_undefined
        },
        "negativeSignatureTamperRejected": !tampered_verify.valid_sig,
        "gpgEncryptSeDecrypt": {
            "packetShape": gpg_to_se_shape.to_json(),
            "recipientMatched": gpg_to_se_decrypt["recipientMatched"],
            "sessionKeyRecovered": gpg_to_se_decrypt["sessionKeyRecovered"],
            "plaintextMatched": gpg_to_se_decrypt["plaintextMatched"],
            "signatureVerified": gpg_to_se_decrypt["signatureVerified"]
        },
        "negativeCiphertextTamperRejected": tampered_gpg_to_se_rejected,
        "seSignEncryptGpgDecryptVerify": {
            "packetShape": se_to_gpg_shape.to_json(),
            "plaintextMatched": se_to_gpg_plaintext_matched,
            "goodSig": se_to_gpg_decrypt.status.good_sig,
            "validSig": se_to_gpg_decrypt.status.valid_sig,
            "decryptionOkay": se_to_gpg_decrypt.status.decryption_okay
        },
        "gpgSignEncryptSeDecryptVerify": {
            "packetShape": gpg_signed_to_se_shape.to_json(),
            "recipientMatched": gpg_signed_to_se_decrypt["recipientMatched"],
            "sessionKeyRecovered": gpg_signed_to_se_decrypt["sessionKeyRecovered"],
            "plaintextMatched": gpg_signed_to_se_decrypt["plaintextMatched"],
            "signatureVerified": gpg_signed_to_se_decrypt["signatureVerified"]
        },
        "gpgGeneratedRecipient": {
            "primaryAlgo19": gpg_key.key_evidence.primary_algo_19,
            "subkeyAlgo18": gpg_key.key_evidence.subkey_algo_18,
            "curveNistp256": gpg_key.key_evidence.curve_nistp256,
            "fingerprintMatched": gpg_key.key_evidence.fingerprint_matched,
            "explicitNoAeadPreferences": true
        },
        "rawSharedSecretLengths": lengths,
        "materialsPrinted": false,
        "summary": "Secure Enclave P-256 v4 certificate, signing, and ECDH decryptor boundary interoperate with isolated local GnuPG while forcing v3 ECDH PKESK plus SEIPDv1/MDC."
    });
    write_optional_result(request, &report)?;
    Ok(report)
}

fn decrypt_candidate(
    version: u8,
    cert_bytes: &[u8],
    ciphertext: Vec<u8>,
    expected_plaintext: &[u8],
    source: DecryptorSource,
) -> ProbeResult<Value> {
    decrypt_candidate_with_verifiers(
        version,
        cert_bytes,
        &[cert_bytes.to_vec()],
        ciphertext,
        expected_plaintext,
        source,
    )
}

fn decrypt_candidate_with_verifiers(
    version: u8,
    cert_bytes: &[u8],
    verifier_cert_bytes: &[Vec<u8>],
    ciphertext: Vec<u8>,
    expected_plaintext: &[u8],
    source: DecryptorSource,
) -> ProbeResult<Value> {
    let matched = pgp_mobile::decrypt::match_recipients(&ciphertext, &[cert_bytes.to_vec()])
        .map_err(sanitize_error)?;
    let seip_version = seip_version(&ciphertext)?;
    let cert = openpgp::Cert::from_bytes(cert_bytes).map_err(sanitize_error)?;
    let verifier_certs = verifier_cert_bytes
        .iter()
        .map(|bytes| openpgp::Cert::from_bytes(bytes).map_err(sanitize_error))
        .collect::<ProbeResult<Vec<_>>>()?;
    let policy = StandardPolicy::new();
    let helper = ExternalDecryptHelper {
        policy: &policy,
        cert: cert.clone(),
        verifier_certs,
        source,
        good_signature: false,
        session_key_recovered: false,
    };
    let mut decryptor = DecryptorBuilder::from_bytes(&ciphertext)
        .map_err(sanitize_error)?
        .with_policy(&policy, None, helper)
        .map_err(sanitize_error)?;
    let mut plaintext = Vec::new();
    if let Err(error) = decryptor.read_to_end(&mut plaintext) {
        plaintext.zeroize();
        return Err(sanitize_error(error));
    }
    let helper = decryptor.into_helper();
    let plaintext_matches = plaintext == expected_plaintext;
    plaintext.zeroize();
    Ok(json!({
        "candidate": format!("p256-v{version}-secure-enclave-ecdh"),
        "keyVersion": version,
        "seipVersion": seip_version,
        "recipientMatched": matched.len() == 1,
        "sessionKeyRecovered": helper.session_key_recovered,
        "plaintextMatched": plaintext_matches,
        "signatureVerified": helper.good_signature,
        "publicCertificateByteLength": cert_bytes.len(),
        "ciphertextByteLength": ciphertext.len(),
        "materialsPrinted": false
    }))
}

impl<'a> DecryptionHelper for ExternalDecryptHelper<'a> {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        for pkesk in pkesks {
            for ka in self
                .cert
                .keys()
                .with_policy(self.policy, None)
                .supported()
                .key_handles(pkesk.recipient())
                .for_transport_encryption()
            {
                let mut decryptor: Box<dyn CryptoDecryptor> = match &self.source {
                    DecryptorSource::SecureEnclave(bridge) => Box::new(SecureEnclaveAppDecryptor {
                        public_key: ka.key().clone().role_into_unspecified(),
                        bridge: bridge.clone(),
                    }),
                    DecryptorSource::Mock(keypair) => Box::new(keypair.clone()),
                };
                if let Some((algo, session_key)) = pkesk.decrypt(decryptor.as_mut(), sym_algo) {
                    self.session_key_recovered = true;
                    if decrypt(algo, &session_key) {
                        return Ok(None);
                    }
                }
            }
        }
        Err(openpgp::anyhow::anyhow!("No key to decrypt message"))
    }
}

impl<'a> VerificationHelper for ExternalDecryptHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.verifier_certs.clone())
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

impl CryptoDecryptor for SecureEnclaveAppDecryptor {
    fn public(&self) -> &packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> {
        &self.public_key
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        let peer_public = match ciphertext {
            mpi::Ciphertext::ECDH { e, .. } => e.value().to_vec(),
            _ => {
                return Err(openpgp::Error::InvalidOperation(
                    "phase4ExpectedECDHCiphertext".to_string(),
                )
                .into())
            }
        };
        let shared_secret = bridge_derive(&self.bridge, &peer_public)
            .map_err(|e| openpgp::Error::InvalidOperation(e))?;
        let protected: Protected = shared_secret.into();
        openpgp::crypto::ecdh::decrypt_unwrap(
            &self.public_key,
            &protected,
            ciphertext,
            plaintext_len,
        )
    }
}

impl CryptoSigner for SecureEnclaveAppSigner {
    fn public(&self) -> &packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> {
        &self.public_key
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &SHA256_ONLY
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        if hash_algo != HashAlgorithm::SHA256 {
            return Err(
                openpgp::Error::InvalidOperation("phase4UnsupportedHash".to_string()).into(),
            );
        }
        if digest.len() != 32 {
            return Err(
                openpgp::Error::InvalidOperation("phase4WrongDigestLength".to_string()).into(),
            );
        }
        bridge_sign(&self.bridge, digest).map_err(|e| openpgp::Error::InvalidOperation(e).into())
    }
}

impl CryptoSigner for MockExternalSigner {
    fn public(&self) -> &packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> {
        &self.public_key
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &SHA256_ONLY
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        if hash_algo != HashAlgorithm::SHA256 {
            return Err(
                openpgp::Error::InvalidOperation("phase4UnsupportedHash".to_string()).into(),
            );
        }
        self.inner.sign(hash_algo, digest)
    }
}

fn build_candidate_from_keys(
    version: u8,
    primary: packet::Key<packet::key::PublicParts, packet::key::PrimaryRole>,
    subkey: packet::Key<packet::key::PublicParts, packet::key::SubordinateRole>,
    signer: &mut dyn CryptoSigner,
) -> ProbeResult<CertEvidence> {
    let user_id: packet::UserID = format!(
        "Phase 4 Secure Enclave Candidate v{version} <phase4-se-v{version}@cypherair.local>"
    )
    .into();
    let features = if version == 4 {
        Features::empty().set_seipdv1()
    } else {
        Features::empty().set_seipdv2()
    };
    let uid_sig =
        openpgp::packet::signature::SignatureBuilder::new(SignatureType::PositiveCertification)
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
            Packet::from(primary),
            Packet::from(user_id),
            Packet::from(uid_sig),
            Packet::from(subkey),
            Packet::from(subkey_sig),
        ]
        .into_iter(),
    )
    .map_err(sanitize_error)?;
    let mut cert_bytes = Vec::new();
    cert.serialize(&mut cert_bytes).map_err(sanitize_error)?;
    let validation =
        pgp_mobile::keys::validate_public_certificate(&cert_bytes).map_err(sanitize_error)?;
    let selectors =
        pgp_mobile::keys::discover_certificate_selectors(&cert_bytes).map_err(sanitize_error)?;
    if validation.public_cert_data != cert_bytes {
        return Err("candidateCertificateValidation".to_string());
    }
    if selectors.user_ids.is_empty() || selectors.subkeys.is_empty() {
        return Err("candidateSelectorDiscovery".to_string());
    }
    Ok(CertEvidence { cert_bytes })
}

fn encrypt_signed_binary<S>(cert_bytes: &[u8], plaintext: &[u8], signer: S) -> ProbeResult<Vec<u8>>
where
    S: CryptoSigner + Send + Sync + 'static,
{
    let cert = openpgp::Cert::from_bytes(cert_bytes).map_err(sanitize_error)?;
    let policy = StandardPolicy::new();
    let recipients: Vec<_> = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .key_flags(&KeyFlags::empty().set_transport_encryption())
        .collect();
    if recipients.is_empty() {
        return Err("noTransportRecipient".to_string());
    }
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .map_err(sanitize_error)?;
    let message = StreamSigner::new(message, signer)
        .map_err(sanitize_error)?
        .hash_algo(HashAlgorithm::SHA256)
        .map_err(sanitize_error)?
        .build()
        .map_err(sanitize_error)?;
    let mut literal = LiteralWriter::new(message)
        .build()
        .map_err(sanitize_error)?;
    literal.write_all(plaintext).map_err(sanitize_error)?;
    literal.finalize().map_err(sanitize_error)?;
    Ok(sink)
}

fn sign_detached_binary<S>(plaintext: &[u8], signer: S) -> ProbeResult<Vec<u8>>
where
    S: CryptoSigner + Send + Sync + 'static,
{
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let mut signer = StreamSigner::new(message, signer)
        .map_err(sanitize_error)?
        .detached()
        .hash_algo(HashAlgorithm::SHA256)
        .map_err(sanitize_error)?
        .build()
        .map_err(sanitize_error)?;
    signer.write_all(plaintext).map_err(sanitize_error)?;
    signer.finalize().map_err(sanitize_error)?;
    Ok(sink)
}

impl GnuPGHarness {
    fn new(start_agent: bool) -> ProbeResult<Self> {
        let gpg = find_gpg()?;
        let version = gpg_version(&gpg)?;
        let root = create_private_temp_dir("cypherair-phase45-gnupg")?;
        let home = root.join("gnupg");
        fs::create_dir(&home).map_err(|_| "gpgHomeCreate".to_string())?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
            .map_err(|_| "gpgHomePolicy".to_string())?;
        validate_owned_dir(&home, 0o700)?;
        write_exclusive_0600(
            &home.join("gpg.conf"),
            b"no-tty\nbatch\nyes\ntrust-model always\nforce-mdc\n",
        )?;
        write_exclusive_0600(
            &home.join("gpg-agent.conf"),
            b"allow-loopback-pinentry\nallow-preset-passphrase\n",
        )?;
        let harness = Self {
            gpg,
            root,
            home,
            version,
        };
        if start_agent {
            harness.start_agent()?;
        }
        Ok(harness)
    }

    fn start_agent(&self) -> ProbeResult<()> {
        let output = Command::new("gpg-agent")
            .env("GNUPGHOME", &self.home)
            .arg("--homedir")
            .arg(&self.home)
            .arg("--daemon")
            .output()
            .map_err(|_| "gpgAgentLaunch".to_string())?;
        if output.status.success() {
            Ok(())
        } else {
            Err("gpgAgentUnavailable".to_string())
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.gpg);
        command.env("GNUPGHOME", &self.home);
        command.arg("--homedir").arg(&self.home);
        command.arg("--batch");
        command.arg("--yes");
        command.arg("--no-tty");
        command.arg("--no-auto-key-locate");
        command.arg("--trust-model").arg("always");
        command
    }

    fn run<I, S>(&self, args: I, label: &str) -> ProbeResult<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = self.command();
        command.args(args);
        run_command(&mut command, label)
    }

    fn private_file(&self, prefix: &str, ext: &str, bytes: &[u8]) -> ProbeResult<PathBuf> {
        let path = unique_path(&self.home, prefix, ext);
        write_exclusive_0600(&path, bytes)?;
        Ok(path)
    }

    fn import_public(&self, cert_bytes: &[u8]) -> ProbeResult<GnuPGImportEvidence> {
        let cert_path = self.private_file("public-cert", "pgp", cert_bytes)?;
        let output = self.run(
            [
                OsStr::new("--status-fd"),
                OsStr::new("1"),
                OsStr::new("--import"),
                cert_path.as_os_str(),
            ],
            "gpgImport",
        )?;
        let _ = fs::remove_file(cert_path);
        let evidence = parse_import_evidence(&output.stdout)?;
        if !output.status.success() && !evidence.imported_or_processed() {
            require_success(&output, "gpgImport")?;
        }
        Ok(evidence)
    }

    fn list_key_evidence(&self, fingerprint: &str) -> ProbeResult<GnuPGKeyEvidence> {
        let colons = self.list_key_colons(fingerprint)?;
        parse_gpg_key_evidence(&colons, fingerprint)
    }

    fn list_key_colons(&self, query: &str) -> ProbeResult<String> {
        let output = self.run(
            ["--with-colons", "--fixed-list-mode", "--list-keys", query],
            "gpgListKeys",
        )?;
        require_success(&output, "gpgListKeys")?;
        String::from_utf8(output.stdout).map_err(|_| "gpgListUtf8".to_string())
    }

    fn verify_detached(
        &self,
        signature: &[u8],
        plaintext: &[u8],
    ) -> ProbeResult<GnuPGStatusEvidence> {
        let sig_path = self.private_file("detached-signature", "sig", signature)?;
        let data_path = self.private_file("detached-data", "bin", plaintext)?;
        let output = self.run(
            [
                OsStr::new("--status-fd"),
                OsStr::new("1"),
                OsStr::new("--verify"),
                sig_path.as_os_str(),
                data_path.as_os_str(),
            ],
            "gpgVerifyDetached",
        )?;
        let _ = fs::remove_file(sig_path);
        let _ = fs::remove_file(data_path);
        Ok(parse_gpg_status(&output.stdout))
    }

    fn encrypt_to_recipient(
        &self,
        recipient_fingerprint: &str,
        plaintext: &[u8],
    ) -> ProbeResult<Vec<u8>> {
        let plaintext_path = self.private_file("encrypt-plaintext", "bin", plaintext)?;
        let output_path = unique_path(&self.home, "encrypt-output", "gpg");
        let output = self.run(
            [
                OsStr::new("--recipient"),
                OsStr::new(recipient_fingerprint),
                OsStr::new("--output"),
                output_path.as_os_str(),
                OsStr::new("--encrypt"),
                plaintext_path.as_os_str(),
            ],
            "gpgEncrypt",
        )?;
        let _ = fs::remove_file(plaintext_path);
        require_success(&output, "gpgEncrypt")?;
        let ciphertext = fs::read(&output_path).map_err(|_| "gpgOutputRead".to_string())?;
        let _ = fs::remove_file(output_path);
        Ok(ciphertext)
    }

    fn generate_p256_key_no_aead(&self) -> ProbeResult<GnuPGGeneratedKey> {
        let params = b"%no-protection
Key-Type: ECDSA
Key-Curve: nistp256
Key-Usage: sign,cert
Subkey-Type: ECDH
Subkey-Curve: nistp256
Subkey-Usage: encrypt
Name-Real: Phase 45 GnuPG P256
Name-Email: phase45-gnupg-p256@example.invalid
Expire-Date: 0
Preferences: AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB ZIP
%commit
";
        let params_path = self.private_file("keygen-params", "txt", params)?;
        let output = self.run(
            [
                OsStr::new("--pinentry-mode"),
                OsStr::new("loopback"),
                OsStr::new("--gen-key"),
                params_path.as_os_str(),
            ],
            "gpgKeygen",
        )?;
        let _ = fs::remove_file(params_path);
        require_success(&output, "gpgKeygen")?;
        let colons = self.list_key_colons("phase45-gnupg-p256@example.invalid")?;
        let fingerprint = first_colons_fingerprint(&colons)?;
        let key_evidence = parse_gpg_key_evidence(&colons, &fingerprint)?;
        let public_cert = self.export_public(&fingerprint)?;
        Ok(GnuPGGeneratedKey {
            fingerprint,
            public_cert,
            key_evidence,
        })
    }

    fn export_public(&self, fingerprint: &str) -> ProbeResult<Vec<u8>> {
        let output_path = unique_path(&self.home, "export-public", "pgp");
        let output = self.run(
            [
                OsStr::new("--output"),
                output_path.as_os_str(),
                OsStr::new("--export"),
                OsStr::new(fingerprint),
            ],
            "gpgExport",
        )?;
        require_success(&output, "gpgExport")?;
        let public_cert = fs::read(&output_path).map_err(|_| "gpgOutputRead".to_string())?;
        let _ = fs::remove_file(output_path);
        Ok(public_cert)
    }

    fn decrypt_message(&self, message: &[u8]) -> ProbeResult<GnuPGDecryptResult> {
        let message_path = self.private_file("decrypt-message", "gpg", message)?;
        let output_path = unique_path(&self.home, "decrypt-output", "bin");
        let output = self.run(
            [
                OsStr::new("--status-fd"),
                OsStr::new("1"),
                OsStr::new("--pinentry-mode"),
                OsStr::new("loopback"),
                OsStr::new("--output"),
                output_path.as_os_str(),
                OsStr::new("--decrypt"),
                message_path.as_os_str(),
            ],
            "gpgDecrypt",
        )?;
        let _ = fs::remove_file(message_path);
        require_success(&output, "gpgDecrypt")?;
        let plaintext = fs::read(&output_path).map_err(|_| "gpgOutputRead".to_string())?;
        let _ = fs::remove_file(output_path);
        Ok(GnuPGDecryptResult {
            plaintext,
            status: parse_gpg_status(&output.stdout),
        })
    }

    fn sign_encrypt_to_recipient(
        &self,
        signer_fingerprint: &str,
        recipient_fingerprint: &str,
        plaintext: &[u8],
    ) -> ProbeResult<Vec<u8>> {
        let plaintext_path = self.private_file("sign-encrypt-plaintext", "bin", plaintext)?;
        let output_path = unique_path(&self.home, "sign-encrypt-output", "gpg");
        let output = self.run(
            [
                OsStr::new("--status-fd"),
                OsStr::new("1"),
                OsStr::new("--pinentry-mode"),
                OsStr::new("loopback"),
                OsStr::new("--local-user"),
                OsStr::new(signer_fingerprint),
                OsStr::new("--recipient"),
                OsStr::new(recipient_fingerprint),
                OsStr::new("--output"),
                output_path.as_os_str(),
                OsStr::new("--sign"),
                OsStr::new("--encrypt"),
                plaintext_path.as_os_str(),
            ],
            "gpgSignEncrypt",
        )?;
        let _ = fs::remove_file(plaintext_path);
        require_success(&output, "gpgSignEncrypt")?;
        let ciphertext = fs::read(&output_path).map_err(|_| "gpgOutputRead".to_string())?;
        let _ = fs::remove_file(output_path);
        Ok(ciphertext)
    }
}

impl Drop for GnuPGHarness {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", &self.home)
            .arg("--homedir")
            .arg(&self.home)
            .arg("--kill")
            .arg("gpg-agent")
            .output();
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl GnuPGImportEvidence {
    fn imported_or_processed(&self) -> bool {
        self.imported > 0 || self.processed > 0
    }
}

impl GnuPGKeyEvidence {
    fn passed(&self) -> bool {
        self.primary_algo_19
            && self.subkey_algo_18
            && self.curve_nistp256
            && self.fingerprint_matched
    }
}

impl PacketShapeEvidence {
    fn to_json(&self) -> Value {
        json!({
            "pkeskVersion3Ecdh": self.pkesk_v3_ecdh,
            "seipdv1Mdc": self.seipdv1_mdc,
            "unexpectedAeadTag20": self.unexpected_aead,
            "pkeskCount": self.pkesk_count,
            "seipVersion": self.seip_version
        })
    }
}

fn find_gpg() -> ProbeResult<PathBuf> {
    for candidate in [
        "gpg",
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        "/usr/bin/gpg",
    ] {
        let output = Command::new(candidate).arg("--version").output();
        if matches!(output, Ok(ref value) if value.status.success()) {
            return Ok(PathBuf::from(candidate));
        }
    }
    Err("gpgUnavailable".to_string())
}

fn gpg_version(gpg: &Path) -> ProbeResult<String> {
    let output = Command::new(gpg)
        .arg("--version")
        .output()
        .map_err(|_| "gpgVersion".to_string())?;
    require_success(&output, "gpgVersion")?;
    let text = String::from_utf8(output.stdout).map_err(|_| "gpgVersionUtf8".to_string())?;
    Ok(text
        .lines()
        .next()
        .unwrap_or("gpg version unavailable")
        .to_string())
}

fn run_command(command: &mut Command, label: &str) -> ProbeResult<Output> {
    command.output().map_err(|_| label.to_string())
}

fn require_success(output: &Output, label: &str) -> ProbeResult<()> {
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{label}:{}", gpg_failure_hint(output)))
    }
}

fn gpg_failure_hint(output: &Output) -> &'static str {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout).to_ascii_lowercase());
    text.push_str(&String::from_utf8_lossy(&output.stderr).to_ascii_lowercase());
    if text.contains("invalid option") {
        "invalidOption"
    } else if text.contains("no valid openpgp data") {
        "noValidOpenPGPData"
    } else if text.contains("no user id") {
        "noUserID"
    } else if text.contains("keybox") || text.contains("resource") {
        "keyboxUnavailable"
    } else if text.contains("permission") || text.contains("operation not permitted") {
        "filePolicy"
    } else if text.contains("agent") || text.contains("pinentry") {
        "gpgAgent"
    } else if text.contains("import") {
        "importRejected"
    } else {
        "commandFailed"
    }
}

fn parse_import_evidence(stdout: &[u8]) -> ProbeResult<GnuPGImportEvidence> {
    let text = String::from_utf8_lossy(stdout);
    let mut processed = 0;
    let mut imported = 0;
    for line in text.lines().filter(|line| line.starts_with("[GNUPG:] ")) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 5 && fields[1] == "IMPORT_RES" {
            processed = fields[2].parse().unwrap_or(0);
            imported = fields[4].parse().unwrap_or(0);
        } else if fields.len() >= 2 && fields[1] == "IMPORT_OK" {
            processed += 1;
        }
    }
    if processed == 0 && imported == 0 {
        Err("gpgImportStatus".to_string())
    } else {
        Ok(GnuPGImportEvidence {
            processed,
            imported,
        })
    }
}

fn parse_gpg_status(stdout: &[u8]) -> GnuPGStatusEvidence {
    let text = String::from_utf8_lossy(stdout);
    GnuPGStatusEvidence {
        good_sig: text
            .lines()
            .any(|line| line.starts_with("[GNUPG:] GOODSIG ")),
        valid_sig: text
            .lines()
            .any(|line| line.starts_with("[GNUPG:] VALIDSIG ")),
        trust_undefined: text
            .lines()
            .any(|line| line.starts_with("[GNUPG:] TRUST_UNDEFINED")),
        decryption_okay: text
            .lines()
            .any(|line| line.starts_with("[GNUPG:] DECRYPTION_OKAY")),
    }
}

fn parse_gpg_key_evidence(
    colons: &str,
    expected_fingerprint: &str,
) -> ProbeResult<GnuPGKeyEvidence> {
    let expected = expected_fingerprint.replace(' ', "").to_ascii_uppercase();
    let mut primary_algo_19 = false;
    let mut subkey_algo_18 = false;
    let mut primary_nistp256 = false;
    let mut subkey_nistp256 = false;
    let mut fingerprint_matched = false;
    for line in colons.lines() {
        let fields: Vec<_> = line.split(':').collect();
        match fields.first().copied() {
            Some("pub") => {
                primary_algo_19 |= fields.get(3).copied() == Some("19");
                primary_nistp256 |= fields.iter().any(|field| *field == "nistp256");
            }
            Some("sub") => {
                subkey_algo_18 |= fields.get(3).copied() == Some("18");
                subkey_nistp256 |= fields.iter().any(|field| *field == "nistp256");
            }
            Some("fpr") => {
                fingerprint_matched |= fields
                    .get(9)
                    .map(|fpr| fpr.to_ascii_uppercase() == expected)
                    .unwrap_or(false);
            }
            _ => {}
        }
    }
    Ok(GnuPGKeyEvidence {
        primary_algo_19,
        subkey_algo_18,
        curve_nistp256: primary_nistp256 && subkey_nistp256,
        fingerprint_matched,
    })
}

fn first_colons_fingerprint(colons: &str) -> ProbeResult<String> {
    colons
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.first().copied() == Some("fpr"))
                .then(|| fields.get(9).map(|fpr| fpr.to_string()))
                .flatten()
        })
        .ok_or_else(|| "gpgFingerprintMissing".to_string())
}

fn cert_fingerprint_hex(cert_bytes: &[u8]) -> ProbeResult<String> {
    Ok(openpgp::Cert::from_bytes(cert_bytes)
        .map_err(sanitize_error)?
        .fingerprint()
        .to_hex()
        .to_ascii_uppercase())
}

fn phase45_v4_cert_evidence(cert_bytes: &[u8]) -> ProbeResult<Value> {
    let cert = openpgp::Cert::from_bytes(cert_bytes).map_err(sanitize_error)?;
    let policy = StandardPolicy::new();
    let primary = cert.primary_key().key();
    let primary_v4 = primary.version() == 4;
    let primary_ecdsa_p256 = matches!(
        primary.mpis(),
        mpi::PublicKey::ECDSA {
            curve: Curve::NistP256,
            ..
        }
    ) && primary.pk_algo() == PublicKeyAlgorithm::ECDSA;
    let subkey = cert
        .keys()
        .subkeys()
        .next()
        .ok_or_else(|| "phase45MissingSubkey".to_string())?;
    let subkey_v4 = subkey.key().version() == 4;
    let subkey_ecdh_p256_sha256_aes256 = matches!(
        subkey.key().mpis(),
        mpi::PublicKey::ECDH {
            curve: Curve::NistP256,
            hash: HashAlgorithm::SHA256,
            sym: SymmetricAlgorithm::AES256,
            ..
        }
    ) && subkey.key().pk_algo() == PublicKeyAlgorithm::ECDH;

    let valid = cert.with_policy(&policy, None).map_err(sanitize_error)?;
    let primary_flags = valid
        .primary_key()
        .key_flags()
        .unwrap_or_else(KeyFlags::empty);
    let primary_flags_sign_cert = primary_flags.for_certification() && primary_flags.for_signing();
    let transport_subkeys = valid.keys().subkeys().for_transport_encryption().count();
    let features = valid
        .primary_userid()
        .map_err(sanitize_error)?
        .features()
        .ok_or_else(|| "phase45MissingFeatures".to_string())?;
    let seipdv1_only = features.supports_seipdv1() && !features.supports_seipdv2();
    let passed = primary_v4
        && primary_ecdsa_p256
        && primary_flags_sign_cert
        && subkey_v4
        && subkey_ecdh_p256_sha256_aes256
        && transport_subkeys == 1
        && seipdv1_only;
    Ok(json!({
        "passed": passed,
        "primaryV4": primary_v4,
        "primaryEcdsaP256": primary_ecdsa_p256,
        "primaryFlagsCertSign": primary_flags_sign_cert,
        "subkeyV4": subkey_v4,
        "subkeyEcdhP256Sha256Aes256": subkey_ecdh_p256_sha256_aes256,
        "transportEncryptionSubkeyCount": transport_subkeys,
        "featuresSeipdv1Only": seipdv1_only
    }))
}

fn packet_shape_evidence(ciphertext: &[u8]) -> ProbeResult<PacketShapeEvidence> {
    let mut ppr = PacketParser::from_bytes(ciphertext).map_err(sanitize_error)?;
    let mut pkesk_v3_ecdh = false;
    let mut seip_version_value = None;
    let mut unexpected_aead = false;
    let mut pkesk_count = 0;
    while let PacketParserResult::Some(pp) = ppr {
        if pp.packet.tag() == Tag::AED {
            unexpected_aead = true;
        }
        match &pp.packet {
            Packet::PKESK(pkesk) => {
                pkesk_count += 1;
                pkesk_v3_ecdh |=
                    pkesk.version() == 3 && pkesk.pk_algo() == PublicKeyAlgorithm::ECDH;
            }
            Packet::SEIP(seip) => {
                seip_version_value = Some(seip.version());
            }
            _ => {}
        }
        let (_, next) = pp.recurse().map_err(sanitize_error)?;
        ppr = next;
    }
    Ok(PacketShapeEvidence {
        pkesk_v3_ecdh,
        seipdv1_mdc: seip_version_value == Some(1),
        unexpected_aead,
        pkesk_count,
        seip_version: seip_version_value,
    })
}

fn assert_gnupg_sev4_packet_shape(shape: &PacketShapeEvidence) -> ProbeResult<()> {
    if shape.unexpected_aead {
        return Err("unexpectedGnuPGAEADForSEV4".to_string());
    }
    if !shape.pkesk_v3_ecdh {
        return Err("missingPkeskV3Ecdh".to_string());
    }
    if !shape.seipdv1_mdc {
        return Err("missingSeipdv1Mdc".to_string());
    }
    Ok(())
}

struct SoftwareMaterial {
    signing: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole>,
    agreement: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole>,
}

impl SoftwareMaterial {
    fn primary_public(&self) -> packet::Key<packet::key::PublicParts, packet::key::PrimaryRole> {
        self.signing.clone().parts_into_public().role_into_primary()
    }

    fn agreement_public(
        &self,
    ) -> packet::Key<packet::key::PublicParts, packet::key::SubordinateRole> {
        self.agreement
            .clone()
            .parts_into_public()
            .role_into_subordinate()
    }

    fn signer(&self) -> ProbeResult<MockExternalSigner> {
        Ok(MockExternalSigner {
            public_key: self
                .signing
                .clone()
                .parts_into_public()
                .role_into_unspecified(),
            inner: self
                .signing
                .clone()
                .into_keypair()
                .map_err(sanitize_error)?,
        })
    }

    fn agreement_keypair(&self) -> ProbeResult<KeyPair> {
        self.agreement
            .clone()
            .into_keypair()
            .map_err(sanitize_error)
    }
}

fn software_material(version: u8) -> ProbeResult<SoftwareMaterial> {
    let mut signing: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole> =
        match version {
            4 => packet::key::Key4::generate_ecc(true, Curve::NistP256)
                .map_err(sanitize_error)?
                .into(),
            6 => packet::key::Key6::generate_ecc(true, Curve::NistP256)
                .map_err(sanitize_error)?
                .into(),
            _ => return Err(format!("unsupportedKeyVersion:{version}")),
        };
    let mut agreement: packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole> =
        match version {
            4 => packet::key::Key4::generate_ecc(false, Curve::NistP256)
                .map_err(sanitize_error)?
                .into(),
            6 => packet::key::Key6::generate_ecc(false, Curve::NistP256)
                .map_err(sanitize_error)?
                .into(),
            _ => return Err(format!("unsupportedKeyVersion:{version}")),
        };
    signing
        .set_creation_time(fixed_creation_time())
        .map_err(sanitize_error)?;
    agreement
        .set_creation_time(fixed_creation_time())
        .map_err(sanitize_error)?;
    force_agreement_kdf_aes256(&mut agreement)?;
    Ok(SoftwareMaterial { signing, agreement })
}

fn force_agreement_kdf_aes256(
    key: &mut packet::Key<packet::key::SecretParts, packet::key::UnspecifiedRole>,
) -> ProbeResult<()> {
    match key.mpis().clone() {
        mpi::PublicKey::ECDH { curve, q, .. } => {
            key.set_mpis(mpi::PublicKey::ECDH {
                curve,
                q,
                hash: HashAlgorithm::SHA256,
                sym: SymmetricAlgorithm::AES256,
            });
            Ok(())
        }
        _ => Err("agreementKdfShape".to_string()),
    }
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

fn bridge_sign(bridge: &BridgeConfig, digest: &[u8]) -> ProbeResult<mpi::Signature> {
    validate_owned_dir(&bridge.work_directory, 0o700)?;
    validate_owned_file(&bridge.state_path, 0o600)?;
    let request_path = unique_path(&bridge.work_directory, "sign-request", "json");
    let response_path = unique_path(&bridge.work_directory, "sign-response", "json");
    let state_path = path_string(&bridge.state_path)?;
    let response = path_string(&response_path)?;
    let request = BridgeSignRequest {
        schema: phase3_request_schema(),
        state_path: &state_path,
        response_path: &response,
        hash_algorithm: "SHA256",
        digest_hex: hex_encode(digest),
        expected_signing_public_key_x963_hex: &bridge.expected_signing_public_hex,
    };
    let request_bytes =
        serde_json::to_vec_pretty(&request).map_err(|_| "requestJson".to_string())?;
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
    let response: BridgeSignResponse = serde_json::from_slice(&read_strict_file(&response_path)?)
        .map_err(|_| "bridgeResponseJson".to_string())?;
    let _ = fs::remove_file(&response_path);
    response_to_signature(response)
}

fn bridge_derive(bridge: &BridgeConfig, peer_public_x963: &[u8]) -> ProbeResult<Vec<u8>> {
    validate_x963_public(peer_public_x963, "peer")?;
    validate_owned_dir(&bridge.work_directory, 0o700)?;
    validate_owned_file(&bridge.state_path, 0o600)?;
    let request_path = unique_path(&bridge.work_directory, "derive-request", "json");
    let response_path = unique_path(&bridge.work_directory, "derive-response", "json");
    let state_path = path_string(&bridge.state_path)?;
    let response = path_string(&response_path)?;
    let request = BridgeDeriveRequest {
        schema: phase4_request_schema(),
        state_path: &state_path,
        response_path: &response,
        peer_public_key_x963_hex: hex_encode(peer_public_x963),
        expected_agreement_public_key_x963_hex: &bridge.expected_agreement_public_hex,
    };
    let request_bytes =
        serde_json::to_vec_pretty(&request).map_err(|_| "requestJson".to_string())?;
    write_exclusive_0600(&request_path, &request_bytes)?;
    let output = Command::new(&bridge.signer_app)
        .arg("--mode")
        .arg("derive-shared")
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
    // POC boundary: success and bridge-failure paths remove the response file, but a
    // malformed 0600 response may remain after read/JSON failures for diagnosis.
    // Phase 5/production must use a narrower fail-clean shared-secret handoff.
    let response: BridgeDeriveResponse = serde_json::from_slice(&read_strict_file(&response_path)?)
        .map_err(|_| "bridgeResponseJson".to_string())?;
    let _ = fs::remove_file(&response_path);
    let shared = response_to_shared_secret(response)?;
    bridge.record_shared_secret_length(shared.len())?;
    Ok(shared)
}

fn response_to_signature(response: BridgeSignResponse) -> ProbeResult<mpi::Signature> {
    if response.schema != phase3_response_schema()
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

fn response_to_shared_secret(response: BridgeDeriveResponse) -> ProbeResult<Vec<u8>> {
    if response.schema != derive_response_schema()
        || response.status != "passed"
        || response.key_agreement_algorithm != "ecdhKeyExchangeStandard"
        || response.shared_secret_length != 32
    {
        return Err("bridgeResponseShape".to_string());
    }
    let shared = hex_decode(&response.shared_secret_hex)?;
    if shared.len() != 32 {
        return Err("bridgeSharedSecretLength".to_string());
    }
    Ok(shared)
}

fn load_se_request(
    request: &ProbeRequest,
) -> ProbeResult<(PublicFixture, BoundPublics, BridgeConfig)> {
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

    let fixture: PublicFixture =
        serde_json::from_slice(&read_strict_file(Path::new(fixture_path))?)
            .map_err(|_| "fixtureJson".to_string())?;
    if fixture.private_material_captured || fixture.keychain_locators_captured {
        return Err("fixtureMaterialPolicy".to_string());
    }
    if !fixture.schema.contains("phase3.fixture") {
        return Err("fixtureSchema".to_string());
    }
    let bound = bound_publics_from_fixture(&fixture)?;
    validate_bound_publics(&bound, &bound, signing_role(), key_agreement_role())?;
    let bridge = BridgeConfig {
        signer_app: PathBuf::from(signer_app),
        state_path: PathBuf::from(state_path),
        work_directory: PathBuf::from(work_directory),
        expected_signing_public_hex: hex_encode(&bound.signing_x963),
        expected_agreement_public_hex: hex_encode(&bound.agreement_x963),
        shared_secret_lengths: Arc::new(Mutex::new(Vec::new())),
    };
    Ok((fixture, bound, bridge))
}

fn bound_publics_from_fixture(fixture: &PublicFixture) -> ProbeResult<BoundPublics> {
    let signing = fixture_key(fixture, signing_role())?;
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
    signing_role_value: &str,
    agreement_role_value: &str,
) -> ProbeResult<()> {
    if signing_role_value != signing_role() {
        return Err("roleBinding:signing".to_string());
    }
    if agreement_role_value != key_agreement_role() {
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

fn seip_version(ciphertext: &[u8]) -> ProbeResult<u8> {
    let mut ppr = PacketParser::from_bytes(ciphertext).map_err(sanitize_error)?;
    while let PacketParserResult::Some(pp) = ppr {
        if let Packet::SEIP(ref seip) = pp.packet {
            return Ok(seip.version());
        }
        let (_, next) = pp.recurse().map_err(sanitize_error)?;
        ppr = next;
    }
    Err("missingSeipPacket".to_string())
}

fn tamper_last_byte(input: &[u8]) -> ProbeResult<Vec<u8>> {
    let mut out = input.to_vec();
    let last = out
        .last_mut()
        .ok_or_else(|| "emptyCiphertext".to_string())?;
    *last ^= 0x01;
    Ok(out)
}

fn tamper_pkesk_byte(input: &[u8]) -> ProbeResult<Vec<u8>> {
    // POC-level recipient/PKESK material tamper test. This intentionally does
    // not prove precise corruption of the AES-wrapped session-key field.
    let mut out = input.to_vec();
    let index = out.len().min(40).saturating_sub(1);
    if out.is_empty() {
        return Err("emptyCiphertext".to_string());
    }
    out[index] ^= 0x01;
    Ok(out)
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
        None | Some("com.cypherair.poc.secure-enclave-custody.phase4.request.v1") => Ok(()),
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

fn create_private_temp_dir(prefix: &str) -> ProbeResult<PathBuf> {
    let path = unique_path(&env::temp_dir(), prefix, "d");
    fs::create_dir(&path).map_err(|_| "tempDirCreate".to_string())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "tempDirPolicy".to_string())?;
    validate_owned_dir(&path, 0o700)?;
    Ok(path)
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

fn decrypt_candidate_passed(candidate: &Value) -> bool {
    candidate["recipientMatched"].as_bool() == Some(true)
        && candidate["sessionKeyRecovered"].as_bool() == Some(true)
        && candidate["plaintextMatched"].as_bool() == Some(true)
        && candidate["signatureVerified"].as_bool() == Some(true)
}

fn decrypt_candidate_plaintext_passed(candidate: &Value) -> bool {
    candidate["recipientMatched"].as_bool() == Some(true)
        && candidate["sessionKeyRecovered"].as_bool() == Some(true)
        && candidate["plaintextMatched"].as_bool() == Some(true)
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
    if error.starts_with("mock")
        || error.starts_with("se")
        || error.starts_with("gpg")
        || error.starts_with("gnupg")
        || error.starts_with("phase45")
        || error.starts_with("missing")
        || error.starts_with("unexpected")
    {
        return error.to_string();
    }
    let lower = error.to_ascii_lowercase();
    if lower.contains("file") || lower.contains("permission") || lower.contains("symlink") {
        "filePolicy".to_string()
    } else if lower.contains("bridge") || lower.contains("derive") || lower.contains("signer") {
        "bridgeFailure".to_string()
    } else if lower.contains("role") || lower.contains("binding") || lower.contains("public") {
        "bindingPolicy".to_string()
    } else if lower.contains("aead")
        || lower.contains("mdc")
        || lower.contains("manipulated")
        || lower.contains("integrity")
        || lower.contains("checksum")
        || lower.contains("bad key")
    {
        "tamperRejected".to_string()
    } else if lower.contains("session") || lower.contains("decrypt") {
        "decryptRejected".to_string()
    } else if lower.contains("key") {
        "keyMaterialPolicy".to_string()
    } else {
        "operationFailed".to_string()
    }
}

fn phase3_request_schema() -> &'static str {
    "com.cypherair.poc.secure-enclave-custody.phase3.request.v1"
}

fn phase4_request_schema() -> &'static str {
    "com.cypherair.poc.secure-enclave-custody.phase4.request.v1"
}

fn phase3_response_schema() -> &'static str {
    "com.cypherair.poc.secure-enclave-custody.phase3.response.v1"
}

fn derive_response_schema() -> &'static str {
    "com.cypherair.poc.secure-enclave-custody.phase4.derive-shared.response.v1"
}

fn signing_role() -> &'static str {
    "signing"
}

fn key_agreement_role() -> &'static str {
    "keyAgreement"
}

impl BridgeConfig {
    fn record_shared_secret_length(&self, length: usize) -> ProbeResult<()> {
        let mut lengths = self
            .shared_secret_lengths
            .lock()
            .map_err(|_| "sharedSecretLengthRecord".to_string())?;
        lengths.push(length);
        Ok(())
    }

    fn shared_secret_lengths(&self) -> Vec<usize> {
        self.shared_secret_lengths
            .lock()
            .map(|lengths| lengths.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_response_requires_raw_p256_length() {
        let response = BridgeDeriveResponse {
            schema: derive_response_schema().to_string(),
            status: "passed".to_string(),
            key_agreement_algorithm: "ecdhKeyExchangeStandard".to_string(),
            shared_secret_hex: "11".repeat(32),
            shared_secret_length: 32,
        };
        assert_eq!(response_to_shared_secret(response).unwrap().len(), 32);
    }

    #[test]
    fn binder_rejects_duplicate_publics() {
        let public = vec![4_u8; 65];
        let fixture = BoundPublics {
            signing_x963: public.clone(),
            agreement_x963: public.clone(),
        };
        assert!(
            validate_bound_publics(&fixture, &fixture, signing_role(), key_agreement_role())
                .is_err()
        );
    }
}
