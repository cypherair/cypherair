use super::*;

#[test]
fn test_external_signer_builds_valid_public_only_p256_certificates() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        assert_valid_public_candidate(version, &material.public_cert);
    }
}
