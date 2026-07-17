import XCTest
@testable import CypherAir

/// Hardware-independent guard for the Secure Enclave custody evidence summary. It runs in the
/// default unit lane (CI) — not the device lanes — and pins the property that an
/// evidence line is sanitized purely by what the type can represent: only enum raw
/// values and integer counts, never key material, fingerprints, or locators.
final class SecureEnclaveCustodyEvidenceLogTests: XCTestCase {
    func test_summaryLine_rendersStableEnumAndCountTokens() {
        let summary = SecureEnclaveCustodyEvidenceSummary(
            scenario: .ecdhDecrypt,
            configuration: .deviceBoundEcdsaNistP256EcdhNistP256,
            outcome: .passed,
            observedCategory: nil,
            handleCount: 2,
            completeSetCount: 1
        )
        XCTAssertEqual(
            summary.line,
            "SE-CUSTODY-EVIDENCE scenario=ecdhDecrypt outcome=passed config=deviceBoundEcdsaNistP256EcdhNistP256 handles=2 completeSets=1"
        )
    }

    func test_summaryLine_omitsAbsentOptionalFields() {
        let summary = SecureEnclaveCustodyEvidenceSummary(scenario: .wrongRole, outcome: .passed)
        XCTAssertEqual(summary.line, "SE-CUSTODY-EVIDENCE scenario=wrongRole outcome=passed")
    }

    /// Structural sanitization invariant: for every scenario × configuration ×
    /// outcome × failure category, a fully-populated evidence line is a sequence of
    /// `key=value` tokens whose keys are lowerCamel identifiers and whose values are
    /// strictly alphanumeric. That structure is what makes the line sanitized by
    /// construction — it cannot contain a filesystem path (`/`), PEM/armor header
    /// (`-`), base64 (`+`, `/`, `=`), or a colon-delimited fingerprint, because the
    /// type renders only enum raw values and integer counts. A future case whose raw
    /// value introduced such a character would fail here.
    func test_evidenceLine_isAlphanumericKeyValueTokensOnly() {
        let pattern = "^SE-CUSTODY-EVIDENCE( [a-z][a-zA-Z]*=[A-Za-z0-9]+)+$"
        let configurations: [SecureEnclaveCustodyEvidenceConfiguration?] =
            [nil] + SecureEnclaveCustodyEvidenceConfiguration.allCases.map { $0 }

        for scenario in SecureEnclaveCustodyEvidenceScenario.allCases {
            for outcome in SecureEnclaveCustodyEvidenceOutcome.allCases {
                for configuration in configurations {
                    for category in PGPKeyOperationFailureCategory.allCases {
                        let line = SecureEnclaveCustodyEvidenceSummary(
                            scenario: scenario,
                            configuration: configuration,
                            outcome: outcome,
                            observedCategory: category,
                            handleCount: 3,
                            completeSetCount: 1
                        ).line
                        XCTAssertNotNil(
                            line.range(of: pattern, options: .regularExpression),
                            "Non-sanitized evidence line shape: \(line)"
                        )
                    }
                }
            }
        }
    }
}
