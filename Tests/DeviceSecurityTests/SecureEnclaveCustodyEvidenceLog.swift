import Foundation
@testable import CypherAir

/// A Secure Enclave custody evidence scenario (the rows of the evidence
/// matrix in docs/SECURE_ENCLAVE_CUSTODY.md §8.1).
enum SecureEnclaveCustodyEvidenceScenario: String, CaseIterable, Sendable {
    case handlePairGenerationPersistence
    case signing
    case ecdhDecrypt
    case hiddenGeneration
    case missingHandle
    case wrongRole
    case wrongPublicBinding
    case interactionNotAllowedProxy
    case payloadTamperHardFail
    case localResetCleanup
    case gnupgInteropV4
}

/// The OpenPGP key family a scenario exercised, when relevant.
enum SecureEnclaveCustodyEvidenceFamily: String, CaseIterable, Sendable {
    case deviceBoundEcdsaNistP256EcdhNistP256V4
    case deviceBoundEcdsaNistP256EcdhNistP256
}

/// The observed result of an evidence scenario.
enum SecureEnclaveCustodyEvidenceOutcome: String, CaseIterable, Sendable {
    case passed
    case failed
    case skipped
}

/// A sanitized-by-construction evidence record for a single Secure Enclave custody
/// scenario. It can hold ONLY enums and integer counts — never key material,
/// fingerprints, Keychain locators, handle-set identifiers, or free-form text — so
/// its rendered `line` is sanitized purely by what the type is able to represent.
/// `SecureEnclaveCustodyEvidenceLogTests` pins that property.
struct SecureEnclaveCustodyEvidenceSummary: Equatable, Sendable {
    let scenario: SecureEnclaveCustodyEvidenceScenario
    let configuration: SecureEnclaveCustodyEvidenceFamily?
    let outcome: SecureEnclaveCustodyEvidenceOutcome
    let observedCategory: PGPKeyOperationFailureCategory?
    let handleCount: Int?
    let completeSetCount: Int?

    init(
        scenario: SecureEnclaveCustodyEvidenceScenario,
        configuration: SecureEnclaveCustodyEvidenceFamily? = nil,
        outcome: SecureEnclaveCustodyEvidenceOutcome,
        observedCategory: PGPKeyOperationFailureCategory? = nil,
        handleCount: Int? = nil,
        completeSetCount: Int? = nil
    ) {
        self.scenario = scenario
        self.configuration = configuration
        self.outcome = outcome
        self.observedCategory = observedCategory
        self.handleCount = handleCount
        self.completeSetCount = completeSetCount
    }

    /// The sanitized one-line rendering, assembled only from enum raw values and
    /// integer counts. Operators paste this line into the Secure Enclave custody evidence matrix.
    var line: String {
        var fields = ["scenario=\(scenario.rawValue)", "outcome=\(outcome.rawValue)"]
        if let configuration {
            fields.append("config=\(configuration.rawValue)")
        }
        if let observedCategory {
            fields.append("category=\(observedCategory.rawValue)")
        }
        if let handleCount {
            fields.append("handles=\(handleCount)")
        }
        if let completeSetCount {
            fields.append("completeSets=\(completeSetCount)")
        }
        return "\(SecureEnclaveCustodyEvidenceLog.linePrefix) \(fields.joined(separator: " "))"
    }
}

/// Emits sanitized Secure Enclave custody evidence lines to the test console so a
/// real-hardware (or interop-harness) run produces a copy-pasteable record for the
/// Secure Enclave custody evidence matrix. Nothing here writes app state or files; the line is the
/// artifact and it is sanitized by construction (see `SecureEnclaveCustodyEvidenceSummary`).
enum SecureEnclaveCustodyEvidenceLog {
    /// Grep anchor for harvesting evidence lines from an `xcodebuild` log.
    static let linePrefix = "SE-CUSTODY-EVIDENCE"

    /// Print a sanitized evidence line and return it so a caller can also assert on it.
    @discardableResult
    static func record(_ summary: SecureEnclaveCustodyEvidenceSummary) -> String {
        let line = summary.line
        print(line)
        return line
    }
}
