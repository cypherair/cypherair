import CryptoKit
import Foundation

enum ContactCertificationArtifactSource: String, Codable, Equatable, Hashable, Sendable {
    case generated
    case imported
}

enum ContactCertificationValidationStatus: String, Codable, Equatable, Hashable, Sendable {
    case valid
    case invalidOrStale
    case revalidationNeeded
}

struct ContactCertificationTargetSelector: Codable, Equatable, Hashable, Sendable {
    enum Kind: String, Codable, Equatable, Hashable, Sendable {
        case directKey
        case userId
    }

    var kind: Kind
    var userIdData: Data?
    var userIdDisplayText: String?
    var occurrenceIndex: Int?

    static var directKey: ContactCertificationTargetSelector {
        ContactCertificationTargetSelector(
            kind: .directKey,
            userIdData: nil,
            userIdDisplayText: nil,
            occurrenceIndex: nil
        )
    }

    static func userId(
        data: Data,
        displayText: String,
        occurrenceIndex: Int
    ) -> ContactCertificationTargetSelector {
        ContactCertificationTargetSelector(
            kind: .userId,
            userIdData: data,
            userIdDisplayText: displayText,
            occurrenceIndex: occurrenceIndex
        )
    }

    var deduplicationKey: String {
        switch kind {
        case .directKey:
            return "direct-key"
        case .userId:
            let occurrence = occurrenceIndex ?? -1
            let dataDigest = ContactCertificationArtifactReference.sha256Hex(
                for: userIdData ?? Data()
            )
            return "user-id:\(occurrence):\(dataDigest)"
        }
    }

    func validate() throws {
        switch kind {
        case .directKey:
            break
        case .userId:
            guard let userIdData, !userIdData.isEmpty,
                  let occurrenceIndex, occurrenceIndex >= 0 else {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains a User ID certification selector without exact User ID metadata."
                )
            }
        }
    }
}

struct ContactCertificationArtifactReference: Codable, Equatable, Hashable, Identifiable, Sendable {
    var id: String { artifactId }

    let artifactId: String
    let keyId: String
    var createdAt: Date
    var canonicalSignatureData: Data
    var signatureDigest: String?
    var source: ContactCertificationArtifactSource
    var targetKeyFingerprint: String?
    var targetSelector: ContactCertificationTargetSelector
    var signerPrimaryFingerprint: String?
    var signingKeyFingerprint: String?
    var certificationKind: OpenPGPCertificationKind?
    var validationStatus: ContactCertificationValidationStatus
    var targetCertificateDigest: String?
    var lastValidatedAt: Date?
    var updatedAt: Date?
    var exportFilename: String?

    var effectiveSignatureDigest: String? {
        if let signatureDigest, !signatureDigest.isEmpty {
            return signatureDigest
        }
        guard !canonicalSignatureData.isEmpty else {
            return nil
        }
        return Self.sha256Hex(for: canonicalSignatureData)
    }

    var deduplicationKey: String? {
        guard let digest = effectiveSignatureDigest else {
            return nil
        }
        return "\(keyId)|\(targetSelector.deduplicationKey)|\(digest)"
    }

    var resolvedExportFilename: String {
        if let exportFilename, !exportFilename.isEmpty {
            return exportFilename
        }
        let shortKeyId = targetKeyFingerprint.map {
            IdentityPresentation.shortKeyId(from: $0)
        } ?? keyId
        switch targetSelector.kind {
        case .directKey:
            return "direct-key-certification-\(shortKeyId).asc"
        case .userId:
            let occurrence = (targetSelector.occurrenceIndex ?? 0) + 1
            return "userid-certification-\(shortKeyId)-\(occurrence).asc"
        }
    }

    func validatedForPersistence(now: Date = Date()) throws -> ContactCertificationArtifactReference {
        var artifact = self
        artifact.signatureDigest = effectiveSignatureDigest
        artifact.updatedAt = artifact.updatedAt ?? now
        if artifact.validationStatus == .valid {
            artifact.lastValidatedAt = artifact.lastValidatedAt ?? now
        }
        try artifact.validatePayload()
        return artifact
    }

    func validatePayload() throws {
        try targetSelector.validate()

        if let signatureDigest, !signatureDigest.isEmpty, !canonicalSignatureData.isEmpty {
            guard signatureDigest == Self.sha256Hex(for: canonicalSignatureData) else {
                throw ContactsDomainValidationError.invalidPayload(
                    reason: "Contacts payload contains a certification artifact with a stale signature digest."
                )
            }
        }

        guard validationStatus != .valid || !canonicalSignatureData.isEmpty else {
            throw ContactsDomainValidationError.invalidPayload(
                reason: "Contacts payload contains a valid certification artifact without signature bytes."
            )
        }
        guard validationStatus != .valid || effectiveSignatureDigest != nil else {
            throw ContactsDomainValidationError.invalidPayload(
                reason: "Contacts payload contains a valid certification artifact without a signature digest."
            )
        }
        guard validationStatus != .valid || targetCertificateDigest?.isEmpty == false else {
            throw ContactsDomainValidationError.invalidPayload(
                reason: "Contacts payload contains a valid certification artifact without a target certificate digest."
            )
        }
    }

    static func sha256Hex(for data: Data) -> String {
        SHA256.hash(data: data).map {
            String(format: "%02x", $0)
        }.joined()
    }
}
