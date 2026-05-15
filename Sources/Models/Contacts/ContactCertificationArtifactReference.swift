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

    var legacyUserIdDisplayText: String? {
        guard kind == .userId else {
            return nil
        }
        return userIdDisplayText
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
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts payload contains a User ID certification selector without exact User ID metadata."
                )
            }
        }
    }
}

struct ContactCertificationArtifactReference: Codable, Equatable, Hashable, Identifiable, Sendable {
    var id: String { artifactId }

    let artifactId: String
    let keyId: String
    var userId: String?
    var createdAt: Date
    var storageHint: String?
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

    init(
        artifactId: String,
        keyId: String,
        userId: String?,
        createdAt: Date,
        storageHint: String?,
        canonicalSignatureData: Data = Data(),
        signatureDigest: String? = nil,
        source: ContactCertificationArtifactSource = .imported,
        targetKeyFingerprint: String? = nil,
        targetSelector: ContactCertificationTargetSelector? = nil,
        signerPrimaryFingerprint: String? = nil,
        signingKeyFingerprint: String? = nil,
        certificationKind: OpenPGPCertificationKind? = nil,
        validationStatus: ContactCertificationValidationStatus = .revalidationNeeded,
        targetCertificateDigest: String? = nil,
        lastValidatedAt: Date? = nil,
        updatedAt: Date? = nil,
        exportFilename: String? = nil
    ) {
        self.artifactId = artifactId
        self.keyId = keyId
        self.userId = userId
        self.createdAt = createdAt
        self.storageHint = storageHint
        self.canonicalSignatureData = canonicalSignatureData
        self.signatureDigest = signatureDigest
        self.source = source
        self.targetKeyFingerprint = targetKeyFingerprint
        self.targetSelector = targetSelector ?? Self.legacyTargetSelector(userId: userId)
        self.signerPrimaryFingerprint = signerPrimaryFingerprint
        self.signingKeyFingerprint = signingKeyFingerprint
        self.certificationKind = certificationKind
        self.validationStatus = validationStatus
        self.targetCertificateDigest = targetCertificateDigest
        self.lastValidatedAt = lastValidatedAt
        self.updatedAt = updatedAt
        self.exportFilename = exportFilename
    }

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
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts payload contains a certification artifact with a stale signature digest."
                )
            }
        }

        guard validationStatus != .valid || !canonicalSignatureData.isEmpty else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts payload contains a valid certification artifact without signature bytes."
            )
        }
        guard validationStatus != .valid || effectiveSignatureDigest != nil else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts payload contains a valid certification artifact without a signature digest."
            )
        }
        guard validationStatus != .valid || targetCertificateDigest?.isEmpty == false else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts payload contains a valid certification artifact without a target certificate digest."
            )
        }
    }

    static func sha256Hex(for data: Data) -> String {
        SHA256.hash(data: data).map {
            String(format: "%02x", $0)
        }.joined()
    }

    private static func legacyTargetSelector(userId: String?) -> ContactCertificationTargetSelector {
        guard let userId, !userId.isEmpty else {
            return .directKey
        }
        return .userId(
            data: Data(userId.utf8),
            displayText: userId,
            occurrenceIndex: 0
        )
    }

    private enum CodingKeys: String, CodingKey {
        case artifactId
        case keyId
        case userId
        case createdAt
        case storageHint
        case canonicalSignatureData
        case signatureDigest
        case source
        case targetKeyFingerprint
        case targetSelector
        case signerPrimaryFingerprint
        case signingKeyFingerprint
        case certificationKind
        case validationStatus
        case targetCertificateDigest
        case lastValidatedAt
        case updatedAt
        case exportFilename
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        artifactId = try container.decode(String.self, forKey: .artifactId)
        keyId = try container.decode(String.self, forKey: .keyId)
        userId = try container.decodeIfPresent(String.self, forKey: .userId)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        storageHint = try container.decodeIfPresent(String.self, forKey: .storageHint)
        canonicalSignatureData = try container.decodeIfPresent(Data.self, forKey: .canonicalSignatureData) ?? Data()
        signatureDigest = try container.decodeIfPresent(String.self, forKey: .signatureDigest)
        source = try container.decodeIfPresent(ContactCertificationArtifactSource.self, forKey: .source)
            ?? .imported
        targetKeyFingerprint = try container.decodeIfPresent(String.self, forKey: .targetKeyFingerprint)
        targetSelector = try container.decodeIfPresent(
            ContactCertificationTargetSelector.self,
            forKey: .targetSelector
        ) ?? Self.legacyTargetSelector(userId: userId)
        signerPrimaryFingerprint = try container.decodeIfPresent(String.self, forKey: .signerPrimaryFingerprint)
        signingKeyFingerprint = try container.decodeIfPresent(String.self, forKey: .signingKeyFingerprint)
        certificationKind = try container.decodeIfPresent(OpenPGPCertificationKind.self, forKey: .certificationKind)
        validationStatus = try container.decodeIfPresent(
            ContactCertificationValidationStatus.self,
            forKey: .validationStatus
        ) ?? .revalidationNeeded
        targetCertificateDigest = try container.decodeIfPresent(String.self, forKey: .targetCertificateDigest)
        lastValidatedAt = try container.decodeIfPresent(Date.self, forKey: .lastValidatedAt)
        updatedAt = try container.decodeIfPresent(Date.self, forKey: .updatedAt)
        exportFilename = try container.decodeIfPresent(String.self, forKey: .exportFilename)
    }
}
