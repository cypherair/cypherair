import Foundation

struct ImportablePublicCertificateInspection: Equatable, Sendable {
    let publicCertData: Data
    let metadata: PGPKeyMetadata
}
