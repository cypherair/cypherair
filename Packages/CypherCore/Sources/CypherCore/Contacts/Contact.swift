import Foundation

/// One contact: one certificate, as computed at unlock, and the user's mark.
public struct Contact: Identifiable, Sendable, Equatable {
    public struct ID: Hashable, Sendable {
        let value: UUID
    }

    public let id: ID
    public let name: String?
    public let email: String?
    public let fingerprint: String
    public let shape: KeyShape?
    public let version: Int
    public let primary: Algorithm
    public let encryption: Algorithm?
    public let created: Date
    /// When the contact was added on this device.
    public let added: Date
    public let expires: Date?
    public let status: KeyStatus
    public let canEncrypt: Bool
    public let isQuantumSafe: Bool
    public let isVerified: Bool
}
