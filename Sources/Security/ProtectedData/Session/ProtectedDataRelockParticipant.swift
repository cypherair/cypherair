import Foundation

protocol ProtectedDataRelockParticipant: AnyObject {
    func relockProtectedData() async throws
}
