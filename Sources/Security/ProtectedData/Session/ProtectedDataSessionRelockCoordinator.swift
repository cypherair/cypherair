import Foundation

final class ProtectedDataSessionRelockCoordinator {
    private var participants: [any ProtectedDataRelockParticipant] = []

    func register(_ participant: any ProtectedDataRelockParticipant) {
        guard !participants.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(participant) }) else {
            return
        }

        participants.append(participant)
    }

    func relockParticipants() async -> Bool {
        var participantErrorOccurred = false
        for participant in participants {
            do {
                try await participant.relockProtectedData()
            } catch {
                participantErrorOccurred = true
            }
        }
        return participantErrorOccurred
    }
}
