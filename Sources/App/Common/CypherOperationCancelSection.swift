import SwiftUI

struct CypherOperationCancelSection: View {
    let isCancelling: Bool
    let cancel: () -> Void

    var body: some View {
        Section {
            if isCancelling {
                LabeledContent {
                    Text(String(localized: "common.cancelling", defaultValue: "Cancelling..."))
                        .foregroundStyle(.secondary)
                } label: {
                    Text(String(localized: "common.cancel", defaultValue: "Cancel"))
                }
            } else {
                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                    cancel()
                }
            }
        }
    }
}
