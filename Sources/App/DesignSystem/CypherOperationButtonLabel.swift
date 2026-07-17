import SwiftUI

struct CypherOperationButtonLabel: View {
    let idleTitle: String
    let runningTitle: String
    let isRunning: Bool
    let isCancelling: Bool
    var progressFraction: Double?
    var minWidth: CGFloat = 180

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if isRunning {
                runningContent
            } else {
                Text(idleTitle)
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
            }
        }
        .cypherPrimaryActionLabelFrame(minWidth: minWidth)
        .animation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion), value: isRunning)
        .animation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion), value: isCancelling)
        .animation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion), value: clampedProgressFraction)
    }

    private var runningContent: some View {
        HStack(spacing: 8) {
            if let clampedProgressFraction {
                ProgressView(value: clampedProgressFraction)
                    .progressViewStyle(.linear)
                    .frame(width: 72)
                Text(statusTitle)
                    .lineLimit(1)
                    .minimumScaleFactor(0.82)
                Text(percentTitle(for: clampedProgressFraction))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                    .lineLimit(1)
            } else {
                ProgressView()
                Text(statusTitle)
                    .lineLimit(1)
                    .minimumScaleFactor(0.82)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private var statusTitle: String {
        if isCancelling {
            String(localized: "common.cancelling", defaultValue: "Cancelling...")
        } else {
            runningTitle
        }
    }

    private var clampedProgressFraction: Double? {
        progressFraction.map { min(max($0, 0), 1) }
    }

    private func percentTitle(for progressFraction: Double) -> String {
        "\(Int((progressFraction * 100).rounded()))%"
    }
}
