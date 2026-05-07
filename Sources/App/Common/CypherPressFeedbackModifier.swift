import SwiftUI

private struct CypherPressFeedbackModifier: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @GestureState private var isPressed = false

    func body(content: Content) -> some View {
        content
            .scaleEffect(isPressed && !reduceMotion ? CypherMotion.pressScale : 1)
            .animation(CypherMotion.spring(reduceMotion: reduceMotion), value: isPressed)
            .simultaneousGesture(
                DragGesture(minimumDistance: 0)
                    .updating($isPressed) { _, state, _ in
                        state = true
                    }
            )
    }
}

extension View {
    func cypherPressFeedback() -> some View {
        modifier(CypherPressFeedbackModifier())
    }
}
