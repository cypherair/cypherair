import SwiftUI

public extension View {
    func screenReady(_ identifier: String) -> some View {
        overlay(alignment: .topLeading) {
            Text(identifier)
                .font(.system(size: 1))
                .foregroundStyle(.clear)
                .accessibilityIdentifier(identifier)
                .allowsHitTesting(false)
        }
    }
}
