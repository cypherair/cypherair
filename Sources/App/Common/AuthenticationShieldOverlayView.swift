import SwiftUI

struct AuthenticationShieldView: View {
    let presentationState: AuthenticationShieldPresentationState

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var cardIsPresented = false
    @State private var breathingGlowIsActive = false

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.ultraThinMaterial)
                .ignoresSafeArea()

            AuthenticationShieldCard(
                iconName: iconName,
                isPendingDismissal: presentationState.isPendingDismissal,
                reduceMotion: reduceMotion,
                cardIsPresented: cardIsPresented,
                breathingGlowIsActive: breathingGlowIsActive
            )
            .padding(24)
            .allowsHitTesting(!presentationState.isPendingDismissal)
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                String(localized: "authShield.a11y.label", defaultValue: "Authentication in progress")
            )
            .accessibilityValue(
                String(localized: "authShield.a11y.value", defaultValue: "Secure content is hidden")
            )
        }
        .onAppear {
            prepareEntranceAnimation()
        }
        .onChange(of: presentationState.isPendingDismissal) { _, _ in
            updateBreathingGlow()
        }
        .onChange(of: reduceMotion) { _, _ in
            prepareEntranceAnimation()
        }
    }

    private var iconName: String {
        #if os(macOS)
        "touchid"
        #elseif os(visionOS)
        "opticid"
        #else
        "faceid"
        #endif
    }

    private func prepareEntranceAnimation() {
        breathingGlowIsActive = false

        guard !reduceMotion else {
            cardIsPresented = true
            return
        }

        cardIsPresented = false
        updateCardPresentation()
        updateBreathingGlow()
    }

    private func updateCardPresentation() {
        guard !reduceMotion else {
            cardIsPresented = true
            return
        }

        withAnimation(
            .spring(
                response: AuthenticationShieldAnimation.cardEntranceResponse,
                dampingFraction: AuthenticationShieldAnimation.cardEntranceDamping
            )
        ) {
            cardIsPresented = true
        }
    }

    private func updateBreathingGlow() {
        guard !reduceMotion else {
            breathingGlowIsActive = false
            return
        }

        if presentationState.isPendingDismissal {
            withAnimation(.easeOut(duration: AuthenticationShieldAnimation.breathingGlowSettleDuration)) {
                breathingGlowIsActive = false
            }
        } else {
            withAnimation(
                .easeInOut(duration: AuthenticationShieldAnimation.breathingGlowDuration)
                    .repeatForever(autoreverses: true)
            ) {
                breathingGlowIsActive = true
            }
        }
    }
}

private struct AuthenticationShieldCard: View {
    let iconName: String
    let isPendingDismissal: Bool
    let reduceMotion: Bool
    let cardIsPresented: Bool
    let breathingGlowIsActive: Bool

    private var isActivelyAuthenticating: Bool {
        cardIsPresented && !isPendingDismissal
    }

    var body: some View {
        VStack(spacing: 18) {
            AuthenticationShieldIcon(
                iconName: iconName,
                isActivelyAuthenticating: isActivelyAuthenticating,
                reduceMotion: reduceMotion,
                breathingGlowIsActive: breathingGlowIsActive
            )

            VStack(spacing: 6) {
                Text(String(localized: "authShield.title", defaultValue: "Authenticating…"))
                    .font(.headline)
                    .foregroundStyle(.primary)

                Text(String(localized: "authShield.subtitle", defaultValue: "Secure content is temporarily hidden"))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            ProgressView()
                .tint(.primary)
                .opacity(isPendingDismissal ? 0.4 : 1)
        }
        .padding(.horizontal, 28)
        .padding(.vertical, 24)
        .frame(maxWidth: 320)
        .background(
            .regularMaterial,
            in: RoundedRectangle(cornerRadius: 24, style: .continuous)
        )
        .overlay {
            AuthenticationShieldCardStroke(
                isActivelyAuthenticating: isActivelyAuthenticating,
                reduceMotion: reduceMotion,
                breathingGlowIsActive: breathingGlowIsActive
            )
        }
        .shadow(
            color: Color.accentColor.opacity(isActivelyAuthenticating && !reduceMotion ? 0.12 : 0),
            radius: breathingGlowIsActive ? 24 : 12,
            y: 8
        )
        .shadow(color: Color.black.opacity(0.08), radius: 18, y: 8)
        .opacity(cardIsPresented ? 1 : 0)
        .scaleEffect(cardIsPresented ? 1 : 0.97)
        .blur(radius: reduceMotion || cardIsPresented ? 0 : 3)
    }
}

private struct AuthenticationShieldIcon: View {
    let iconName: String
    let isActivelyAuthenticating: Bool
    let reduceMotion: Bool
    let breathingGlowIsActive: Bool

    private var glowScale: CGFloat {
        breathingGlowIsActive ? 1.08 : 0.96
    }

    private var glowOpacity: Double {
        if reduceMotion {
            return isActivelyAuthenticating ? 0.24 : 0.12
        }
        return breathingGlowIsActive ? 0.34 : 0.16
    }

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    RadialGradient(
                        colors: [
                            Color.accentColor.opacity(glowOpacity),
                            Color.accentColor.opacity(glowOpacity * 0.34),
                            Color.accentColor.opacity(0)
                        ],
                        center: .center,
                        startRadius: 12,
                        endRadius: 52
                    )
                )
                .frame(width: 104, height: 104)
                .scaleEffect(reduceMotion ? 1 : glowScale)
                .opacity(isActivelyAuthenticating || reduceMotion ? 1 : 0.34)

            Circle()
                .fill(.thinMaterial)
                .frame(width: 78, height: 78)
                .overlay {
                    Circle()
                        .stroke(Color.primary.opacity(0.08), lineWidth: 1)
                }
                .shadow(
                    color: Color.accentColor.opacity(glowOpacity * 0.54),
                    radius: breathingGlowIsActive && !reduceMotion ? 16 : 8
                )

            Image(systemName: iconName)
                .font(.system(size: 38, weight: .medium))
                .foregroundStyle(.primary)
                .if(isActivelyAuthenticating && !reduceMotion) { view in
                    view.symbolEffect(.pulse, options: .repeating)
                }
        }
    }
}

private struct AuthenticationShieldCardStroke: View {
    let isActivelyAuthenticating: Bool
    let reduceMotion: Bool
    let breathingGlowIsActive: Bool

    private var glowOpacity: Double {
        guard isActivelyAuthenticating else {
            return reduceMotion ? 0.08 : 0
        }
        guard !reduceMotion else {
            return 0.18
        }
        return breathingGlowIsActive ? 0.26 : 0.12
    }

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 24, style: .continuous)

        ZStack {
            shape
                .stroke(Color.primary.opacity(0.08), lineWidth: 1)

            if glowOpacity > 0 {
                shape
                    .stroke(
                        RadialGradient(
                            colors: [
                                Color.accentColor.opacity(glowOpacity),
                                Color.accentColor.opacity(glowOpacity * 0.48),
                                Color.accentColor.opacity(0)
                            ],
                            center: .center,
                            startRadius: 48,
                            endRadius: 220
                        ),
                        lineWidth: 1.2
                    )
                    .shadow(
                        color: Color.accentColor.opacity(glowOpacity),
                        radius: breathingGlowIsActive && !reduceMotion ? 16 : 8
                    )
            }
        }
    }
}

enum AuthenticationShieldAnimation {
    static let cardEntranceResponse = 0.34
    static let cardEntranceDamping = 0.84
    static let overlayDismissalDuration = 0.26
    static let breathingGlowDuration = 1.8
    static let breathingGlowSettleDuration = 0.24
}

private extension View {
    @ViewBuilder
    func `if`<Content: View>(
        _ condition: Bool,
        transform: (Self) -> Content
    ) -> some View {
        if condition {
            transform(self)
        } else {
            self
        }
    }
}
