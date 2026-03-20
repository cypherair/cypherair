import SwiftUI

/// Six-page usage tutorial teaching the core CypherAir workflow.
/// Accessible from onboarding page 3 and Settings.
struct TutorialView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var currentPage = 0

    private let totalPages = 6

    var body: some View {
        NavigationStack {
            tutorialContent
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) {
                        Button(String(localized: "common.done", defaultValue: "Done")) {
                            dismiss()
                        }
                    }
                }
                .navigationTitle(String(localized: "tutorial.title", defaultValue: "Usage Tutorial"))
                #if canImport(UIKit)
                .navigationBarTitleDisplayMode(.inline)
                #endif
        }
    }

    @ViewBuilder
    private var tutorialContent: some View {
        #if canImport(UIKit)
        TabView(selection: $currentPage) {
            TutorialPageOne().tag(0)
            TutorialPageTwo().tag(1)
            TutorialPageThree().tag(2)
            TutorialPageFour().tag(3)
            TutorialPageFive().tag(4)
            TutorialPageSix().tag(5)
        }
        .tabViewStyle(.page(indexDisplayMode: .always))
        .indexViewStyle(.page(backgroundDisplayMode: .always))
        #else
        VStack {
            Group {
                switch currentPage {
                case 0: TutorialPageOne()
                case 1: TutorialPageTwo()
                case 2: TutorialPageThree()
                case 3: TutorialPageFour()
                case 4: TutorialPageFive()
                default: TutorialPageSix()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            HStack {
                Button(String(localized: "tutorial.back", defaultValue: "Back")) {
                    withAnimation { currentPage -= 1 }
                }
                .disabled(currentPage == 0)

                Spacer()

                HStack(spacing: 8) {
                    ForEach(0..<totalPages, id: \.self) { index in
                        Circle()
                            .fill(index == currentPage ? Color.primary : Color.secondary.opacity(0.3))
                            .frame(width: 8, height: 8)
                    }
                }

                Spacer()

                if currentPage < totalPages - 1 {
                    Button(String(localized: "tutorial.next", defaultValue: "Next")) {
                        withAnimation { currentPage += 1 }
                    }
                }
            }
            .padding()
        }
        #endif
    }
}

// MARK: - Tutorial Pages

/// Page 1: Public & Private Keys concept
struct TutorialPageOne: View {
    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "key.horizontal.fill")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.blue)
                .accessibilityHidden(true)

            Text(String(localized: "tutorial.p1.title", defaultValue: "Public & Private Keys"))
                .font(.title.bold())

            Text(String(localized: "tutorial.p1.body", defaultValue: "Encryption uses a pair of keys. Your public key is shared with friends so they can send you encrypted messages. Your private key stays on your device and is used to decrypt those messages. Never share your private key."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()
            Spacer()
        }
    }
}

/// Page 2: Step 1 — Generate Your Key
struct TutorialPageTwo: View {
    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "key.fill")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)

            Text(String(localized: "tutorial.p2.title", defaultValue: "Step 1: Generate Your Key"))
                .font(.title.bold())

            Text(String(localized: "tutorial.p2.body", defaultValue: "Go to the Keys tab and tap \"Generate My Key.\" Enter your name and optionally your email. Choose Universal (compatible with GnuPG) or Advanced (stronger security). Your key will be created and protected by Face ID or Touch ID."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()
            Spacer()
        }
    }
}

/// Page 3: Step 2 — Exchange Public Keys
struct TutorialPageThree: View {
    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "person.2.fill")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.green)
                .accessibilityHidden(true)

            Text(String(localized: "tutorial.p3.title", defaultValue: "Step 2: Exchange Public Keys"))
                .font(.title.bold())

            Text(String(localized: "tutorial.p3.body", defaultValue: "Share your public key with friends via QR code, file, or copy-paste. Add their public keys the same way in the Contacts tab. Meet in person for the most secure exchange — scan each other's QR codes with the system camera."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()
            Spacer()
        }
    }
}

/// Page 4: Step 3 — Encrypt
struct TutorialPageFour: View {
    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.fill")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.purple)
                .accessibilityHidden(true)

            Text(String(localized: "tutorial.p4.title", defaultValue: "Step 3: Encrypt"))
                .font(.title.bold())

            Text(String(localized: "tutorial.p4.body", defaultValue: "Type or paste your message, select recipients from your contacts, and tap Encrypt. The encrypted message can be copied or shared through any messaging app. Only the selected recipients can decrypt it."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()
            Spacer()
        }
    }
}

/// Page 5: Step 4 — Decrypt
struct TutorialPageFive: View {
    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.open.fill")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.teal)
                .accessibilityHidden(true)

            Text(String(localized: "tutorial.p5.title", defaultValue: "Step 4: Decrypt"))
                .font(.title.bold())

            Text(String(localized: "tutorial.p5.body", defaultValue: "Paste the encrypted message you received and tap Decrypt. CypherAir will verify it is addressed to you, then ask for Face ID or Touch ID. The decrypted message is shown in memory only and cleared when you leave."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()
            Spacer()
        }
    }
}

/// Page 6: Protect Your Keys
struct TutorialPageSix: View {
    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.red)
                .accessibilityHidden(true)

            Text(String(localized: "tutorial.p6.title", defaultValue: "Protect Your Keys"))
                .font(.title.bold())

            Text(String(localized: "tutorial.p6.body", defaultValue: "Back up your private key from the key detail page — if you lose your device without a backup, your key is gone forever. Enable High Security mode in Settings for biometric-only protection. Keep your backup passphrase in a safe place."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()
            Spacer()
        }
    }
}
