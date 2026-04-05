import SwiftUI

struct TutorialSandboxAcknowledgementView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label(
                        String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                        systemImage: "testtube.2"
                    )
                    .font(.headline)
                    .foregroundStyle(.orange)

                    Text(
                        String(
                            localized: "guidedTutorial.sandbox.confirm.body",
                            defaultValue: "The Guided Tutorial runs in a separate sandbox. The keys, contacts, settings, messages, exports, and temporary data created here never affect your real workspace, and the sandbox data is cleaned up when you reset or finish the tutorial."
                        )
                    )
                    .font(.body)
                }

                Section(String(localized: "guidedTutorial.sandbox.confirm.points", defaultValue: "Before You Continue")) {
                    Label(
                        String(
                            localized: "guidedTutorial.sandbox.confirm.realData",
                            defaultValue: "Your real keys, contacts, settings, and files stay unchanged."
                        ),
                        systemImage: "lock.shield"
                    )

                    Label(
                        String(
                            localized: "guidedTutorial.sandbox.confirm.temporaryData",
                            defaultValue: "Everything you create in the sandbox is temporary and can be cleared."
                        ),
                        systemImage: "trash"
                    )

                    Label(
                        String(
                            localized: "guidedTutorial.sandbox.confirm.realUI",
                            defaultValue: "You will use the real app interface inside the sandbox."
                        ),
                        systemImage: "square.on.square"
                    )
                }

                Section {
                    Button(
                        String(
                            localized: "guidedTutorial.sandbox.confirm.primary",
                            defaultValue: "I Understand, Continue"
                        )
                    ) {
                        tutorialStore.confirmSandboxAcknowledgement()
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            .navigationTitle(
                String(
                    localized: "guidedTutorial.sandbox.confirm.title",
                    defaultValue: "Confirm the Sandbox"
                )
            )
            #if canImport(UIKit)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial")) {
                        tutorialStore.returnToOverview()
                    }
                }
            }
        }
    }
}
