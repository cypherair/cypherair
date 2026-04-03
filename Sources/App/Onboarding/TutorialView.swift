import SwiftUI

struct TutorialView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(TutorialSessionStore.self) private var tutorialStore
    #if canImport(UIKit)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    @ViewBuilder
    var body: some View {
        #if canImport(UIKit)
        if sizeClass == .compact {
            ZStack {
                if !tutorialStore.session.isShellPresented {
                    tutorialHome
                        .transition(.move(edge: .leading).combined(with: .opacity))
                }

                if tutorialStore.session.isShellPresented {
                    TutorialMirrorShellView()
                        .environment(tutorialStore)
                        .transition(.move(edge: .trailing).combined(with: .opacity))
                }
            }
            .animation(.easeInOut(duration: 0.22), value: tutorialStore.session.isShellPresented)
        } else {
            tutorialHome
                .fullScreenCover(
                    isPresented: Binding(
                        get: { tutorialStore.session.isShellPresented },
                        set: { if !$0 { tutorialStore.dismissShell() } }
                    )
                ) {
                    TutorialMirrorShellView()
                        .environment(tutorialStore)
                }
        }
        #else
        tutorialHome
            .sheet(
                isPresented: Binding(
                    get: { tutorialStore.session.isShellPresented },
                    set: { if !$0 { tutorialStore.dismissShell() } }
                )
            ) {
                TutorialMirrorShellView()
                    .environment(tutorialStore)
                    .frame(minWidth: 880, minHeight: 640)
            }
        #endif
    }

    private var tutorialHome: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    heroCard

                    ForEach(TutorialPhaseID.allCases) { phase in
                        phaseCard(phase)
                    }
                }
                .padding()
            }
            .navigationTitle(String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"))
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "common.done", defaultValue: "Done")) {
                        dismiss()
                    }
                }
            }
            .task {
                tutorialStore.ensureSession()
            }
        }
    }

    private var heroCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(
                String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                systemImage: "testtube.2"
            )
            .font(.headline)
            .foregroundStyle(.orange)

            Text(String(localized: "guidedTutorial.hero.title", defaultValue: "Learn CypherAir in a real sandbox"))
                .font(.title2.weight(.semibold))

            Text(String(localized: "guidedTutorial.hero.body", defaultValue: "This guided tutorial uses the real app UI with isolated sandbox data. Your real keys, contacts, settings, exports, and files are never touched."))
                .foregroundStyle(.secondary)

            ProgressView(value: tutorialStore.session.progressValue)

            HStack(spacing: 12) {
                if let nextTask = tutorialStore.nextTask {
                    Button(nextTask == .understandSandbox
                           ? String(localized: "guidedTutorial.start", defaultValue: "Start Guided Tutorial")
                           : String(localized: "guidedTutorial.continue", defaultValue: "Continue")) {
                        Task {
                            let task = nextTask == .understandSandbox ? TutorialTaskID.generateAliceKey : nextTask
                            await tutorialStore.openTask(task)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }

                Button(String(localized: "guidedTutorial.reset", defaultValue: "Reset Tutorial")) {
                    tutorialStore.resetTutorial()
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(20)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }

    private func phaseCard(_ phase: TutorialPhaseID) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(phase.title)
                .font(.headline)

            ForEach(phase.tasks) { task in
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(task.title)
                            .font(.subheadline.weight(.medium))
                        Text(taskStatusDescription(task))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    if tutorialStore.isCompleted(task) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else if canOpen(task) {
                        Button(String(localized: "guidedTutorial.openTask", defaultValue: "Open")) {
                            Task {
                                await tutorialStore.openTask(task)
                            }
                        }
                        .buttonStyle(.bordered)
                    } else {
                        Image(systemName: "lock.fill")
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .padding(20)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private func canOpen(_ task: TutorialTaskID) -> Bool {
        if tutorialStore.isCompleted(task) {
            return true
        }

        guard let index = TutorialTaskID.allCases.firstIndex(of: task) else { return false }
        if index == 0 {
            return true
        }
        let previousTasks = TutorialTaskID.allCases.prefix(index)
        return previousTasks.allSatisfy { tutorialStore.isCompleted($0) }
    }

    private func taskStatusDescription(_ task: TutorialTaskID) -> String {
        if tutorialStore.isCompleted(task) {
            return String(localized: "guidedTutorial.status.complete", defaultValue: "Completed in this sandbox session")
        }
        if canOpen(task) {
            return String(localized: "guidedTutorial.status.ready", defaultValue: "Ready to start")
        }
        return String(localized: "guidedTutorial.status.locked", defaultValue: "Complete earlier steps first")
    }
}
