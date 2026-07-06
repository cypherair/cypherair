import SwiftUI

/// Key generation flow. Step 1 is a custody-first key-family picker; selecting
/// Continue pushes the identity/expiry details step where the key is generated.
struct KeyGenerationView: View {
    struct Configuration {
        enum PostGenerationBehavior: Equatable {
            case showPrompt
            case externalPrompt
            case suppressPrompt
        }

        var prefilledName: String?
        var prefilledEmail: String?
        var lockedFamily: PGPKeyConfiguration.Identity?
        var lockedExpiryMonths: Int?
        var postGenerationBehavior: PostGenerationBehavior = .showPrompt
        var onGenerated: (@MainActor (PGPKeyIdentity) -> Void)?
        var onPostGenerationPromptRequested: (@MainActor (PGPKeyIdentity) -> Void)?

        static let `default` = Configuration()
    }

    enum Field {
        case name
        case email
    }

    let configuration: Configuration

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
    @Environment(\.appRouteNavigator) private var routeNavigator

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        KeyGenerationScreenHostView(
            keyManagement: keyManagement,
            appSessionOrchestrator: appSessionOrchestrator,
            routeNavigator: routeNavigator,
            configuration: configuration
        )
    }
}

private struct KeyGenerationScreenHostView: View {
    let keyManagement: KeyManagementService
    let appSessionOrchestrator: AppSessionOrchestrator

    @State private var model: KeyGenerationScreenModel

    init(
        keyManagement: KeyManagementService,
        appSessionOrchestrator: AppSessionOrchestrator,
        routeNavigator: AppRouteNavigator,
        configuration: KeyGenerationView.Configuration
    ) {
        self.keyManagement = keyManagement
        self.appSessionOrchestrator = appSessionOrchestrator

        let postGenerationPromptAction: KeyGenerationScreenModel.PostGenerationPromptAction?
        #if os(macOS)
        postGenerationPromptAction = { identity in
            routeNavigator.open(.postGenerationPrompt(identity: identity))
        }
        #else
        postGenerationPromptAction = nil
        #endif

        _model = State(
            initialValue: KeyGenerationScreenModel(
                keyManagement: keyManagement,
                configuration: configuration,
                postGenerationPromptAction: postGenerationPromptAction
            )
        )
    }

    var body: some View {
        @Bindable var model = model

        KeyFamilyCustodyPickerView(model: model)
            .accessibilityIdentifier("keygen.root")
            .screenReady("keygen.ready")
            .navigationTitle(String(localized: "keygen.title", defaultValue: "Generate Key"))
            .navigationDestination(item: $model.detailFamily) { family in
                KeyGenerationDetailsView(model: model, family: family)
            }
            .alert(
                String(localized: "error.title", defaultValue: "Error"),
                isPresented: Binding(
                    get: { model.showError },
                    set: { if !$0 { model.dismissError() } }
                ),
                presenting: model.error
            ) { _ in
                Button(String(localized: "error.ok", defaultValue: "OK")) {
                    model.dismissError()
                }
            } message: { err in
                Text(err.localizedDescription)
            }
            .sheet(isPresented: Binding(
                get: { model.deviceBoundCommitmentPending },
                set: { if !$0 { model.cancelDeviceBoundCommitment() } }
            )) {
                DeviceBoundKeyCommitmentSheet(
                    family: model.selectedFamily,
                    onConfirm: { model.confirmDeviceBoundGeneration() },
                    onCancel: { model.cancelDeviceBoundCommitment() }
                )
            }
            .sheet(isPresented: Binding(
                get: { model.presentedFamilyDetail != nil },
                set: { if !$0 { model.dismissFamilyDetail() } }
            )) {
                if let family = model.presentedFamilyDetail {
                    KeyFamilyDetailSheet(
                        family: family,
                        onDismiss: { model.dismissFamilyDetail() }
                    )
                }
            }
            .sheet(item: Binding(
                get: { model.generatedIdentity },
                set: { if $0 == nil { model.dismissGeneratedIdentity() } }
            )) { identity in
                AppRouteHost(
                    resolver: .production,
                    macSheetSizing: .routedModal
                ) {
                    PostGenerationPromptView(identity: identity)
                        .environment(keyManagement)
                        .interactiveDismissDisabled(false)
                }
            }
            .onAppear {
                model.handleAppear()
            }
            .onChange(of: appSessionOrchestrator.contentClearGeneration) {
                model.handleContentClearGenerationChange()
            }
    }
}
