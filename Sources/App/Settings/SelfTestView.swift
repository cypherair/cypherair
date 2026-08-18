import SwiftUI

/// One-tap self-diagnostic view.
struct SelfTestView: View {
    @Environment(SelfTestService.self) private var selfTestService
    @State private var exportController = FileExportController()
    @State private var exportError: CypherAirError?

    var body: some View {
        List {
            switch selfTestService.state {
            case .idle:
                Section {
                    Button {
                        let service = selfTestService
                        Task {
                            await service.runAllTests()
                        }
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "play.circle.fill")
                            Text(String(localized: "selftest.run", defaultValue: "Run Self-Test"))
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }

            case .running(let progress):
                Section {
                    VStack(spacing: 12) {
                        ProgressView(value: progress)
                        Text(String(localized: "selftest.running", defaultValue: "Running diagnostics..."))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical)
                }

            case .completed(let results):
                let passed = results.filter(\.passed).count
                Section {
                    HStack {
                        Text(String(localized: "selftest.results", defaultValue: "Results"))
                            .font(.headline)
                        Spacer()
                        Text(String(localized: "selftest.results.ratio", defaultValue: "\(passed)/\(results.count)"))
                            .font(.headline)
                            .foregroundStyle(passed == results.count ? .green : .red)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel(String(localized: "selftest.results.a11y", defaultValue: "\(passed) of \(results.count) tests passed"))
                }

                Section {
                    ForEach(results) { result in
                        HStack {
                            Image(systemName: result.passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(result.passed ? .green : .red)
                            VStack(alignment: .leading) {
                                Text(result.name)
                                    .font(.body)
                                if let suite = result.suite {
                                    Text(suite.portableFamily.familyDisplayName)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                if !result.passed {
                                    Text(result.message)
                                        .font(.caption)
                                        .foregroundStyle(.red)
                                }
                            }
                            Spacer()
                            Text(String(localized: "selftest.duration", defaultValue: "\(String(format: "%.1f", result.duration))s"))
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                    }
                }

            case .failed(let error):
                Section {
                    Text(error.localizedDescription)
                        .foregroundStyle(.red)
                }
            }
        }
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .cypherMacReadableContent()
        .accessibilityIdentifier("selftest.root")
        .screenReady("selftest.ready")
        .navigationTitle(String(localized: "selftest.title", defaultValue: "Self-Test"))
        .toolbar {
            if case .completed = selfTestService.state, selfTestService.latestReport != nil {
                ToolbarItem(placement: .automatic) {
                    Button {
                        saveReport()
                    } label: {
                        Label(
                            String(localized: "selftest.share", defaultValue: "Save Report"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                }
            }
        }
        .fileExport(exportController) { result in
            // A failed save keeps the report, so the user can try again.
            if case .success = result {
                selfTestService.clearLatestReport()
            }
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: Binding(
                get: { exportError != nil },
                set: { if !$0 { exportError = nil } }
            ),
            presenting: exportError
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                exportError = nil
            }
        } message: { error in
            Text(error.localizedDescription)
        }
    }

    private func saveReport() {
        guard let report = selfTestService.latestReport else {
            return
        }

        do {
            try exportController.prepareDataExport(report.data, filename: report.exportFilename)
        } catch {
            exportError = CypherAirError.from(error) { .fileIoError(reason: $0) }
        }
    }
}
