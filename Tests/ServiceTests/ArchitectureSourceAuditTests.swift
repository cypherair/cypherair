import Foundation
import XCTest

final class ArchitectureSourceAuditTests: XCTestCase {
    func test_generatedUniFFITypes_doNotLeakIntoNewUpperLayerFiles() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.generatedFFITypes)
    }

    func test_appLayerPgpErrorHandling_isLimitedToKnownTemporaryExceptions() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.appLayerPgpErrorHandling)
    }

    func test_appLayerFFIAdapterUsage_isBlocked() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.appLayerFFIAdapterUsage)
    }

    func test_modelsSwiftUIPresentationPolicy_isLimitedToKnownTemporaryExceptions() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.modelsSwiftUIPresentationPolicy)
    }

    func test_contactArrayRuntimeDependencies_areLimitedToKnownTemporaryExceptions() throws {
        try assertRulePasses(ArchitectureSourceAuditRules.contactArrayRuntimeDependencies)
    }

    func test_sourceAuditRules_detectViolationsAndAllowFileExceptions() throws {
        try assertRuleBehavior(
            ArchitectureSourceAuditRules.generatedFFITypes.withTemporaryExceptions([
                "Sources/App/AppContainer.swift": "fixture exception"
            ]),
            violatingPath: "Sources/App/NewScreenModel.swift",
            violatingContents: "struct NewScreenModel { let engine: PgpEngine }",
            allowedPath: "Sources/App/AppContainer.swift",
            allowedContents: "struct AppContainer { let engine: PgpEngine }",
            cleanContents: "struct CleanContainer {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.appLayerPgpErrorHandling.withTemporaryExceptions([
                "Sources/App/Common/OperationController.swift": "fixture exception"
            ]),
            violatingPath: "Sources/App/NewView.swift",
            violatingContents: "func handle(_ error: Error) { _ = error as? PgpError }",
            allowedPath: "Sources/App/Common/OperationController.swift",
            allowedContents: "func shouldIgnore(_ error: Error) -> Bool { error is PgpError }",
            cleanContents: "func shouldIgnore(_ error: Error) -> Bool { false }"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.appLayerFFIAdapterUsage.withTemporaryExceptions([
                "Sources/App/Contacts/Import/LegacyImportLoader.swift": "fixture exception"
            ]),
            violatingPath: "Sources/App/Contacts/Import/NewImportLoader.swift",
            violatingContents: "struct NewImportLoader { let adapter = PGPKeyMetadataAdapter.self }",
            allowedPath: "Sources/App/Contacts/Import/LegacyImportLoader.swift",
            allowedContents: "struct LegacyImportLoader { let adapter = PGPCertificateSelectionAdapter.self }",
            cleanContents: "struct ImportLoader {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.modelsSwiftUIPresentationPolicy.withTemporaryExceptions([
                "Sources/Models/ColorTheme.swift": "fixture exception"
            ]),
            violatingPath: "Sources/Models/NewDomainModel.swift",
            violatingContents: "import SwiftUI\nstruct NewDomainModel {}",
            allowedPath: "Sources/Models/ColorTheme.swift",
            allowedContents: "import SwiftUI\nstruct ColorTheme {}",
            cleanContents: "import Foundation\nstruct ColorTheme {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.contactArrayRuntimeDependencies.withTemporaryExceptions([
                "Sources/Services/ContactService.swift": "fixture exception"
            ]),
            violatingPath: "Sources/Services/NewRecipientService.swift",
            violatingContents: "struct NewRecipientService { let contacts: [Contact] }",
            allowedPath: "Sources/Services/ContactService.swift",
            allowedContents: "final class ContactService { private var contacts: [Contact] = [] }",
            cleanContents: "final class ContactService {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.contactArrayRuntimeDependencies.withTemporaryExceptions([
                "Sources/Services/ContactService.swift": "fixture exception"
            ]),
            violatingPath: "Sources/Services/NewRecipientService.swift",
            violatingContents: "struct NewRecipientService { let contacts: Array<Contact> }",
            allowedPath: "Sources/Services/ContactService.swift",
            allowedContents: "final class ContactService { private var contacts: Array<Contact> = [] }",
            cleanContents: "final class ContactService {}"
        )

        try assertRuleBehavior(
            ArchitectureSourceAuditRules.generatedFFITypes.withTemporaryExceptions([
                "Sources/Services/FileProgressReporter.swift": "fixture exception"
            ]),
            violatingPath: "Sources/App/NewReporterFactory.swift",
            violatingContents: "struct NewReporterFactory { let reporter: ProgressReporterImpl }",
            allowedPath: "Sources/Services/FileProgressReporter.swift",
            allowedContents: "struct FileProgressReporterBox { let reporter: ProgressReporterImpl }",
            cleanContents: "struct FileProgressReporterBox {}"
        )
    }

    func test_sourceAuditRules_ignoreCommentsAndStringLiterals() throws {
        let source = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: """
            // PgpEngine, PgpError, and PGPKeyMetadataAdapter should be ignored in comments.
            let message = "KeyInfo [Contact] import SwiftUI"
            let raw = #"ProgressReporterImpl KeyProfile Array<Contact> PGPCertificateSelectionAdapter"#
            struct NewView {}
            """
        )

        XCTAssertTrue(
            ArchitectureSourceAuditRules.generatedFFITypes.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.appLayerPgpErrorHandling.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.appLayerFFIAdapterUsage.violations(in: [source]).isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.contactArrayRuntimeDependencies.violations(in: [source]).isEmpty
        )

        let modelsSource = AuditedSource(
            path: "Sources/Models/NewDomainModel.swift",
            contents: """
            // import SwiftUI should be ignored in comments.
            let note = "import SwiftUI"
            struct NewDomainModel {}
            """
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.modelsSwiftUIPresentationPolicy.violations(in: [modelsSource]).isEmpty
        )
    }

    func test_sourceAuditRules_preserveStringInterpolationCode() throws {
        let generatedInterpolationSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: #"""
            struct NewView {
                let profile = "\(KeyProfile.advanced)"
            }
            """#
        )
        let generatedViolations = ArchitectureSourceAuditRules.generatedFFITypes
            .violations(in: [generatedInterpolationSource])
        XCTAssertEqual(generatedViolations.map(\.path), ["Sources/App/NewView.swift"])
        XCTAssertEqual(generatedViolations.first?.matches, ["KeyProfile"])

        let pgpErrorInterpolationSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: #"""
            struct NewView {
                let message = "\(PgpError.cancelled)"
            }
            """#
        )
        let pgpErrorViolations = ArchitectureSourceAuditRules.appLayerPgpErrorHandling
            .violations(in: [pgpErrorInterpolationSource])
        XCTAssertEqual(pgpErrorViolations.map(\.path), ["Sources/App/NewView.swift"])
        XCTAssertEqual(pgpErrorViolations.first?.matches, ["PgpError"])

        let adapterInterpolationSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: #"""
            struct NewView {
                let adapterName = "\(PGPKeyMetadataAdapter.self)"
            }
            """#
        )
        let adapterViolations = ArchitectureSourceAuditRules.appLayerFFIAdapterUsage
            .violations(in: [adapterInterpolationSource])
        XCTAssertEqual(adapterViolations.map(\.path), ["Sources/App/NewView.swift"])
        XCTAssertEqual(adapterViolations.first?.matches, ["PGPKeyMetadataAdapter"])

        let rawInterpolationSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: ##"""
            struct NewView {
                let profile = #"\#(KeyProfile.advanced)"#
            }
            """##
        )
        let rawViolations = ArchitectureSourceAuditRules.generatedFFITypes
            .violations(in: [rawInterpolationSource])
        XCTAssertEqual(rawViolations.map(\.path), ["Sources/App/NewView.swift"])
        XCTAssertEqual(rawViolations.first?.matches, ["KeyProfile"])

        let nestedStringAndCommentSource = AuditedSource(
            path: "Sources/App/NewView.swift",
            contents: #"""
            struct NewView {
                let message = "\(String(describing: "PgpError KeyProfile Array<Contact>") /* PgpError */)"
            }
            """#
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.generatedFFITypes
                .violations(in: [nestedStringAndCommentSource])
                .isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.appLayerPgpErrorHandling
                .violations(in: [nestedStringAndCommentSource])
                .isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.appLayerFFIAdapterUsage
                .violations(in: [nestedStringAndCommentSource])
                .isEmpty
        )
        XCTAssertTrue(
            ArchitectureSourceAuditRules.contactArrayRuntimeDependencies
                .violations(in: [nestedStringAndCommentSource])
                .isEmpty
        )
    }

    private func assertRulePasses(
        _ rule: ArchitectureSourceAuditRule,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let sources = try productionSwiftSources()
        let violations = rule.violations(in: sources)
        XCTAssertTrue(
            violations.isEmpty,
            rule.violationMessage(for: violations),
            file: file,
            line: line
        )

        let staleExceptions = rule.staleTemporaryExceptions(in: sources)
        XCTAssertTrue(
            staleExceptions.isEmpty,
            rule.staleExceptionMessage(for: staleExceptions),
            file: file,
            line: line
        )
    }

    private func assertRuleBehavior(
        _ rule: ArchitectureSourceAuditRule,
        violatingPath: String,
        violatingContents: String,
        allowedPath: String,
        allowedContents: String,
        cleanContents: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let violatingSource = AuditedSource(path: violatingPath, contents: violatingContents)
        let allowedSource = AuditedSource(path: allowedPath, contents: allowedContents)
        let staleSource = AuditedSource(path: allowedPath, contents: cleanContents)
        let cleanSource = AuditedSource(path: violatingPath, contents: cleanContents)

        XCTAssertEqual(
            rule.violations(in: [violatingSource]).map(\.path),
            [violatingPath],
            file: file,
            line: line
        )
        XCTAssertTrue(
            rule.violations(in: [allowedSource]).isEmpty,
            file: file,
            line: line
        )
        XCTAssertEqual(
            rule.staleTemporaryExceptions(in: [staleSource]).map(\.path),
            [allowedPath],
            file: file,
            line: line
        )
        XCTAssertTrue(
            rule.violations(in: [cleanSource]).isEmpty,
            file: file,
            line: line
        )
    }

    private func productionSwiftSources() throws -> [AuditedSource] {
        try RepositoryAuditLoader.swiftSourceRelativePaths()
            .filter { !$0.hasPrefix("Sources/PgpMobile/") }
            .map { path in
                AuditedSource(
                    path: path,
                    contents: try RepositoryAuditLoader.loadString(relativePath: path)
                )
            }
    }
}

private enum ArchitectureSourceAuditRules {
    static let generatedFFITypes = ArchitectureSourceAuditRule(
        name: "Generated UniFFI type containment",
        failureSummary: "Generated UniFFI types should not leak into new upper-layer source files.",
        pattern: wordPattern(for: [
            "ArmorKind",
            "CertificateMergeOutcome",
            "CertificateMergeResult",
            "CertificateSignatureResult",
            "CertificateSignatureStatus",
            "CertificationKind",
            "DecryptDetailedResult",
            "DetailedSignatureEntry",
            "DetailedSignatureStatus",
            "DiscoveredCertificateSelectors",
            "DiscoveredSubkey",
            "DiscoveredUserId",
            "FileDecryptDetailedResult",
            "FileVerifyDetailedResult",
            "GeneratedKey",
            "KeyInfo",
            "KeyProfile",
            "ModifyExpiryResult",
            "PasswordDecryptResult",
            "PasswordDecryptStatus",
            "PasswordMessageFormat",
            "PgpEngine",
            "PgpEngineProtocol",
            "PgpError",
            "ProgressReporter",
            "ProgressReporterImpl",
            "PublicCertificateValidationResult",
            "S2kInfo",
            "SignatureStatus",
            "SignatureVerificationState",
            "UserIdSelectorInput",
            "VerifyDetailedResult",
        ]),
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "Composition roots still construct or inject PgpEngine until the FFI adapter graph exists.",
                [
                    "Sources/App/AppContainer.swift",
                    "Sources/App/Onboarding/TutorialSandboxContainer.swift",
                ]
            ),
            (
                "App UI and ScreenModel surfaces still carry generated error or result vocabulary pending Phase 1/4 cleanup.",
                [
                    "Sources/App/Contacts/AddContactScreenModel.swift",
                    "Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift",
                    "Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift",
                    "Sources/App/Keys/BackupKeyView.swift",
                    "Sources/App/Keys/ImportKeyView.swift",
                    "Sources/App/Keys/KeyGenerationView.swift",
                    "Sources/App/Keys/SelectiveRevocationScreenModel.swift",
                ]
            ),
            (
                "FFI adapter files intentionally contain generated UniFFI types while exposing app-owned contracts upward.",
                [
                    "Sources/Services/FFI/PGPErrorMapper.swift",
                    "Sources/Services/FFI/PGPCertificateOperationAdapter.swift",
                    "Sources/Services/FFI/PGPCertificateSelectionAdapter.swift",
                    "Sources/Services/FFI/PGPKeyMetadataAdapter.swift",
                    "Sources/Services/FFI/PGPMessageOperationAdapter.swift",
                    "Sources/Services/FFI/PGPMessageResultMapper.swift",
                ]
            ),
            (
                "Models still include generated enum/result vocabulary pending Phase 1/2 adapter and model cleanup.",
                [
                    "Sources/Models/CypherAirError.swift",
                ]
            ),
            (
                "Security still consumes generated S2K metadata until the import/FFI boundary is narrowed.",
                [
                    "Sources/Security/Argon2idMemoryGuard.swift",
                ]
            ),
            (
                "Services still call PgpEngine and map generated results directly until Phase 1 introduces adapter contracts.",
                [
                    "Sources/Services/ContactImportMatcher.swift",
                    "Sources/Services/ContactImportPublicCertificateValidator.swift",
                    "Sources/Services/ContactService.swift",
                    "Sources/Services/ContactSnapshotMutator.swift",
                    "Sources/Services/ContactsLegacyMigrationSource.swift",
                    "Sources/Services/KeyManagement/KeyExportService.swift",
                    "Sources/Services/KeyManagement/KeyMutationService.swift",
                    "Sources/Services/KeyManagement/KeyProvisioningService.swift",
                    "Sources/Services/KeyManagementService.swift",
                    "Sources/Services/QRService.swift",
                    "Sources/Services/SelfTestService.swift",
                ]
            ),
        ])
    )

    static let appLayerPgpErrorHandling = ArchitectureSourceAuditRule(
        name: "App-layer PgpError handling",
        failureSummary: "New App-layer files should not inspect generated PgpError directly.",
        pattern: #"\bPgpError\b"#,
        scope: { path in
            path.hasPrefix("Sources/App/") && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "Current cancellation-ignore handling checks generated PgpError until generated errors are normalized at the adapter boundary.",
                [
                    "Sources/App/Contacts/AddContactScreenModel.swift",
                    "Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift",
                    "Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift",
                    "Sources/App/Keys/BackupKeyView.swift",
                    "Sources/App/Keys/ImportKeyView.swift",
                    "Sources/App/Keys/KeyGenerationView.swift",
                    "Sources/App/Keys/SelectiveRevocationScreenModel.swift",
                ]
            ),
        ])
    )

    static let appLayerFFIAdapterUsage = ArchitectureSourceAuditRule(
        name: "App-layer FFI adapter usage",
        failureSummary: "App-layer files should not call FFI adapters directly.",
        pattern: wordPattern(for: [
            "PGPCertificateSelectionAdapter",
            "PGPCertificateOperationAdapter",
            "PGPKeyMetadataAdapter",
            "PGPMessageOperationAdapter",
            "PGPMessageResultMapper",
            "PGPErrorMapper",
        ]),
        scope: { path in
            path.hasPrefix("Sources/App/") && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "Composition roots may construct FFI adapters while wiring the dependency graph.",
                [
                    "Sources/App/AppContainer.swift",
                    "Sources/App/Onboarding/TutorialSandboxContainer.swift",
                ]
            ),
        ])
    )

    static let modelsSwiftUIPresentationPolicy = ArchitectureSourceAuditRule(
        name: "Models SwiftUI presentation policy",
        failureSummary: "Core Models should not import SwiftUI in new files.",
        pattern: #"^\s*import\s+SwiftUI\b"#,
        scope: { path in
            path.hasPrefix("Sources/Models/") && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        expressionOptions: [.anchorsMatchLines],
        temporaryExceptions: temporaryExceptions([
            (
                "Theme and signature display policy still live in Models pending Phase 2 presentation extraction.",
                [
                    "Sources/Models/ColorTheme.swift",
                    "Sources/Models/SignatureVerification.swift",
                ]
            ),
        ])
    )

    static let contactArrayRuntimeDependencies = ArchitectureSourceAuditRule(
        name: "Legacy Contact array runtime dependencies",
        failureSummary: "New production code should not introduce ordinary runtime Contact collection dependencies.",
        pattern: #"(?:\[\s*Contact\s*\]|\bArray\s*<\s*Contact\s*>)"#,
        scope: { path in
            path.hasPrefix("Sources/")
                && !path.hasPrefix("Sources/PgpMobile/")
                && path.hasSuffix(".swift")
        },
        stripsCommentsAndStrings: true,
        temporaryExceptions: temporaryExceptions([
            (
                "Legacy verification models still resolve signer identity from flat Contact arrays pending Phase 1/3 cleanup.",
                [
                    "Sources/Models/CertificateSignatureSignerIdentity.swift",
                    "Sources/Models/SignatureVerification.swift",
                ]
            ),
            (
                "Contacts compatibility and migration paths intentionally retain flat Contact arrays during Phase 0.",
                [
                    "Sources/Services/ContactImportMatcher.swift",
                    "Sources/Services/ContactsCompatibilityMapper.swift",
                    "Sources/Services/ContactsLegacyMigrationSource.swift",
                    "Sources/Services/ContactService.swift",
                ]
            ),
            (
                "FFI mapping boundaries still accept legacy verification contexts until Contacts runtime contracts move to summaries.",
                [
                    "Sources/Services/FFI/PGPCertificateOperationAdapter.swift",
                    "Sources/Services/FFI/PGPMessageOperationAdapter.swift",
                    "Sources/Services/FFI/PGPMessageResultMapper.swift",
                ]
            ),
        ])
    )

    private static func wordPattern(for symbols: [String]) -> String {
        let alternation = symbols
            .sorted { lhs, rhs in
                if lhs.count != rhs.count {
                    return lhs.count > rhs.count
                }
                return lhs < rhs
            }
            .map(NSRegularExpression.escapedPattern(for:))
            .joined(separator: "|")
        return "\\b(?:\(alternation))\\b"
    }

    private static func temporaryExceptions(
        _ groups: [(reason: String, paths: [String])]
    ) -> [String: String] {
        var exceptions: [String: String] = [:]
        for group in groups {
            for path in group.paths {
                precondition(exceptions[path] == nil, "Duplicate source-audit exception: \(path)")
                exceptions[path] = group.reason
            }
        }
        return exceptions
    }
}

private struct AuditedSource {
    let path: String
    let contents: String
}

private struct ArchitectureSourceAuditRule: @unchecked Sendable {
    let name: String
    let failureSummary: String
    let expression: NSRegularExpression
    let scope: (String) -> Bool
    let stripsCommentsAndStrings: Bool
    let temporaryExceptions: [String: String]

    init(
        name: String,
        failureSummary: String,
        pattern: String,
        scope: @escaping (String) -> Bool,
        stripsCommentsAndStrings: Bool,
        expressionOptions: NSRegularExpression.Options = [],
        temporaryExceptions: [String: String]
    ) {
        self.name = name
        self.failureSummary = failureSummary
        self.expression = try! NSRegularExpression(pattern: pattern, options: expressionOptions)
        self.scope = scope
        self.stripsCommentsAndStrings = stripsCommentsAndStrings
        self.temporaryExceptions = temporaryExceptions
    }

    private init(
        name: String,
        failureSummary: String,
        expression: NSRegularExpression,
        scope: @escaping (String) -> Bool,
        stripsCommentsAndStrings: Bool,
        temporaryExceptions: [String: String]
    ) {
        self.name = name
        self.failureSummary = failureSummary
        self.expression = expression
        self.scope = scope
        self.stripsCommentsAndStrings = stripsCommentsAndStrings
        self.temporaryExceptions = temporaryExceptions
    }

    func withTemporaryExceptions(_ exceptions: [String: String]) -> Self {
        Self(
            name: name,
            failureSummary: failureSummary,
            expression: expression,
            scope: scope,
            stripsCommentsAndStrings: stripsCommentsAndStrings,
            temporaryExceptions: exceptions
        )
    }

    func violations(in sources: [AuditedSource]) -> [ArchitectureSourceAuditViolation] {
        sources
            .filter { scope($0.path) }
            .compactMap { source in
                let matches = matches(in: source)
                guard !matches.isEmpty, temporaryExceptions[source.path] == nil else {
                    return nil
                }
                return ArchitectureSourceAuditViolation(path: source.path, matches: matches)
            }
            .sorted { $0.path < $1.path }
    }

    func staleTemporaryExceptions(in sources: [AuditedSource]) -> [ArchitectureSourceAuditStaleException] {
        let sourcesByPath = Dictionary(uniqueKeysWithValues: sources.map { ($0.path, $0) })
        return temporaryExceptions
            .map { path, reason in
                guard let source = sourcesByPath[path] else {
                    return ArchitectureSourceAuditStaleException(
                        path: path,
                        reason: reason,
                        problem: "file is no longer present in the RepositoryAudit snapshot"
                    )
                }
                guard scope(path) else {
                    return ArchitectureSourceAuditStaleException(
                        path: path,
                        reason: reason,
                        problem: "file is outside this rule's audited scope"
                    )
                }
                guard matches(in: source).isEmpty else {
                    return nil
                }
                return ArchitectureSourceAuditStaleException(
                    path: path,
                    reason: reason,
                    problem: "exception no longer matches this rule and should be removed"
                )
            }
            .compactMap { $0 }
            .sorted { $0.path < $1.path }
    }

    func violationMessage(for violations: [ArchitectureSourceAuditViolation]) -> String {
        let details = violations.map { violation in
            "- \(violation.path): \(violation.matches.joined(separator: ", "))"
        }
        return ([failureSummary, "Unexpected matches:"] + details).joined(separator: "\n")
    }

    func staleExceptionMessage(for exceptions: [ArchitectureSourceAuditStaleException]) -> String {
        let details = exceptions.map { stale in
            "- \(stale.path): \(stale.problem). Reason was: \(stale.reason)"
        }
        return (["\(name) has stale temporary exceptions:"] + details).joined(separator: "\n")
    }

    private func matches(in source: AuditedSource) -> [String] {
        let text = stripsCommentsAndStrings
            ? SwiftSourceSanitizer.codeOnly(source.contents)
            : source.contents
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        let matches = expression.matches(in: text, range: range).compactMap { match -> String? in
            guard let matchRange = Range(match.range, in: text) else {
                return nil
            }
            return String(text[matchRange]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return Array(Set(matches)).sorted()
    }
}

private struct ArchitectureSourceAuditViolation {
    let path: String
    let matches: [String]
}

private struct ArchitectureSourceAuditStaleException {
    let path: String
    let reason: String
    let problem: String
}

private enum SwiftSourceSanitizer {
    static func codeOnly(_ text: String) -> String {
        var result = ""
        var index = text.startIndex

        while index < text.endIndex {
            if text[index...].hasPrefix("//") {
                replaceLineComment(in: text, index: &index, result: &result)
            } else if text[index...].hasPrefix("/*") {
                replaceBlockComment(in: text, index: &index, result: &result)
            } else if let literal = stringLiteralStart(in: text, at: index) {
                replaceStringLiteral(
                    in: text,
                    index: &index,
                    result: &result,
                    literal: literal
                )
            } else {
                result.append(text[index])
                index = text.index(after: index)
            }
        }

        return result
    }

    private static func replaceLineComment(
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        while index < text.endIndex {
            let character = text[index]
            appendPlaceholder(for: character, result: &result)
            index = text.index(after: index)
            if character == "\n" {
                break
            }
        }
    }

    private static func replaceBlockComment(
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        var depth = 0
        while index < text.endIndex {
            if text[index...].hasPrefix("/*") {
                depth += 1
                replaceCharacters(2, in: text, index: &index, result: &result)
            } else if text[index...].hasPrefix("*/") {
                depth -= 1
                replaceCharacters(2, in: text, index: &index, result: &result)
                if depth == 0 {
                    break
                }
            } else {
                replaceCharacters(1, in: text, index: &index, result: &result)
            }
        }
    }

    private static func replaceStringLiteral(
        in text: String,
        index: inout String.Index,
        result: inout String,
        literal: StringLiteralStart
    ) {
        replaceCharacters(literal.openingLength, in: text, index: &index, result: &result)

        if literal.isMultiline {
            replaceMultilineStringBody(
                in: text,
                index: &index,
                result: &result,
                hashCount: literal.hashCount
            )
        } else {
            replaceSingleLineStringBody(
                in: text,
                index: &index,
                result: &result,
                hashCount: literal.hashCount
            )
        }
    }

    private static func replaceSingleLineStringBody(
        in text: String,
        index: inout String.Index,
        result: inout String,
        hashCount: Int
    ) {
        var escaped = false
        while index < text.endIndex {
            if hashCount == 0, escaped {
                let character = text[index]
                replaceCharacters(1, in: text, index: &index, result: &result)
                escaped = false
                if character == "\n" {
                    break
                }
                continue
            }

            if isInterpolationStart(hashCount: hashCount, in: text, at: index) {
                replaceInterpolationOpening(hashCount: hashCount, in: text, index: &index, result: &result)
                preserveInterpolationBody(in: text, index: &index, result: &result)
                continue
            }

            let character = text[index]
            replaceCharacters(1, in: text, index: &index, result: &result)

            if character == "\n" {
                break
            }
            if hashCount == 0, character == "\\" {
                escaped = true
                continue
            }
            if character == "\"", consumeClosingHashes(hashCount, in: text, index: &index, result: &result) {
                break
            }
        }
    }

    private static func replaceMultilineStringBody(
        in text: String,
        index: inout String.Index,
        result: inout String,
        hashCount: Int
    ) {
        while index < text.endIndex {
            if text[index...].hasPrefix("\"\"\"") {
                let cursor = text.index(index, offsetBy: 3)
                if hasHashes(hashCount, in: text, at: cursor) {
                    replaceCharacters(3, in: text, index: &index, result: &result)
                    _ = consumeClosingHashes(hashCount, in: text, index: &index, result: &result)
                    break
                }
            }
            if isInterpolationStart(hashCount: hashCount, in: text, at: index) {
                replaceInterpolationOpening(hashCount: hashCount, in: text, index: &index, result: &result)
                preserveInterpolationBody(in: text, index: &index, result: &result)
                continue
            }
            replaceCharacters(1, in: text, index: &index, result: &result)
        }
    }

    private static func preserveInterpolationBody(
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        var parenDepth = 0
        while index < text.endIndex {
            if text[index...].hasPrefix("//") {
                replaceLineComment(in: text, index: &index, result: &result)
            } else if text[index...].hasPrefix("/*") {
                replaceBlockComment(in: text, index: &index, result: &result)
            } else if let literal = stringLiteralStart(in: text, at: index) {
                replaceStringLiteral(
                    in: text,
                    index: &index,
                    result: &result,
                    literal: literal
                )
            } else {
                let character = text[index]
                if character == "(" {
                    result.append(character)
                    parenDepth += 1
                    index = text.index(after: index)
                } else if character == ")" {
                    if parenDepth == 0 {
                        appendPlaceholder(for: character, result: &result)
                        index = text.index(after: index)
                        break
                    }
                    result.append(character)
                    parenDepth -= 1
                    index = text.index(after: index)
                } else {
                    result.append(character)
                    index = text.index(after: index)
                }
            }
        }
    }

    private static func isInterpolationStart(
        hashCount: Int,
        in text: String,
        at index: String.Index
    ) -> Bool {
        guard text[index] == "\\" else {
            return false
        }

        var cursor = text.index(after: index)
        for _ in 0..<hashCount {
            guard cursor < text.endIndex, text[cursor] == "#" else {
                return false
            }
            cursor = text.index(after: cursor)
        }

        return cursor < text.endIndex && text[cursor] == "("
    }

    private static func replaceInterpolationOpening(
        hashCount: Int,
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        replaceCharacters(hashCount + 2, in: text, index: &index, result: &result)
    }

    private static func stringLiteralStart(in text: String, at index: String.Index) -> StringLiteralStart? {
        var cursor = index
        var hashCount = 0
        while cursor < text.endIndex, text[cursor] == "#" {
            hashCount += 1
            cursor = text.index(after: cursor)
        }

        guard cursor < text.endIndex, text[cursor] == "\"" else {
            return nil
        }

        let isMultiline = text[cursor...].hasPrefix("\"\"\"")
        return StringLiteralStart(
            hashCount: hashCount,
            isMultiline: isMultiline,
            openingLength: hashCount + (isMultiline ? 3 : 1)
        )
    }

    private static func consumeClosingHashes(
        _ count: Int,
        in text: String,
        index: inout String.Index,
        result: inout String
    ) -> Bool {
        guard hasHashes(count, in: text, at: index) else {
            return false
        }
        replaceCharacters(count, in: text, index: &index, result: &result)
        return true
    }

    private static func hasHashes(_ count: Int, in text: String, at index: String.Index) -> Bool {
        var cursor = index
        for _ in 0..<count {
            guard cursor < text.endIndex, text[cursor] == "#" else {
                return false
            }
            cursor = text.index(after: cursor)
        }
        return true
    }

    private static func replaceCharacters(
        _ count: Int,
        in text: String,
        index: inout String.Index,
        result: inout String
    ) {
        for _ in 0..<count where index < text.endIndex {
            appendPlaceholder(for: text[index], result: &result)
            index = text.index(after: index)
        }
    }

    private static func appendPlaceholder(for character: Character, result: inout String) {
        result.append(character == "\n" ? "\n" : " ")
    }
}

private struct StringLiteralStart {
    let hashCount: Int
    let isMultiline: Bool
    let openingLength: Int
}
