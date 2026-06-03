import XCTest
@testable import CypherAir

final class ContactServiceArchitectureAuditTests: ContactServiceTestCase {
    func test_pr8RepositoryAuditSnapshotIncludesContactsOrganizationSources() throws {
        let requiredPaths = [
            "Sources/App/Contacts/ContactTagAssignmentSheet.swift",
            "Sources/App/Contacts/ContactsScreenModel.swift",
            "Sources/App/Contacts/TagDetailScreenModel.swift",
            "Sources/App/Contacts/TagDetailView.swift",
            "Sources/App/Contacts/TagManagementScreenModel.swift",
            "Sources/App/Contacts/TagManagementView.swift",
            "Sources/Services/ContactsSearchIndex.swift",
            "Sources/Models/Contacts/ContactTagSummary.swift",
        ]

        for path in requiredPaths {
            XCTAssertNoThrow(try RepositoryAuditLoader.loadString(relativePath: path), path)
        }
    }

    func test_securitySourcesDoNotDependOnServicesLayerImplementationTypes() throws {
        let securityRoot = try RepositoryAuditLoader.url(relativePath: "Sources/Security")
        let forbiddenPatterns: [(label: String, regex: String)] = [
            ("contacts domain repository", #"\bContactsDomainRepository\b"#),
            ("contacts compatibility mapper", #"\bContactsCompatibilityMapper\b"#),
            ("disk space provider", #"\bDiskSpaceProvidable\b"#),
            ("disk space checker", #"\bDiskSpaceChecker\b"#),
            ("contact service facade", #"\bContactService\b"#),
            ("PGP engine", #"\bPgpEngine\b"#),
        ]
        var violations: [String] = []

        let enumerator = FileManager.default.enumerator(
            at: securityRoot,
            includingPropertiesForKeys: nil
        )
        while let fileURL = enumerator?.nextObject() as? URL {
            guard fileURL.pathExtension == "swift" else {
                continue
            }

            let contents = try String(contentsOf: fileURL, encoding: .utf8)
            for pattern in forbiddenPatterns where contents.range(
                of: pattern.regex,
                options: .regularExpression
            ) != nil {
                let relativePath = fileURL.path
                    .replacingOccurrences(of: securityRoot.path + "/", with: "Security/")
                violations.append("\(relativePath): \(pattern.label)")
            }
        }

        XCTAssertTrue(
            violations.isEmpty,
            "Security sources must not depend on Services implementation types:\n\(violations.joined(separator: "\n"))"
        )
    }

    func test_productionContactsCallsitesUseGatedAccessors() throws {
        let sourcesRoot = try RepositoryAuditLoader.sourcesRootURL()
        let allowedRelativePaths: Set<String> = [
            "App/Onboarding/TutorialSandboxContainer.swift",
            "Services/ContactService.swift",
        ]
        let forbiddenPatterns: [(label: String, regex: String)] = [
            ("raw loadContacts", #"contactService\.loadContacts\s*\("#),
            ("raw contacts property", #"contactService\.contacts\b"#),
            ("raw contact lookup", #"contactService\.contact\s*\("#),
            ("private raw add", #"contactService\.performAddContact\s*\("#),
            ("private raw remove", #"contactService\.performRemoveContact\s*\("#),
            ("private raw verification mutation", #"contactService\.performSetVerificationState\s*\("#),
            ("private raw legacy load", #"contactService\.loadLegacyCompatibilityRuntimeValues\s*\("#),
        ]
        var violations: [String] = []

        let enumerator = FileManager.default.enumerator(
            at: sourcesRoot,
            includingPropertiesForKeys: nil
        )
        while let fileURL = enumerator?.nextObject() as? URL {
            guard fileURL.pathExtension == "swift" else {
                continue
            }

            let relativePath = fileURL.path
                .replacingOccurrences(of: sourcesRoot.path + "/", with: "")
            guard !allowedRelativePaths.contains(relativePath) else {
                continue
            }

            let contents = try String(contentsOf: fileURL, encoding: .utf8)
            for pattern in forbiddenPatterns where contents.range(
                of: pattern.regex,
                options: .regularExpression
            ) != nil {
                violations.append("\(relativePath): \(pattern.label)")
            }
        }

        XCTAssertTrue(
            violations.isEmpty,
            "Production Contacts callsites must use gated accessors:\n\(violations.joined(separator: "\n"))"
        )
    }

    func test_contactsUnavailableStateDoesNotOfferAddContactAction() throws {
        let contents = try RepositoryAuditLoader.loadString(
            relativePath: "Sources/App/Contacts/ContactsView.swift"
        )
        let unavailableBlock = try sourceBlock(
            in: contents,
            from: "func contactsUnavailableContent",
            to: "var emptyStateContent"
        )
        let toolbarBlock = try sourceBlock(
            in: contents,
            from: ".toolbar {",
            to: ".alert("
        )

        XCTAssertFalse(unavailableBlock.contains("routeNavigator.open(.addContact)"))
        XCTAssertFalse(unavailableBlock.contains("contacts.add"))
        XCTAssertTrue(toolbarBlock.contains("if model.contactsAvailability.isAvailable"))
        XCTAssertTrue(toolbarBlock.contains("if model.canManageTags"))
        XCTAssertTrue(toolbarBlock.contains("routeNavigator.open(.tagManagement)"))
        XCTAssertTrue(toolbarBlock.contains("routeNavigator.open(.addContact)"))
    }

    func test_pr5ProductionRecipientResolutionUsesOnlyContactIds() throws {
        let sourcesRoot = try RepositoryAuditLoader.sourcesRootURL()
        let allowedRelativePaths: Set<String> = []
        let fingerprintRecipientParameterPattern = "recipient" + #"Fingerprints\s*:"#
        let fingerprintResolverPattern = "public" + #"KeysForRecipientFingerprints\s*\("#
        let legacyFingerprintResolverPattern = "legacy" + #"PublicKeysForRecipientFingerprints\s*\("#
        let forbiddenPatterns: [(label: String, regex: String)] = [
            ("fingerprint recipient parameter", fingerprintRecipientParameterPattern),
            ("fingerprint recipient resolver", fingerprintResolverPattern),
            ("legacy fingerprint recipient resolver", legacyFingerprintResolverPattern),
        ]
        var violations: [String] = []

        let enumerator = FileManager.default.enumerator(
            at: sourcesRoot,
            includingPropertiesForKeys: nil
        )
        while let fileURL = enumerator?.nextObject() as? URL {
            guard fileURL.pathExtension == "swift" else {
                continue
            }

            let relativePath = fileURL.path
                .replacingOccurrences(of: sourcesRoot.path + "/", with: "")
            guard !allowedRelativePaths.contains(relativePath) else {
                continue
            }

            let contents = try String(contentsOf: fileURL, encoding: .utf8)
            for pattern in forbiddenPatterns where contents.range(
                of: pattern.regex,
                options: .regularExpression
            ) != nil {
                violations.append("\(relativePath): \(pattern.label)")
            }
        }

        XCTAssertTrue(
            violations.isEmpty,
            "Production recipient resolution must use contact IDs outside compatibility seams:\n\(violations.joined(separator: "\n"))"
        )
    }

    // MARK: - PR5 Contact Identities
}
