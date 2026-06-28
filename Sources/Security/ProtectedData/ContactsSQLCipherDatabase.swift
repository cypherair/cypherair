import Foundation
import SQLCipher

final class ContactsSQLCipherDatabase {
    private static let applicationID: Int32 = 0x43414354
    private static let schemaVersion = ContactsDomainSnapshot.currentSchemaVersion
    private static let transientDestructor = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private let storageRoot: ProtectedDataStorageRoot
    private let domainID: ProtectedDataDomainID
    private let databaseURL: URL
    private var db: OpaquePointer?

    init(
        storageRoot: ProtectedDataStorageRoot,
        domainID: ProtectedDataDomainID = "contacts"
    ) {
        self.storageRoot = storageRoot
        self.domainID = domainID
        self.databaseURL = storageRoot.contactsSQLCipherDatabaseURL(for: domainID)
    }

    deinit {
        try? close()
    }

    func createFresh(
        snapshot: ContactsDomainSnapshot,
        domainMasterKey: Data
    ) throws {
        try validateSnapshotForStorage(snapshot)
        try close()
        try storageRoot.removeContactsSQLCipherDatabaseFilesIfPresent(for: domainID)
        try storageRoot.ensureDomainDirectoryExists(for: domainID)

        try open(mode: .createFresh)
        do {
            try keyDatabase(with: domainMasterKey)
            try enableForeignKeyChecks()
            try configureFreshDatabase()
            try createSchema()
            try replaceSnapshot(snapshot)
            try validateConfiguration()
            try applyFileProtectionToDatabaseFiles()
        } catch {
            try? close()
            throw error
        }
    }

    func openExisting(domainMasterKey: Data) throws -> ContactsDomainSnapshot {
        guard try storageRoot.managedItemExists(at: databaseURL) else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher database is missing."
            )
        }

        try close()
        try open(mode: .existingCommittedDomain)
        do {
            try keyDatabase(with: domainMasterKey)
            try enableForeignKeyChecks()
            try validateConfiguration()
            let snapshot = try loadSnapshot()
            try validateSnapshotForStorage(snapshot)
            return snapshot
        } catch {
            try? close()
            throw error
        }
    }

    func replaceSnapshot(_ snapshot: ContactsDomainSnapshot) throws {
        try validateSnapshotForStorage(snapshot)
        try requireOpenDatabase()
        try runTransaction {
            try deleteSnapshotRows()
            try insertSnapshot(snapshot)
        }
        try applyFileProtectionToDatabaseFiles()
    }

    func loadSnapshot() throws -> ContactsDomainSnapshot {
        try requireOpenDatabase()

        let metadata = try loadMetadata()
        let identities = try loadIdentities()
        let tags = try loadTags()
        let artifacts = try loadCertificationArtifacts()
        let keyRecords = try loadKeyRecords()
        let snapshot = ContactsDomainSnapshot(
            schemaVersion: ContactsDomainSnapshot.currentSchemaVersion,
            identities: identities,
            keyRecords: keyRecords,
            tags: tags,
            certificationArtifacts: artifacts,
            createdAt: metadata.createdAt,
            updatedAt: metadata.updatedAt
        )
        try validateSnapshotForStorage(snapshot)
        return snapshot
    }

    func close() throws {
        guard let database = db else {
            return
        }

        db = nil
        let rc = sqlite3_close(database)
        guard rc == SQLITE_OK else {
            db = database
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher database could not be closed."
            )
        }
    }

    private enum OpenMode {
        case createFresh
        case existingCommittedDomain

        var flags: Int32 {
            switch self {
            case .createFresh:
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
            case .existingCommittedDomain:
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
            }
        }

        var operation: String {
            switch self {
            case .createFresh: "create"
            case .existingCommittedDomain: "open"
            }
        }
    }

    private struct SnapshotMetadata {
        let createdAt: Date
        let updatedAt: Date
    }

    private func open(mode: OpenMode) throws {
        var openedDatabase: OpaquePointer?
        let rc = sqlite3_open_v2(databaseURL.path, &openedDatabase, mode.flags, nil)
        guard rc == SQLITE_OK, let openedDatabase else {
            if let openedDatabase {
                sqlite3_close(openedDatabase)
            }
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher database \(mode.operation) failed."
            )
        }
        db = openedDatabase
    }

    private func keyDatabase(with domainMasterKey: Data) throws {
        guard domainMasterKey.count == SQLCipherRawKey.rawKeyLength else {
            throw ProtectedDataError.invalidDomainMasterKeyLength(domainMasterKey.count)
        }

        var domainMasterKeyCopy = Data(domainMasterKey)
        var keySpec: [UInt8]
        do {
            keySpec = try SQLCipherRawKey.keySpecBytes(for: domainMasterKeyCopy)
        } catch let error as SQLCipherRawKeyError {
            domainMasterKeyCopy.protectedDataZeroize()
            switch error {
            case .invalidRawKeyLength(let length):
                throw ProtectedDataError.invalidDomainMasterKeyLength(length)
            }
        }
        defer {
            domainMasterKeyCopy.protectedDataZeroize()
            SQLCipherRawKey.zeroize(&keySpec)
        }

        let database = try requireOpenDatabase()
        let rc = keySpec.withUnsafeBytes { buffer in
            sqlite3_key_v2(database, "main", buffer.baseAddress, Int32(buffer.count))
        }
        guard rc == SQLITE_OK else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher raw-key application failed."
            )
        }
    }

    private func configureFreshDatabase() throws {
        try exec("PRAGMA application_id = \(Self.applicationID);", operation: "set-application-id")
        try exec("PRAGMA user_version = \(Self.schemaVersion);", operation: "set-user-version")
    }

    private func enableForeignKeyChecks() throws {
        try exec("PRAGMA foreign_keys = ON;", operation: "enable-foreign-keys")
    }

    private func createSchema() throws {
        try exec(
            """
            CREATE TABLE IF NOT EXISTS contacts_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version INTEGER NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contact_identities (
                contact_id TEXT PRIMARY KEY,
                sort_order INTEGER NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                primary_email TEXT,
                notes TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contact_tags (
                tag_id TEXT PRIMARY KEY,
                sort_order INTEGER NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                normalized_name TEXT NOT NULL UNIQUE,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contact_identity_tags (
                contact_id TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                PRIMARY KEY (contact_id, ordinal),
                UNIQUE (contact_id, tag_id),
                FOREIGN KEY (contact_id) REFERENCES contact_identities(contact_id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES contact_tags(tag_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS contact_key_records (
                key_id TEXT PRIMARY KEY,
                sort_order INTEGER NOT NULL UNIQUE,
                contact_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                primary_user_id TEXT,
                display_name TEXT NOT NULL,
                email TEXT,
                key_version INTEGER NOT NULL,
                profile TEXT NOT NULL,
                primary_algo TEXT NOT NULL,
                subkey_algo TEXT,
                has_encryption_subkey INTEGER NOT NULL,
                is_revoked INTEGER NOT NULL,
                is_expired INTEGER NOT NULL,
                manual_verification_state TEXT NOT NULL,
                usage_state TEXT NOT NULL,
                certification_projection_status TEXT NOT NULL,
                certification_projection_last_validated_at REAL,
                public_key_data BLOB NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                FOREIGN KEY (contact_id) REFERENCES contact_identities(contact_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS contact_certification_artifacts (
                artifact_id TEXT PRIMARY KEY,
                sort_order INTEGER NOT NULL UNIQUE,
                key_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                canonical_signature_data BLOB NOT NULL,
                signature_digest TEXT,
                source TEXT NOT NULL,
                target_key_fingerprint TEXT,
                target_selector_kind TEXT NOT NULL,
                target_selector_user_id_data BLOB,
                target_selector_user_id_display_text TEXT,
                target_selector_occurrence_index INTEGER,
                signer_primary_fingerprint TEXT,
                signing_key_fingerprint TEXT,
                certification_kind TEXT,
                validation_status TEXT NOT NULL,
                target_certificate_digest TEXT,
                last_validated_at REAL,
                updated_at REAL,
                export_filename TEXT,
                FOREIGN KEY (key_id) REFERENCES contact_key_records(key_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS contact_key_certification_artifact_ids (
                key_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                PRIMARY KEY (key_id, ordinal),
                UNIQUE (key_id, artifact_id),
                FOREIGN KEY (key_id) REFERENCES contact_key_records(key_id) ON DELETE CASCADE,
                FOREIGN KEY (artifact_id) REFERENCES contact_certification_artifacts(artifact_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS contact_key_projection_artifact_ids (
                key_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                PRIMARY KEY (key_id, ordinal),
                UNIQUE (key_id, artifact_id),
                FOREIGN KEY (key_id) REFERENCES contact_key_records(key_id) ON DELETE CASCADE,
                FOREIGN KEY (artifact_id) REFERENCES contact_certification_artifacts(artifact_id) ON DELETE CASCADE
            );
            """,
            operation: "create-schema"
        )
    }

    private func validateConfiguration() throws {
        guard sqlite3_compileoption_used("SQLITE_HAS_CODEC") != 0 else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher runtime is missing SQLITE_HAS_CODEC."
            )
        }
        guard sqlite3_compileoption_used("SQLITE_TEMP_STORE=2") != 0 else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher runtime is missing SQLITE_TEMP_STORE=2."
            )
        }

        let cipherVersion = try querySingleString(
            "PRAGMA cipher_version;",
            operation: "cipher-version"
        )
        guard !cipherVersion.isEmpty else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher runtime did not report a cipher version."
            )
        }

        let applicationID = try querySingleInt(
            "PRAGMA application_id;",
            operation: "application-id"
        )
        guard applicationID == Self.applicationID else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher application identifier is unsupported."
            )
        }

        let userVersion = try querySingleInt(
            "PRAGMA user_version;",
            operation: "user-version"
        )
        guard userVersion == Self.schemaVersion else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher schema version is unsupported."
            )
        }

        let integrityResults = try queryStrings(
            "PRAGMA cipher_integrity_check;",
            operation: "cipher-integrity-check"
        )
        guard integrityResults.isEmpty || integrityResults == ["ok"] else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher integrity check failed."
            )
        }
    }

    private func deleteSnapshotRows() throws {
        for table in [
            "contact_key_projection_artifact_ids",
            "contact_key_certification_artifact_ids",
            "contact_certification_artifacts",
            "contact_key_records",
            "contact_identity_tags",
            "contact_tags",
            "contact_identities",
            "contacts_metadata",
        ] {
            try exec("DELETE FROM \(table);", operation: "delete-\(table)")
        }
    }

    private func insertSnapshot(_ snapshot: ContactsDomainSnapshot) throws {
        try withStatement(
            """
            INSERT INTO contacts_metadata (
                id,
                schema_version,
                created_at,
                updated_at
            ) VALUES (1, ?, ?, ?);
            """,
            operation: "insert-metadata"
        ) { statement in
            try bindInt(Self.schemaVersion, to: statement, at: 1)
            try bindDate(snapshot.createdAt, to: statement, at: 2)
            try bindDate(snapshot.updatedAt, to: statement, at: 3)
            try stepDone(statement, operation: "insert-metadata")
        }

        for (index, identity) in snapshot.identities.enumerated() {
            try insertIdentity(identity, sortOrder: index)
        }
        for (index, tag) in snapshot.tags.enumerated() {
            try insertTag(tag, sortOrder: index)
        }
        for identity in snapshot.identities {
            for (ordinal, tagID) in identity.tagIds.enumerated() {
                try insertIdentityTag(contactID: identity.contactId, tagID: tagID, ordinal: ordinal)
            }
        }
        for (index, keyRecord) in snapshot.keyRecords.enumerated() {
            try insertKeyRecord(keyRecord, sortOrder: index)
        }
        for (index, artifact) in snapshot.certificationArtifacts.enumerated() {
            try insertCertificationArtifact(artifact, sortOrder: index)
        }
        for keyRecord in snapshot.keyRecords {
            for (ordinal, artifactID) in keyRecord.certificationArtifactIds.enumerated() {
                try insertKeyArtifactLink(
                    table: "contact_key_certification_artifact_ids",
                    keyID: keyRecord.keyId,
                    artifactID: artifactID,
                    ordinal: ordinal
                )
            }
            for (ordinal, artifactID) in keyRecord.certificationProjection.artifactIds.enumerated() {
                try insertKeyArtifactLink(
                    table: "contact_key_projection_artifact_ids",
                    keyID: keyRecord.keyId,
                    artifactID: artifactID,
                    ordinal: ordinal
                )
            }
        }
    }

    private func insertIdentity(_ identity: ContactIdentity, sortOrder: Int) throws {
        try withStatement(
            """
            INSERT INTO contact_identities (
                contact_id,
                sort_order,
                display_name,
                primary_email,
                notes,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            operation: "insert-identity"
        ) { statement in
            try bindText(identity.contactId, to: statement, at: 1)
            try bindInt(sortOrder, to: statement, at: 2)
            try bindText(identity.displayName, to: statement, at: 3)
            try bindOptionalText(identity.primaryEmail, to: statement, at: 4)
            try bindOptionalText(identity.notes, to: statement, at: 5)
            try bindDate(identity.createdAt, to: statement, at: 6)
            try bindDate(identity.updatedAt, to: statement, at: 7)
            try stepDone(statement, operation: "insert-identity")
        }
    }

    private func insertTag(_ tag: ContactTag, sortOrder: Int) throws {
        try withStatement(
            """
            INSERT INTO contact_tags (
                tag_id,
                sort_order,
                display_name,
                normalized_name,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?);
            """,
            operation: "insert-tag"
        ) { statement in
            try bindText(tag.tagId, to: statement, at: 1)
            try bindInt(sortOrder, to: statement, at: 2)
            try bindText(tag.displayName, to: statement, at: 3)
            try bindText(tag.normalizedName, to: statement, at: 4)
            try bindDate(tag.createdAt, to: statement, at: 5)
            try bindDate(tag.updatedAt, to: statement, at: 6)
            try stepDone(statement, operation: "insert-tag")
        }
    }

    private func insertIdentityTag(contactID: String, tagID: String, ordinal: Int) throws {
        try withStatement(
            """
            INSERT INTO contact_identity_tags (
                contact_id,
                tag_id,
                ordinal
            ) VALUES (?, ?, ?);
            """,
            operation: "insert-identity-tag"
        ) { statement in
            try bindText(contactID, to: statement, at: 1)
            try bindText(tagID, to: statement, at: 2)
            try bindInt(ordinal, to: statement, at: 3)
            try stepDone(statement, operation: "insert-identity-tag")
        }
    }

    private func insertKeyRecord(_ keyRecord: ContactKeyRecord, sortOrder: Int) throws {
        try withStatement(
            """
            INSERT INTO contact_key_records (
                key_id,
                sort_order,
                contact_id,
                fingerprint,
                primary_user_id,
                display_name,
                email,
                key_version,
                profile,
                primary_algo,
                subkey_algo,
                has_encryption_subkey,
                is_revoked,
                is_expired,
                manual_verification_state,
                usage_state,
                certification_projection_status,
                certification_projection_last_validated_at,
                public_key_data,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            operation: "insert-key-record"
        ) { statement in
            try bindText(keyRecord.keyId, to: statement, at: 1)
            try bindInt(sortOrder, to: statement, at: 2)
            try bindText(keyRecord.contactId, to: statement, at: 3)
            try bindText(keyRecord.fingerprint, to: statement, at: 4)
            try bindOptionalText(keyRecord.primaryUserId, to: statement, at: 5)
            try bindText(keyRecord.displayName, to: statement, at: 6)
            try bindOptionalText(keyRecord.email, to: statement, at: 7)
            try bindInt(Int(keyRecord.keyVersion), to: statement, at: 8)
            try bindText(keyRecord.profile.rawValue, to: statement, at: 9)
            try bindText(keyRecord.primaryAlgo, to: statement, at: 10)
            try bindOptionalText(keyRecord.subkeyAlgo, to: statement, at: 11)
            try bindBool(keyRecord.hasEncryptionSubkey, to: statement, at: 12)
            try bindBool(keyRecord.isRevoked, to: statement, at: 13)
            try bindBool(keyRecord.isExpired, to: statement, at: 14)
            try bindText(keyRecord.manualVerificationState.rawValue, to: statement, at: 15)
            try bindText(keyRecord.usageState.rawValue, to: statement, at: 16)
            try bindText(keyRecord.certificationProjection.status.rawValue, to: statement, at: 17)
            try bindOptionalDate(keyRecord.certificationProjection.lastValidatedAt, to: statement, at: 18)
            try bindBlob(keyRecord.publicKeyData, to: statement, at: 19)
            try bindDate(keyRecord.createdAt, to: statement, at: 20)
            try bindDate(keyRecord.updatedAt, to: statement, at: 21)
            try stepDone(statement, operation: "insert-key-record")
        }
    }

    private func insertCertificationArtifact(
        _ artifact: ContactCertificationArtifactReference,
        sortOrder: Int
    ) throws {
        try withStatement(
            """
            INSERT INTO contact_certification_artifacts (
                artifact_id,
                sort_order,
                key_id,
                created_at,
                canonical_signature_data,
                signature_digest,
                source,
                target_key_fingerprint,
                target_selector_kind,
                target_selector_user_id_data,
                target_selector_user_id_display_text,
                target_selector_occurrence_index,
                signer_primary_fingerprint,
                signing_key_fingerprint,
                certification_kind,
                validation_status,
                target_certificate_digest,
                last_validated_at,
                updated_at,
                export_filename
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            operation: "insert-certification-artifact"
        ) { statement in
            try bindText(artifact.artifactId, to: statement, at: 1)
            try bindInt(sortOrder, to: statement, at: 2)
            try bindText(artifact.keyId, to: statement, at: 3)
            try bindDate(artifact.createdAt, to: statement, at: 4)
            try bindBlob(artifact.canonicalSignatureData, to: statement, at: 5)
            try bindOptionalText(artifact.signatureDigest, to: statement, at: 6)
            try bindText(artifact.source.rawValue, to: statement, at: 7)
            try bindOptionalText(artifact.targetKeyFingerprint, to: statement, at: 8)
            try bindText(artifact.targetSelector.kind.rawValue, to: statement, at: 9)
            try bindOptionalBlob(artifact.targetSelector.userIdData, to: statement, at: 10)
            try bindOptionalText(artifact.targetSelector.userIdDisplayText, to: statement, at: 11)
            try bindOptionalInt(artifact.targetSelector.occurrenceIndex, to: statement, at: 12)
            try bindOptionalText(artifact.signerPrimaryFingerprint, to: statement, at: 13)
            try bindOptionalText(artifact.signingKeyFingerprint, to: statement, at: 14)
            try bindOptionalText(artifact.certificationKind?.rawValue, to: statement, at: 15)
            try bindText(artifact.validationStatus.rawValue, to: statement, at: 16)
            try bindOptionalText(artifact.targetCertificateDigest, to: statement, at: 17)
            try bindOptionalDate(artifact.lastValidatedAt, to: statement, at: 18)
            try bindOptionalDate(artifact.updatedAt, to: statement, at: 19)
            try bindOptionalText(artifact.exportFilename, to: statement, at: 20)
            try stepDone(statement, operation: "insert-certification-artifact")
        }
    }

    private func insertKeyArtifactLink(
        table: String,
        keyID: String,
        artifactID: String,
        ordinal: Int
    ) throws {
        try withStatement(
            """
            INSERT INTO \(table) (
                key_id,
                artifact_id,
                ordinal
            ) VALUES (?, ?, ?);
            """,
            operation: "insert-\(table)"
        ) { statement in
            try bindText(keyID, to: statement, at: 1)
            try bindText(artifactID, to: statement, at: 2)
            try bindInt(ordinal, to: statement, at: 3)
            try stepDone(statement, operation: "insert-\(table)")
        }
    }

    private func loadMetadata() throws -> SnapshotMetadata {
        try withStatement(
            """
            SELECT schema_version, created_at, updated_at
            FROM contacts_metadata
            WHERE id = 1;
            """,
            operation: "load-metadata"
        ) { statement in
            guard sqlite3_step(statement) == SQLITE_ROW else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts SQLCipher metadata is missing."
                )
            }
            let schemaVersion = try columnInt(statement, at: 0)
            guard schemaVersion == Self.schemaVersion else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts SQLCipher metadata schema is unsupported."
                )
            }
            return SnapshotMetadata(
                createdAt: try columnDate(statement, at: 1),
                updatedAt: try columnDate(statement, at: 2)
            )
        }
    }

    private func loadIdentities() throws -> [ContactIdentity] {
        try withStatement(
            """
            SELECT contact_id, display_name, primary_email, notes, created_at, updated_at
            FROM contact_identities
            ORDER BY sort_order;
            """,
            operation: "load-identities"
        ) { statement in
            var identities: [ContactIdentity] = []
            while try stepRow(statement, operation: "load-identities") {
                let contactID = try columnString(statement, at: 0)
                identities.append(
                    ContactIdentity(
                        contactId: contactID,
                        displayName: try columnString(statement, at: 1),
                        primaryEmail: try columnOptionalString(statement, at: 2),
                        tagIds: try loadIdentityTagIDs(contactID: contactID),
                        notes: try columnOptionalString(statement, at: 3),
                        createdAt: try columnDate(statement, at: 4),
                        updatedAt: try columnDate(statement, at: 5)
                    )
                )
            }
            return identities
        }
    }

    private func loadTags() throws -> [ContactTag] {
        try withStatement(
            """
            SELECT tag_id, display_name, normalized_name, created_at, updated_at
            FROM contact_tags
            ORDER BY sort_order;
            """,
            operation: "load-tags"
        ) { statement in
            var tags: [ContactTag] = []
            while try stepRow(statement, operation: "load-tags") {
                tags.append(
                    ContactTag(
                        tagId: try columnString(statement, at: 0),
                        displayName: try columnString(statement, at: 1),
                        normalizedName: try columnString(statement, at: 2),
                        createdAt: try columnDate(statement, at: 3),
                        updatedAt: try columnDate(statement, at: 4)
                    )
                )
            }
            return tags
        }
    }

    private func loadKeyRecords() throws -> [ContactKeyRecord] {
        try withStatement(
            """
            SELECT
                key_id,
                contact_id,
                fingerprint,
                primary_user_id,
                display_name,
                email,
                key_version,
                profile,
                primary_algo,
                subkey_algo,
                has_encryption_subkey,
                is_revoked,
                is_expired,
                manual_verification_state,
                usage_state,
                certification_projection_status,
                certification_projection_last_validated_at,
                public_key_data,
                created_at,
                updated_at
            FROM contact_key_records
            ORDER BY sort_order;
            """,
            operation: "load-key-records"
        ) { statement in
            var records: [ContactKeyRecord] = []
            while try stepRow(statement, operation: "load-key-records") {
                let keyID = try columnString(statement, at: 0)
                let profileRawValue = try columnString(statement, at: 7)
                guard let profile = PGPKeyProfile(rawValue: profileRawValue) else {
                    throw ProtectedDataError.invalidEnvelope(
                        "Contacts SQLCipher key profile is unsupported."
                    )
                }
                let verificationRawValue = try columnString(statement, at: 13)
                guard let verificationState = ContactVerificationState(rawValue: verificationRawValue) else {
                    throw ProtectedDataError.invalidEnvelope(
                        "Contacts SQLCipher verification state is unsupported."
                    )
                }
                let usageRawValue = try columnString(statement, at: 14)
                guard let usageState = ContactKeyUsageState(rawValue: usageRawValue) else {
                    throw ProtectedDataError.invalidEnvelope(
                        "Contacts SQLCipher usage state is unsupported."
                    )
                }
                let projectionStatusRawValue = try columnString(statement, at: 15)
                guard let projectionStatus = ContactCertificationProjection.Status(
                    rawValue: projectionStatusRawValue
                ) else {
                    throw ProtectedDataError.invalidEnvelope(
                        "Contacts SQLCipher certification projection status is unsupported."
                    )
                }
                let keyVersion = try columnInt(statement, at: 6)
                guard keyVersion >= 0, keyVersion <= Int(UInt8.max) else {
                    throw ProtectedDataError.invalidEnvelope(
                        "Contacts SQLCipher key version is unsupported."
                    )
                }

                records.append(
                    ContactKeyRecord(
                        keyId: keyID,
                        contactId: try columnString(statement, at: 1),
                        fingerprint: try columnString(statement, at: 2),
                        primaryUserId: try columnOptionalString(statement, at: 3),
                        displayName: try columnString(statement, at: 4),
                        email: try columnOptionalString(statement, at: 5),
                        keyVersion: UInt8(keyVersion),
                        profile: profile,
                        primaryAlgo: try columnString(statement, at: 8),
                        subkeyAlgo: try columnOptionalString(statement, at: 9),
                        hasEncryptionSubkey: try columnBool(statement, at: 10),
                        isRevoked: try columnBool(statement, at: 11),
                        isExpired: try columnBool(statement, at: 12),
                        manualVerificationState: verificationState,
                        usageState: usageState,
                        certificationProjection: ContactCertificationProjection(
                            status: projectionStatus,
                            artifactIds: try loadKeyArtifactIDs(
                                table: "contact_key_projection_artifact_ids",
                                keyID: keyID
                            ),
                            lastValidatedAt: try columnOptionalDate(statement, at: 16)
                        ),
                        certificationArtifactIds: try loadKeyArtifactIDs(
                            table: "contact_key_certification_artifact_ids",
                            keyID: keyID
                        ),
                        publicKeyData: try columnData(statement, at: 17),
                        createdAt: try columnDate(statement, at: 18),
                        updatedAt: try columnDate(statement, at: 19)
                    )
                )
            }
            return records
        }
    }

    private func loadCertificationArtifacts() throws -> [ContactCertificationArtifactReference] {
        try withStatement(
            """
            SELECT
                artifact_id,
                key_id,
                created_at,
                canonical_signature_data,
                signature_digest,
                source,
                target_key_fingerprint,
                target_selector_kind,
                target_selector_user_id_data,
                target_selector_user_id_display_text,
                target_selector_occurrence_index,
                signer_primary_fingerprint,
                signing_key_fingerprint,
                certification_kind,
                validation_status,
                target_certificate_digest,
                last_validated_at,
                updated_at,
                export_filename
            FROM contact_certification_artifacts
            ORDER BY sort_order;
            """,
            operation: "load-certification-artifacts"
        ) { statement in
            var artifacts: [ContactCertificationArtifactReference] = []
            while try stepRow(statement, operation: "load-certification-artifacts") {
                let sourceRawValue = try columnString(statement, at: 5)
                guard let source = ContactCertificationArtifactSource(rawValue: sourceRawValue) else {
                    throw ProtectedDataError.invalidEnvelope(
                        "Contacts SQLCipher certification artifact source is unsupported."
                    )
                }
                let selectorKindRawValue = try columnString(statement, at: 7)
                guard let selectorKind = ContactCertificationTargetSelector.Kind(rawValue: selectorKindRawValue) else {
                    throw ProtectedDataError.invalidEnvelope(
                        "Contacts SQLCipher certification target selector is unsupported."
                    )
                }
                let certificationKind: OpenPGPCertificationKind?
                if let certificationKindRawValue = try columnOptionalString(statement, at: 13) {
                    guard let decodedKind = OpenPGPCertificationKind(rawValue: certificationKindRawValue) else {
                        throw ProtectedDataError.invalidEnvelope(
                            "Contacts SQLCipher certification kind is unsupported."
                        )
                    }
                    certificationKind = decodedKind
                } else {
                    certificationKind = nil
                }
                let validationRawValue = try columnString(statement, at: 14)
                guard let validationStatus = ContactCertificationValidationStatus(
                    rawValue: validationRawValue
                ) else {
                    throw ProtectedDataError.invalidEnvelope(
                        "Contacts SQLCipher certification validation status is unsupported."
                    )
                }

                artifacts.append(
                    ContactCertificationArtifactReference(
                        artifactId: try columnString(statement, at: 0),
                        keyId: try columnString(statement, at: 1),
                        createdAt: try columnDate(statement, at: 2),
                        canonicalSignatureData: try columnData(statement, at: 3),
                        signatureDigest: try columnOptionalString(statement, at: 4),
                        source: source,
                        targetKeyFingerprint: try columnOptionalString(statement, at: 6),
                        targetSelector: ContactCertificationTargetSelector(
                            kind: selectorKind,
                            userIdData: try columnOptionalData(statement, at: 8),
                            userIdDisplayText: try columnOptionalString(statement, at: 9),
                            occurrenceIndex: try columnOptionalInt(statement, at: 10)
                        ),
                        signerPrimaryFingerprint: try columnOptionalString(statement, at: 11),
                        signingKeyFingerprint: try columnOptionalString(statement, at: 12),
                        certificationKind: certificationKind,
                        validationStatus: validationStatus,
                        targetCertificateDigest: try columnOptionalString(statement, at: 15),
                        lastValidatedAt: try columnOptionalDate(statement, at: 16),
                        updatedAt: try columnOptionalDate(statement, at: 17),
                        exportFilename: try columnOptionalString(statement, at: 18)
                    )
                )
            }
            return artifacts
        }
    }

    private func loadIdentityTagIDs(contactID: String) throws -> [String] {
        try loadOrderedStringIDs(
            sql: """
            SELECT tag_id
            FROM contact_identity_tags
            WHERE contact_id = ?
            ORDER BY ordinal;
            """,
            value: contactID,
            operation: "load-identity-tags"
        )
    }

    private func loadKeyArtifactIDs(table: String, keyID: String) throws -> [String] {
        try loadOrderedStringIDs(
            sql: """
            SELECT artifact_id
            FROM \(table)
            WHERE key_id = ?
            ORDER BY ordinal;
            """,
            value: keyID,
            operation: "load-\(table)"
        )
    }

    private func loadOrderedStringIDs(
        sql: String,
        value: String,
        operation: String
    ) throws -> [String] {
        try withStatement(sql, operation: operation) { statement in
            try bindText(value, to: statement, at: 1)
            var ids: [String] = []
            while try stepRow(statement, operation: operation) {
                ids.append(try columnString(statement, at: 0))
            }
            return ids
        }
    }

    private func runTransaction(_ work: () throws -> Void) throws {
        try exec("BEGIN IMMEDIATE TRANSACTION;", operation: "begin-transaction")
        do {
            try work()
            try exec("COMMIT;", operation: "commit-transaction")
        } catch {
            try? exec("ROLLBACK;", operation: "rollback-transaction")
            throw error
        }
    }

    @discardableResult
    private func requireOpenDatabase() throws -> OpaquePointer {
        guard let db else {
            throw ProtectedDataError.authorizingUnavailable
        }
        return db
    }

    private func exec(_ sql: String, operation: String) throws {
        let database = try requireOpenDatabase()
        var errorMessage: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(database, sql, nil, nil, &errorMessage)
        if let errorMessage {
            sqlite3_free(errorMessage)
        }
        guard rc == SQLITE_OK else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher \(operation) failed."
            )
        }
    }

    private func withStatement<T>(
        _ sql: String,
        operation: String,
        _ work: (OpaquePointer) throws -> T
    ) throws -> T {
        let database = try requireOpenDatabase()
        var statement: OpaquePointer?
        let rc = sqlite3_prepare_v2(database, sql, -1, &statement, nil)
        guard rc == SQLITE_OK, let statement else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher \(operation) prepare failed."
            )
        }
        defer {
            sqlite3_finalize(statement)
        }
        return try work(statement)
    }

    private func stepDone(_ statement: OpaquePointer, operation: String) throws {
        let rc = sqlite3_step(statement)
        guard rc == SQLITE_DONE else {
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher \(operation) step failed."
            )
        }
    }

    private func stepRow(_ statement: OpaquePointer, operation: String) throws -> Bool {
        let rc = sqlite3_step(statement)
        switch rc {
        case SQLITE_ROW:
            return true
        case SQLITE_DONE:
            return false
        default:
            throw ProtectedDataError.invalidEnvelope(
                "Contacts SQLCipher \(operation) step failed."
            )
        }
    }

    private func querySingleString(_ sql: String, operation: String) throws -> String {
        try withStatement(sql, operation: operation) { statement in
            let rc = sqlite3_step(statement)
            guard rc == SQLITE_ROW else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts SQLCipher \(operation) did not return a row."
                )
            }
            return try columnString(statement, at: 0)
        }
    }

    private func querySingleInt(_ sql: String, operation: String) throws -> Int32 {
        try withStatement(sql, operation: operation) { statement in
            let rc = sqlite3_step(statement)
            guard rc == SQLITE_ROW else {
                throw ProtectedDataError.invalidEnvelope(
                    "Contacts SQLCipher \(operation) did not return a row."
                )
            }
            return Int32(try columnInt(statement, at: 0))
        }
    }

    private func queryStrings(_ sql: String, operation: String) throws -> [String] {
        try withStatement(sql, operation: operation) { statement in
            var values: [String] = []
            while try stepRow(statement, operation: operation) {
                values.append(try columnString(statement, at: 0))
            }
            return values
        }
    }

    private func applyFileProtectionToDatabaseFiles() throws {
        for url in storageRoot.contactsSQLCipherDatabaseFileURLs(for: domainID) {
            try storageRoot.applyProtectionToManagedItemIfPresent(at: url)
        }
    }

    private func validateSnapshotForStorage(_ snapshot: ContactsDomainSnapshot) throws {
        do {
            try snapshot.validateContract()
        } catch let error as ContactsDomainValidationError {
            throw ProtectedDataError.invalidEnvelope(error.reason)
        }
    }

    private func bindText(_ value: String, to statement: OpaquePointer, at index: Int32) throws {
        let utf8 = Array(value.utf8CString)
        let rc = utf8.withUnsafeBufferPointer { buffer in
            sqlite3_bind_text(
                statement,
                index,
                buffer.baseAddress,
                Int32(buffer.count - 1),
                Self.transientDestructor
            )
        }
        guard rc == SQLITE_OK else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher text binding failed.")
        }
    }

    private func bindOptionalText(_ value: String?, to statement: OpaquePointer, at index: Int32) throws {
        guard let value else {
            try bindNull(to: statement, at: index)
            return
        }
        try bindText(value, to: statement, at: index)
    }

    private func bindBlob(_ value: Data, to statement: OpaquePointer, at index: Int32) throws {
        let rc: Int32
        if value.isEmpty {
            rc = sqlite3_bind_zeroblob(statement, index, 0)
        } else {
            rc = value.withUnsafeBytes { buffer in
                sqlite3_bind_blob(
                    statement,
                    index,
                    buffer.baseAddress,
                    Int32(buffer.count),
                    Self.transientDestructor
                )
            }
        }
        guard rc == SQLITE_OK else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher blob binding failed.")
        }
    }

    private func bindOptionalBlob(_ value: Data?, to statement: OpaquePointer, at index: Int32) throws {
        guard let value else {
            try bindNull(to: statement, at: index)
            return
        }
        try bindBlob(value, to: statement, at: index)
    }

    private func bindDate(_ value: Date, to statement: OpaquePointer, at index: Int32) throws {
        let rc = sqlite3_bind_double(statement, index, value.timeIntervalSince1970)
        guard rc == SQLITE_OK else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher date binding failed.")
        }
    }

    private func bindOptionalDate(_ value: Date?, to statement: OpaquePointer, at index: Int32) throws {
        guard let value else {
            try bindNull(to: statement, at: index)
            return
        }
        try bindDate(value, to: statement, at: index)
    }

    private func bindInt(_ value: Int, to statement: OpaquePointer, at index: Int32) throws {
        let rc = sqlite3_bind_int64(statement, index, sqlite3_int64(value))
        guard rc == SQLITE_OK else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher integer binding failed.")
        }
    }

    private func bindOptionalInt(_ value: Int?, to statement: OpaquePointer, at index: Int32) throws {
        guard let value else {
            try bindNull(to: statement, at: index)
            return
        }
        try bindInt(value, to: statement, at: index)
    }

    private func bindBool(_ value: Bool, to statement: OpaquePointer, at index: Int32) throws {
        try bindInt(value ? 1 : 0, to: statement, at: index)
    }

    private func bindNull(to statement: OpaquePointer, at index: Int32) throws {
        let rc = sqlite3_bind_null(statement, index)
        guard rc == SQLITE_OK else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher null binding failed.")
        }
    }

    private func columnString(_ statement: OpaquePointer, at index: Int32) throws -> String {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL,
              let value = sqlite3_column_text(statement, index) else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher text column is invalid.")
        }
        let byteCount = Int(sqlite3_column_bytes(statement, index))
        guard let string = String(data: Data(bytes: value, count: byteCount), encoding: .utf8) else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher text column is invalid.")
        }
        return string
    }

    private func columnOptionalString(_ statement: OpaquePointer, at index: Int32) throws -> String? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else {
            return nil
        }
        return try columnString(statement, at: index)
    }

    private func columnData(_ statement: OpaquePointer, at index: Int32) throws -> Data {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher blob column is invalid.")
        }
        let byteCount = Int(sqlite3_column_bytes(statement, index))
        guard byteCount > 0 else {
            return Data()
        }
        guard let bytes = sqlite3_column_blob(statement, index) else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher blob column is invalid.")
        }
        return Data(bytes: bytes, count: byteCount)
    }

    private func columnOptionalData(_ statement: OpaquePointer, at index: Int32) throws -> Data? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else {
            return nil
        }
        return try columnData(statement, at: index)
    }

    private func columnDate(_ statement: OpaquePointer, at index: Int32) throws -> Date {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher date column is invalid.")
        }
        return Date(timeIntervalSince1970: sqlite3_column_double(statement, index))
    }

    private func columnOptionalDate(_ statement: OpaquePointer, at index: Int32) throws -> Date? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else {
            return nil
        }
        return try columnDate(statement, at: index)
    }

    private func columnInt(_ statement: OpaquePointer, at index: Int32) throws -> Int {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else {
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher integer column is invalid.")
        }
        return Int(sqlite3_column_int64(statement, index))
    }

    private func columnOptionalInt(_ statement: OpaquePointer, at index: Int32) throws -> Int? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else {
            return nil
        }
        return try columnInt(statement, at: index)
    }

    private func columnBool(_ statement: OpaquePointer, at index: Int32) throws -> Bool {
        let value = try columnInt(statement, at: index)
        switch value {
        case 0: return false
        case 1: return true
        default:
            throw ProtectedDataError.invalidEnvelope("Contacts SQLCipher boolean column is invalid.")
        }
    }
}
