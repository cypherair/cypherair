import Foundation

/// The document types the app tells the system it can open.
///
/// The list is the Swift half of `CFBundleDocumentTypes` in `CypherAir-Info
/// .plist`: a file arriving through any other extension was not offered to this
/// app, and is refused before its bytes are read.
enum OpenedDocumentType: String, CaseIterable {
    case gpg
    case pgp
    case asc
    case sig

    init?(fileName: String) {
        self.init(rawValue: (fileName as NSString).pathExtension.lowercased())
    }

    /// What this extension is entitled to hold.
    ///
    /// `.gpg` and `.pgp` name an encrypted message and `.sig` a detached
    /// signature, each a single claim that content either meets or contradicts.
    /// `.asc` claims only that the content is armored, so it covers everything
    /// armor can carry — choosing among those is dispatch, not mismatch.
    var permittedContent: Set<PGPDataKind> {
        switch self {
        case .gpg, .pgp:
            [.ciphertext]
        case .asc:
            [.publicCertificate, .secretKey, .ciphertext, .signedMessage, .detachedSignature]
        case .sig:
            [.detachedSignature]
        }
    }
}

/// What an opened file turns out to be for.
enum OpenedDocumentPurpose: Equatable {
    /// The contact-import confirmation, the same one a scanned QR code reaches.
    case contactImport
    /// A tool screen, which the app navigates to and which then claims the
    /// document.
    case screen(OpenedDocumentScreen)
}

/// The screens a document can be handed to.
///
/// Contact import is not among them: a certificate is confirmed in a sheet the
/// app raises over whatever is on screen, so there is nowhere to arrive and
/// nothing to claim.
enum OpenedDocumentScreen: Equatable {
    /// Import Key, with the file already chosen.
    case keyImport
    /// Decrypt, with the file already selected.
    case decryption
    /// Verify, with the signed message already loaded.
    case verification

    var route: AppRoute {
        switch self {
        case .keyImport: .importKey
        case .decryption: .decrypt
        case .verification: .verify
        }
    }

    /// The tab the route is stacked on.
    ///
    /// The tools go on Home, on every platform: the tool tabs are hidden at
    /// compact width, so Home is the one place the route exists everywhere —
    /// and it is where Home's own buttons open the same screens. Importing a key
    /// belongs on Keys for the same reason: that is where the reader would have
    /// started.
    var tab: AppShellTab {
        switch self {
        case .keyImport: .keys
        case .decryption, .verification: .home
        }
    }
}

/// The dispatch from an opened file to a purpose — or to a refusal.
///
/// Content decides and the name constrains: the packets say what the file is,
/// and the extension says what it was allowed to be. A file that is not what its
/// name claims is refused rather than processed by content, because acting on it
/// would let whoever named the file choose a destination its reader did not.
enum OpenedDocumentDispatch {
    static func purpose(
        of content: PGPDataKind,
        declaredAs type: OpenedDocumentType
    ) throws -> OpenedDocumentPurpose {
        guard type.permittedContent.contains(content) else {
            throw CypherAirError.openedFileUnsupportedContent
        }

        switch content {
        case .publicCertificate:
            return .contactImport
        case .secretKey:
            return .screen(.keyImport)
        case .ciphertext:
            return .screen(.decryption)
        case .signedMessage:
            return .screen(.verification)
        case .detachedSignature:
            // A signature alone proves nothing about a file the app does not
            // have. The reader is told what is missing rather than walked into
            // a half-filled Verify screen.
            throw CypherAirError.openedDetachedSignatureNeedsOriginal
        case .revocationCertificate:
            // Never reached: no extension permits a revocation certificate, so
            // the guard above has already refused it. Kept explicit so that
            // adding one to `permittedContent` is a decision rather than an
            // accident.
            throw CypherAirError.openedFileUnsupportedContent
        }
    }
}

/// A document the system handed the app, read and identified, on its way to the
/// screen that handles it.
struct OpenedDocument: Identifiable, Equatable {
    /// How the screen receives it.
    enum Delivery: Equatable {
        /// The content itself, for a screen that puts it in front of the reader.
        case content(Data)
        /// A file the app owns and the screen may keep reading — the route for
        /// an encrypted message, which has no size worth holding in memory.
        case file(URL)
    }

    let id = UUID()
    let screen: OpenedDocumentScreen
    let fileName: String
    let delivery: Delivery

    /// The content, for every screen but Decrypt.
    var content: Data? {
        guard case .content(let content) = delivery else { return nil }
        return content
    }

    /// The file, for Decrypt alone.
    var fileURL: URL? {
        guard case .file(let fileURL) = delivery else { return nil }
        return fileURL
    }

    static func == (lhs: OpenedDocument, rhs: OpenedDocument) -> Bool {
        lhs.id == rhs.id
    }
}

/// What reading an opened file produced.
enum OpenedDocumentOutcome {
    /// A public certificate, to confirm before anything is imported.
    case contactImport(certificate: Data)
    /// A document waiting for the screen the app is about to show.
    case handoff(OpenedDocument)
}
