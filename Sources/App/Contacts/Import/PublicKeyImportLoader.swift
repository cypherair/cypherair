import CoreImage
import Foundation
import PhotosUI
import SwiftUI

struct LoadedPublicKeyFile {
    let data: Data
    let text: String?
    let fileName: String
}

struct PublicKeyImportInspection {
    let keyData: Data
    let keyInfo: KeyInfo
    let profile: KeyProfile
}

@MainActor
struct PublicKeyImportLoader {
    let qrService: QRService

    func inspect(keyData: Data) throws -> PublicKeyImportInspection {
        let validated = try qrService.inspectImportablePublicCertificate(keyData: keyData)
        return PublicKeyImportInspection(
            keyData: validated.publicCertData,
            keyInfo: validated.keyInfo,
            profile: validated.profile
        )
    }

    func loadFromURL(_ url: URL) throws -> PublicKeyImportInspection {
        try inspect(keyData: qrService.parseImportURL(url))
    }

    func loadKeyDataFromQRPhoto(_ item: PhotosPickerItem) async throws -> Data {
        guard let data = try await item.loadTransferable(type: Data.self) else {
            throw CypherAirError.invalidQRCode
        }

        guard let ciImage = CIImage(data: data) else {
            throw CypherAirError.invalidQRCode
        }

        let qrStrings = try await qrService.decodeQRCodes(from: ciImage)

        guard let urlString = qrStrings.first(where: { $0.hasPrefix("cypherair://") }),
              let url = URL(string: urlString) else {
            throw CypherAirError.invalidQRCode
        }

        return try qrService.parseImportURL(url)
    }

    func loadFromQRPhoto(_ item: PhotosPickerItem) async throws -> PublicKeyImportInspection {
        try inspect(keyData: try await loadKeyDataFromQRPhoto(item))
    }

    func loadFromFile(url: URL, failure: CypherAirError) throws -> LoadedPublicKeyFile {
        let data = try SecurityScopedFileAccess.withAccess(to: url, failure: failure) {
            try Data(contentsOf: url)
        }

        return LoadedPublicKeyFile(
            data: data,
            text: String(data: data, encoding: .utf8),
            fileName: url.lastPathComponent
        )
    }
}
