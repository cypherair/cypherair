import Foundation

struct SecureEnclaveCustodyHandleInventoryItem: Equatable, Sendable {
    let applicationTagData: Data
    let reference: SecureEnclaveCustodyHandleReference?
    let serviceKind: String

    init?(applicationTagData: Data) {
        let prefixData = Data("\(SecureEnclaveCustodyHandleReference.applicationTagPrefix).".utf8)
        guard applicationTagData.count >= prefixData.count,
              applicationTagData.prefix(prefixData.count).elementsEqual(prefixData) else {
            return nil
        }
        self.applicationTagData = applicationTagData
        if let applicationTagString = String(data: applicationTagData, encoding: .utf8) {
            self.reference = try? SecureEnclaveCustodyHandleReference(applicationTagString: applicationTagString)
            self.serviceKind = AuthTraceMetadata.keychainServiceKind(for: applicationTagString)
        } else {
            self.reference = nil
            self.serviceKind = "secureEnclaveCustodyHandle"
        }
    }

    var role: PGPPrivateOperationRole? {
        reference?.role
    }

    var isMalformed: Bool {
        reference == nil
    }
}
