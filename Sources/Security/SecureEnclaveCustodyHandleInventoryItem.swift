import Foundation

struct SecureEnclaveCustodyHandleInventoryItem: Equatable, Sendable {
    let applicationTagData: Data
    let reference: SecureEnclaveCustodyHandleReference?

    init?(applicationTagData: Data) {
        let prefixData = Data("\(SecureEnclaveCustodyHandleReference.applicationTagPrefix).".utf8)
        guard applicationTagData.count >= prefixData.count,
              applicationTagData.prefix(prefixData.count).elementsEqual(prefixData) else {
            return nil
        }
        self.applicationTagData = applicationTagData
        if let applicationTagString = String(data: applicationTagData, encoding: .utf8) {
            self.reference = try? SecureEnclaveCustodyHandleReference(applicationTagString: applicationTagString)
        } else {
            self.reference = nil
        }
    }

    var role: PGPPrivateOperationRole? {
        reference?.role
    }
}
