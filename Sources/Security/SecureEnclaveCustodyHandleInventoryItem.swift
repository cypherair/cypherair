import Foundation

struct SecureEnclaveCustodyHandleInventoryItem: Equatable, Sendable {
    let applicationTagData: Data
    let reference: SecureEnclaveCustodyHandleReference?
    let serviceKind: String

    init?(applicationTagData: Data) {
        guard let applicationTagString = String(data: applicationTagData, encoding: .utf8) else {
            return nil
        }
        guard applicationTagString.hasPrefix("\(SecureEnclaveCustodyHandleReference.applicationTagPrefix).") else {
            return nil
        }
        self.applicationTagData = applicationTagData
        self.reference = try? SecureEnclaveCustodyHandleReference(applicationTagString: applicationTagString)
        self.serviceKind = AuthTraceMetadata.keychainServiceKind(for: applicationTagString)
    }

    var role: PGPPrivateOperationRole? {
        reference?.role
    }

    var isMalformed: Bool {
        reference == nil
    }
}
