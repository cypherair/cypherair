internal import Sealing
internal import Stores
internal import Vault

/// The vault and its stores, composed in this one place: the hardware enclave
/// and the Keychain on a device; the software enclave and memory on the
/// simulator, in previews and in tests. The Keychain holds the sealed root
/// alone; every key's material lives in the sealed key list.
struct Composition: Sendable {
    let vault: Vault
    let keychain: any Keychain
    let files: any DomainFiles
    let domains: Domains
    let custody: CustodyKeyStore
    let prompts: PromptTexts

    init(
        enclave: any Enclave,
        keychain: any Keychain,
        files: any DomainFiles,
        stretcher: any PassphraseStretcher,
        authenticator: any Authenticator,
        prompts: PromptTexts
    ) {
        vault = Vault(
            enclave: enclave,
            rootRows: keychain.rows(service: Vault.sealedRootService),
            stretcher: stretcher,
            authenticator: authenticator
        )
        self.keychain = keychain
        self.files = files
        domains = Domains(files: files)
        custody = CustodyKeyStore(enclave: enclave)
        self.prompts = prompts
    }

    static func live(prompts: PromptTexts) throws(StoreError) -> Composition {
        #if targetEnvironment(simulator)
        software(prompts: prompts)
        #else
        Composition(
            enclave: HardwareEnclave(),
            keychain: SystemKeychain(),
            files: try ProtectedDataDirectory.applicationSupport(),
            stretcher: EngineStretcher(),
            authenticator: SystemAuthenticator(),
            prompts: prompts
        )
        #endif
    }

    /// Never for user data: nothing outlives the process.
    static func software(
        prompts: PromptTexts,
        enclave: any Enclave = SoftwareEnclave(),
        keychain: any Keychain = InMemoryKeychain(),
        files: any DomainFiles = InMemoryDomainFiles(),
        stretcher: any PassphraseStretcher = EngineStretcher(),
        authenticator: any Authenticator = NoPromptAuthenticator()
    ) -> Composition {
        Composition(enclave: enclave, keychain: keychain, files: files, stretcher: stretcher, authenticator: authenticator, prompts: prompts)
    }
}
