# Documentation Map

Which document owns which facts. Pointer lines only — this file states no facts itself. Doc classes, metadata headers, and the update-triggers table: docs/WORKFLOW.md §4.

- docs/PRODUCT.md — product promises: deployment targets and the minimum-RAM floor (build-settings side: `CypherAir.xcodeproj`), key-family promises, message-format selection (§5), compatibility promises (§6).
- docs/SECURITY.md — the security model: authentication modes (§4), MIE (§8), security-critical predicates and coding invariants (§10).
- docs/CUSTODY.md — key custody: software vs Secure Enclave, exportability.
- docs/STORAGE.md — persisted state: protected domains, Keychain rows, the envelope version map (§5), storage target design (§6, roadmap).
- docs/ARCHITECTURE.md — layer and boundary rules; service ownership; where each UI framework is used.
- docs/TESTING.md — test plans, CI lanes, per-target cargo commands, the hosted-runner caveat.
- docs/BUILD.md — stable release ordering (§1), compliance assets, the arm64e toolchain contract (§3), FFI artifact shape (§5), the Rust↔Xcode sync contract and rebuild table (§6).
- docs/WORKFLOW.md — the development loop, verification gates, the security gate, the documentation contract.
- docs/ARM64E_STATUS.md — the machine-parsed arm64e stage1 pin, nothing else.
