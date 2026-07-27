# Architecture

*Layer and boundary rules only. The directory listing is the source of truth for structure — this document never inventories modules, files, or flows. Security invariants: [SECURITY.md](SECURITY.md); custody: [CUSTODY.md](CUSTODY.md); storage: [STORAGE.md](STORAGE.md); the XCFramework/bindings artifact decision: [FFI_ARTIFACT_DECISION.md](FFI_ARTIFACT_DECISION.md).*

## Layers

CypherAir X is a layered application: a SwiftUI presentation layer (`Sources/App/`), a Swift services layer (`Sources/Services/`), a Security layer (`Sources/Security/`), app-owned Models (`Sources/Models/`), and a Rust cryptographic engine (`pgp-mobile/`) reached through the Swift FFI adapters in `Sources/Services/FFI/` and generated UniFFI bindings. UI is SwiftUI; `UIKit`/`AppKit` imports are narrow platform bridges (pasteboard, windowing and the shield window, text-input hosting, presentation polish), never a screen framework.

Boundary rules:

- **App → Security is a narrow edge.** Feature views reach crypto, Keychain, and lock state through the Services layer; only composition (`AppContainer`), the shell/lock surfaces, and the settings surfaces touch Security types directly.
- **Services never call `PgpEngine` directly** — each operation family has a dedicated FFI adapter; the adapter directory listing is the source of truth for which exist. **One documented exception:** `EncryptScreenModel` calls the stateless generated engine directly for quantum-safety classification of the produced artifact.
- **Error normalization has one chokepoint.** Generated `PgpError` is normalized into the app-owned `CypherAirError` vocabulary only at the FFI adapter boundary (`PGPErrorMapper`); Models, ScreenModels, and Views never see `PgpError`. External-seam callback failures travel as sanitized categories, never free-form strings.
- **`PasswordMessageService` is deliberately outside the two-phase recipient flow** — no PKESK matching; it is its own path end to end.

## Rust / FFI contract rules

- **The API surface is `pgp-mobile/src/lib.rs`**, UniFFI-annotated, taking and returning `Vec<u8>`/`String` — Sequoia types never cross the boundary.
- **Evolution is additive.** Superseded surfaces are deleted intentionally; nothing is kept as a permanent compatibility API.
- **Payload input classes stay explicit** — every input is `binary-only`, `armored-only`, or `dual-format`, stated at the function.
- **Cryptographic selectors use bytes, not display strings** (e.g. `userIdData` + occurrence index); discovery helpers are part of the contract when a selector needs enumerating, so string inference never leaks into Swift.
- **Signer fingerprint means the primary key's fingerprint, not the subkey's** — the naming trap the contract exists to pin.
- Sequoia was chosen as the only Rust OpenPGP implementation with complete RFC 9580 support plus production RFC 9980.
