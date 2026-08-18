# Architecture

*Layer and boundary rules only. The directory listing is the source of truth for structure — this document never inventories modules, files, or flows. Security invariants: [SECURITY.md](SECURITY.md); custody: [CUSTODY.md](CUSTODY.md); storage: [STORAGE.md](STORAGE.md); the XCFramework/bindings artifact decision: [BUILD.md](BUILD.md) §5.*

## Layers

CypherAir X is a layered application: a SwiftUI presentation layer, a Swift services layer, a Security layer, app-owned Models, and a Rust cryptographic engine reached through Swift FFI adapters and generated UniFFI bindings. UI is SwiftUI; `UIKit`/`AppKit` imports are narrow platform bridges.

Boundary rules:

- **App → Security is a narrow edge.** Feature views reach crypto, Keychain, and lock state through the Services layer; only composition, the shell/lock surfaces, and the settings surfaces touch Security types directly.
- **Services never call the engine directly** — each operation family has a dedicated FFI adapter. **One documented exception:** quantum-safety classification of the produced artifact calls the stateless generated engine directly.
- **Error normalization has one chokepoint.** Generated `PgpError` is normalized into the app-owned `CypherAirError` vocabulary only at the FFI adapter boundary; Models, ScreenModels, and Views never see `PgpError`. External-seam callback failures travel as sanitized categories, never free-form strings.

## Rust / FFI contract rules

- **The FFI surface is UniFFI-annotated, taking and returning `Vec<u8>`/`String`** — Sequoia types never cross the boundary.
- **Payload input classes stay explicit** — every input is `binary-only`, `armored-only`, or `dual-format`, stated at the function.
- **Cryptographic selectors use bytes, not display strings**; discovery helpers are part of the contract when a selector needs enumerating, so string inference never leaks into Swift.
- **Signer fingerprint means the primary key's fingerprint, not the subkey's** — the naming trap the contract exists to pin.
- **The engine holds no expiry policy of its own.** A certificate's validity is exactly what the caller stated: `KeyValidity` names both cases, so declining an expiry is a value the caller passes rather than an argument it omits, and no generation path can substitute a term nobody asked for ([PRODUCT.md](PRODUCT.md) §5).
- **The outgoing message format is the engine's to state, never Swift's to derive.** The engine answers it from the same recipient arguments `encrypt` takes, so anything shown before sending describes the message that gets sent ([PRODUCT.md](PRODUCT.md) §5).
