# Architecture

*Layer and boundary rules only. The directory listing is the source of truth for structure — this document never inventories modules, files, or flows. Security invariants: [SECURITY.md](SECURITY.md); custody: [CUSTODY.md](CUSTODY.md); storage: [STORAGE.md](STORAGE.md); the artifact decision: [BUILD.md](BUILD.md).*

## Boundary rules

- **App → Security is a narrow edge.** Feature views reach crypto, Keychain, and lock state through the Services layer; only composition, the shell/lock surfaces, and the settings surfaces touch Security types directly. UI is SwiftUI; `UIKit`/`AppKit` imports are narrow platform bridges.
- **Services never call the engine directly** — each operation family has a dedicated FFI adapter. One documented exception: quantum-safety classification of the produced artifact calls the stateless generated engine directly.
- **An exported artifact's name is decided once, where the artifact is produced, and never recomputed** ([PRODUCT.md](PRODUCT.md)).
- **Error normalization has one chokepoint.** Generated `PgpError` is normalized into the app-owned `CypherAirError` vocabulary only at the FFI adapter boundary; Models, ScreenModels, and Views never see `PgpError`. External-seam callback failures travel as sanitized categories, never free-form strings.

## Rust / FFI contract rules

- **The FFI surface is UniFFI-annotated, taking and returning `Vec<u8>`/`String`** — Sequoia types never cross the boundary.
- **Payload input classes stay explicit** — every input is `binary-only`, `armored-only`, or `dual-format`, stated at the function.
- **Cryptographic selectors use bytes, not display strings**; discovery helpers are part of the contract when a selector needs enumerating, so string inference never leaks into Swift.
- **Signer fingerprint means the primary key's fingerprint, not the subkey's.**
- **The engine holds no expiry policy of its own.** A certificate's validity is exactly what the caller stated; declining an expiry is a value the caller passes, never an argument it omits ([PRODUCT.md](PRODUCT.md)).
- **The outgoing message format is the engine's to state, never Swift's to derive**, answered from the same recipient arguments `encrypt` takes ([PRODUCT.md](PRODUCT.md)).
