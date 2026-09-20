# Architecture

## Boundary rules

- **The security core is a local Swift package, `Packages/CypherVault`, with three targets that depend downward only: Sealing, Vault, Stores.** Sealing is pure functions — the enclave-sealed envelope codec, the snapshot codec, the HKDF derivations, the passphrase stretcher — with no I/O. Vault owns the sealed root, the unlock chain, the session values, the identity wrapping key, and the workflows: onboarding, unlock, relock, passphrase change, reset, recovery classification. Stores hold contacts, settings, the key list, portable envelopes, device-bound handles, and split custody, and receive keys and contexts from Vault, never the passphrase. The package imports Foundation, CryptoKit, Security, and LocalAuthentication only: no UI framework, no engine. The app imports Vault and Stores; nothing in the package can import the app.
- **App → Services → package is the only path to keys and lock state.** Feature views reach crypto, the vault, and lock state through the Services layer; only composition, the shell/lock surfaces, and the settings surfaces touch Vault types directly. UI is SwiftUI; `UIKit`/`AppKit` imports are narrow platform bridges.
- **Services never call the engine directly** — each operation family has a dedicated FFI adapter. One documented exception: quantum-safety classification of the produced artifact calls the stateless generated engine directly.
- **An exported artifact's name is decided once, where the artifact is produced, and never recomputed** ([PRODUCT.md](PRODUCT.md)).
- **Error normalization has one chokepoint.** Generated `PgpError` is normalized into the app-owned `CypherAirError` vocabulary only at the FFI adapter boundary; Models, ScreenModels, and Views never see `PgpError`. External-seam callback failures travel as sanitized categories, never free-form strings.

## Package build rules

- **Packages are built for every app slice through the shared workspace setting** `iOSPackagesShouldBuildARM64e` in the project's embedded workspace, Apple's documented mechanism. Without it Xcode builds packages for arm64 alone and the linker drops them from the arm64e and x1 slices with only a warning. No separate check guards this: the app calls the vault at every unlock, so a package missing a slice fails the link on undefined symbols.
- **The package manifest mirrors the project's Swift settings** — Swift 6 language mode and the upcoming features approachable concurrency enables — because packages inherit none of them. Platform floors stay equal to the app's.

## Rust / FFI contract rules

- **The FFI surface is UniFFI-annotated, taking and returning `Vec<u8>`/`String`** — Sequoia types never cross the boundary.
- **Payload input classes stay explicit** — every input is `binary-only`, `armored-only`, or `dual-format`, stated at the function.
- **Cryptographic selectors use bytes, not display strings**; discovery helpers are part of the contract when a selector needs enumerating, so string inference never leaks into Swift.
- **Signer fingerprint means the primary key's fingerprint, not the subkey's.**
- **The engine holds no expiry policy of its own.** A certificate's validity is exactly what the caller stated; declining an expiry is a value the caller passes, never an argument it omits ([PRODUCT.md](PRODUCT.md)).
- **The outgoing message format is the engine's to state, never Swift's to derive**, answered from the same recipient arguments `encrypt` takes ([PRODUCT.md](PRODUCT.md)).
- **The unlock stretch is an engine function with fixed parameters and no policy.** Swift passes the passphrase bytes and the salt; the engine returns the 32-byte stretched value and zeroizes its copies. The backup S2K paths are untouched by it.
