# CypherAir X

**Fully offline OpenPGP encryption for Apple platforms — zero network, minimal permissions.** CypherAir X is an open-source OpenPGP tool for people who want to communicate securely without cryptographic knowledge: encrypt, decrypt, sign, and verify, with keys and contacts managed entirely on device. It is a SwiftUI app over a Rust OpenPGP engine (Sequoia PGP) bridged through UniFFI.

- **Platforms** — iOS, iPadOS, macOS, and visionOS.
- **Zero network access** — no HTTP(S), no networked SDKs, no telemetry, no update checks; the app works in airplane mode.
- **One usage description** — for local biometric authentication. No camera, photo library, contacts, or network permission; any other entitlement in the project is a resource, sandbox, or hardening entitlement, not a privacy permission.
- **One unlock passphrase** — mandatory and never stored. Every key on the device is sealed by the Secure Enclave with that passphrase folded in, so a copy of the app's files and Keychain decrypts nothing, on this device or any other, without it. Design: [docs/SECURITY.md](docs/SECURITY.md).
- **Key families** — portable (software custody, exportable) and device-bound (Secure Enclave custody, never exportable), chosen at key generation and immutable per key. Promises: [docs/PRODUCT.md](docs/PRODUCT.md); custody: [docs/CUSTODY.md](docs/CUSTODY.md).

## Build

- macOS on Apple Silicon with a current Xcode.
- Rust stable with the Apple targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin aarch64-apple-visionos aarch64-apple-visionos-sim`
- A fresh clone cannot build until the sync in [docs/BUILD.md](docs/BUILD.md) has run. The sync downloads pinned, attested artifacts, so the build toolchain needs network access even though the app never does.

## License

Unless otherwise noted, first-party CypherAir source code in this repository is
made available under either of the following licenses, at your option:

- GNU General Public License, version 3 or any later version
- Mozilla Public License, version 2.0

SPDX expression for first-party code: **`GPL-3.0-or-later OR MPL-2.0`**.

Full license texts are provided in [LICENSE-GPL](LICENSE-GPL) and
[LICENSE-MPL](LICENSE-MPL).

The OpenPGP engine uses [Sequoia PGP](https://sequoia-pgp.org/) (`LGPL-2.0-or-later`).

Third-party components remain under their own licenses. See the bundled notices
and repository documentation for third-party license details and distribution
compliance materials.
