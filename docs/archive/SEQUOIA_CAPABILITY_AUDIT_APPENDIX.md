# Sequoia Capability Audit Appendix

> Status: Archived appendix snapshot. Kept as historical boundary context; no longer treated as an active companion planning document.

> Purpose: Record the Sequoia 2.2 surface that is outside CypherAir's current build baseline or current product/security boundary.
> Audience: Human developers, reviewers, and AI coding tools.

This appendix is intentionally **not** a defect list or backlog by itself. Its job is to capture `out-of-boundary surface` and keep it separate from the current-build inventory in [`SEQUOIA_CAPABILITY_AUDIT.md`](../SEQUOIA_CAPABILITY_AUDIT.md).

## 1. Classification Rule

A Sequoia capability belongs in this appendix only if at least one of the following is true:

- it is **not compiled into the current repository build**
- it is **intentionally outside CypherAir's current product/security boundary**

The converse also matters:

- if a capability is available in the current repository build and is still missing or disconnected, it belongs in the main audit as a `current-build omission`
- if the project decides to actively pursue wrapper work for a current-build omission, it belongs in a live roadmap document rather than this archived snapshot

This appendix should therefore stay narrower than both the main audit and the archived roadmap snapshot.

## 2. Feature-Gated Sequoia Surface Not Compiled In This Repository

CypherAir builds `sequoia-openpgp` with:

- `default-features = false`
- `crypto-openssl`
- `compression-deflate`

The following Sequoia 2.2 surfaces exist upstream but are not available in the current repository build:

| Sequoia surface | Upstream evidence | Current repo status | Why it is kept in the appendix |
|---|---|---|---|
| `compression-bzip2` | Sequoia feature list | Unavailable in current build | Feature not enabled; CypherAir docs already exclude bzip2 for dependency reasons. |
| `compression` default bundle (`deflate + bzip2`) | Sequoia feature list | Unavailable in current build | Repository explicitly opts out of default features. |
| `crypto-nettle` backend | Sequoia feature list | Unavailable in current build | Product standardizes on OpenSSL backend. |
| `crypto-rust` backend | Sequoia feature list | Unavailable in current build | Product standardizes on OpenSSL backend. |
| `crypto-botan` / `crypto-botan2` backends | Sequoia feature list | Unavailable in current build | Not selected by current dependency policy. |
| `crypto-cng` backend | Sequoia feature list | Unavailable in current build | Windows-specific backend outside current Apple-platform scope. |
| `allow-experimental-crypto` | Sequoia feature list | Unavailable in current build | Security model does not opt into experimental crypto. |
| `allow-variable-time-crypto` | Sequoia feature list | Unavailable in current build | Security model does not opt into variable-time crypto. |

## 3. Official Sequoia Surface Outside CypherAir's Current Product Or Security Boundary

The Sequoia source and examples expose capability families that CypherAir does not currently surface as product features:

| Sequoia surface | Upstream evidence | Current repo status | Why it is kept in the appendix |
|---|---|---|---|
| Web-of-trust example flows | Sequoia examples (`web-of-trust`) | Not wrapped | Outside CypherAir's current product model. |
| Statistics / supported-algorithms examples | Sequoia examples (`statistics`, `supported-algorithms`) | Not wrapped | Diagnostic tooling, not a current product gap. |
| Notarization example flow | Sequoia examples (`notarize`) | Not wrapped | Outside current CypherAir scope. |
| Padding / wrap-literal helper examples | Sequoia examples (`pad`, `wrap-literal`) | Not wrapped | Not part of CypherAir's current message UX. |
| Group-key example flows | Sequoia examples (`generate-group-key`) | Not wrapped | Outside the current key-management model. |

## 4. Relationship To The Main Audit And Roadmap

Read the companion documents as follows:

- [`SEQUOIA_CAPABILITY_AUDIT.md`](../SEQUOIA_CAPABILITY_AUDIT.md): canonical inventory of the current build, including every relevant `current-build omission`
- [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md): archived roadmap snapshot from the Sequoia expansion phase
- this appendix: archived `out-of-boundary surface` snapshot only

In practice:

- `password/SKESK`, `merge_public`, `revoke`, `certify`, binding verification, and richer signature-result work remain in the main audit because they are available in the current build
- alternative compression and crypto backends remain in this appendix because the repository does not compile them in
- example-driven families such as web-of-trust, notarization, and group-key flows remain in this appendix until CypherAir explicitly expands its product/security boundary
