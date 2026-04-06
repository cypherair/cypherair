# Sequoia Capability Audit Appendix

> Purpose: Record the broader Sequoia 2.2 capability surface that sits outside CypherAir's current build baseline or product boundary.
> Audience: Human developers, reviewers, and AI coding tools.

This appendix is not a defect list by itself. Its role is to separate:

- features that Sequoia supports but CypherAir does not currently compile
- capability families that Sequoia documents but CypherAir intentionally does not surface

## 1. Feature-Gated Sequoia Surface Not Compiled In This Repository

CypherAir builds `sequoia-openpgp` with:

- `default-features = false`
- `crypto-openssl`
- `compression-deflate`

The following Sequoia 2.2 surfaces exist upstream but are not available in the current repository build:

| Sequoia surface | Upstream evidence | Current repo status | Why it is not scored as a primary gap |
|---|---|---|---|
| `compression-bzip2` | Sequoia feature list | Unavailable in current build | Feature not enabled; CypherAir docs already exclude bzip2 for dependency reasons. |
| `compression` default bundle (`deflate + bzip2`) | Sequoia feature list | Unavailable in current build | Repository explicitly opts out of default features. |
| `crypto-nettle` backend | Sequoia feature list | Unavailable in current build | Product standardizes on OpenSSL backend. |
| `crypto-rust` backend | Sequoia feature list | Unavailable in current build | Product standardizes on OpenSSL backend. |
| `crypto-botan` / `crypto-botan2` backends | Sequoia feature list | Unavailable in current build | Not selected by current dependency policy. |
| `crypto-cng` backend | Sequoia feature list | Unavailable in current build | Windows-specific backend outside current Apple-platform scope. |
| `allow-experimental-crypto` | Sequoia feature list | Unavailable in current build | Security model does not opt into experimental crypto. |
| `allow-variable-time-crypto` | Sequoia feature list | Unavailable in current build | Security model does not opt into variable-time crypto. |

## 2. Broader Official Sequoia Surface Outside CypherAir's Current Product Boundary

The Sequoia source and examples expose capability families that CypherAir does not currently surface as product features:

| Sequoia surface | Upstream evidence | Current repo status | Audit interpretation |
|---|---|---|---|
| Web-of-trust example flows | Sequoia examples (`web-of-trust`) | Not wrapped | Outside current CypherAir product model. |
| Statistics / supported-algorithms examples | Sequoia examples (`statistics`, `supported-algorithms`) | Not wrapped | Diagnostic tooling, not a current product gap. |
| Notarization example flow | Sequoia examples (`notarize`) | Not wrapped | Outside current CypherAir scope. |
| Padding / wrap-literal helper examples | Sequoia examples (`pad`, `wrap-literal`) | Not wrapped | Not part of CypherAir's current message UX. |
| Group-key example flows | Sequoia examples (`generate-group-key`) | Not wrapped | Outside the current key-management model. |

## 3. Relationship To The Main Audit

The main report should be read as:

- **Primary gap list**: items that are compiled today and are missing or disconnected in CypherAir
- **Appendix**: items that exist upstream, but are not actionable gaps unless the build policy or product boundary changes

In practice:

- `password/SKESK`, `merge_public`, `revoke`, `certify`, and binding verification remain **actionable omissions** because they are available in the current build.
- alternative compression and crypto backends remain **non-actionable for now** because the repository does not compile them in.
