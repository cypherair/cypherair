# App Store Listing — CypherAir X

> Status: Canonical current-state.
> Purpose: The App Store Connect product-page copy — entered manually in App Store Connect; nothing here is read by the build.
> Audience: Maintainer, release owners, and AI coding tools.
> Update triggers: Product-page copy, keywords, reviewer notes, or listing metadata change.

Field limits are noted per field. Price ($2.99 USD tier) is configured in App
Store Connect Pricing and Availability and is never shown inside the app.

Positioning in one line: **CypherAir X is a fully offline OpenPGP encryption
app** — one app offering all nine key families, from portable software keys to
Secure Enclave device-bound custody and post-quantum protection (RFC 9980), on a
zero-network, minimal-permission privacy model.

---

## en-US

### Name (30 chars max)

```
CypherAir X
```

### Subtitle (30 chars max)

```
Offline PGP + Post-Quantum
```

### Promotional Text (170 chars max)

```
Fully offline OpenPGP encryption with Secure Enclave device-bound keys and post-quantum protection. No network, no accounts, no tracking — open source on GitHub.
```

### Description (4000 chars max)

```
CypherAir X is a fully offline OpenPGP encryption tool. It never connects to the internet: no telemetry, no accounts, no key servers. Your keys and messages stay on your device.

NINE KEY FAMILIES
CypherAir X offers nine key families across portable software keys and Secure Enclave device-bound custody:
• Portable Legacy — Ed25519 v4 software keys, GnuPG-compatible
• Portable Modern — RFC 9580 v6 software keys
• Portable Modern · High — RFC 9580 v6 keys using the stronger Ed448 curve
• Portable Post-Quantum — RFC 9980 software keys you can back up
• Portable Post-Quantum · High — RFC 9980 with ML-KEM-1024, the strongest tier
• Device-Bound Legacy — P-256 keys held in the Secure Enclave
• Device-Bound Modern — RFC 9580 v6 keys held in the Secure Enclave
• Device-Bound Post-Quantum — RFC 9980 keys with Secure Enclave split custody
• Device-Bound Post-Quantum · High — RFC 9980 ML-KEM-1024 with Secure Enclave split custody

Device-Bound private keys are created inside this device's Secure Enclave and can never be exported. Post-Quantum keys are designed to resist future quantum computers.

EVERYTHING YOU NEED FOR OPENPGP
• Encrypt, decrypt, sign, and verify — text or files
• GnuPG-compatible: exchange messages with any standards-compliant PGP software
• Message format selected automatically for each recipient's key
• Contacts with fingerprint verification, tags, and QR public-key exchange
• A guided tutorial in an isolated sandbox — learn safely before touching real keys

PRIVATE BY ARCHITECTURE
• Zero network access — the app contains no networking code at all
• Minimal permissions: only Face ID / Touch ID, used to protect your keys
• Hardware memory protection (Enhanced Security) enabled
• Sensitive memory is zeroed after use; tampered messages are rejected outright
• App access protection and re-authentication controls in Settings

OPEN SOURCE
CypherAir X is dual-licensed under GPL-3.0-or-later OR MPL-2.0. The complete source code is available on GitHub: https://github.com/cypherair/cypherair

Designed for iPhone, iPad, Mac, and Apple Vision with 8 GB of memory or more.
```

### Keywords (100 chars max, comma-separated)

```
pgp,openpgp,gpg,encryption,encrypt,privacy,offline,secure enclave,post-quantum,pqc,security
```

### URLs

- Support URL: `https://github.com/cypherair/cypherair/issues`
- Marketing URL: `https://cypherair.com`

### What's New template (4000 chars max)

```
• Fully offline OpenPGP encryption: encrypt, decrypt, sign, and verify text or files — no network, no accounts, no tracking.
• Nine key families: Portable Legacy, Modern, Modern · High (Ed448), Post-Quantum, and Post-Quantum · High (RFC 9980, ML-KEM-1024) software keys, plus four Device-Bound families whose private keys are held by the Secure Enclave and never leave this device.
• Post-quantum keys (RFC 9980): see at a glance when a message is quantum-safe.
• Guided tutorial in an isolated sandbox, contacts with fingerprint verification, and QR public-key exchange.
```

---

## zh-Hans

### 名称（最多 30 字符）

```
CypherAir X
```

### 副标题（最多 30 字符）

```
完全离线的 PGP·后量子加密
```

### 推广文本（最多 170 字符）

```
完全离线的 OpenPGP 加密：安全隔区设备绑定密钥与后量子保护。无网络、无账户、无跟踪，源代码在 GitHub 完全开源。
```

### 描述（最多 4000 字符）

```
CypherAir X 是一款完全离线的 OpenPGP 加密工具。它永不联网：没有遥测、没有账户、没有密钥服务器。你的密钥和消息始终留在你的设备上。

九个密钥家族
CypherAir X 提供九个密钥家族，涵盖便携软件密钥与安全隔区设备绑定托管：
• 便携旧版——Ed25519 v4 软件密钥，兼容 GnuPG
• 便携现代——RFC 9580 v6 软件密钥
• 便携现代 · 高强度——采用更强 Ed448 曲线的 RFC 9580 v6 密钥
• 便携后量子——可备份的 RFC 9980 软件密钥
• 便携后量子 · 高强度——采用 ML-KEM-1024 的 RFC 9980 最强等级
• 设备绑定旧版——保存在安全隔区中的 P-256 密钥
• 设备绑定现代——保存在安全隔区中的 RFC 9580 v6 密钥
• 设备绑定后量子——采用安全隔区分离托管的 RFC 9980 密钥
• 设备绑定后量子 · 高强度——采用 ML-KEM-1024 的安全隔区分离托管 RFC 9980 密钥

设备绑定密钥的私钥在本机安全隔区内生成，永远无法导出；后量子密钥旨在抵御未来的量子计算机。

完整的 OpenPGP 能力
• 加密、解密、签名、验证——支持文本与文件
• 兼容 GnuPG：可与任何符合标准的 PGP 软件互通
• 按接收者密钥自动选择消息格式
• 联系人支持指纹核验、标签和二维码公钥交换
• 引导教程运行在隔离沙盒中——先安全上手，再接触真实密钥

以架构保障隐私
• 零网络访问——应用不包含任何网络代码
• 最小权限：仅使用面容 ID / 触控 ID 保护你的密钥
• 启用硬件内存保护（增强安全性）
• 敏感内存用后清零；被篡改的消息会被直接拒绝
• 设置中提供应用访问保护与重新认证控制

开源
CypherAir X 以 GPL-3.0-or-later 或 MPL-2.0 双许可证开源，完整源代码见 GitHub：https://github.com/cypherair/cypherair

适用于 8 GB 内存及以上的 iPhone、iPad、Mac 和 Apple Vision。
```

### 关键词（最多 100 字符，逗号分隔）

```
加密,PGP,OpenPGP,GPG,隐私,离线,安全隔区,后量子,抗量子,签名,解密,私密
```

### 新功能模板

```
• 完全离线的 OpenPGP 加密：加密、解密、签名、验证，支持文本与文件——无网络、无账户、无跟踪。
• 九个密钥家族：便携旧版、现代、现代 · 高强度（Ed448）、后量子与后量子 · 高强度（RFC 9980，ML-KEM-1024）软件密钥，以及四个由安全隔区持有私钥、私钥永不离开本机的设备绑定家族。
• 后量子密钥（RFC 9980）：直观查看消息是否量子安全。
• 隔离沙盒中的引导教程、支持指纹核验的联系人与二维码公钥交换。
```

---

## App Review Information (English; reviewers read English notes)

### Notes for the reviewer (4000 chars max)

```
CypherAir X is a paid OpenPGP encryption app by the developer of CypherAir. Key points for review:

- Nine key families in one app: five portable software families and four Device-Bound families that generate and hold private keys inside the Apple Secure Enclave (non-exportable by design). The Post-Quantum families implement RFC 9980 to protect messages against future quantum-computer attacks.
- A guided welcome tour, unified security settings, and dedicated About and App Icon pages.

How to review:

1. The app is fully offline by design. It contains no networking code, contacts no servers, and requires no account, sign-in, or demo credentials. Every feature can be exercised locally on the device.
2. On first launch, the welcome tour offers a guided tutorial that runs in an isolated sandbox and walks through key generation, contact import, and encrypt/decrypt. It can be replayed later from Settings.
3. The only permission used is Face ID (NSFaceIDUsageDescription), to protect private keys. Biometric prompts appear when the app session requires authentication and when device-bound keys are generated or used.
4. Generating Device-Bound (Secure Enclave) key families requires a physical device; on hardware without a Secure Enclave those options are not offered.
5. The app is open source, dual-licensed GPL-3.0-or-later OR MPL-2.0 (https://github.com/cypherair/cypherair). Paid App Store distribution is permitted by both licenses.
6. Encryption: the app performs OpenPGP encryption locally using the open-source Sequoia-PGP library and Apple CryptoKit. Export compliance answers are provided in the App Store Connect questionnaire.
```

### App Privacy

- Data collection: **Data Not Collected** (the app has no network code; nothing
  leaves the device). Answer the App Privacy questionnaire accordingly.

### Demo account

- Not applicable — no accounts exist.

---

## Screenshot checklist (produced separately)

- iPhone 6.9" set — Home, Encrypt, key generation (nine families), About.
- iPad 13" set.
- Mac set (wide layout).
- Apple Vision Pro set (optional but supported).
- Localize captions for en-US and zh-Hans.
