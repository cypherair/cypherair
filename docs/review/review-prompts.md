# CypherAir 全面代码审查 — 提示词手册

> 本文档包含 6 个独立对话的审查提示词，覆盖项目的所有关键维度。
> 每个对话设计为在 Claude Code 中独立运行，使用多个 agent 并行审查并交叉验证发现。
>
> **使用方法：** 将每个对话的提示词完整复制到一个新的 Claude Code 会话中执行。

---

## 对话 1：安全架构审查

**审查重点：** Secure Enclave 包装方案、Keychain 存储、认证模式、内存清零、AEAD 硬失败、两阶段解密边界

```
你是安全审查员。请对 CypherAir 项目进行全面的安全架构审查。

**背景：** CypherAir 是一个完全离线的 iOS OpenPGP 加密工具，使用 Secure Enclave P-256 密钥包装保护 Ed25519/X25519/Ed448/X448 私钥，通过 Keychain 存储，支持标准模式和高安全模式两种认证方式。

**审查范围和方法：**

请启动 3 个并行 agent 分别审查以下区域，然后你亲自交叉验证它们的发现：

**Agent 1 — SE 包装方案审查：**
- 完整阅读 `Sources/Security/SecureEnclaveManager.swift` 和 `Sources/Security/SecureEnclaveManageable.swift`
- 验证包装流程：P-256 密钥生成 → self-ECDH → HKDF(SHA-256) → AES-GCM seal
- 检查 HKDF info 字符串是否包含版本前缀和指纹（domain separation）
- 检查密钥存储顺序：先确认 3 个 Keychain 项全部写入成功，再清零原始密钥字节
- 检查解包流程：SE 密钥重建是否正确触发生物认证
- 检查 `WrappedKeyBundle` 结构完整性
- 对照 `docs/SECURITY.md` Section 3 验证实现一致性

**Agent 2 — 认证与模式切换审查：**
- 完整阅读 `Sources/Security/AuthenticationManager.swift` 和 `Sources/Security/AuthenticationEvaluable.swift`
- 验证标准模式标志：`[.privateKeyUsage, .biometryAny, .or, .devicePasscode]`
- 验证高安全模式标志：`[.privateKeyUsage, .biometryAny]`（无密码回退）
- 审查模式切换的原子性：临时 Keychain 项 → 验证全部写入 → 删除旧项 → 重命名
- 审查崩溃恢复逻辑：`rewrapInProgress` 标志 + app 启动时检查
- 检查是否存在认证绕过路径
- 对照 `docs/SECURITY.md` Section 4 验证

**Agent 3 — 内存安全与数据保护审查：**
- 完整阅读 `Sources/Extensions/Data+Zeroing.swift` 和 `Sources/Security/MemoryZeroingUtility.swift`
- 验证 `@_optimize(none)` barrier 是否正确防止编译器消除清零操作
- 搜索所有 `Sources/Services/` 文件，检查每次私钥使用后是否调用 `.zeroize()`
- 搜索全项目的 `print()`, `os_log()`, `NSLog()` 调用，检查是否泄露密钥/明文
- 检查 `Sources/Security/Argon2idMemoryGuard.swift` 的 75% 内存阈值逻辑
- 检查 `Sources/Services/DecryptionService.swift` 的两阶段边界：Phase 1 不触发 SE 认证，Phase 2 必须触发
- 对照 `docs/SECURITY.md` Section 7 (已知限制 - String 密码短语不可清零) 检查缓解措施

**你的交叉验证任务：**
等所有 agent 完成后：
1. 逐一检查每个 agent 报告的问题，亲自阅读相关代码确认问题是否真实存在
2. 检查 agent 之间是否有遗漏：例如 Agent 1 检查了 SE 包装但没检查 `KeyManagementService` 中对 SE 的调用是否正确
3. 检查 `Sources/Services/KeyManagementService.swift` 中 `generateKey()`, `unwrapPrivateKey()`, `importKey()` 是否正确协调 SE 和 Keychain 操作
4. 检查 entitlements 文件 (`CypherAir.entitlements`) 中 MIE/Enhanced Security 配置完整性
5. 生成最终报告，按严重程度（严重/高/中/低/信息）分级

**输出格式：**
对每个发现的问题提供：
- 严重程度等级
- 文件路径和行号
- 问题描述
- 影响分析
- 建议修复方案
```

---

## 对话 2：密码学实现审查

**审查重点：** Rust PGP 引擎、双配置文件实现、加密格式自动选择、S2K 处理、错误分类

```
你是密码学审查员。请对 CypherAir 项目的 Rust 密码学引擎进行全面审查。

**背景：** CypherAir 使用 Sequoia PGP 2.2.0 通过 pgp-mobile Rust crate 实现 OpenPGP 操作，支持两个加密配置文件：
- Profile A (Universal): v4, Ed25519+X25519, SEIPDv1, Iterated+Salted S2K
- Profile B (Advanced): v6, Ed448+X448, SEIPDv2 AEAD OCB, Argon2id S2K

**审查范围和方法：**

请启动 4 个并行 agent 分别审查以下区域，然后你亲自交叉验证：

**Agent 1 — 密钥生成与配置文件审查：**
- 完整阅读 `pgp-mobile/src/keys.rs`
- 验证 Profile A：`CipherSuite::Cv25519` + `Profile::RFC4880` + `Features::empty().set_seipdv1()`
- 验证 Profile B：`CipherSuite::Cv448` + `Profile::RFC9580`
- 检查 `set_features()` 设置是否正确（Profile A 必须显式设置 SEIPDv1 以确保 GnuPG 兼容性）
- 验证 S2K 导出：Profile A → Iterated+Salted, Profile B → Argon2id (m=19, p=4, t=3)
- 检查密钥解析 (`parse_key_info`) 的完整性和鲁棒性
- 检查 `modify_expiry()` 是否正确重签绑定签名
- 检查 `detect_profile()` 逻辑是否可靠

**Agent 2 — 加密/解密流程审查：**
- 完整阅读 `pgp-mobile/src/encrypt.rs` 和 `pgp-mobile/src/decrypt.rs`
- 验证加密格式自动选择：all v4 → SEIPDv1, all v6 → SEIPDv2, mixed → SEIPDv1
- 检查 `collect_recipients()` 的吊销/过期/加密能力验证
- 验证 AEAD 硬失败：认证错误时明文必须被清零并中止
- 审查 `classify_decrypt_error()` 的三层错误分类策略（结构化 downcast → IO unwrap → 字符串匹配）
- 检查字符串匹配 fallback 是否可能在 Sequoia 版本升级后失效
- 验证 Phase 1 (`parse_recipients`, `match_recipients`) 不需要私钥
- 检查签名验证分级结果的正确性

**Agent 3 — 签名/验证 + Armor + 错误映射审查：**
- 完整阅读 `pgp-mobile/src/sign.rs`, `pgp-mobile/src/verify.rs`, `pgp-mobile/src/armor.rs`, `pgp-mobile/src/error.rs`
- 验证签名类型：cleartext (内联) 和 detached
- 验证验证结果分级：Valid/Bad/UnknownSigner/Expired
- 检查 `PgpError` 枚举是否覆盖所有错误场景
- **关键：验证没有 blanket `From<anyhow::Error>` impl**（安全审计发现 H1）
- 检查 Armor 编解码的鲁棒性（损坏输入处理）
- 对比 `PgpError` 与 Swift 侧 `CypherAirError` 的 1:1 映射完整性

**Agent 4 — 流式文件操作审查：**
- 完整阅读 `pgp-mobile/src/streaming.rs`
- 检查 64KB 缓冲区的清零：是否使用 `Zeroizing<Vec<u8>>` 而非 `std::io::copy`
- 验证 `secure_delete_file()` 的实现（先覆写零再删除）
- 检查流式解密的 AEAD 硬失败：写入 `.tmp` → 错误时安全删除临时文件 → 成功时重命名
- 验证取消操作 (`ProgressReporter` 返回 false → `ErrorKind::Interrupted`)
- 检查是否存在部分明文泄露路径

**你的交叉验证任务：**
等所有 agent 完成后：
1. 亲自确认每个报告的问题是否真实存在
2. 检查 `pgp-mobile/src/lib.rs` (PgpEngine 公共 API) 是否正确调用了各模块
3. 对照 `docs/TDD.md` Section 1 验证 Profile 配置一致性
4. 检查 `Cargo.toml` 的依赖版本和 feature flags 是否正确
5. 检查 `zeroize` crate 是否正确应用于所有敏感数据路径
6. 生成最终报告

**输出格式：**
对每个发现提供严重程度、文件路径:行号、描述、影响、建议修复。
特别关注可能导致密钥泄露、明文泄露或互操作性失败的问题。
```

---

## 对话 3：FFI 边界与 Swift-Rust 集成审查

**审查重点：** UniFFI 绑定、类型映射、错误传播、并发安全、内存生命周期

```
你是 FFI 集成审查员。请对 CypherAir 项目的 Swift-Rust FFI 边界进行全面审查。

**背景：** CypherAir 使用 Mozilla UniFFI 0.31 通过三层桥接将 Rust pgp-mobile crate 暴露给 Swift：
pgp-mobile (Rust) → UniFFI C scaffolding → 生成的 Swift 绑定 (pgp_mobile.swift)

**审查范围和方法：**

请启动 3 个并行 agent 分别审查以下区域，然后你亲自交叉验证：

**Agent 1 — FFI API 表面审查：**
- 完整阅读 `pgp-mobile/src/lib.rs`（所有 `#[uniffi::export]` 方法）
- 完整阅读 `Sources/PgpMobile/pgp_mobile.swift`（生成的绑定）
- 验证每个 Rust pub fn 在 Swift 中都有对应的调用
- 检查类型映射：`Vec<u8>` ↔ `Data`, `String` ↔ `String`, `Result<T,E>` ↔ `throws`
- 验证 `PgpError` 枚举变体在 Rust 和 Swift 两侧完全一致
- 检查 `KeyProfile` 枚举的 FFI 传递是否正确
- 检查 Option<T> → T? 的映射
- 验证 `PgpEngine` 的 `Send + Sync` 安全性

**Agent 2 — Services 层 FFI 调用审查：**
- 阅读所有 `Sources/Services/*.swift` 文件
- 检查每个 PgpEngine 方法调用的参数和返回值处理
- 验证 `Data` 参数传递时的拷贝语义（RustBuffer 拷贝，不是零拷贝）
- 检查错误处理链：Rust PgpError → Swift PgpError → CypherAirError 的映射是否有遗漏
- 检查 `CypherAirError.from(_:fallback:)` 工厂方法的覆盖完整性
- 验证每个 Service 的 `@concurrent` 标记是否正确（PGP 操作应在后台 actor 执行）
- 检查 `@preconcurrency import` 是否正确处理 UniFFI 生成代码的并发兼容性

**Agent 3 — 内存与生命周期审查：**
- 搜索全项目对 `PgpEngine` 实例的使用方式
- 检查 PgpEngine 实例在 `CypherAirApp.swift` 中的初始化和共享方式
- 验证 Arc 生命周期管理（UniFFI Object 类型在 Swift 中的 class 映射）
- 检查是否存在内存泄露路径（尤其是循环引用）
- 验证 RustBuffer 在所有路径上被正确释放
- 检查传递大数据（文件加密）时的内存峰值
- 搜索测试中的并发安全测试 (`test_concurrentEncrypt_threadsafe` 等)

**你的交叉验证任务：**
1. 亲自确认报告问题的真实性
2. 对照 `docs/TDD.md` Section 2 (UniFFI Architecture) 验证实现一致性
3. 检查 `docs/ARCHITECTURE.md` Section 4 (Tightly Coupled Modules) 列出的耦合关系是否都被正确维护
4. 验证构建脚本 `pgp-mobile/build-xcframework.sh` 中的绑定生成流程
5. 检查是否有 Swift 6.2 并发模型兼容问题（`Sendable`, actor isolation）
6. 生成最终报告
```

---

## 对话 4：测试覆盖与质量审查

**审查重点：** 测试完整性、安全测试覆盖、Profile 测试矩阵、Mock 质量、测试遗漏

```
你是测试质量审查员。请对 CypherAir 项目的测试套件进行全面审查。

**背景：** CypherAir 有 4 层测试：
- Layer 1: Rust 单元测试 (cargo test)
- Layer 2: Swift 单元测试 (模拟器)
- Layer 3: FFI 集成测试 (模拟器)
- Layer 4: 设备专用测试 (物理设备 SE/MIE)
总计 170+ 测试用例。

**审查范围和方法：**

请启动 4 个并行 agent 分别审查以下区域，然后你亲自交叉验证：

**Agent 1 — Rust 测试审查：**
- 完整阅读 `pgp-mobile/tests/` 目录下所有测试文件
- 对照 `docs/TESTING.md` Section 3 (Profile Test Matrix) 检查覆盖情况
- 检查是否每个 Profile A 测试都有对应的 Profile B 测试
- 验证 tamper 测试（1-bit flip）是否覆盖两个 Profile
- 验证 cross-profile 测试是否正确测试格式自动选择
- 检查 GnuPG 互操作测试的 fixture 完整性
- 检查 security_audit_tests 是否覆盖所有安全红线

**Agent 2 — Swift Service 测试审查：**
- 完整阅读 `Tests/ServiceTests/` 目录下所有测试文件
- 检查 `KeyManagementServiceTests`：密钥生命周期是否全覆盖（生成/加载/导出/导入/删除/修改过期/崩溃恢复）
- 检查 `DecryptionServiceTests`：两阶段解密边界测试是否充分（Phase 1 不触发 SE，Phase 2 必须触发）
- 检查 `EncryptionServiceTests`：cross-profile、encrypt-to-self、文件大小验证
- 检查 `SigningServiceTests`：双 Profile 签名/验证/篡改检测
- 对照 `docs/TESTING.md` Section 5 (Test Naming Convention) 检查命名规范一致性

**Agent 3 — FFI 集成与 GnuPG 互操作测试审查：**
- 完整阅读 `Tests/FFIIntegrationTests/FFIIntegrationTests.swift`
- 完整阅读 `Tests/ServiceTests/GnuPGInteropTests.swift`
- 验证 FFI 边界测试：binary round-trip、Unicode preservation、error enum mapping
- 检查并发测试的覆盖范围和质量
- 检查 Argon2id 内存保护测试的边界条件
- 验证 GnuPG 互操作测试的 fixture 加载和比对逻辑
- 检查 `FixtureLoader.swift` 的鲁棒性

**Agent 4 — Mock 质量与测试遗漏分析：**
- 完整阅读 `Sources/Security/Mocks/` 目录下所有 Mock 文件
- 验证 `MockSecureEnclave` 是否正确模拟 SE 行为（软件 P-256 + HKDF + AES-GCM）
- 验证 `MockKeychain` 是否模拟了所有生产行为（save/load/delete/list/exists）
- 检查 `MockAuthenticator` 是否支持所有认证场景（成功/失败/生物不可用）
- 检查 `TestHelpers.swift` 的工厂方法是否正确初始化依赖关系
- **关键任务：** 对照 `docs/TESTING.md` Section 3 (Profile Test Matrix)，列出所有未被测试覆盖的场景

**你的交叉验证任务：**
1. 亲自确认每个 agent 报告的测试遗漏是否真实存在
2. 交叉比对：某个 agent 说某个测试存在，另一个 agent 说不存在 → 亲自检查
3. 检查 `DeviceSecurityTests.swift` 的完整性（SE 包装/解包、认证模式切换、崩溃恢复）
4. 按照 `docs/CODE_REVIEW.md` 中 "Security-Related PRs" 的检查清单，验证安全变更是否都有正面和反面测试
5. 生成测试覆盖报告，包括：
   - 已覆盖场景列表（标注 Profile A/B/Both）
   - 未覆盖场景列表（按优先级排序）
   - Mock 质量评估
   - 建议新增的测试
```

---

## 对话 5：UI/UX、无障碍与合规审查

**审查重点：** SwiftUI 视图层、Liquid Glass 合规、VoiceOver、本地化、离线/权限约束

```
你是 UI/UX 与合规审查员。请对 CypherAir 项目的视图层和合规性进行全面审查。

**背景：** CypherAir 是 iOS 26 应用，使用 Liquid Glass 设计语言，要求：
- 完全离线（零网络访问）
- 最小权限（仅 NSFaceIDUsageDescription）
- VoiceOver 全覆盖
- Dynamic Type 支持
- 英文 + 简体中文本地化

**审查范围和方法：**

请启动 3 个并行 agent 分别审查以下区域，然后你亲自交叉验证：

**Agent 1 — 视图架构与业务逻辑隔离审查：**
- 阅读所有 `Sources/App/` 下的视图文件
- 检查是否有业务逻辑泄漏到视图层（视图中不应有 Keychain/SE/PGP 操作）
- 验证 `NavigationStack` + `AppRoute` 的类型安全路由
- 检查 `@Environment` 注入的正确性
- 验证 `PrivacyScreenModifier.swift` 的隐私屏幕逻辑（后台模糊、恢复认证、宽限期）
- 检查 `CypherAirApp.swift` 的初始化顺序和生命周期管理
- 验证 URL scheme 处理 (`cypherair://`) 是否要求用户确认才添加密钥

**Agent 2 — Liquid Glass + 无障碍审查：**
- 阅读所有视图文件，检查 Liquid Glass 合规性：
  - 标准组件（TabView, NavigationStack, sheets）是否保留自动 Glass 效果
  - 自定义浮动控件是否使用 `.glassEffect()`
  - 是否有 `.background()` 修饰符覆盖了 Glass 效果
  - 语义着色是否正确使用（蓝=主要操作，红=破坏性）
- 检查所有交互元素的 VoiceOver 标签
- 检查指纹显示的分段朗读（4 字符一组）
- 验证 44×44pt 最小触摸目标
- 检查 Dynamic Type 支持（使用系统文本样式而非固定字号）
- 对照 `docs/LIQUID_GLASS.md` 和 `docs/CONVENTIONS.md` Section 6 验证

**Agent 3 — 本地化与合规约束审查：**
- 搜索全项目硬编码的用户可见字符串（应全部在 String Catalog 中）
- 检查所有 `String(localized:)` 调用的格式正确性
- 搜索全项目的网络 API 使用：`URLSession`, `NWConnection`, `URL(string: "http`, `URL(string: "https`
- 检查 `Info.plist`：是否只有 `NSFaceIDUsageDescription`，无其他权限声明
- 搜索全项目的 `import Network`, `import WebKit` 等网络相关 import
- 检查 `CypherAir.entitlements`：是否包含任何网络 entitlement
- 检查错误消息是否符合 PRD Section 4.7 的用户友好要求
- 验证剪贴板安全提示（首次复制通知）

**你的交叉验证任务：**
1. 亲自确认每个 agent 发现的问题是否真实存在
2. 检查 `ContentView.swift` 中 TabView 结构和平台条件编译 (`#if os(macOS)`)
3. 验证 `AppConfiguration.swift` 的 UserDefaults 键名与文档 (`ARCHITECTURE.md` Section 5) 一致性
4. 检查 macOS 平台适配的条件编译正确性
5. 生成最终报告
```

---

## 对话 6：代码质量、架构一致性与文档审查

**审查重点：** 编码规范、架构一致性、文档与代码同步、依赖管理、构建配置

```
你是代码质量与架构审查员。请对 CypherAir 项目的代码质量和架构一致性进行全面审查。

**背景：** CypherAir 遵循严格的编码规范（见 docs/CONVENTIONS.md），使用 Swift 6.2 + @Observable + async/await，Rust crate 通过 UniFFI 桥接。项目文档详细记录了架构、安全模型和测试策略。

**审查范围和方法：**

请启动 3 个并行 agent 分别审查以下区域，然后你亲自交叉验证：

**Agent 1 — Swift 代码质量审查：**
- 搜索全项目的 force-unwrap (`!`) 使用，排除测试代码
- 搜索 `try!` 使用（生产代码中不应存在）
- 检查访问控制：是否遵循 "尽可能严格" 原则（private > internal > public）
- 检查是否正确使用 `guard let` / `guard else` 进行早期返回
- 验证 async/await 使用（无 Combine 新代码）
- 检查 `@Observable` 使用（替代旧的 ObservableObject + @Published）
- 检查 Swift 6.2 并发模型：main actor isolation、`@concurrent` 标记、`Sendable` 符合性
- 验证一个类型一个文件的组织方式

**Agent 2 — 架构一致性与耦合审查：**
- 对照 `docs/ARCHITECTURE.md` Section 4 (Tightly Coupled Modules) 表格：
  - `pgp-mobile/src/error.rs` ↔ `Sources/Models/CypherAirError.swift`：枚举变体是否 1:1 匹配
  - `pgp-mobile/src/lib.rs` ↔ `Sources/Services/*Service.swift`：API 变更是否同步
  - `SecureEnclaveManager` ↔ `KeychainManager`：写入 3 项 Keychain 的协调
  - `SecureEnclaveManager` ↔ `AuthenticationManager`：模式切换协调
  - `DecryptionService` ↔ `AuthenticationManager`：Phase 2 认证策略
  - `KeyManagementService` ↔ `pgp-mobile/src/keys.rs`：Profile→CipherSuite 映射
- 检查数据流是否严格遵循分层架构（View → Service → Security / PGP Engine）
- 检查是否有视图层直接访问安全层或 PGP 引擎的违规

**Agent 3 — 文档与代码同步审查：**
- 对照 `docs/ARCHITECTURE.md` Section 5 (Storage Layout)：
  - Keychain key 命名常量是否与代码中的 `KeychainConstants` 一致
  - UserDefaults key 名称是否与 `AppConfiguration.swift` 一致
- 对照 `docs/SECURITY.md` Section 1 (算法表)：
  - Profile A/B 的算法是否与 `pgp-mobile/src/keys.rs` 的实际实现一致
- 对照 `docs/PRD.md` Section 4.7 (错误消息表)：
  - 每个错误消息是否在 `CypherAirError.swift` 中有对应实现
- 检查 `docs/CONVENTIONS.md` 中列出的文件结构是否与实际项目结构匹配
- 检查 `Cargo.toml` 中的依赖版本是否与文档声明一致
- 检查 build 命令（`CLAUDE.md` Build Commands）是否仍然准确

**你的交叉验证任务：**
1. 亲自确认报告问题的真实性
2. 检查 `.gitignore` 是否正确排除构建产物和生成文件
3. 检查 commit history 的消息格式是否符合 conventional format
4. 对照 `docs/CODE_REVIEW.md` 的 "All PRs" 检查清单，验证当前代码库状态
5. 汇总所有发现，生成按严重程度分级的最终报告
6. 特别标注文档与代码不一致的地方（文档说 X 但代码做了 Y）
```

---

## 综合审查检查清单

以上 6 个对话全部完成后，使用此清单确认覆盖了所有关键区域：

### 安全（对话 1 + 2）
- [ ] SE 包装方案的正确性和完整性
- [ ] AEAD 硬失败在所有路径上的执行
- [ ] 两阶段解密边界的不可绕过性
- [ ] 内存清零在所有敏感数据路径上的执行
- [ ] 认证模式切换的原子性和崩溃恢复
- [ ] 无网络 API 使用
- [ ] 无日志泄露密钥/明文
- [ ] 安全随机数使用 (SecRandomCopyBytes / getrandom)

### 密码学（对话 2）
- [ ] Profile A 正确生成 v4 Ed25519+X25519 密钥
- [ ] Profile B 正确生成 v6 Ed448+X448 密钥
- [ ] 加密格式自动选择逻辑正确
- [ ] S2K 处理（Iterated+Salted 和 Argon2id）正确
- [ ] 错误分类无遗漏
- [ ] 流式操作的安全性

### FFI（对话 3）
- [ ] 类型映射完整正确
- [ ] 错误传播无丢失
- [ ] 并发安全
- [ ] 内存管理无泄漏

### 测试（对话 4）
- [ ] 双 Profile 测试覆盖
- [ ] 安全操作的正/反面测试
- [ ] Mock 质量充分
- [ ] 测试遗漏已识别

### UI/合规（对话 5）
- [ ] 视图层无业务逻辑
- [ ] Liquid Glass 合规
- [ ] VoiceOver + Dynamic Type 完整
- [ ] 本地化完整
- [ ] 零网络/最小权限确认

### 代码质量（对话 6）
- [ ] 编码规范一致
- [ ] 架构分层正确
- [ ] 文档与代码同步
- [ ] 依赖管理正确
