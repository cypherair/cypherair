# Sequoia 能力审计

> 目的：系统性审计 CypherAir 当前对 Sequoia 2.2 能力的封装、导出、消费与缺失情况。
> 受众：人类开发者、审查者，以及 AI 编码工具。

## 1. 范围与基线

本审计使用两个基线：

1. **主基线：当前仓库构建配置**
   - `sequoia-openpgp = 2.2.0`
   - `default-features = false`
   - 已启用特性：`crypto-openssl`、`compression-deflate`
   - 事实依据：[`pgp-mobile/Cargo.toml`](../pgp-mobile/Cargo.toml)
2. **次基线：更广义的 Sequoia 2.2 能力面**
   - 单独记录于 [`SEQUOIA_CAPABILITY_AUDIT_APPENDIX_ZH.md`](SEQUOIA_CAPABILITY_AUDIT_APPENDIX_ZH.md)

审计层级：

- Rust 包装层：`pgp-mobile/src`
- FFI 导出面：`pgp-mobile/src/lib.rs` 与生成文件 `Sources/PgpMobile/pgp_mobile.swift`
- Swift 消费层：`Sources/Services/`
- 测试覆盖：`pgp-mobile/tests`、`Tests/FFIIntegrationTests`、`Tests/ServiceTests`

### 状态图例

结论使用以下固定标签：

- `端到端已实现`
- `仅在 Rust 中封装`
- `已导出但未使用`
- `缺少封装`
- `当前构建中不可用`
- `因产品/安全策略被有意排除`

### 解释说明

- `Services` 表示该能力被生产环境的 Swift `Services` 层消费，而不只是被测试使用。
- `Tests` 表示存在 Rust、FFI 或 Swift 测试的直接证据，证明该能力可用，或其缺失是有意的。
- 像二维码 URL 编码/解码这类应用特有辅助功能，会作为扩展能力记录，但不计入 Sequoia 能力缺口。

## 2. 当前构建能力矩阵

当前所有 `PgpEngine` 导出项都在 2.1 到 2.5 节中覆盖。

### 2.1 证书与密钥生命周期

| 能力 | 领域 | Sequoia | 构建可用 | Rust | FFI | Services | Tests | 结论 | 说明 |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
| 双配置证书生成（v4 Cv25519 / v6 Cv448） | 证书生命周期 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 由 `keys::generate_key_with_profile` 实现；由 `KeyManagementService.generateKey` 消费；有 Rust、FFI 与服务层测试覆盖。 |
| 在密钥生成期间自动生成密钥吊销证书 | 证书生命周期 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 由 `CertBuilder::generate` 生成；保存在新生成的身份上，并可在 UI 中为本地生成的密钥导出。 |
| 解析证书元数据（指纹、版本、UID、吊销状态、到期时间、子密钥可用性） | 证书生命周期 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 由 `parse_key_info` 支撑；用于联系人、密钥、二维码、自检以及相关测试。 |
| 检测密钥版本与配置档案 | 证书生命周期 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 由 `get_key_version` 与 `detect_profile` 封装；被导入/联系人/二维码流程消费。 |
| 使用口令保护的私钥导出，并根据配置档案选择对应 S2K | 证书生命周期 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 配置档案 A 使用 Iterated+Salted；配置档案 B 使用 Argon2id。 |
| 使用口令保护的私钥导入 | 证书生命周期 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | Swift 侧包含导入前 S2K 检查。 |
| 导入前解析 S2K 参数 | 证书生命周期 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 由 `Argon2idMemoryGuard` 在导入前使用。 |
| 通过重新签名绑定来修改证书到期时间 | 证书生命周期 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 基于 `Cert::set_expiration_time`；由 `KeyManagementService.modifyExpiry` 消费。 |
| 针对目标证书验证独立的密钥吊销签名 | 证书生命周期 | Yes | Yes | Yes | Yes | No | Yes | 已导出但未使用 | `parse_revocation_cert` 已导出且有测试，但生产服务未消费它。 |
| 将相同指纹的公钥证书更新合并到现有本地证书 | 证书生命周期 | Yes | Yes | No | No | No | No | 缺少封装 | Sequoia 提供 `merge_public` 与 `insert_packets`；当前联系人处理会把相同指纹导入视为重复项，而不是更新。 |
| 从现有私钥重新生成新的密钥吊销签名 | 证书生命周期 | Yes | Yes | No | No | No | No | 缺少封装 | Sequoia 提供 `Cert::revoke`，但 CypherAir 目前仅保存生成时输出的吊销证书。导入密钥后失去这一路径。 |

### 2.2 消息加密与解密

| 能力 | 领域 | Sequoia | 构建可用 | Rust | FFI | Services | Tests | 结论 | 说明 |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
| 基于收件人的消息加密（ASCII armor） | 加密/解密 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 包含可选签名与给自己加密。 |
| 基于收件人的消息加密（二进制） | 加密/解密 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 用于文件加密。 |
| 针对 v4/v6/混合收件人的消息格式自动选择 | 加密/解密 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 通过跨配置档案 Rust 测试与 Swift 服务流程验证。 |
| 第一阶段收件人头解析与 PKESK 到证书的匹配 | 加密/解密 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 由 `parse_recipients`、`match_recipients` 与 `match_recipients_from_file` 封装；服务层使用后两种匹配形式。 |
| 基于收件人的解密，并对 AEAD/MDC 认证失败进行硬失败处理 | 加密/解密 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | Rust 在出错时会显式清零部分明文；服务层强制执行两阶段认证流程。 |
| 读取来向压缩消息，支持 deflate/zlib 兼容路径 | 加密/解密 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 由 `compression-deflate` 启用；通过 GnuPG 互操作测试与服务层测试验证。 |
| 带进度与取消能力的流式文件加密/解密 | 加密/解密 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 包含安全临时文件处理与取消传播。 |
| 口令/SKESK 消息加密 | 加密/解密 | Yes | Yes | No | No | No | No | 缺少封装 | Sequoia 支持 `Encryptor::with_passwords` 与 `add_passwords`；CypherAir 仅暴露基于收件人的加密。 |
| 口令/SKESK 消息解密 | 加密/解密 | Yes | Yes | No | No | No | No | 缺少封装 | 当前 `DecryptHelper` 会忽略 `SKESK` 数据包，只尝试收件人密钥解密。 |

### 2.3 签名、验证与解析辅助能力

| 能力 | 领域 | Sequoia | 构建可用 | Rust | FFI | Services | Tests | 结论 | 说明 |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
| Cleartext 签名 | 签名/验证 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 已封装并由 `SigningService` 消费。 |
| Detached 签名 | 签名/验证 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 包含内存内与流式文件两种变体。 |
| 带分级结果的 Cleartext 验证 | 签名/验证 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | CypherAir 暴露 `valid`、`unknownSigner`、`bad`、`expired` 与 `notSigned`。 |
| 带分级结果的 Detached 验证 | 签名/验证 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 包含流式文件验证。 |
| 通用多签名结果模型 | 签名/验证 | Yes | Yes | No | No | No | No | 缺少封装 | 当前封装会把签名分组折叠为单个 `status`，以及可选的单个签名者指纹。 |
| 第三方认证与绑定验证（`verify_direct_key`、`verify_userid_binding` 及相关检查） | 签名/验证 | Yes | Yes | No | No | No | No | 缺少封装 | 目前未在 Rust、FFI 或服务层暴露。 |
| 面向任意 OpenPGP 类型的通用 ASCII armor 编码 | 解析/工具 | Yes | Yes | Yes | Yes | No | Yes | 已导出但未使用 | `engine.armor` 已导出，并通过 FFI 间接测试，但生产服务仅使用 `dearmor` 与 `armorPublicKey`。 |
| 通用 dearmor | 解析/工具 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 用于联系人、密钥、解密、二维码测试与服务层互操作。 |
| 公钥 armor 便捷方法 | 解析/工具 | Yes | Yes | Yes | Yes | Yes | Yes | 端到端已实现 | 用于公钥导出与导入规范化流程。 |
| 超出收件人头解析之外的通用数据包/元数据探查 | 解析/工具 | Yes | Yes | No | No | No | No | 缺少封装 | 当前数据包解析有意保持狭窄，仅限于 PKESK 头检查。 |

### 2.4 证书结构更新与策略控制

| 能力 | 领域 | Sequoia | 构建可用 | Rust | FFI | Services | Tests | 结论 | 说明 |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
| 添加或合并新的 User ID、子密钥与更新后的绑定 | 证书结构 | Yes | Yes | No | No | No | No | 缺少封装 | Sequoia 提供 `bind`、`insert_packets` 与 merge API；CypherAir 未封装它们。 |
| 面向特定子密钥的吊销构建器 | 证书结构 | Yes | Yes | No | No | No | No | 缺少封装 | `SubkeyRevocationBuilder` 未被封装。 |
| 面向特定 User ID 的吊销构建器 | 证书结构 | Yes | Yes | No | No | No | No | 缺少封装 | `UserIDRevocationBuilder` 未被封装。 |
| 第三方认证（`UserID::certify` 及相关流程） | 证书结构 | Yes | Yes | No | No | No | No | 缺少封装 | 与未来认证功能相关，但当前缺失。 |
| 超出 `StandardPolicy` 的运行时策略自定义 | 策略 | Yes | Yes | No | No | No | No | 因产品/安全策略被有意排除 | 当前封装硬编码 `StandardPolicy` 与产品默认算法决策。 |
| 向调用者暴露算法/后端选择开关 | 策略 | Yes | Yes | No | No | No | No | 因产品/安全策略被有意排除 | 产品固定使用 OpenSSL 后端、出站压缩策略与格式选择行为。 |

### 2.5 应用特定的导出扩展

这些方法属于 `PgpEngine` 的导出面，但它们是构建在 Sequoia 解析能力之上的 CypherAir 特有扩展，而不是缺失的 Sequoia 封装。

| 能力 | 领域 | Sequoia | 构建可用 | Rust | FFI | Services | Tests | 结论 | 说明 |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
| 公钥二维码 URL 编码（`cypherair://import/v1/...`） | 应用扩展 | No | n/a | Yes | Yes | Yes | Yes | 端到端已实现 | 在编码前使用 Sequoia 进行证书校验，并拒绝私钥。 |
| 二维码 URL 解码并校验公钥负载 | 应用扩展 | No | n/a | Yes | Yes | Yes | Yes | 端到端已实现 | 使用 Sequoia 解析解码后的负载，并拒绝私钥材料。 |

## 3. 仅 Rust 内部清单

以下未导出的 Rust 函数目前已存在，但它们是实现辅助函数，并不是缺失的公共能力：

| Rust 项 | 作用 | 审计处理 |
|---|---|---|
| `encrypt::collect_recipients` | 收件人校验与去重 | 仅为辅助函数 |
| `encrypt::build_recipients` | 将证书转换为 Sequoia 收件人句柄 | 仅为辅助函数 |
| `encrypt::setup_signer` | 配置可选的流式签名器 | 仅为辅助函数 |
| `sign::extract_signing_keypair` | 提取 Sequoia 签名密钥对 | 仅为辅助函数 |
| `armor::armor_writer` | 共享的 armored writer 构造逻辑 | 仅为辅助函数 |
| `decrypt::classify_decrypt_error` | 将 Sequoia/OpenSSL 错误映射到 `PgpError` | 仅为辅助函数 |
| `decrypt::is_expired_error` | 在 verify/decrypt 之间共享过期密钥检测 | 仅为辅助函数 |
| `streaming::zeroing_copy` | 带清零能力的流拷贝原语 | 仅为辅助函数 |
| `streaming::secure_delete_file` | 尽力删除临时文件 | 仅为辅助函数 |

有一个内部项看起来像封装面，但当前应用并不需要它：

| Rust 项 | 作用 | 结论 | 说明 |
|---|---|---|---|
| `keys::extract_secret_key_bytes` | 将 TSK 再序列化为原始私钥字节 | 仅在 Rust 中封装 | 在当前设计中是冗余的，因为生成/导入流程已经会返回完整私有证书字节用于 SE 包裹。 |

## 4. 缺口列表

### P0

1. **缺少对相同指纹证书更新的吸收能力**
   - 证据：Sequoia 提供 `merge_public` 与数据包插入路径，但 `ContactService.addContact` 会将相同指纹的导入视为重复项，且从不合并更新。
   - 影响：一旦某个指纹已存在，本地无法吸收其吊销状态、到期时间刷新，以及新增的第三方签名。
   - 分类：`缺少封装`

2. **导入的私钥无法重新生成/导出吊销证书**
   - 证据：在 `KeyManagementService.importKey` 中，导入身份会存储 `revocationCert = Data()`，而 UI 仅在该字段有值时才提供吊销导出功能。
   - 影响：在其他地方创建的密钥导入后，无法保持与本地生成密钥同等的吊销导出能力。
   - 分类：`缺少封装`

### P1

1. **缺少口令/SKESK 消息支持**
   - 当前构建中的 Sequoia 已支持。
   - Rust 封装未暴露加密/解密入口。
   - 解密辅助逻辑明确忽略 `SKESK`。

2. **缺少第三方认证与绑定验证**
   - 没有对 direct-key、User ID 绑定或相关认证验证方法的 Rust 封装。

3. **缺少证书结构更新封装**
   - 没有用于添加或合并更新后的 User ID、子密钥或绑定数据包的封装。

4. **缺少子密钥与 User ID 吊销构建器**
   - 如果产品未来需要选择性吊销流程，目前没有对应路径。

5. **缺少详细的多签名结果**
   - 当前 verify/decrypt 模型会把多个签名折叠成单一结果。

### P2

1. **独立吊销签名校验虽已导出，但生产服务未使用**
   - 只有测试消费 `parse_revocation_cert`。

2. **通用 armor 编码虽已导出，但生产服务未使用**
   - 生产代码使用的是 `dearmor` 和 `armorPublicKey`，而不是通用 `armor`。

### P3

1. **运行时策略自定义被有意不暴露**
   - CypherAir 固定使用 `StandardPolicy`、收件人驱动的格式选择，以及由配置档案驱动的导出规则。

2. **算法/后端开关被有意固定**
   - 应用统一使用 `crypto-openssl`，并禁止产品层面的后端切换。

## 5. 设计层面的排除项与非缺口

以下项目在主报告中不应被视为缺陷：

- **二维码 URL 编码/解码辅助能力**
  - 这些是构建在 Sequoia 密钥解析之上的应用特定封装，而不是缺失的 Sequoia 集成。
- **出站压缩**
  - Sequoia 可以构建压缩输出管线，但 CypherAir 在其产品/安全模型中明确禁止出站压缩。
- **`pgp-mobile/src` 中的通用辅助函数**
  - 错误分类器、收件人构建器以及带清零能力的流工具，不属于公共能力缺口。
- **Sequoia 其他受 feature gate 控制的能力面**
  - 这些内容记录在附录中，不纳入当前构建的主缺口统计。

## 6. 最小修复路径

1. **证书更新吸收**
   - 在 Rust 中为 Sequoia 的公钥证书 merge/update 流程添加封装。
   - 增加一个 FFI 入口，接收现有证书以及传入的更新证书或更新数据包。
   - 让 `ContactService` 区分：
     - 完全重复
     - 指纹相同但公钥材料更新
     - User ID 相同但指纹不同
   - 增加针对吊销更新、到期刷新以及额外签名合并的测试。

2. **为导入私钥重新生成吊销证书**
   - 在 Rust 中封装基于现有私有证书生成 Sequoia 吊销证书的能力。
   - 通过 `PgpEngine` 导出。
   - 在 `KeyManagementService.importKey` 或按需导出流程中使用它，让导入身份重新获得与本地生成身份相同的吊销导出能力。
   - 为两个配置档案都添加测试。

3. **口令/SKESK 支持**
   - 如果产品范围需要对称消息兼容性，就增加基于口令的加密/解密 Rust 封装与显式错误映射。
   - 只有在产品流程获批时，才扩展 Swift 服务层；否则应将此缺失明确记录为有意设计。

4. **认证与高级签名语义**
   - 只有在计划引入认证功能时，才添加专门封装。
   - 在把多签名或认证验证接入 Swift 之前，优先设计更丰富的结果模型。

5. **文档清理**
   - 在产品/安全文档中澄清：当前支持的中心是基于收件人密钥的工作流，而不是口令消息或证书合并/更新导入。

## 7. 证据来源

本次审计使用的主要证据：

- `pgp-mobile/Cargo.toml`
- `pgp-mobile/src/lib.rs`
- `pgp-mobile/src/keys.rs`
- `pgp-mobile/src/encrypt.rs`
- `pgp-mobile/src/decrypt.rs`
- `pgp-mobile/src/sign.rs`
- `pgp-mobile/src/verify.rs`
- `pgp-mobile/src/streaming.rs`
- `Sources/Services/`
- `pgp-mobile/tests/`
- `Tests/FFIIntegrationTests/`
- `Tests/ServiceTests/`
- Sequoia 2.2 源码：`src/cert.rs`、`src/serialize/stream.rs`、`src/parse/stream.rs`
