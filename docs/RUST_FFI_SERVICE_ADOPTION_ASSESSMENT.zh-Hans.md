# Rust / FFI 服务采用情况评估

> 目的：评估最近新增的五类 Rust / FFI 能力族如何接入 Swift 服务层、应用入口点以及测试栈。
> 读者：人类开发者、评审者以及 AI 编码工具。
> 配套文档：[RUST_FFI_IMPLEMENTATION_REFERENCE](RUST_FFI_IMPLEMENTATION_REFERENCE.md) · [SEQUOIA_CAPABILITY_AUDIT](SEQUOIA_CAPABILITY_AUDIT.md) · [RUST_SEQUOIA_INTEGRATION_TODO](RUST_SEQUOIA_INTEGRATION_TODO.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md)

## 1. 范围与分类

本评估对每个能力族都遵循相同的五层审查路径：

1. 参考文档中的预期
2. Rust 包装层与 UniFFI 导出
3. Swift 服务层采用情况
4. `Sources/App/` 下的直接应用入口点
5. Rust、FFI 与服务测试覆盖

本文的范围有意比密码学审计更窄：

- 不会重新审计已经由 Rust 和 FFI 测试覆盖的 Sequoia 语义
- 重点关注服务层采用情况是完整、部分、缺失，还是有意延后
- 只有当生产服务真正消费该能力族语义时，才将其视为“已采用”，而不只是存在 Rust 或 FFI 导出

下文使用的分类标签：

- `Production-adopted`：生产服务已消费该能力族，并暴露出其预期语义
- `Production-adopted with contract gap`：生产服务已消费该能力族，但某个重要的服务层不变量尚未端到端落实
- `Service ready, app dormant`：生产服务已存在且经过测试，但当前没有直接的应用入口点在使用它
- `FFI only`：Rust 与 UniFFI 导出已存在，但没有生产服务所有者
- `Partial internal service use`：某个生产服务调用了该能力族，但只覆盖其一个子集，或仅用于恢复旧行为
- `Documented deferred`：当前未在服务层采用的状态与参考文档一致，不视为意外遗漏

## 2. 当前状态矩阵

| 能力族 | 文档预期 | 当前服务所有者 | 当前应用入口 | 当前分类 | 测试覆盖 | 关键缺口 | 建议动作 |
|---|---|---|---|---|---|---|---|
| 证书合并 / 更新 | 已在 `ContactService` 中实现，用于相同指纹的公钥更新 | `ContactService` | `ContactImportWorkflow`、`AddContactView`、`CypherAirApp` 中的 URL 导入流程 | `Production-adopted` | Rust + FFI + 服务测试 | 联系人导入的“仅公钥”门禁落地后，当前无服务层缺口 | 继续验证稳定的联系人导入“仅公钥”令牌，以及服务层持久化保护 |
| 吊销构造 | 已批准在 Swift 侧采用密钥级路径；子密钥和 User ID 构造器延后，待选择器发现能力就绪 | 仅密钥级由 `KeyManagementService` 持有 | `KeyDetailView` 吊销证书导出 | 密钥级已在生产环境采用；选择性构造器为文档化延后 | Rust + FFI + 密钥级服务测试 | 已批准的密钥级路径当前无缺口；选择性构造器按设计没有服务所有者 | 在选择器发现辅助能力和下游所有者出现之前，继续保持子密钥 / User ID 构造器延后 |
| 密码 / SKESK 对称消息 | 已批准专用 `PasswordMessageService`；UI 暴露延后 | `PasswordMessageService` | 除 `AppContainer` 构造外，未在 `Sources/App/` 下发现直接应用调用点 | `Service ready, app dormant` | Rust + FFI + 服务测试 | 当前没有面向用户的工作流消费该服务 | 若产品不需要 UI，则继续延后；若启用，需明确定义明文清零与 UX 行为 |
| 认证与绑定验证 | 默认延后服务层采用 | 无 | 无 | `FFI only`；且为文档化延后 | Rust + FFI 测试 | 没有服务所有者，也没有应用路径 | 在出现专门的证书管理或信任工作流之前，继续延后 |
| 更丰富的签名结果 | 服务层采用延后；并行的详细 API 供后续消费者使用 | `SigningService` 使用了一条详细文件验证路径；`DecryptionService` 没有对应所有者 | `VerifyView` 仅使用流式 detached verify | `Partial internal service use`；对外仍是旧语义 | Rust + FFI 测试，以及仅覆盖旧字段的间接服务测试 | 详细语义在服务边界被丢弃，且未作为能力族进行服务测试 | 要么显式采用该能力族并补充专用服务结果类型与测试，要么为保持清晰，将唯一那处详细调用点回退到旧 API |

## 3. 各能力族结论

### 3.1 证书合并 / 更新

**预期的服务层立场**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) 第 3.1 节与 [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) 第 2.1 节都要求在 Swift 联系人流程中，吸收边界明确的“相同指纹公钥证书更新”。
- [`SEQUOIA_CAPABILITY_AUDIT.md`](SEQUOIA_CAPABILITY_AUDIT.md) 将该能力族记录为端到端已实现。

**当前实现证据**

- Rust / FFI 导出：[`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) 导出 `merge_public_certificate_update`。
- 生产服务所有者：[`Sources/Services/ContactService.swift`](../Sources/Services/ContactService.swift) 在相同指纹路径上调用 `engine.mergePublicCertificateUpdate(...)`，并保留 `.duplicate` 与 `.updated` 语义。
- 应用入口点：[`Sources/App/Contacts/Import/ContactImportWorkflow.swift`](../Sources/App/Contacts/Import/ContactImportWorkflow.swift)、[`Sources/App/Contacts/AddContactView.swift`](../Sources/App/Contacts/AddContactView.swift)，以及 [`Sources/App/CypherAirApp.swift`](../Sources/App/CypherAirApp.swift) 中的 URL 导入流程。
- 测试：
  - Rust：[`pgp-mobile/tests/certificate_merge_tests.rs`](../pgp-mobile/tests/certificate_merge_tests.rs)
  - FFI：[`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)
  - 服务：[`Tests/ServiceTests/ContactServiceTests.swift`](../Tests/ServiceTests/ContactServiceTests.swift)

**已对齐的部分**

- 保留了相同指纹下 duplicate / no-op 的行为。
- 相同指纹更新吸收覆盖有效期刷新、吊销更新、主 User ID 变更，以及新增加密子密钥。
- 应用层导入工作流仍将“同 UID 但不同指纹”的替换视为独立确认流程。

**当前服务层保护**

- 联系人导入现在会在 UI 检查和服务持久化之前，先使用专用的公钥证书校验辅助方法。
- Rust / FFI 暴露了一个公钥证书校验器，它会在 `cert.is_tsk()` 时以 `InvalidKeyData` 和一个稳定的机器可读令牌拒绝该联系人导入违规情况。
- Swift 侧联系人导入辅助方法会把该令牌映射为显式的联系人导入公钥证书错误，而不是依赖面向人的原因字符串。
- [`Sources/Services/ContactService.swift`](../Sources/Services/ContactService.swift) 会在 `confirmKeyUpdate(...)` 中重新校验待替换联系人的字节，并基于校验后的字节重建权威 `Contact`，因此文件名、内存态和校验元数据都不再信任调用方传入的联系人对象。

**评估**

- 分类：`Production-adopted`
- 先前联系人导入“仅公钥”契约缺口现已补齐。

### 3.2 吊销构造

**预期的服务层立场**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) 第 3.2 节与 [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) 第 2.2 节明确只批准密钥级生产采用。
- 子密钥和 User ID 吊销构造器有意延后，待选择器发现辅助能力存在后再说。

**当前实现证据**

- Rust / FFI 导出：[`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) 导出 `generate_key_revocation`、`generate_subkey_revocation` 和 `generate_user_id_revocation`。
- 已批准路径的生产服务所有者：[`Sources/Services/KeyManagementService.swift`](../Sources/Services/KeyManagementService.swift)
  - 在生成 / 导入时提供密钥级吊销能力
  - 为历史导入密钥做惰性补回
  - 导出 armored 吊销证书
- 应用入口点：[`Sources/App/Keys/KeyDetailView.swift`](../Sources/App/Keys/KeyDetailView.swift) 使用 `exportRevocationCertificate(...)`。
- 测试：
  - Rust：[`pgp-mobile/tests/revocation_construction_tests.rs`](../pgp-mobile/tests/revocation_construction_tests.rs)
  - FFI：[`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)
  - 服务：[`Tests/ServiceTests/KeyManagementServiceTests.swift`](../Tests/ServiceTests/KeyManagementServiceTests.swift)

**已对齐的部分**

- 密钥级吊销生成已完整接入获批的导入 / 导出流程。
- 历史导入密钥的能力对齐与惰性补回行为已有服务测试覆盖。
- `KeyManagementService` 中对敏感秘密证书的处理遵循文档要求的 unwrap / zeroize 模式。

**仍然延后的部分**

- 子密钥级与 User ID 级吊销构造器虽然已导出并测试，但没有生产服务所有者。
- 这与参考文档一致，因为 Swift 侧仍缺少选择器发现能力。

**评估**

- 分类：`Key-level production-adopted; selective builders documented deferred`
- 在已批准的密钥级路径上，未发现需要立即处理的服务层不匹配。

### 3.3 密码 / SKESK 对称消息

**预期的服务层立场**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) 第 3.3 节与 [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) 第 2.3 节都允许并期望存在一个专用 Swift 服务包装层，同时将产品 UI 暴露延后。

**当前实现证据**

- Rust / FFI 导出：[`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) 导出增量式的密码加密 / 解密方法，以及专用的密码结果枚举 / 记录。
- 生产服务所有者：[`Sources/Services/PasswordMessageService.swift`](../Sources/Services/PasswordMessageService.swift)
- 应用装配：[`Sources/App/AppContainer.swift`](../Sources/App/AppContainer.swift) 会构造该服务。
- 应用入口点：当前对 `Sources/App/` 的源码审查未发现 `AppContainer` 构造之外的直接调用点。
- 测试：
  - Rust：[`pgp-mobile/tests/password_message_tests.rs`](../pgp-mobile/tests/password_message_tests.rs)
  - FFI：[`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)
  - 服务：[`Tests/ServiceTests/PasswordMessageServiceTests.swift`](../Tests/ServiceTests/PasswordMessageServiceTests.swift)

**已对齐的部分**

- 该服务将密码消息流程与基于接收者密钥的解密流程保持分离。
- `noSkesk`、`passwordRejected` 以及成功解密结果都被保留为服务层结果。
- 致命认证 / 完整性失败以及不支持的算法仍然通过 `CypherAirError.from(...)` 映射，而不是被折叠成该能力族内部状态。

**当前限制**

- 该服务已具备生产可用性并完成测试，但应用当前尚未暴露相应用户工作流。
- 由于尚不存在视图 / 控制器路径，调用方侧的明文清零契约还没有像接收者密钥解密流程那样，在 UI 边界处被最终敲定。

**评估**

- 分类：`Service ready, app dormant`
- 这是产品暴露层面的缺口，不是 Rust / FFI 覆盖缺口。

### 3.4 认证与绑定验证

**预期的服务层立场**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) 第 3.4 节与 [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) 第 2.4 节都说明：默认延后服务层采用。

**当前实现证据**

- Rust / FFI 导出：[`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) 导出 direct-key verification、User ID binding verification，以及 User ID certification generation。
- [`Sources/Services/`](../Sources/Services/) 下不存在生产服务包装层。
- [`Sources/App/`](../Sources/App/) 下不存在直接应用入口点。
- 测试：
  - Rust：[`pgp-mobile/tests/certification_binding_tests.rs`](../pgp-mobile/tests/certification_binding_tests.rs)
  - FFI：[`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)

**评估**

- 分类：`FFI only; documented deferred`
- 这并非意外遗漏。当前仓库已将该能力族的目标界定为 Rust 完整性，而尚未定义下游服务所有者。

### 3.5 更丰富的签名结果

**预期的服务层立场**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) 第 3.5 节与 [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) 第 2.5 节都将该详细结果能力族记为“增量式能力”，并延后其在生产服务层的采用。

**当前实现证据**

- Rust / FFI 导出：[`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) 导出 `verify_*_detailed`、`decrypt_detailed` 以及文件级详细 API。
- 生产服务使用范围很窄：
  - [`Sources/Services/SigningService.swift`](../Sources/Services/SigningService.swift) 中的 `verifyDetachedStreaming(...)` 会调用 `engine.verifyDetachedFileDetailed(...)`
  - 但它会立刻只使用 `legacyStatus` 与 `legacySignerFingerprint`，把结果重新折叠回 `SignatureVerification`
- [`Sources/Services/DecryptionService.swift`](../Sources/Services/DecryptionService.swift) 中不存在对应 `decrypt_detailed` 或 `decrypt_file_detailed` 的详细服务所有者。
- 应用入口点：[`Sources/App/Sign/VerifyView.swift`](../Sources/App/Sign/VerifyView.swift) 只使用流式 detached verify 路径。
- 测试：
  - Rust：[`pgp-mobile/tests/detailed_signature_tests.rs`](../pgp-mobile/tests/detailed_signature_tests.rs)
  - FFI：[`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)
  - 服务：[`Tests/ServiceTests/StreamingServiceTests.swift`](../Tests/ServiceTests/StreamingServiceTests.swift) 覆盖了流式验证路径的成功 / 失败 / 取消场景，但没有断言详细能力族语义，例如签名数组保留、解析顺序、重复签名者或未知签名者条目

**已对齐的部分**

- 增量式详细 API 已存在，并保留对旧字段的折叠兼容。
- 当前唯一的服务调用点不会破坏旧 UI 行为。

**关键服务层缺口**

- 该能力族的独特语义从未跨过服务边界。
- 当前生产行为即便在那一条已经依赖详细 API 的路径上，仍然只是单一折叠状态。
- 这一个“部分调用点”造成了语义歧义：
  - 维护者可能会把代码理解为“详细能力族已被采用”
  - 用户实际收到的仍只有旧语义
  - 服务测试没有保护该能力族级别的详细结果契约

**评估**

- 分类：`Partial internal service use; externally still legacy`
- 这是五个能力族中当前最主要的剩余服务层问题。

## 4. 优先级后续动作

### P1

1. 决定“更丰富的签名结果”到底是真的继续延后，还是应该升级为一等服务特性。
   - 受影响能力族：更丰富的签名结果
   - 重要性：`SigningService` 当前依赖一个详细 API，但立即丢弃了详细语义，而服务测试只保护旧的折叠结果。
   - 决策边界：
     - 如果该能力族继续延后，就把这条狭窄调用路径切回旧的文件验证 API，让代码准确反映真实产品语义
     - 如果该能力族开始启用，就为详细验证 / 解密路径定义显式服务层结果类型，并补充 parser order、repeated signers、unknown signers 以及 legacy-compat fields 的服务测试
   - 敏感边界说明：未来若要在 [`Sources/Services/DecryptionService.swift`](../Sources/Services/DecryptionService.swift) 中采用详细解密路径，必须按照 [`SECURITY.md`](SECURITY.md) 要求经过人工审查

### P2

1. 在产品范围未变化前，保持“密码消息”能力族处于“应用未启用”状态。
   - 受影响能力族：密码 / SKESK 对称消息
   - 当前状态已与文档一致：服务已实现并完成测试，但应用尚无对应工作流。
   - 如果产品范围扩大，需要定义：
     - 调用方侧的明文清零规则
     - `noSkesk`、`passwordRejected`、认证 / 完整性失败，以及可选签名的 UI / 错误处理

2. 在选择器发现能力就绪之前，继续延后选择性吊销构造器。
   - 受影响能力族：吊销构造
   - 当前状态与文档一致：密钥级采用已完成，子密钥 / User ID 构造器按设计仍停留在 FFI 层。

3. 在出现专门所有者之前，继续延后证书签名验证能力族。
   - 受影响能力族：认证与绑定验证
   - 当前状态与文档一致：Rust 与 FFI 完整性已交付，但尚无生产服务或 UI 工作流。
   - 当该能力族真正启用时，应增加专用服务，而不是把它折叠进当前消息验证服务中。

## 5. 最终分类摘要

- 证书合并 / 更新：`Production-adopted`
- 吊销构造：`Key-level production-adopted; selective builders documented deferred`
- 密码 / SKESK 对称消息：`Service ready, app dormant`
- 认证与绑定验证：`FFI only; documented deferred`
- 更丰富的签名结果：`Partial internal service use; externally still legacy`

这一分类消除了当前的灰色地带：

- 每个能力族现在都有了明确的服务所有者状态
- 每个 FFI 导出能力族都有了直接的下游分类
- 每个延后能力族都与真正的服务缺口区分开来
- 目前唯一仍然重要的服务层问题，是围绕“更丰富的签名结果”的 P1 部分采用清晰度问题
