# Service / View 重构实施规范

> 目的：为未来的 Service / View 重构定义实施基线，同时保证不改变任何用户可见行为和当前安全语义。
> 读者：人类开发者、评审者以及 AI 编码工具。
> 配套文档：[SERVICE_VIEW_REFACTOR_ASSESSMENT](SERVICE_VIEW_REFACTOR_ASSESSMENT.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [CONVENTIONS](CONVENTIONS.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)
> 规范姿态：本文是未来重构工作的执行基线。它比评估文档更具体，但在评估文档被评审接受之前，不授权直接进入实现。

## 1. 意图

这次重构要解决的是结构问题，而不是产品问题。

CypherAir 当前在生产应用和 guided tutorial 中都已经具备可工作的行为。问题在于，若干 services 和 screens 现在混合了承载渲染、协调、状态机、持久化决策与集成接缝的职责，这会提高 review 成本，也会降低后续安全迭代速度。

本次重构的意图是：

- 保持当前所有用户可见行为不变
- 保持当前所有安全语义不变
- 降低过载的 service 和 view ownership
- 在重构生产页面时保留 tutorial 兼容性
- 让未来功能迭代更容易评审，也更不容易回归相邻流程

本规范假定 [SERVICE_VIEW_REFACTOR_ASSESSMENT](SERVICE_VIEW_REFACTOR_ASSESSMENT.md) 已经先被评审并接受。在该评审门槛通过之前，不应开始任何实现阶段。

## 2. 重构目标

本次重构必须同时达成以下目标：

1. 保持现有生产 service 入口点对下游调用者稳定。
2. 将 `KeyManagementService` 与 `ContactService` 从多重 ownership 的实现体，收敛为面向更小内部 collaborator 的 façade。
3. 将最大几个生产页面中的 workflow coordination 移出 view，转入专门的 `@Observable` screen model。
4. 保留当前基于 `Configuration` 的 tutorial 适配模式，让 tutorial 继续包装真实生产页面，而不是分叉出另一套页面。
5. 通过引入专门的 coordinator，让 `CypherAirApp` 回到 composition root 的角色。
6. 将工作固定分成四个功能簇波次，保证验证与评审都可控。

这次重构并不要求每个 screen 都变得很小，但必须恢复清晰的 ownership boundary。

## 3. 目标架构

### 3.1 Service 层

#### 3.1.1 总体规则

现有通过 environment 注入的 service 类型继续作为应用级 façade 层存在：

- `KeyManagementService`
- `ContactService`
- `EncryptionService`
- `DecryptionService`
- `SigningService`
- `QRService`

首波重构不得要求大量调用方迁出这些名称。

#### 3.1.2 `KeyManagementService`

`KeyManagementService` 继续作为暴露给 views 和其他 services 的 façade，但其内部 ownership 被拆为若干更小、职责更窄的 collaborator。

目标 collaborator 边界：

- `KeyCatalogStore`
  - 拥有 loading、内存中 key collection updates、default-key state 与 metadata persistence coordination
- `KeyProvisioningService`
  - 拥有 generate / import workflow，以及从 engine 原始输出到已存 identity 的转换
- `KeyExportService`
  - 拥有 secret-key export、public-key export 与 revocation export workflow
- `KeyMutationService`
  - 拥有 expiry mutation、deletion 以及相关 transactional mutation flow
- `PrivateKeyAccessService`
  - 拥有 Secure Enclave unwrap access 与下游密码流程使用的 raw private-key retrieval

规则：

- 首波中 `KeyManagementService` 保留当前公开方法。
- `keys` 与 `defaultKey` 继续通过 façade 可观察。
- 即使内部 ownership 迁移，也不得改变安全敏感的时序语义。
- 首波不允许改变 `AuthenticationManager`、Secure Enclave wrapping、Keychain access-control 语义或 crash-recovery 语义。

#### 3.1.3 `ContactService`

`ContactService` 继续作为暴露给 App 层的 façade，但其内部 ownership 被拆为：

- `ContactRepository`
  - 拥有 contact file persistence、metadata manifest persistence 与 load/save 操作
- `ContactImportService`
  - 拥有 validation、same-fingerprint merge 决策、replacement detection 与 import/update result shaping

规则：

- 首波中 `ContactService` 的公开方法保持兼容。
- contact-import public-only validation path 必须保持完整。
- 文件命名、metadata 格式、duplicate / update / replacement 语义和 verification-state persistence 必须保持不变。

#### 3.1.4 其他 Service

首波对其他 services 的处理：

- `EncryptionService`：公开 API 保持不变；仅在 screen-model 集成需要时允许做内部 helper 提取。
- `DecryptionService`：公开 API 保持不变，并严格保留 Phase 1 / Phase 2 边界。
- `SigningService`：公开 API 保持不变；可以做内部 helper 提取，但不是硬性要求。
- `PasswordMessageService` 与 `SelfTestService`：首波不要求结构重构。

### 3.2 View 层

#### 3.2.1 总体规则

大的生产页面迁移到 screen-model-backed 结构：

- 顶层 view 保持为路由与调用点类型
- 专门的 `@Observable` screen model 拥有 workflow state、async actions、transient results 与 presentation state
- 渲染内容通过 binding 连接到该 screen model

screen model 成为以下职责的 owner：

- task 与 progress lifecycle
- async action orchestration
- input/output state invalidation
- file importer 与 exporter state
- error 与 confirmation state
- output interception decision

view 本身保留以下职责：

- layout
- bindings
- 纯渲染相关的本地派生
- 将 toolbar、sheet、alert 与 navigation modifier 连接到 model state

#### 3.2.2 首波必须纳入的 Screen Model

首波必须明确覆盖以下 screen model：

- `EncryptScreenModel`
- `DecryptScreenModel`
- `SignScreenModel`
- `VerifyScreenModel`
- `SettingsScreenModel`
- `KeyDetailScreenModel`
- `AddContactScreenModel`

这些是首波的强制目标，因为它们正对应当前最大的 coordination hotspot。

#### 3.2.3 首波不强制 Screen Model 化的页面

以下页面不是首波必须转为 screen model 的目标：

- `KeyGenerationView`
- `ImportKeyView`
- `BackupKeyView`
- `ModifyExpirySheetView`
- tutorial hub 与 onboarding screens

如有兼容性需要，可以做小规模 helper 提取，但它们不是首波架构驱动点。

#### 3.2.4 共享 App Helper

重构应保留并复用当前 App 层 helper 接缝，而不是整体替换：

- `OperationController`
- `FileExportController`
- `SecurityScopedFileAccess`
- `ImportedTextInputState`
- `PublicKeyImportLoader`
- `ContactImportWorkflow`
- `ImportConfirmationCoordinator`

首选策略是“ownership relocation”，而不是删除 helper。例如 screen model 可以拥有一个 `OperationController`，但这个工具本身仍应保持可复用。

### 3.3 Tutorial / Onboarding 兼容性

tutorial 兼容性是硬约束，而不是锦上添花。

首波必须保留当前适配模式：

- production screens 保留自己的 `Configuration` struct
- tutorial 限制继续通过 `TutorialConfigurationFactory` 注入
- tutorial route hosting 继续通过 `TutorialRouteDestinationView`、`TutorialSurfaceView` 与 `TutorialShellDefinitionsBuilder`
- `TutorialSessionStore` 继续作为 tutorial 状态机与 artifact owner
- `TutorialSandboxContainer` 继续作为独立 composition root

规则：

- 首波不要重写 tutorial 状态机
- 首波不要合并 production 与 tutorial containers
- 在替代接缝被证明之前，不要移除当前基于 callback 的 `Configuration` hooks

### 3.4 App Root 与流程协调

重构结束后，`CypherAirApp` 应回到“composition root + top-level scene declaration”的角色，而不是继续作为多流程 coordinator。

目标 coordinator 边界：

- `AppPresentationCoordinator`
  - 拥有 onboarding / tutorial presentation state 与 handoff 规则
- `IncomingURLImportCoordinator`
  - 拥有 `cypherair://` 公钥导入协调与 alert state

规则：

- 当前由 `AppStartupCoordinator` 承担的 startup 行为保持不变
- tutorial launch 语义与 onboarding dismissal 规则保持不变
- 全局 alert 的内容与触发时机保持不变

## 4. 兼容性规则

以下是首波不可妥协的约束：

- 不改变任何用户可见行为。
- 不改变字符串、路由、tutorial 模块顺序或导出文件名。
- 不改变当前 import / export 语义、clipboard 行为或 output-interception 行为。
- 不改变 UI tests 使用的 ready markers。
- 不改变 `UITEST_*` launch-environment 语义。
- 首波不改 Rust。
- 首波不改 `Sources/Security/` 下的行为。
- 首波不改变 `AuthenticationManager` 的行为。
- 现有生产页面的 `Configuration` 类型保持 source-compatible。
- 现有通过 environment 注入的 façade types 继续作为 App 层的主要入口。

按领域细化后的兼容性规则：

- `DecryptionService` 的 Phase 1 / Phase 2 行为，从调用方视角必须保持完全兼容。
- `KeyManagementService` 的 recovery 与 unwrap 行为，外部表现必须完全一致。
- `ContactService` 的 duplicate / update / replacement 语义，外部表现必须完全一致。
- `TutorialConfigurationFactory` 必须继续能够表达当前 tutorial 限制和回调，而不需要为 tutorial 分叉生产页面。

## 5. 分阶段推进

实施阶段固定为四个功能簇。不要将其压缩成一个分支上的“大重写”。

### 5.1 第一阶段：Key Lifecycle + Settings

**范围**

- `KeyManagementService` 内部拆分
- `SettingsScreenModel`
- `KeyDetailScreenModel`
- 为兼容新内部结构所需的最小适配工作

**必须产出**

- 保留 `KeyManagementService` façade
- 建立内部 collaborator 边界，并由单元测试覆盖
- `SettingsView` 不再直接协调 mode switching
- `KeyDetailView` 不再直接拥有 export / delete / revocation / expiry workflow state

**完成定义**

- 调用方仍通过 `KeyManagementService` 使用能力
- key detail 与 settings 页面保持当前行为
- auth-mode warning、mode switching、revocation export、default-key change、delete flow 与 modify-expiry flow 均无行为变化

**明确不在范围内**

- `AuthenticationManager` 行为改动
- `KeyGenerationView`、`ImportKeyView`、`BackupKeyView` 与 `ModifyExpirySheetView` 的完整 screen-model 化

### 5.2 第二阶段：Encrypt / Decrypt / Sign / Verify

**范围**

- `EncryptScreenModel`
- `DecryptScreenModel`
- `SignScreenModel`
- `VerifyScreenModel`
- 四个生产页面的 thin host/content restructuring
- 仅在 screen-model split 确有需要时，才在 `EncryptionService`、`DecryptionService` 与 `SigningService` 中做 helper extraction

**必须产出**

- workflow state 从四个 view 中移出
- 当前 `Configuration` structs 继续可被 production 与 tutorial host 双方使用
- export / import / cancel / error / presentation 行为保持不变

**完成定义**

- `EncryptView`、`DecryptView`、`SignView` 与 `VerifyView` 主要绑定到 screen-model state
- 文件检查、invalidation 与 cleanup 逻辑不再与 rendering code 交错
- `DecryptionService` 的 Phase 1 / Phase 2 语义保持不变

**明确不在范围内**

- service façade 重命名
- 启用 `PasswordMessageService` 的 UI

### 5.3 第三阶段：Contacts Import Flows

**范围**

- `ContactService` 内部拆分
- `AddContactScreenModel`
- QR photo import 与 confirmation-host flow 的兼容性调整

**必须产出**

- 保留 `ContactService` façade
- 将 contact persistence 与 contact-import workflow responsibility 在内部拆开
- `AddContactView` 不再拥有主导入流程状态机

**完成定义**

- duplicate / update / replacement 语义保持不变
- 当前 confirmation coordinator 与 import-confirmation UI 保持完整
- tutorial add-contact 流程仍通过 `TutorialConfigurationFactory` 工作

**明确不在范围内**

- 联系人导入用户体验的重新设计
- tutorial-specific contact flow 重写

### 5.4 第四阶段：App Root + Tutorial / Onboarding Host

**范围**

- `AppPresentationCoordinator`
- `IncomingURLImportCoordinator`
- tutorial host layers 对 screen-model-backed 生产页面的适配

**必须产出**

- `CypherAirApp` 收敛回 composition 与 top-level scene wiring
- onboarding / tutorial handoff logic 迁入专门 coordinator
- URL import coordination 从 app root 中移出
- tutorial host wrappers 对生产页面 configuration 继续兼容

**完成定义**

- tutorial launch、replay 与 dismissal 行为保持不变
- startup warning 与 import alert 保持不变
- 生产页面在 tutorial 与 onboarding-connected context 中继续正确渲染

**明确不在范围内**

- 重写 `TutorialSessionStore`
- 合并 tutorial 与 production containers
- 重新设计 tutorial host UX

## 6. 测试与验证门槛

### 6.1 任何代码阶段开始前的基线门槛

在启动任何实现阶段前，先用当前仓库命令确认基线：

```bash
cargo test --manifest-path pgp-mobile/Cargo.toml
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'
```

如果基线本身不是绿色，必须先修复或隔离基线问题，再开始重构。

### 6.2 每个阶段的强制验证

每个阶段结束时都必须运行：

- `cargo test --manifest-path pgp-mobile/Cargo.toml`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'`
- 对照 [CODE_REVIEW](CODE_REVIEW.md) 做定向 review

### 6.3 分阶段测试要求

#### 第一阶段

- 为新的 `KeyManagementService` collaborator 增加或扩展单元测试
- 保持 `KeyManagementServiceTests` 绿色
- 当 key detail 与 settings 页面被间接覆盖时，对应 tutorial tests 也必须保持绿色

#### 第二阶段

- 保持 `EncryptionServiceTests`、`DecryptionServiceTests`、`SigningServiceTests` 与 `StreamingServiceTests` 绿色
- 为 screen model 增加测试，覆盖：
  - import / export 状态转换
  - cancellation 行为
  - invalidation 与 cleanup 行为
  - warning / confirmation 状态转换
- 当 ready-state ownership 变化影响 UI tests 时，扩展 macOS smoke coverage

#### 第三阶段

- 保持 `ContactServiceTests` 绿色
- 保持 `TutorialSessionStoreTests` 中 add-contact 路径绿色
- 为 add-contact mode switching、QR / file import 以及 replacement confirmation flow 增加 screen-model 测试

#### 第四阶段

- 保持 `TutorialSessionStoreTests` 绿色
- 保持 `MacUISmokeTests` 中 tutorial 与 settings launch 流程绿色
- 为 onboarding / tutorial handoff 与 URL import coordination 增加 coordinator 测试

### 6.4 Device Test 规则

只有当某个阶段意外触碰到 device-auth 或 Secure Enclave 语义时，才要求跑 device-only test plan。首波设计的目标正是避免触碰这些行为边界。

## 7. 评审检查点

### 7.1 文档门槛

在开始任何代码实现前，必须先完成：

- [SERVICE_VIEW_REFACTOR_ASSESSMENT](SERVICE_VIEW_REFACTOR_ASSESSMENT.md) 的评审
- 本实施规范的评审
- 对阶段顺序的接受，不再重新打开架构范围

### 7.2 每阶段设计评审

每个阶段开始前，确认：

- 该阶段的目标文件与 collaborator
- 该阶段的明确非目标
- 需要更新或新增的测试
- 是否靠近任何敏感边界

### 7.3 敏感边界评审

如果某一阶段触碰或可能触碰以下任何内容，合并前必须经过人工评审：

- `Sources/Security/`
- `Sources/Services/DecryptionService.swift`
- `Sources/Services/QRService.swift`
- `CypherAir.xcodeproj/project.pbxproj`
- onboarding / tutorial launch 与 auth-mode confirmation 行为

### 7.4 行为一致性评审

每个阶段结束时，都要对照当前生产行为做 parity review：

- 无可见导航变化
- 无 alert 时序变化
- 无 tutorial 能力变化
- 无 import / export 命名变化
- 无 settings 语义变化

## 8. 暂缓项

以下内容明确延后到首波之后：

- 重写 `TutorialSessionStore` 中的 tutorial 状态机
- 统一 tutorial 与 production containers
- 收窄或重命名公共 service facades
- 为 `PasswordMessageService` 激活新的产品表面
- 将所有 key 相关页面都纳入首波 screen-model 强制范围
- 重新设计 tutorial hub、onboarding 文案或 tutorial host UX
- 改变 Rust、Secure Enclave、Keychain 或 auth-mode 的行为语义

这些延后项是有意为之。它们能让首波结构重构聚焦在 ownership boundary 与 coordination flow，而不是让范围失控。

## 9. 执行摘要

未来的重构应被视为一次“保留现有架构语义的内部重写”，并受以下严格约束：

- 保留 facades
- 拆内部 ownership
- 将 screen workflow logic 移到专门的 `@Observable` screen model
- 保留 tutorial `Configuration` 兼容性
- 保留当前安全语义
- 将 app-root coordination 移到专门 coordinator

如果某个实现提议无法满足这些约束，那么它就不属于首波规范范围，应被延后，而不是强行塞进同一轮重构。
