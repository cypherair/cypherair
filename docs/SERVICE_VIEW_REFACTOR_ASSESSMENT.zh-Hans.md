# Service / View 重构评估

> 目的：在开始任何结构性重构之前，评估 CypherAir 当前 Service 层与 App 层的边界情况。
> 读者：人类开发者、评审者以及 AI 编码工具。
> 配套文档：[ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [CONVENTIONS](CONVENTIONS.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)

## 1. 范围与分类

本评估将三类相关表面一起审查：

1. `Sources/Services/` 下的生产服务
2. `Sources/App/` 下的生产视图与应用宿主
3. 将生产页面适配到 Guided Tutorial 沙箱中的 tutorial / onboarding 宿主层

目标不是给出补丁级实现步骤，而是对当前状态进行分类、记录证据，并识别哪些设计边界仍然成立，哪些已经出现过载。

本文统一使用以下分类标签：

- `Within boundary`：该文件仍在承担其所在层应有的职责，即使体量并不小。
- `Large but coherent`：文件较大，但职责大体仍围绕一个清晰领域。
- `Boundary overflow`：文件混合了本应属于不同层或不同抽象的职责。
- `Coordination hotspot`：文件成为过多流程的汇合点，即使单个流程本身仍然可理解。
- `Sensitive / constrained`：文件靠近安全或产品边界，结构调整需要额外谨慎。

边界判断基于当前代码形态、现有集成接缝以及项目规则，而不是仅凭行数。相关 UI 约束已经写在 [CONVENTIONS](CONVENTIONS.md) 中：视图应保持轻量，避免在视图中承载业务逻辑、Keychain 访问和密码学操作。[CODE_REVIEW](CODE_REVIEW.md) 也重复了相同要求。

## 2. 当前状态矩阵

| 表面 | 当前职责 | 体量约值 | 分类 | 证据摘要 | 直接影响 |
|---|---|---:|---|---|---|
| [`KeyManagementService`](../Sources/Services/KeyManagementService.swift) | 密钥生命周期 façade，同时承担 SE unwrap、导出、修改、metadata 与恢复逻辑 | 679 行 | `Boundary overflow`、`Sensitive / constrained` | 一个类型同时拥有生成、导入、导出、吊销导出、有效期修改、删除、默认 key 逻辑、崩溃恢复与私钥解包 | 这是 Service 层最典型的 god service 候选，也是风险最高的重构面 |
| [`ContactService`](../Sources/Services/ContactService.swift) | 公钥联系人持久化、merge/update 处理、替换检测、verification-state 存储 | 385 行 | `Large but coherent`，正向 `Boundary overflow` 靠近 | 同一文件同时拥有校验衔接、merge 决策、文件 I/O、metadata manifest 和内存列表维护 | 适合做内部 repository / import split，同时保持 façade 稳定 |
| [`EncryptionService`](../Sources/Services/EncryptionService.swift) | 文本/文件加密编排 | 334 行 | `Large but coherent` | 服务仍聚焦加密，但 text / file / streaming 三条路径存在协调逻辑重复 | 不是第一优先级的结构拆分目标；首波只需做 helper 提取 |
| [`DecryptionService`](../Sources/Services/DecryptionService.swift) | 两阶段解密编排、流式文件解密、签名解析 | 356 行 | `Large but coherent`、`Sensitive / constrained` | Phase 1 / Phase 2 边界清晰，但文件本身安全关键且承载多条编排路径 | 应保留当前公开契约，在视图瘦身期间避免语义变动 |
| [`SigningService`](../Sources/Services/SigningService.swift) | 文本/文件签名与验签编排 | 290 行 | `Large but coherent` | 职责清晰，主要是对 engine 调用的传输/编排层 | 不是首波 service 拆分目标 |
| [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift) | 加密表单、收件人选择、导出 UX、文件导入导出、任务编排 | 614 行 | `Boundary overflow` | 4 个 environment 依赖、16 个状态属性、351 行 `body`，同时承载 file-export wiring、output interception、warning flow 和异步编排 | 该页面已经明显超出“thin view”预期 |
| [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift) | 两阶段解密页面、导入启发式、临时文件清理、导出 UX | 754 行 | `Boundary overflow` | 17 个状态属性、289 行 `body`，包含手动 invalidation、armored 文本启发式、文件检查、临时文件删除与异步编排 | 这是 App 层最过载的页面，也是最强的 screen model 候选 |
| [`SignView`](../Sources/App/Sign/SignView.swift) | cleartext / detached 签名页面 | 414 行 | `Large but coherent` | 仍基本围绕一个工作流，但同时拥有渲染与任务/导出编排 | 值得在核心流程重构波次里迁到 screen model，但不是当前最糟糕的热点 |
| [`VerifyView`](../Sources/App/Sign/VerifyView.swift) | cleartext / detached 验签页面 | 475 行 | `Large but coherent` | 与 `SignView` 相同模式，外加文件导入与 streaming verify 协调 | 处理方式应与 `SignView` 一致，优先级低于 decrypt / encrypt |
| [`SettingsView`](../Sources/App/Settings/SettingsView.swift) | 设置 UI，同时承担 auth-mode 切换与 onboarding/tutorial 启动协调 | 433 行 | `Coordination hotspot`、`Sensitive / constrained` | 视图直接协调 auth-mode 确认、模式切换、备份感知风险提醒和平台特定 presentation 分支 | 这已经不只是一个表单，而是藏在 View 里的 coordinator |
| [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift) | key detail UI，同时承担导出、默认 key、删除、吊销、modify-expiry 协调 | 418 行 | `Coordination hotspot` | 视图直接发起异步吊销导出、剪贴板写入、默认 key 更新、删除与 modal presentation | 即使 key generation/import 页面暂缓，这里也很适合引入 screen model |
| [`AddContactView`](../Sources/App/Contacts/AddContactView.swift) | paste / QR / file 三种联系人导入 UI | 349 行 | `Coordination hotspot` | 已经用了 `PublicKeyImportLoader` 与 `ContactImportWorkflow`，但视图仍拥有 import-mode 状态、QR 任务生命周期、fallback host wiring 与 alert flow | 这是将来抽离模式的好参考，但当前还不够“thin” |
| [`CypherAirApp`](../Sources/App/CypherAirApp.swift) | 应用 composition root，同时承担 startup、onboarding/tutorial handoff、URL 导入协调与全局 alert | 380 行 | `Coordination hotspot`、`Sensitive / constrained` | app root 构造 container、执行 startup、管理 iOS presentation state、协调 tutorial handoff 并处理 URL 联系人导入 | app root 已经不只是 composition，需要专门 coordinator 才能继续扩展 |
| [`TutorialSessionStore`](../Sources/App/Onboarding/TutorialSessionStore.swift) | tutorial session 状态机与 sandbox 流程 owner | 432 行 | `Large but coherent`、`Coordination hotspot` | 它按设计就是 tutorial 生命周期、sandbox artifacts、导航、modal 路由与任务推进的中心状态源 | 这是有意集中的状态机，首波应保留而不是重写 |
| [`TutorialView`](../Sources/App/Onboarding/TutorialView.swift) | tutorial host UI 与 hub/completion 展示 | 382 行 | `Large but coherent` | 虽然较大，但职责仍围绕 tutorial 体验本身，没有明显泄漏到其他领域 | 优先级低于生产页面，首波应保持稳定，仅适配集成变化 |
| [`TutorialConfigurationFactory`](../Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift) | 从 tutorial 状态到生产页面 configuration 的适配器 | 195 行 | `Within boundary` | 它是一个聚焦的兼容接缝，可以把限制和回调喂给生产页面，而不必重写页面本身 | 应保留该接缝；这是生产页面重构后仍可兼容 tutorial 的关键原因 |
| [`TutorialRouteDestinationView`](../Sources/App/Onboarding/Tutorial/TutorialRouteDestinationView.swift) | 生产页面的 tutorial 路由适配器 | 150 行 | `Within boundary` | 职责几乎完全是 route adaptation 与 host wrapping | 应保持稳定，只在生产页面形态变化时做必要更新 |
| [`TutorialSurfaceView`](../Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift) | tutorial host wrapper 与 inline-header 集成 | 237 行 | `Large but coherent` | 它集中处理 tutorial host chrome 与 visible-surface reporting | 集成较重，但结构本身健康 |
| [`TutorialShellDefinitionsBuilder`](../Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift) | tutorial tab/root 组装 | 106 行 | `Within boundary` | 目的单一且清晰 | 当前没有边界问题 |
| [`TutorialSandboxContainer`](../Sources/App/Onboarding/TutorialSandboxContainer.swift) | 隔离的 tutorial dependency graph 与 sandbox 存储 | 118 行 | `Within boundary`、`Sensitive / constrained` | 它是一个聚焦的 tutorial-only composition root，基于沙箱存储与 mock security primitives | 应保留这条隔离边界；首波不要把它折叠进主应用 container |

## 3. Service 结论

### 3.1 [`KeyManagementService`](../Sources/Services/KeyManagementService.swift)

**分类**

- `Boundary overflow`
- `Sensitive / constrained`

**证据**

- 它是仓库里最大的 service 文件，达到 679 行。
- 至少承载五类不同职责：
  - key enumeration 与 metadata loading
  - generation 与 import
  - export 与 revocation export
  - expiry mutation、deletion 与 default-key mutation
  - crash recovery 与 private-key unwrap
- 它注入并直接拥有 9 个 collaborator 或 store，包括 Secure Enclave、Keychain、defaults、metadata storage 与 migration coordination。
- 最大的几个方法读起来已经更像内部 workflow，而不是 façade entry point：
  - `generateKey(...)`
  - `importKey(...)`
  - `modifyExpiry(...)`
  - `exportRevocationCertificate(...)`

**为什么它已经越界**

`KeyManagementService` 已不只是“key management service façade”。它实际上还同时扮演：

- catalog store
- provisioning workflow owner
- export workflow owner
- mutation transaction coordinator
- crash-recovery coordinator
- private-key access gateway

真正关键的是职责广度，而不是单纯的行数，因为每一类职责都带来了不同的风险面与测试面。

**影响**

- review 成本高，因为日常 key 功能修改与安全敏感的 recovery / unwrap 路径混在同一个文件里。
- 该 service 已成为其他下游关注点的默认依赖，拖得越久，后续越难拆。
- 一个 key 流程上的小变更可能误伤另一个流程，因为很多行为只在这一个文件里集中表达。

**建议动作**

- 首波保留当前 façade 名称与公开调用面。
- 在 façade 背后拆分内部 ownership，让这个文件不再是所有 key-lifecycle 关注点的唯一承载体。

### 3.2 [`ContactService`](../Sources/Services/ContactService.swift)

**分类**

- `Large but coherent`

**证据**

- 文件为 385 行，整体仍主要围绕一个领域：导入的公钥联系人。
- 最大压力点是 `addContact(...)`，它横跨：
  - validation
  - same-fingerprint merge
  - same-user replacement detection
  - file persistence
  - verification-state persistence
  - in-memory updates
- 它还同时拥有 contact 文件存储与 verification-state manifest 格式。

**为什么它仍基本算 coherent**

与 `KeyManagementService` 不同，这里的问题不是领域错位，而是同一个领域中的 repository、import policy 与 merge/replacement workflow 都被折叠进了一个类型。

**影响**

- 联系人导入行为比它本该有的复杂度更难推理。
- 如果想复用或单测“持久化行为”和“merge 行为”，现在很难不通过整个 service 表面。
- 当前结构会鼓励 App 层把它当成 transaction script endpoint 来使用。

**建议动作**

- 保留 `ContactService` 作为 façade。
- 在 façade 背后拆开 persistence 责任和 import / merge workflow 责任。

### 3.3 其他 Service

剩余 services 不是当前首要拆分目标：

- [`EncryptionService`](../Sources/Services/EncryptionService.swift)：`Large but coherent`。在核心页面不再自己编排流程之后，它应继续专注于加密编排。
- [`DecryptionService`](../Sources/Services/DecryptionService.swift)：`Large but coherent`、`Sensitive / constrained`。应保留现有 two-phase contract，避免结构调整遮蔽 auth boundary。
- [`SigningService`](../Sources/Services/SigningService.swift)：`Large but coherent`。做内部 helper 提取即可，暂不急于 façade split。
- [`PasswordMessageService`](../Sources/Services/PasswordMessageService.swift)：`Within boundary`。体量小且目标明确。
- [`SelfTestService`](../Sources/Services/SelfTestService.swift)：`Large but coherent`。它本来就是诊断编排器，而非生产工作流 owner。

## 4. View 结论

### 4.1 核心消息页面

#### [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift)

**分类**

- `Boundary overflow`

**证据**

- 总计 614 行，其中 `body` 为 351 行。
- 有 4 个 environment 依赖和 16 个本地状态属性。
- 视图不只是渲染：
  - 计算 recipient compatibility state
  - 协调 confirmation dialog
  - 运行文件操作
  - 管理 export 与 clipboard interception
  - 通过 `OperationController` 自己拥有 task lifecycle state

**影响**

- 展示变化与工作流变化被紧密耦合。
- tutorial 限制与 production 行为都被穿在同一个 view type 里。

**建议动作**

- 把状态迁移、任务编排与输出处理移动到专门的 screen model，同时保留当前 `Configuration` 接缝。

#### [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift)

**分类**

- `Boundary overflow`

**证据**

- 总计 754 行，其中 `body` 为 289 行。
- 有 17 个本地状态属性。
- 视图直接承担多种非渲染职责：
  - text / file mode invalidation 与 cleanup
  - armored-text 文件检查与建议分支
  - imported-file 状态协调
  - temporary-output 删除
  - async parse / decrypt 编排

**影响**

- 这是 App 层里最典型的“screen 自己扮演 workflow state machine”的例子。
- 由于 View 逻辑与 workflow 逻辑交错，安全敏感的 decrypt 体验更难评审。

**建议动作**

- 将它作为 View 层首个 screen-model 提取目标。

#### [`SignView`](../Sources/App/Sign/SignView.swift) 与 [`VerifyView`](../Sources/App/Sign/VerifyView.swift)

**分类**

- `Large but coherent`

**证据**

- 两个页面都沿用了与 encrypt / decrypt 相同的模式：
  - 渲染表单控件
  - 管理 file picker state
  - 运行异步任务
  - 自己拥有 export 与 error presentation
- `VerifyView` 还承担了 detached-file import 与 streaming verify setup。

**影响**

- 虽然它们没有 decrypt 那么过载，但复用了同一套会让页面越长越重的架构模式。

**建议动作**

- 与 encrypt / decrypt 放在同一波重构，统一 message tools 的 screen 架构。

### 4.2 Settings 与 Key Detail

#### [`SettingsView`](../Sources/App/Settings/SettingsView.swift)

**分类**

- `Coordination hotspot`
- `Sensitive / constrained`

**证据**

- 视图直接协调：
  - auth-mode picker interception
  - warning 生成
  - backup-aware risk messaging
  - async mode switching
  - onboarding / tutorial launch routing
  - platform-specific presentation fallback

**影响**

- 一个设置项修改现在需要同时审 UI 行为与 security-mode orchestration。
- 这个视图实际上已经在扮演 coordinator。

**建议动作**

- 将 mode-switch intent handling 与 presentation state 移到 screen model，同时保持 `AuthenticationManager` 行为不变。

#### [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift)

**分类**

- `Coordination hotspot`

**证据**

- 视图直接驱动 revocation export、public-key copy、delete confirmation、default-key mutation 和 modify-expiry presentation。
- 它还自己拥有多组 export 相关状态机和异步任务状态。

**影响**

- 这已经不是纯 detail page，而是一个小型 workflow surface，因此它是很高价值的重构目标。

**建议动作**

- 将 action orchestration 与 export state 移入 screen model；可见布局与导航结构保持不变。

### 4.3 联系人导入

#### [`AddContactView`](../Sources/App/Contacts/AddContactView.swift)

**分类**

- `Coordination hotspot`

**证据**

- 该视图已经依赖两个抽取出来的 helper：
  - [`PublicKeyImportLoader`](../Sources/App/Contacts/Import/PublicKeyImportLoader.swift)
  - [`ContactImportWorkflow`](../Sources/App/Contacts/Import/ContactImportWorkflow.swift)
- 这是一个积极信号，但视图仍然自己拥有：
  - import-mode 切换
  - QR task lifecycle
  - fallback confirmation-host coordination
  - key-update alert state
  - file-load branching

**影响**

- 这个页面说明“抽 helper”这条方向是可行的，但也说明它的上限：剩下的协调逻辑仍然在 view 里。

**建议动作**

- 将剩余的视图自有协调逻辑提升到 screen model，同时保留现有 loader / workflow helper 与 confirmation coordinator。

### 4.4 App Root

#### [`CypherAirApp`](../Sources/App/CypherAirApp.swift)

**分类**

- `Coordination hotspot`
- `Sensitive / constrained`

**证据**

- app root 当前同时承担：
  - 构建 dependency container
  - 执行 startup recovery
  - 管理 iOS onboarding / tutorial presentation state
  - 协调 onboarding-to-tutorial handoff
  - 处理 URL-driven contact import
  - 暴露 import 与 startup 的全局 alert

**影响**

- 这让 app root 比一个 composition root 应有的复杂度高得多。
- tutorial host 与 URL import 行为都依赖同一个同时负责初始依赖构建的文件。

**建议动作**

- 将应用流程协调拆到专门的 coordinator，让 `CypherAirApp` 重新回到 composition root 角色。

## 5. Tutorial / Onboarding 结论

### 5.1 [`TutorialSessionStore`](../Sources/App/Onboarding/TutorialSessionStore.swift)

**分类**

- `Large but coherent`
- `Coordination hotspot`

**证据**

- 它按设计就是 tutorial 的中心状态 owner。
- 它拥有 lifecycle state、sandbox container lifecycle、navigation state、visible-surface reporting、module progression 与 tutorial artifacts。
- [`TutorialSessionStoreTests`](../Tests/ServiceTests/TutorialSessionStoreTests.swift) 已经把它当作 tutorial 行为的 source of truth 来测试。

**判断**

- 这不是那种应立即拆开的“大文件”。
- 它之所以大，是因为它本来就是 tutorial 产品的有意状态机。

**建议动作**

- 首波保持这个状态机稳定。
- 重构围绕它的 production-page adapters，而不是重写 tutorial 状态模型本身。

### 5.2 [`TutorialConfigurationFactory`](../Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift)

**分类**

- `Within boundary`

**证据**

- 这个 factory 是当前 tutorial 状态到 production pages 的兼容接缝。
- 它可以注入限制与回调，而不必为 tutorial 分叉一套生产页面。

**判断**

- 这个文件在战略上非常重要，因为它让生产页面重构成为可能，同时不强迫 tutorial 重写。

**建议动作**

- 保留该 factory 模式，并将 `Configuration` 兼容性作为设计约束。

### 5.3 [`TutorialRouteDestinationView`](../Sources/App/Onboarding/Tutorial/TutorialRouteDestinationView.swift)、[`TutorialSurfaceView`](../Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift) 与 [`TutorialShellDefinitionsBuilder`](../Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift)

**分类**

- `Within boundary` 到 `Large but coherent`

**证据**

- 这些文件大多是 host adapter：
  - route 到 view 的适配
  - tutorial host wrapping
  - tab/root definition building
- 它们集成密度高，但职责本身清晰。

**判断**

- 它们不是首波的重写候选。
- 只需要在生产页面形态变化时做必要适配。

### 5.4 [`TutorialSandboxContainer`](../Sources/App/Onboarding/TutorialSandboxContainer.swift)

**分类**

- `Within boundary`
- `Sensitive / constrained`

**证据**

- 它是一个聚焦的 tutorial-only composition root，基于沙箱存储与 mock security primitives。
- 现有测试已经验证了其隔离保证。

**判断**

- 这条边界对当前产品是有效的。
- 首波不应把它与主应用 container 合并。

### 5.5 [`OnboardingView`](../Sources/App/Onboarding/OnboardingView.swift) 与 [`TutorialView`](../Sources/App/Onboarding/TutorialView.swift)

**分类**

- `Within boundary` 到 `Large but coherent`

**证据**

- `OnboardingView` 仍主要是展示逻辑与 handoff action。
- `TutorialView` 虽然较大，但它的体量主要来自 tutorial-owned 的 hub / completion presentation 和导航，而不是直接 service orchestration。

**判断**

- tutorial / onboarding 最大的风险不在这些 view 本身。
- 最大风险在于负责启动和包裹它们的 app-root 与兼容接缝。

## 6. 优先级排序

| 优先级 | 表面 | 排名原因 | 风险等级 | 建议下一步 |
|---|---|---|---|---|
| P1 | [`KeyManagementService`](../Sources/Services/KeyManagementService.swift) | 最大 service、职责扩散最广、最靠近安全敏感行为 | 高 | 在保留 façade 的前提下拆内部 ownership |
| P1 | [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift) | 最过载的生产页面，也是 workflow 最重的 App 文件 | 高 | 优先迁到专门的 screen model |
| P1 | [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift) | 与 decrypt 存在同样的架构压力，协调面很大 | 高 | 与 decrypt 同波重构 |
| P1 | [`SettingsView`](../Sources/App/Settings/SettingsView.swift) | 安全敏感协调逻辑隐藏在 view 中 | 高 | 引入 screen model，但不改变 `AuthenticationManager` 行为 |
| P1 | [`CypherAirApp`](../Sources/App/CypherAirApp.swift) | app root 被 startup、handoff 与 URL import 协调逻辑压得过重 | 高 | 引入专门 app-flow coordinators |
| P2 | [`ContactService`](../Sources/Services/ContactService.swift) | repository 与 import policy 仍折叠在同一个 service 里 | 中 | 在 façade 后拆 persistence 与 import policy |
| P2 | [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift) | detail page 已变成 workflow coordinator | 中 | 在 key/settings 波次里迁成 screen model |
| P2 | [`AddContactView`](../Sources/App/Contacts/AddContactView.swift) | 已经部分抽离，但剩余协调仍由 view 持有 | 中 | 保留现有 helper，并把剩余状态机移出 view |
| P2 | Tutorial app-host integration seams | tutorial 兼容性依赖多个 adapter 在生产页面重构中保持稳定 | 中 | 把 `Configuration` 兼容性视作不可妥协约束 |
| P3 | [`SignView`](../Sources/App/Sign/SignView.swift) 与 [`VerifyView`](../Sources/App/Sign/VerifyView.swift) | 没那么紧急，但在架构模式上与 encrypt/decrypt 一致 | 中 | 在核心 message-flow 波次中一起处理 |
| P3 | [`TutorialView`](../Sources/App/Onboarding/TutorialView.swift) 与 [`TutorialSurfaceView`](../Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift) | 文件较大，但目前并不是边界漂移的主要来源 | 低 | 保持稳定，仅为兼容性做适配 |
| P4 | 更小的 helper 与单一职责 service | 大多数已经足够窄、足够有用 | 低 | 除非高优先级改动证明它们需要调整，否则不要动 |

## 7. 风险与非目标

### 7.1 重构风险

- 即使目标文件在 `Sources/App/` 下，也常常紧邻安全相关代码边界。
- tutorial 兼容性不是可选项；生产页面重构必须保留当前 configuration-driven adaptation 模式。
- 一旦新增文件，Xcode project 更新将不可避免，因此实现阶段必须谨慎批量化 project-file 变更。
- 当前测试对 services 与 tutorial state 覆盖较强，但对 encrypt/decrypt/sign/verify 的 UI 层行为一致性覆盖，弱于其 service 语义覆盖。

### 7.2 首波重构的明确非目标

- 不改变任何用户可见行为、文案、路由结构、tutorial 模块顺序或当前导入导出语义。
- 不改 Rust。
- 首波不改 `Sources/Security/` 下的行为。
- 不重写 [`TutorialSessionStore`](../Sources/App/Onboarding/TutorialSessionStore.swift) 的 tutorial 状态机。
- 不尝试统一 production 与 tutorial containers。
- 不在首波结构拆分中收窄 façade 外部 API。

## 8. 评估摘要

当前仓库并不是一个“所有东西都太大”的通用问题，而是一个更具体的结构模式：

- 一个明确的 god service：[`KeyManagementService`](../Sources/Services/KeyManagementService.swift)
- 一个二级 service，混合了 repository 与 import policy ownership：[`ContactService`](../Sources/Services/ContactService.swift)
- 多个已经长成 workflow coordinator 的生产页面：[`EncryptView`](../Sources/App/Encrypt/EncryptView.swift)、[`DecryptView`](../Sources/App/Decrypt/DecryptView.swift)、[`SettingsView`](../Sources/App/Settings/SettingsView.swift)、[`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift) 与 [`AddContactView`](../Sources/App/Contacts/AddContactView.swift)
- 一个承担了过多协调工作的 app root：[`CypherAirApp`](../Sources/App/CypherAirApp.swift)
- 一组当前非常有价值、首波应保留而非重写的 tutorial host seams

这意味着，后续重构应聚焦 ownership boundary 与 coordination flow，而不是为了缩短行数而缩短行数。
