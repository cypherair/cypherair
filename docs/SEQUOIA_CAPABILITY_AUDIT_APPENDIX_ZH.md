# Sequoia 能力审计附录

> 目的：记录位于 CypherAir 当前构建基线或产品边界之外、更广义的 Sequoia 2.2 能力面。
> 受众：人类开发者、审查者，以及 AI 编码工具。

这份附录本身不是缺陷清单。它的作用是把以下两类内容区分开来：

- Sequoia 支持、但 CypherAir 当前并未编译进来的能力
- Sequoia 文档中存在、但 CypherAir 有意不暴露的能力族

## 1. 本仓库未编译进来的、受 feature gate 控制的 Sequoia 能力面

CypherAir 构建 `sequoia-openpgp` 时使用：

- `default-features = false`
- `crypto-openssl`
- `compression-deflate`

以下 Sequoia 2.2 能力面在上游存在，但在当前仓库构建中不可用：

| Sequoia 能力面 | 上游证据 | 当前仓库状态 | 为什么不计为主缺口 |
|---|---|---|---|
| `compression-bzip2` | Sequoia feature 列表 | 当前构建中不可用 | 该特性未启用；CypherAir 文档已因依赖原因排除 bzip2。 |
| `compression` 默认组合（`deflate + bzip2`） | Sequoia feature 列表 | 当前构建中不可用 | 仓库明确关闭默认特性。 |
| `crypto-nettle` 后端 | Sequoia feature 列表 | 当前构建中不可用 | 产品统一使用 OpenSSL 后端。 |
| `crypto-rust` 后端 | Sequoia feature 列表 | 当前构建中不可用 | 产品统一使用 OpenSSL 后端。 |
| `crypto-botan` / `crypto-botan2` 后端 | Sequoia feature 列表 | 当前构建中不可用 | 不符合当前依赖策略。 |
| `crypto-cng` 后端 | Sequoia feature 列表 | 当前构建中不可用 | Windows 专用后端，不在当前 Apple 平台范围内。 |
| `allow-experimental-crypto` | Sequoia feature 列表 | 当前构建中不可用 | 安全模型不启用实验性密码学。 |
| `allow-variable-time-crypto` | Sequoia feature 列表 | 当前构建中不可用 | 安全模型不启用 variable-time 密码学。 |

## 2. 超出 CypherAir 当前产品边界的、更广的官方 Sequoia 能力面

Sequoia 的源码与示例暴露了一些能力族，但 CypherAir 当前并未将它们作为产品功能对外提供：

| Sequoia 能力面 | 上游证据 | 当前仓库状态 | 审计解释 |
|---|---|---|---|
| Web-of-trust 示例流程 | Sequoia 示例（`web-of-trust`） | 未封装 | 超出当前 CypherAir 的产品模型。 |
| 统计 / 支持算法示例 | Sequoia 示例（`statistics`、`supported-algorithms`） | 未封装 | 这是诊断工具，不属于当前产品缺口。 |
| 公证（notarization）示例流程 | Sequoia 示例（`notarize`） | 未封装 | 超出当前 CypherAir 范围。 |
| Padding / wrap-literal 辅助示例 | Sequoia 示例（`pad`、`wrap-literal`） | 未封装 | 不属于 CypherAir 当前消息 UX。 |
| 组密钥（group-key）示例流程 | Sequoia 示例（`generate-group-key`） | 未封装 | 超出当前密钥管理模型。 |

## 3. 与主审计的关系

主报告应当被理解为：

- **主缺口列表**：今天已经编译进来、但在 CypherAir 中缺失或未接通的项目
- **附录**：上游存在、但除非构建策略或产品边界发生变化，否则不构成可执行缺口的项目

在实践中：

- `password/SKESK`、`merge_public`、`revoke`、`certify` 与绑定验证，仍然属于**可执行的缺失项**，因为它们在当前构建中可用。
- 替代压缩后端与密码后端则暂时属于**不可执行项**，因为仓库并未将它们编译进来。
