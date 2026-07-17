# MindOne v1.0.0 实施计划

## 1. 目标与完成定义

本计划以 `docs/specs/mindone_1.0.0.md`、`docs/specs/mindone_cli_1.0.0.md`
以及用户提供的“完整可用 MVP 总任务”为共同合同。MindOne v1.0.0 必须形成真实闭环：

1. 消费者通过本地 OpenAI 兼容代理提交请求。
2. 协调服务器鉴权、检查额度并执行两阶段调度。
3. 贡献节点通过出站连接领取带租约的任务。
4. 节点使用已验证的 GGUF 与受管 `llama.cpp` 进行真实推理。
5. 节点幂等提交结果；协调服务器在同一 PostgreSQL 事务中完成任务与三类账本结算。
6. 消费者收到真实模型响应，并能查询余额、历史及荣誉账单。

只有代码质量门、数据库集成测试、真实 GGUF E2E、公网验证、安装验证和发布流程全部有真实证据后，才宣告完成。

## 2. 已确认现实边界

- 初始仓库为空，`main` 没有提交；已在本地创建 `codex/complete-cli-mvp-v1`。
- `origin` 指向任务指定仓库，但当前终端缺少 GitHub 凭据，尚不能抓取、推送或创建 PR。
- 本机为 Apple Silicon macOS，只能报告真实的 `Standard-Limited`，不能伪造 Enhanced TEE。
- 初始环境缺少 Rust、PostgreSQL、Docker Compose、llama.cpp 与 GitHub CLI；依赖会按验证阶段逐项安装。
- GitHub OAuth App、Cloudflare 路由保存、账号验证码和系统权限属于需要用户确认的外部步骤。

这些边界不会被伪造为成功，也不会被用来省略应由代码完成的核心功能。

## 3. 架构与模块

| 模块 | 职责 | 主要验证 |
|---|---|---|
| `mindone-common` | 路径、原子配置、错误码、凭证抽象、HTTP 安全、进程状态、脱敏 | 单元测试 |
| `mindone-protocol` | API DTO、任务状态机、分页、OpenAI 协议、错误 envelope | 序列化与状态机测试 |
| `mindone-accounting` | microquota、结算、哈希链、Tier、两阶段评分、准备金规则 | 金值与性质测试 |
| `mindone-engine` | 模型登记/验证/下载、硬件检测、引擎适配器、llama.cpp 生命周期 | 格式与进程集成测试 |
| `mindone-sandbox` | 跨平台能力探测、真实启动包装、信任映射 | 平台探测测试 |
| `mindone-coordinator` | Axum API、认证、节点、模型、任务租约、调度、事务结算 | PostgreSQL 与 API 集成测试 |
| `mindone-cli` | 中文命令树、输出、OAuth、服务、共享 worker、本地代理、诊断 | 命令解析与 E2E |

## 4. 关键工程决策

1. 模型格式采用 `docs/adr/0001-model-formats.md`：GGUF 与 safetensors 可登记，危险反序列化格式拒绝。
2. 金额使用有符号 64 位整数 microquota；乘法使用更宽中间值、checked arithmetic 与明确舍入。
3. 账本只追加，每条账项包含前后余额、请求 ID、前哈希和自身哈希。
4. 生产账户初始余额为零；测试或运营赠额必须走受控、可审计的独立账本入口。
5. 跨主机通信必须 HTTPS；权限受限的 `127.0.0.1` 开发源站允许 HTTP，Cloudflare 公网层终止 TLS。
6. CLI 不持有数据库凭据，只通过协调服务器 API 操作账户。
7. `share publish` 启动持久 worker，承担心跳、领取、续租、二次策略检查、推理与幂等回传。
8. 不支持流式推理时，对 `stream: true` 返回明确的 OpenAI 风格错误，不伪造 SSE。

## 5. 分阶段交付

### 阶段 A：仓库与合同基线

- 归档两份规范。
- 建立实施计划、CLI 合规矩阵与 ADR。
- 创建分支并提交文档基线。

验收：规范文件哈希与用户提供文件一致；合规矩阵覆盖全部命令、参数、行为、退出码和两个业务场景。

### 阶段 B：公共核心

- 建立 Cargo workspace 与七个 crate。
- 实现公共错误、配置、路径、协议、定点经济、哈希链、Tier 与路由。
- 实现真实模型格式验证和跨平台沙盒能力报告。

验收：`cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`、核心单元测试通过。

### 阶段 C：协调服务器与数据库

- 编写幂等 PostgreSQL migrations 与约束/索引。
- 实现全部指定 API、短期访问令牌、刷新与撤销。
- 实现节点/模型状态、带租约任务、调度、失败重试和同事务结算。
- 增加限流、超时、请求大小限制、结构化脱敏日志。

验收：迁移可重复运行；认证、心跳、发布、双重领取保护、结算、失败不扣、准备金及撤销集成测试通过。

### 阶段 D：CLI 与本地执行面

- 完成简体中文 clap 命令树和统一 JSON 输出。
- 实现系统凭证、OAuth Device Flow、设备密钥生命周期。
- 实现模型下载/登记/验证、llama.cpp 安装与受管服务。
- 实现共享 worker、节点策略与阈值、OpenAI 兼容本地代理、doctor。

验收：全部命令解析测试通过；真实 PID/端口/health 验证；本地服务只监听 loopback。

### 阶段 E：部署、发布与文档

- Dockerfile、Compose、Cloudflare 示例配置。
- macOS/Linux/Windows 安装、升级检查与卸载脚本。
- CI、Release、安全工作流。
- API、安装、运维、安全与多人协作文档。

验收：干净临时目录安装/卸载成功；工作流配置可解析；不包含 Secret 或本地数据。

### 阶段 F：真实端到端与公网

- 用两个隔离 `MINDONE_HOME` 模拟消费者 A 和节点 B。
- 运行 PostgreSQL、协调服务器、真实 llama.cpp 和许可证允许的小型 GGUF。
- 完成总任务指定 20 步并核对消费者、节点、贡献值和准备金账本。
- 经用户确认后配置 Cloudflare，只公开 8787 协调服务。

验收：真实推理响应、账本、HTTPS、鉴权、端口不可见和安装测试均有命令输出证据。

### 阶段 G：发布协作

- 清除所有功能性 TODO、FIXME、`unimplemented!`、生产 `panic!`、固定成功结果与 Secret。
- 更新 `docs/CLI_COMPLIANCE.md` 为全部完成。
- 分模块提交，推送分支，创建不自动合并的 PR，等待 CI。

## 6. 测试策略

- 单元：命令解析、配置/凭证抽象、格式验证、定点经济、哈希链、Tier、路由、策略、阈值。
- 集成：真实 PostgreSQL migrations 与 API，事务、锁、幂等、令牌撤销。
- 进程：真实端口、PID 身份、健康检查、停止顺序、日志轮转。
- E2E：真实 GGUF，不允许 mock 推理结果。
- 公网：Cloudflare HTTPS、未认证拒绝、正确 Token、数据库和 llama-server 不暴露。
- 发布：压缩包 checksum、安装、版本、帮助、doctor、卸载残留。

## 7. 提交策略

采用 Conventional Commits，每个独立模块单独提交，例如：

- `docs: establish implementation and compliance baseline`
- `feat(core): add protocol accounting and safety primitives`
- `feat(server): add transactional coordinator APIs`
- `feat(cli): implement local execution and sharing workflows`
- `test(e2e): verify real llama.cpp settlement flow`

不直接向 `main` 推送，不 force push，不提交模型、数据库、Token、私钥或本地配置。

