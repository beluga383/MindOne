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

- 当前工作分支为 `codex/complete-cli-mvp-v1`；源码已推进到连续 39 个 migration（`0001..0039`）。0038 固化 fast/standard/slow 任务档位，0039 增加 inference-only API Key 与只追加事件。
- fresh-v37 `43/43` 与 workspace `556/0/5` 是 0038/0039、模型目录和公网网关之前的历史证据。当前树已通过 workspace `590/0/5`，并在一次性 PostgreSQL 17 上让 16 个 binary 各用独立数据库完成 fresh-v39 `49/49`、无 skip；公网 E2E 仍未回填。
- 当前 debug 工作树的隔离 CPU-only E2E 已使用 fresh PostgreSQL v37、两个账号/device、真实 llama.cpp `b10064` 与 `Qwen3-0.6B-Q4_0.gguf` 从头退出 0；当前平台安装发行 smoke 也已通过。上述结果仍不等于正式发布门禁，多平台构建、外部 Actions、签名、SMTP、真实 TEE、private 双 GGUF 和 production 均另列待验证。
- 本机 live production 是受保护的 v26 实例，不是 v39 验收环境；在完成维护窗口、无活动租约检查、旧节点 device rebind、独立 HMAC key/完整预算和回滚方案前不得升级或扰动。
- private `global_reserve_entries` 的跨 catalog 核心算法已实现：availability 前持有全局 advisory transaction lock，并按受控 catalog 目录全部 entry 的 legacy/v2 唯一冲突键并集计算 remaining。不同 catalog 真重叠、两个独立 `PgPool` 的回归已进入 fresh-v37 `43/43` 强制 PostgreSQL gate。
- GitHub 仓库、`main`、raw 安装器和旧 `v1.0.0` 标签已公开；旧标签不会强制移动。最新 Security workflow 已全绿，CI 已证明五个原生构建目标、核心质量、PostgreSQL、Unix/Windows 安装、macOS Seatbelt、Linux 四层沙盒和当前四槽真实小模型业务链可以运行；最近一次 E2E 只在最终审计暴露了脚本固定查找默认端口日志名，现已改为使用 `serve --json` 的权威 `log_path`。当前树为 `v1.0.1`，仍须取得该修复精确提交的完整外部全绿后再发行。Cloudflare 公网路由、正式签名和 production v26→v39 切换均没有完成证据。
- 本机为 Apple Silicon macOS，只能报告真实的 `Standard-Limited`，不能伪造 Enhanced TEE。
- GitHub OAuth App、Cloudflare 路由保存、账号验证码和系统权限属于需要用户确认的外部步骤。
- `C_base` 已选择稳定合同 `server_reference_upper_bound_v1`：协调器按授权输入/输出上界和 operator 发布的不可变参考 profile，对 token、参考 GPU 时间、参考显存积分三个分项分别向上取整后求和。仓库不内置生产费率；具体 profile 数值仍必须由产品/运维通过审计 provisioning 决定，节点自报实际用量不进入金额。

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
4. 生产账户初始余额为零；不做自动注册赠额或 HTTP admin 路由。运营启动供给只允许服务器侧 `mindone-coordinator quota-grant`，通过 migration `0020` 在同一事务写入账户、`operator_grant` quota 账项和只追加审计；它是任务结算公式之外的显式外生供给。
5. 跨主机通信必须 HTTPS；权限受限的 `127.0.0.1` 开发源站允许 HTTP，Cloudflare 公网层终止 TLS。
6. CLI 不持有数据库凭据，只通过协调服务器 API 操作账户。
7. `share publish` 启动持久 worker，承担心跳、领取、续租、二次策略检查、推理与幂等回传。
8. 不支持流式推理时，对 `stream: true` 返回明确的 OpenAI 风格错误，不伪造 SSE。
9. migration `0030` 要求节点、普通 attempt 和隐藏 challenge 绑定到领取账号的精确 device key；旧节点迁移后保持 offline，直到显式重新注册绑定。节点 owner/既有设备和 claim identity 均不可变。
10. 新 private hidden challenge 只使用 migration `0031` 的 commitment v2：独立外部 HMAC key 经 PostgreSQL key-state 启动门禁后签发 opaque capability；数据库只保存域分离 keyed commitments，原始 catalog/evaluator 标识符及裸 Prompt/expected SHA-256 为 `NULL`。迁移前 legacy v1 行不回填、不伪装成 v2，只保留终态兼容。
11. private issuance 只有在 HMAC key 与六项预算配置完整时启用；先在 availability 前取得全局 advisory xact lock，对目录全部 entry 的 legacy/v2 entry、Prompt、expected 唯一键冲突做去重并集，再按 `catalog → account → device → node` 固定顺序锁四级 scope 并检查小时上限、cooldown 与 reserve。跨 catalog 真重叠双 `PgPool` 回归源码已存在，发布证据以 fresh-v37 实际运行结果为准。

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
- 实现仅服务器侧可执行、严格限额且幂等可审计的生产初始额度赠额命令，不向客户端或 HTTP 暴露管理能力。
- 实现 node/device binding、private HMAC v2 commitment、prepared terminal capability、四级 PostgreSQL 预算及 legacy v1 收口边界。
- 增加限流、超时、请求大小限制、结构化脱敏日志。

验收：迁移可重复运行；认证、心跳、发布、双重领取保护、结算、失败不扣、准备金及撤销集成测试通过。

当前证据：fresh v39 的 16 个 coordinator integration binary 已在一次性 PostgreSQL 17 上各用独立数据库通过，合计 `49/49`、无 skip，持久库 metadata `39|1|39|t`；速度档调度、API Key/OpenAI JSON 与真实密文 SSE 网关事务 E2E 包含其中。production 仍为 v26。

### 阶段 D：CLI 与本地执行面

- 完成简体中文 clap 命令树和统一 JSON 输出。
- 实现系统凭证、OAuth Device Flow、设备密钥生命周期。
- 邮箱/password 只为既有 Ed25519 Device Flow 提供同源浏览器授权：用户手工输入终端 12 位 `user_code`，浏览器不收 bearer，最终 poll 必须设备签名；password reset 尚未实现。
- 实现模型下载/登记/验证、llama.cpp 安装与受管服务。
- CPU-only 作为 `ServeRequest` 的类型化受管策略传入引擎层，由引擎固定设备、GPU layer 与 KV/op offload 参数并清除对应环境覆盖；不通过未受信 `additional_args` 绕行。
- 实现共享 worker、节点策略与阈值、OpenAI 兼容本地代理、doctor。
- worker 对 reasoning-only 且无可见 `content` 的结果立即失败，对协调器确定性 HTTP 400 提交一次脱敏 failure；运行期策略文件删除、损坏、非普通文件或符号链接均失败关闭。
- 完成新版 TUI 的 10 类/40 公开叶子映射，使用 Space/Action/Overview/Activity/Command 响应式工作台；新增 65 模型选择器、推荐置顶与关键词过滤，以及 `M/R/D/?` 主路径快捷键。仍复用同一 Clap 与业务处理；安全分词不经过 shell，高风险动作二次确认，执行时 suspend/raw-screen 后恢复，并保留非零退出码。

验收：全部命令解析测试通过；真实 PID/端口/health 验证；本地服务只监听 loopback。

### 阶段 E：部署、发布与文档

- Dockerfile、Compose、Cloudflare 示例配置。
- macOS/Linux/Windows 安装、升级检查与卸载脚本。
- CI、Release、安全工作流。
- API、安装、运维、安全与多人协作文档。

验收：干净临时目录安装/卸载成功；工作流配置可解析；不包含 Secret 或本地数据。

### 阶段 F：真实端到端与公网

- 用隔离 `MINDONE_HOME` 模拟消费者与贡献节点/模型实例。当前 debug 工作树的 `scripts/e2e-test.sh` 已以 fresh PostgreSQL v37、真实 llama.cpp b10064 与 Qwen3-0.6B-Q4_0 GGUF 完成双账号/device、确定性 public canary 终态、消费/节点贡献/网络准备金三轨账本核对并退出 0。
- 当前真实模型代理验收已记录 `GET /v1/models`、`POST /v1/chat/completions` 与兼容 `POST /v1/completions`，覆盖非流式、双端点 SSE、游标故障恢复、AEAD 密文、独立唯一结算、策略二检零结算、Regulated 流式拒绝、日志扫描和资源清理；多模型/private 双 GGUF 路由仍待扩展。
- 使用独立 key、完整预算与真实签名 catalog 验证 private v2 的普通 wire、零财务、raw identifier/bare SHA 为 `NULL`、终态 capability 和跨 catalog reserve；不得在 production v26 上试验。**仍待外部验证。**
- 经用户确认后配置 Cloudflare，只公开 8787 协调服务。**仍待外部验证。**

验收：Standard 单模型双端点真实推理、账本、两次策略检查、slot erase、日志扫描与本轮资源清理已有当前 debug 命令输出。它不代表 GitHub Actions、签名发布、外部 SMTP、真实 TEE、private 双 GGUF、production HTTPS 或公网端口已验证。

### 阶段 G：发布协作

- 清除所有功能性 TODO、FIXME、`unimplemented!`、生产 `panic!`、固定成功结果与 Secret。
- 按实际命令输出更新 `docs/CLI_COMPLIANCE.md`；未取得证据的项目继续标记待验证，不能批量改成完成。
- 分模块提交，推送分支，创建不自动合并的 PR，等待 CI。

## 6. 测试策略

- 单元：命令解析、配置/凭证抽象、格式验证、定点经济、哈希链、Tier、路由、策略、阈值。
- 集成：真实 PostgreSQL migrations 与 API，事务、固定锁序、幂等、令牌撤销、device binding、private key-state/capability、四级预算和跨 catalog reserve。
- 进程：真实端口、PID 身份、健康检查、停止顺序、日志轮转。
- E2E：真实 GGUF，不允许 mock 推理结果；chat 与 legacy completions 分项记录。当前 debug 隔离执行已覆盖两类非流式与 SSE，后续修改相关路径时必须重跑。
- 公网：Cloudflare HTTPS、未认证拒绝、正确 Token、数据库和 llama-server 不暴露。
- 发布：压缩包 checksum、安装、版本、帮助、doctor、卸载残留。

## 7. 当前剩余门禁顺序

1. 当前工作树已通过 fmt、全 workspace all-target/all-feature check/strict Clippy 与全 workspace tests；31 个 result set 为 `590 passed / 0 failed / 5 ignored`。fresh-v39 16 个 binary 为 `49/49`、无 skip。
2. 当前 debug 隔离真实 GGUF E2E、日志泄露扫描、结算与清理闭环已通过，覆盖 chat、`/v1/completions` 与两端点 Standard SSE；后续修改引擎、worker、代理、SSE 或结算路径时重跑。
3. 当前 `mindone 1.0.1` / `aarch64-apple-darwin` 二进制的归档 SHA-256、安装、`--check`、重装、中文帮助/版本、doctor、默认保留与 purge 卸载已通过；发行相关源码再改动时必须重跑。
4. 完成 ModelScope 真实公网 artifact smoke、外部 SMTP/浏览器/CLI 签名 poll 和 private 双 GGUF harness，或继续明确标为未验证。
5. 用户授权后再执行 GitHub/Actions、Cloudflare、公网端口审计和 production v26→v39 受控升级；正式 SNP/TDX、GPU 与签名仍各自需要真实外部证据。

## 8. 提交策略

采用 Conventional Commits，每个独立模块单独提交，例如：

- `docs: establish implementation and compliance baseline`
- `feat(core): add protocol accounting and safety primitives`
- `feat(server): add transactional coordinator APIs`
- `feat(cli): implement local execution and sharing workflows`
- `test(e2e): verify real llama.cpp settlement flow`

不直接向 `main` 推送，不 force push，不提交模型、数据库、Token、私钥或本地配置。
