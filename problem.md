# MindOne 当前问题与 MVP 收口方向

更新时间：2026-07-22（Asia/Shanghai）

## 1. 当前结论

MindOne 的主要源码、CLI/TUI、schema v39 和本地自动化门禁已收口，但尚不能宣称 v1.0.0 正式发布或 production 已升级。

当前可复用的本地证据：

- schema 连续为 `0001..0039`；
- 隔离 PostgreSQL 17 上的 16 个 coordinator integration binary 合计 `49/49`、无 skip，migration metadata 为 `39|1|39|t`；
- fmt、workspace all-target/all-feature check 和 strict Clippy 通过；
- workspace tests 为 31 个 result set，`587 passed / 0 failed / 5 ignored`，退出 0；
- TUI 覆盖 10 类、40 个公开 CLI 叶子命令，复用同一 Clap 解析与 `app::execute`，不经 shell；
- Shell 语法、MVP smoke 安全合同、邮箱认证静态合同、Compose test config 与 actionlint 通过；
- RustSec audit 为 0 vulnerability / 0 warning，`cargo deny` 通过，Gitleaks 对精确 non-ignored 集合扫描通过。
- 当前 `mindone 1.0.0` / `aarch64-apple-darwin` 二进制 release/install/uninstall smoke 通过，包括归档 SHA-256、`--check`、重装、doctor JSON、默认保留数据和 purge。
- 最近一次 debug 隔离 CPU-only E2E 以 fresh PostgreSQL v37、两个账号/device、真实 llama.cpp b10064 和 Qwen3-0.6B-Q4_0 GGUF 从头退出 0；它早于本轮四槽/统一 KV 参数变更。

这些证据证明当前本机的自动化合同与单 Standard GGUF 真实模型链，不证明外部邮件交付、公网、多平台 Actions、签名发布、真实 TEE、private 双 GGUF 或 production 已验收。完整数字和命令见 `README.md`、`docs/HANDOFF.md` 和 `docs/CLI_COMPLIANCE.md`。

## 2. 已解决的历史阻塞

- 受管多 slot 合同已统一：slot 0 只供本机代理，slot 1..3 只供贡献任务，`max_concurrent=1..3` 对应真实独立槽；双槽并发、逐槽 erase 与并发会话轮换已有确定性测试。
- 当前 workspace 已全绿；5 个 ignored 是明确的外部或平台能力门禁，未冒充通过。
- 数据库门禁不再使用未设 `DATABASE_URL` 的提前返回作为证据；v37 已在 fresh 隔离库真实通过 `43/43`。
- 邮箱身份已绑定既有 Ed25519 Device Flow；浏览器不接收 bearer，验证链接 GET 只显示确认页，POST 才消费 token。
- 开发 smoke 的 Secret、临时文件和 CLI Home 已隔离，不读真实用户会话，不改写默认配置。
- TUI 已与公开 CLI 命令矩阵对齐，并保留 JSON/quiet/verbose、确认、退出码和终端恢复语义。
- CPU-only 不再通过未受信附加参数传递，而是由 `ServeRequest` 类型化表达并由引擎注入受管 device/offload 参数。
- worker 对 reasoning-only 无可见内容、result 确定性 HTTP 400 和运行期策略文件删除/损坏/符号链接分别执行立即失败、脱敏 terminal failure 和策略失败关闭。

## 3. P0 收口状态

### 3.1 历史真实 Standard GGUF/SSE E2E（四槽改动后待重跑）

最近一次完整 debug 模型链已在独立 loopback 端口和临时 Home 中从头完成；它早于本轮四槽与统一 KV 参数变更，因此发布前仍须用同一个小模型重跑：

- fresh PostgreSQL v37、两个账号/device、官方 llama.cpp b10064 和 Qwen3-0.6B-Q4_0 GGUF；
- 确定性 public canary worker 终态，以及 chat 与 `/v1/completions` 非流式真实模型结果；
- 两端点 SSE 的连续 event ID、唯一 `[DONE]`、故障注入后的非零游标恢复、Standard 密文与唯一结算；
- 领取前和执行前两次策略检查，领取后策略改变时在 llama HTTP 前拒绝且零结算；
- 消费额度、节点贡献和网络准备金三轨账本唯一结算，Regulated `stream:true` 明确拒绝；
- 每请求终态 slot erase、Prompt/Response 日志扫描，以及 stop/unpublish/logout 和本轮临时资源清理。

这是本机 debug、单 Standard GGUF 的隔离证据；游标恢复保持同一 downstream 连接，不代表客户端重新 POST resume token。它不覆盖 private 双 GGUF、真实 TEE、外部 SMTP/浏览器、GitHub Actions、签名发布或 production。未经用户授权仍不得删除 Docker image、volume 或历史证据库。

### 3.2 Git 交付集合

基线提交很小，当前约 226 个 non-ignored 文件仍未跟踪，且本轮没有获得 stage/commit/push 授权。交付前必须：

1. 重新计数并逐路径审阅，不依赖本文的数字；
2. 排除 `target/`、模型、Secret、数据库、日志、备份和本地配置；
3. 不使用 `git add .`，只按已审阅路径精确 stage；
4. 对 staged diff 重跑格式、Secret 扫描与文件清单复核。

## 4. P1 与外部验收

- 邮箱认证还需隔离 SMTP/Mailhog + 浏览器 + CLI 签名 poll 的跨进程 E2E。
- 注册流程还没有事务型 outbox；SMTP 接收后数据库 commit 失败可产生失效邮件。
- password reset 未实现，不存在 reset 路由或表；只能使用部署方受审人工恢复。
- ModelScope 官方 repo-files discovery 与本地 mock 已实现，真实公网 artifact smoke 未完成。
- private hidden v2 已有 HMAC、预算、capability 和仲裁自动化证据，但双真实 GGUF 验收未完成。
- Regulated/TEE 仍需真实硬件、固件 collateral、verifier、adapter、allowlist 和消费者复验；缺少时必须失败关闭。
- Linux/macOS/Windows Actions、平台签名、notarization、Cloudflare 公网验收和真实 SMTP 均需外部证据。
- production 仍为 migration 26；未授权 v26 -> v39 升级。

## 5. Standard MVP 完成定义

只有以下条件全部满足，才可以将当前交付物称为 Standard MVP：

1. 当前树 fmt、workspace check、strict Clippy、workspace tests 和必需的 fresh PostgreSQL 门禁全绿，ignored/skip 单列。
2. 真实 GGUF 完成 chat、completions、SSE、策略二检、slot erase 和唯一结算；历史 debug 单 GGUF 证据已取得，本轮四槽/统一 KV 改动后必须复用小模型重跑。
3. 当前平台 release/install/doctor/uninstall 闭环通过。
4. README、API、CLI、安全、运维、安装与实施计划与最终行为一致。
5. Git 交付集合可审查，不含 Token、密码、Secret、私钥、数据库、模型、日志、备份或本地配置。
6. 未完成的 private、Regulated、TEE、多平台签名和 production 能力明确标记并保持失败关闭。

## 6. 不得牺牲的边界

- 不放宽 slot 隔离与真实容量、TLS、模型格式、数据库权限或设备签名边界。
- 不使用固定推理响应、假余额、假 receipt、假证明或状态文件冒充真实运行。
- 不在日志或数据库保存 Prompt、Response、Token、nonce 或 Secret 明文。
- CLI 不直连数据库；金额继续使用整数 microquota，结算、准备金和账本操作必须事务、幂等且可审计。
- 不删除、truncate 或复用历史证据数据库。
- 不将 ignored、skip、mock、静态检查或历史结果写成当前真实 E2E 通过。
- 没有维护窗口、可恢复备份、隔离演练和 owner 授权时，不升级 production。
