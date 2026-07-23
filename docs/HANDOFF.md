# MindOne v1.0.1 续接任务与行为合同

> 2026-07-23 当前增量：工作树源码目标仍是连续 `0001..0039`，65 项 HF 目录、硬件推荐、用户端一键 GGUF 部署、40 个 CLI/TUI 对等动作、三档速度路由、推理 API Key 与 OpenAI JSON/SSE 网关均已完成本地门禁。TUI 已重做为响应式 Space/Action/Overview/Activity/Command 工作台。本补丁序列修复了原生 Linux Secret UID、PowerShell information stream 捕获、headless Linux keyutils，并让 `share publish --port` 与隔离 E2E 的非默认端口真正一致；精确候选提交仍必须由 CI 与 Security 同时全绿后才能打 `v1.0.1` 标签。当前 v26 production 已完成 custom dump、TOC 校验、独立恢复与真实 `26→39` 演练；live coordinator 仍健康运行 v26，尚未停机或迁移。公开仓库、`main`、raw 安装器和旧 `v1.0.0` 标签均已上线，旧标签不会强制移动，尚无新 Release 资产。Cloudflare 已登录并停在新建独立 `mindone` Tunnel 的最终保存按钮前，尚未创建凭据或 DNS route。不得把测试提交、标签、失败流水线、恢复副本、已构建镜像或本地 release 写成 production/公网已发布。

更新时间：2026-07-23（Asia/Shanghai）

本文是当前工作树的交接入口。下一位接手者先读 `AGENTS.md`，再按本文顺序执行。不要从旧聊天里的 v29/v31/v35 停止点继续，也不要把脚本存在、复用数据库的 migration metadata 或历史测试结果写成当前最终树已经通过。

> 当前结论：源码现为连续 schema `0001..0039`。当前 workspace `589/0/5`、fresh-v39 `49/49`、API Key 网关 JSON/SSE 数据库 E2E，以及 production 备份恢复副本的真实 `26→39` 演练均已通过；live 仍是 v26。公开 Actions 已真实证明 macOS arm64/x86_64、Linux x86_64/arm64、Windows x86_64 原生编译、macOS Seatbelt 与 Linux 四层沙盒路径；是否满足本次发行门禁必须查看精确候选提交的 CI 与 Security 终态。公网 TLS 链还依赖尚未创建的独立 Tunnel，MindOne 尚未正式发布。

当前 macOS arm64 又完成一轮仓库外源码安装闭环：`cargo install --locked --path crates/mindone-cli --root <隔离目录>` 成功；只保留隔离 `bin` 与系统目录的最小 PATH 下，`mindone --version`、非交互裸 `mindone` 均退出 0；真实 80×24 PTY 中裸 `mindone` 进入新版工作台，按 `q` 后终端恢复且退出 0。为修复该 smoke 暴露的自动化误报，非 TTY 裸调用现在直接渲染中文根帮助并成功退出，另有二进制合同测试锁定。该证据不代表 GitHub Release 已产出，也不替代 Windows/Linux 原生安装器运行。

ARM64 Linux 现有两轮互补证据。既有无网络、只读源码验证覆盖固定 `rust:1.88.0-bookworm` 镜像内 CLI `176/0/2`、strict Clippy、release build 与 SHA-256 安装/重装/默认卸载/purge。当前修正版又在同架构、Rust 1.88、无网络和源码只读条件下通过全 workspace check；CLI library `173/0/1`、入口 `4/0/0`、Linux 适用二进制合同 `7/0/0` 全部通过，release `--version`、非交互裸命令与真实 80×24 PTY TUI 均退出 0。该轮发现共享测试上下文错误使用真实 Secret Service，在无桌面 DBus 的 Linux 上会让并发刷新用例失败；现已增加仅 `cfg(test)` 可见的内存凭证库构造器，production 仍强制系统凭证库。当前容器未预装 Clippy，因此本轮没有把“组件缺失”冒充当前 Linux strict Clippy；该门禁仍由既有 Linux 证据和当前 macOS 全 workspace strict Clippy 覆盖。

此前还用 Debian x86_64 交叉工具链构建 release，并在真实 amd64 Debian 用户态执行版本、中文帮助、硬件推荐、`api info`，再完成相同 SHA-256 安装/`--launch`/重装/卸载/purge 闭环。安装器新增 Unix `--launch` / Windows `-Launch`，可在发布后用单条命令安装并直接进入 TUI，CI/管道会安全降级为帮助页。公开仓库和两份 raw 安装器现已匿名返回 200；latest Release 仍不存在，因此远程安装不能成功下载二进制。`api.holarchic.cn` 的 Tunnel/DNS route 尚未提交，所以公网 API 也未上线；Windows 真机、Linux 真实沙盒/模型下载和平台签名仍待外部 runner。

Windows 侧已有两层证据。脚本曾用微软官方 PowerShell 7.5 解析器真实解析 `install.ps1` 与 `uninstall.ps1`，GitHub Actions 文件继续通过 `actionlint`。当前又用官方哈希校验的 `cargo-xwin 0.23.0`、Microsoft SDK/CRT 和 `llvm-mingw 20260616` 在 macOS arm64 完成 `x86_64-pc-windows-msvc` 全 workspace/all-target/all-feature check、`-D warnings` 严格 Clippy 与 release 构建；交叉门禁实际发现并修复 `windows_job.rs` 临时借用错误以及 Windows-only lint。最终 17 MiB 产物为 `PE32+ console x86-64`，静态 CRT 后不再导入 `VCRUNTIME140.dll`/`api-ms-win-crt-*`，且 Job Object 三个关键 API 均存在。`.cargo/config.toml` 固定 Windows 静态 CRT，CI/Release 通过 `scripts/verify-windows-self-contained.ps1` 在原生 runner 用 `dumpbin` 复验。交叉编译仍不能证明 EXE 启动、Windows Credential Manager、TUI、Job Object 生命周期或 PowerShell 安装器原子替换；这些仍只能由 `windows-latest` 或真实 Windows 主机证明。

公网实测显示 `https://holarchic.cn` 的 Cloudflare/TLS 正常，但 `/health`、`/ready`、`/auth/login` 和 `/v1/models` 均由现有官网返回普通 404，不是 MindOne；把根域整站 `/*` 切到协调器会破坏官网。当前合同因此改用专用子域 `https://api.holarchic.cn`，Base URL 为 `https://api.holarchic.cn/v1`，并只在该子域把 `/*` 转给 `http://coordinator:8787`。子域当前尚无可用 TLS/route，必须由部署方配置后再做 identity/CF-Ray E2E；旧客户端配置不会自动覆盖，需显式 `mindone config set server.url https://api.holarchic.cn`。

## 1. 工作树和受保护现场

- 仓库：`/Users/beluga/Documents/MindOne`
- 分支：`codex/complete-cli-mvp-v1`
- 远端发布基线：`d2598ba`；本地分支含本轮 Actions 失败修复和证据文档增量，提交前必须重新核对实际 HEAD。
- MVP 主体已经提交；继续操作前仍须重新运行 `git status --short` 并逐路径审阅本轮增量，不得覆盖用户文件或把 ignored 的 production Secret、备份、模型和构建缓存加入版本控制。
- 禁止 `git add .`、`git clean`、reset、批量覆盖或删除。最终只能逐路径审阅和 stage，三个顶层规格输入默认保留。
- production `mindone-coordinator-1` 当前健康，经 loopback `127.0.0.1:18787` 可达；production 数据库只读确认仍为 `26|1|26|t`。当前 v26 已备份并在独立 tmpfs PostgreSQL 上完成 v39 演练，但 live 停机、迁移与切换尚未执行。
- PostgreSQL 测试容器：`mindone-pg-final-20260718`，loopback 端口 `55435`。已有证据库不得 drop、truncate 或复用为 fresh gate。
- `*:8787` 由其他 Python 服务占用；LM Studio、它的 llama-server、现有 cloudflared、`aistudio` 和其他项目均不在本任务范围，禁止停止或修改。
- 本机内存压力高。Cargo、PostgreSQL gate、Docker 和真实模型 E2E 必须串行；所有 Cargo 命令固定 `CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1` 并加 `-j1`。

开始工作前重新采集状态，不要假设上述 PID、端口以外的瞬时状态仍相同：

```bash
cd /Users/beluga/Documents/MindOne
git status --short
git branch --show-current
git rev-parse HEAD
lsof -nP -iTCP:18787 -sTCP:LISTEN
lsof -nP -iTCP:8787 -sTCP:LISTEN
docker ps --format '{{.Names}}\t{{.Ports}}\t{{.Status}}'
```

## 2. 已落盘的行为

### 2.1 既有身份、私有评测和账本边界

- 0030 固化 node、attempt 和 challenge 的账号/设备身份；同账号另一设备不能接管既有资源。
- 领取前和真正执行推理前各检查一次节点策略；策略变化必须在 llama HTTP 前失败关闭。
- 0031 使用独立、domain-separated HMAC commitment；private v2 不持久化 raw catalog identifier、bare prompt SHA 或 bare expected SHA。
- private v2 的 result、fail、expiry、sweep 和 arbitration 需要数据库 runtime prepare 成功后签发的 opaque capability；缺 key/capability 时首个持久化 mutation 前拒绝。
- private 预算按 `catalog -> account -> device -> node` 固定锁序在 PostgreSQL 中执行；跨 catalog 真重叠、两个独立 `PgPool` 的 global reserve 回归已进入本轮 fresh-v37 `43/43` 强制 PostgreSQL gate，不能回退为进程内计数。
- private v2 Compose overlay 已接入独立只读 HMAC Secret 和六项显式预算；`scripts/validate-private-v2-compose.sh` 检查缺项、挂载和 secret 不进入普通环境。生产预算没有默认值，必须由 operator 明确填写。
- canonical ledger、receipt 和事件只追加、可重算、幂等；金额保持整数 microquota。Standard payload 仍只是 Base64/Base64URL JSON，不具保密性。

### 2.2 贡献路由 v1

- `contribution-routing-v1` 使用最近 30 天已结算贡献值的确定性 midrank percentile。
- 只有唯一节点 cohort 至少 5 个、数据库可见 ready demand 大于服务端计算的 free slots、候选基础路由分位于最佳值 2% 内时，贡献 percentile 才用于破近同分。
- free slots 使用服务端持久化 active jobs、prepared routes、hidden leases 和 node policy；节点自报并发量只参与保守负载过滤，不能扩张容量。
- Standard claim 与 Regulated prepare 都已接线；非拥堵、小 cohort、非近同分时保持原基础排序。
- 已知语义边界：Regulated prepare 当前尚未持久化的本次请求不计入 ready demand。若产品要求并发 prepare 流量触发贡献优先，应设计同事务、可审计的 demand/reservation 计数；不能简单在内存里 `+1`。

### 2.3 0032：物理参考上界计费合同

稳定合同标识为 `server_reference_upper_bound_v1`。节点上报的实际 token、GPU 时间、显存或 TPS **不进入金额**；它们只能用于风险和质量判断。

对协调器授权的输入上界 `I` 和最大输出上界 `O`：

```text
T = I + O
G = fixed_gpu_time_us + ceil(T * gpu_time_us_per_1k_tokens / 1000)
V = G * reference_vram_mib
token_cost = ceil(T * token_rate_micro_per_1k / 1000)
gpu_cost = ceil(G * gpu_rate_micro_per_second / 1_000_000)
vram_cost = ceil(V * vram_rate_micro_per_gib_second / 1_024_000_000)
C_base = token_cost + gpu_cost + vram_cost
```

三个分项分别向上取整后求和，全部使用 checked integer arithmetic。准备金额使用同一冻结 `C_base` 再覆盖最高 High tier；实际返回 token 较少不会改变冻结的参考上界基础成本。

0032 增加：

- 不可变 `billing_profiles`；profile 与 canonical model weights hash 绑定，并由数据库计算完整 fingerprint。
- jobs、regulated_routes、receipts 上的完整 26 字段冻结计费快照。
- 只允许 migration 0032 写入的 legacy allowlist；历史行被标记为 `legacy_token_v1`，不能伪造新的 legacy 行。
- profile、snapshot 和 receipt 的 shape、公式、不可变性约束。
- 0032 的 NULL transitional state 只为同一发布中的 writer cutover 存在，不能被当成有效计费合同。

### 2.4 0033：服务端审计 provisioning

- 用户 `mindone` CLI 和 HTTP API 不暴露 profile 写入口；仅协调服务器二进制提供 `billing-profile-record` 运维命令。
- evidence 必须是规范绝对路径、非 symlink 普通文件、非空且不超过 1 GiB；流式读取 SHA-256，并复核读取期间文件没有变化。数据库只保存内容哈希，不保存本地路径。
- profile、operator、reason、idempotency key 和 evidence hash 共同进入请求 fingerprint；时间最多微秒精度。
- `mindone_record_billing_profile_v1` 在一个数据库语句/事务中执行 advisory lock、模型权重绑定、profile fingerprint、profile insert 和只追加 audit insert。
- 相同幂等键与完全相同请求返回 replay；相同键不同请求、相同 model/version 不同键都确定性冲突。
- runtime role 不再能直接 INSERT `billing_profiles`；数据库函数是唯一写入口。
- 不得把这个实现描述成“签名 profile”。当前保证是 evidence 内容 SHA-256、数据库 fingerprint 和 operator audit，不包含 profile 数字签名。

### 2.5 路由、冻结和结算

- Development/Production 不自动生成 profile；Test 环境的测试 profile 也通过审计 provisioning 函数创建。
- Standard 创建 job、Regulated prepare route 时选择“当前最高版本且 active”的 profile；若该最高版本不覆盖请求，必须失败关闭，不能回退旧版本。
- Regulated route 的 expiry 被 profile validity 截断；consume 只复制 prepare 时冻结的全部 26 字段。profile 轮换后，旧 route 仍按原 profile 结算。
- 缺 profile、过期、weights mismatch、授权上界不足时，不创建 job/route、不增加 reserved quota。
- settlement 从 job 冻结快照重算并验证公式；实际 token 只能用于不超过授权上界的校验和风险信号，金额始终使用冻结 `billing_base_cost_micro`。
- receipt 复制完整 26 字段，顶层 `base_cost_micro` 必须等于嵌套 billing base；settlement hash 覆盖完整 canonical billing snapshot。
- `/v1/quota/receipts/{id}` 返回嵌套 billing；历史 legacy receipt 仍可读。用户 CLI 以“服务器参考上界计费”展示 profile、evidence、授权 token、参考 GPU/VRAM 三分项和有效期。

### 2.6 0034：物理计费 cutover

0034 已落盘，并已在 fresh-v34 组合门禁中完成真实 PostgreSQL 验证：

- migration 开头以 `SHARE ROW EXCLUSIVE` 锁住 jobs、regulated_routes、receipts，关闭 preflight 与 trigger 安装之间的 writer race。
- 存在 `queued/leased/retry` 且非 v1 的 job，或存在未过期、仍为 `prepared` 且非 v1 的 route 时，迁移以中文错误拒绝；operator 必须停 writer、排空或取消并按账本释放准备金、消费/作废/等待 route 过期。
- `succeeded/failed/cancelled` 历史 job、已不可消费 route 和 legacy receipt 保留且可读，不回填伪造快照。
- 三个 `BEFORE INSERT` trigger 强制新 job/route/receipt 具有完整 v1 snapshot；job/route 协议 token 授权必须和 billing 授权一致；receipt top base 必须等于 billing base。
- 新 trigger 函数对 PUBLIC 和 runtime role 都没有直接 EXECUTE 权限。

相关文件：

- `migrations/0032_physical_billing_contract.sql`
- `migrations/0033_billing_profile_provisioning.sql`
- `migrations/0034_require_current_physical_billing.sql`
- `crates/mindone-accounting/src/billing.rs`
- `crates/mindone-coordinator/src/operator_billing.rs`
- `crates/mindone-coordinator/src/routes/jobs.rs`
- `crates/mindone-coordinator/src/routes/regulated_jobs.rs`
- `crates/mindone-coordinator/src/settlement.rs`
- `crates/mindone-coordinator/src/routes/quota.rs`

### 2.7 0035 Standard SSE 与本地收口

- `0035_standard_job_sse_events.sql` 增加 Standard 专用只追加事件通道。data 事件使用 coordinator-held AEAD 静态保护，Regulated 明确拒绝且不回退；worker 通过容量 8 的有界通道转发真实 llama SSE，消费者可按游标恢复，本地代理输出事件 ID、keepalive 和唯一 `[DONE]`。相关 schema 已进入 fresh-v37 `43/43` 门禁；四槽改动前的 debug 隔离 E2E 已用真实 GGUF 跑通 chat 与 `/v1/completions` 两类 SSE、故障注入后的非零游标恢复、密文持久化和唯一结算。
- `share stats` 增加由服务端权威累计值计算的固定 24 格贡献进度，以及不包含 user/device/node/model 标识和精确低样本记录的匿名荣誉榜；cohort 小于 5 时整表抑制，人数向下量化到 5 的倍数，并列节点共享 midrank 档位。协议兼容、协调器纯逻辑、CLI、定向 PostgreSQL 和 fresh-v36 路径已有证据。
- operator billing/quality/SLA evidence 共用有界安全文件原语：规范绝对路径、父链与最终路径无 symlink、Unix `O_NOFOLLOW|O_NONBLOCK`、读取前后文件身份/长度/时间/权限复核，并覆盖同大小 rename-replace。
- 开发 Compose 已增加 one-shot `database-migrator`，PostgreSQL healthy 后 migration 成功才启动 coordinator；migration/latest、runtime schema、CI 和 role-init 的版本期望已整体推进到 39。role-init 会精确恢复受保护表的最小权限边界，并只允许审核过的审计函数由 runtime role 执行。
- Unix 安装器已拒绝带 userinfo、query、fragment、反斜杠、空 authority、伪 loopback 或越界端口的发行根 URL，并增加独立负例 smoke。
- ModelScope 使用官方 `/api/v1/models/{owner}/{repo}/repo/files` 清单解析标准 repo/branch/name 旅程：唯一安全 GGUF/safetensors 自动选择，多个候选要求 `--file`，可信哈希只接受 `Sha256`，缺失、畸形或与用户 SHA 冲突时失败关闭。官方 API 形状已有本地 mock 测试，真实公网 artifact smoke 尚未执行。
- `mindone engine install --name llama.cpp` 省略 `--version` 时固定 audited `b10064`；registry 和默认引擎使用精确版本选择，后来显式安装的更新版本不能遮蔽受管默认。此行为已进入当前 workspace 全量门禁。
- 本地受管进程固定为四个真实 slot，并显式启用统一 KV 缓存，避免单请求上下文被静态切成四份。slot 0 只供本机代理；贡献 worker 从 slot 1..3 独占分配、按任务精确 erase，CLI 和持久 policy 只接受 `max_concurrent=1..3`。服务端容量仍只能由真实租约/有效心跳收缩，不能用节点自报扩张。
- 独立 `mindone serve` 已增加 loopback 管理代理，将 llama.cpp 放在内部随机端口，并强制本机请求使用 slot 0；贡献 worker 只使用 slot 1..3。每个终态推理请求后执行精确 slot erase；请求/响应使用有界通道并尽力 zeroize，清理失败会在下一次推理前失败关闭。受管启动固定注入 `--parallel 4 --kv-unified --slot-save-path`，缺少任一能力均失败关闭。定向门禁已覆盖 all-or-nothing handoff、engine-dead/proxy-live 回收与双贡献槽独立 erase；历史真实 b10064/GGUF E2E 早于四槽参数变更，发布前须复验。

### 2.8 0036：audited SLA exclusion

- `0036_audited_sla_exclusions.sql` 增加只追加 `sla_exclusion_events`；同一 job 最多一条决定，类别只允许 `content_policy_refusal` 和 `force_majeure`，job 必须已经是 `failed` 或 `cancelled`。
- 唯一写入口是 coordinator-only `sla-exclusion-record` 和 `SECURITY DEFINER` 函数；普通 CLI/HTTP 无伪造入口。完全相同请求精确 replay，同幂等键不同请求和同 job 不同决定确定性冲突。
- evidence 使用 bounded-file 原语，数据库只保存 SHA-256 与 fingerprint，不保存本地路径、Prompt 或 Response。runtime role 无事件表直接 DML，只能调用 allowlist 函数。
- 公开统计 scope 为 `accepted_jobs_audited_terminal_outcomes_v2`。只有已审计且 `failed` 的事件从 failed 分母中排除；cancelled 本来就不进入分母，其审计事件只增加类别计数。节点或 worker 的 `error_class` 永不自动排除。
- 协议新增字段使用 serde default；migration shape/只追加/ACL、函数 replay/冲突、治理公式、命令和旧协议兼容均有定向测试，并已进入 fresh-v36 `41/41` 组合门禁。

### 2.9 0037：邮箱身份授权既有 Device Flow

- `0037_email_password_auth.sql` 增加规范化邮箱、password hash、邮箱验证时间、HMAC-only 验证 token，以及 `auth_device_flows` 上的邮箱授权状态；这是当前 `0001..0039` 序列中的历史阶段。
- CLI 没有第二套 Web bearer 登录。`auth login` 始终生成/使用 Ed25519 设备密钥，调用 `/v1/auth/device/start`，并在每次 `/v1/auth/device/poll` 中提交设备签名。浏览器成功登录只标记既有 flow 已授权，不能领取 access/refresh token。
- verification URI 固定为与 coordinator 同源的 `/auth/login`，不得包含 query 或 fragment。终端显示随机 12 位 `user_code`；用户必须核对 origin 后在浏览器手工输入该代码，不应相信邮件、聊天或陌生网页给出的代码。
- 邮箱验证链接中的一次性 token 只以带服务器 pepper 的 HMAC 保存；GET 只显示确认页，只有用户显式同源 POST 才消费 token，邮件安全扫描器不能自动激活账户。HTTP tracing 只记录 path，不记录 query 或表单正文。注册、验证和授权使用数据库事务收口。
- production 的公开基址必须为 HTTPS；邮箱 provider 启动时必须验证 SMTP 必填项、发件人和传输构造参数，传输只允许 TLS 或 STARTTLS。浏览器不保存 bearer，CLI 会话与 Ed25519 私钥仍只进入系统凭证库。
- password reset 尚未实现；`send_password_reset_email` 辅助函数不等于存在公开 reset route 或可用产品流程。
- fresh-v37 schema、role ACL 与认证集成已进入隔离 PostgreSQL 17 的 `43/43`、无 skip 门禁；metadata 为 `37|1|37|t`。最终 workspace tests 也已通过：29 个 result set，`556 passed / 0 failed / 5 ignored`。

### 2.10 0038/0039、用户端模型部署与多端口实例

- `0038_job_speed_class.sql` 持久化 `fast/standard/slow` 路由类别；`0039_inference_api_keys.sql` 增加 HMAC-only 推理 Key、只显示一次的 Secret 和只追加 Key 事件。runtime 对 Key 表仅有 `SELECT/INSERT/UPDATE`，对事件表仅有 `SELECT/INSERT`，两表均无 `DELETE`，PUBLIC 与应用的宽权限已撤销。
- OpenAI 网关以真实 Standard job 路径执行。fresh PostgreSQL E2E 已覆盖会话创建/列举/撤销 API Key、三档模型名、fast speed class、worker claim/result/settlement、Base64 解码后的非流式响应，以及 `stream:true` 的连续密文 data 事件、`text/event-stream`、唯一 `[DONE]` 与同一最终结算；该 E2E 暴露并修复了“解密后直接把 Base64 文本当 JSON”的 500 缺陷。公开网关不接受客户端 resume token 或 `Last-Event-ID`；Regulated 仍明确拒绝流式且不降级。
- 65 项模型目录是允许选择的 HF repo ID，不是仓库、许可、GGUF 或本机容量可用性的静态承诺。`model probe --deployment --metadata-only` 只读取 HF tree/LFS 元数据；`scripts/audit-hf-model-catalog.sh` 用同一路径审计完整目录。2026-07-22 的低并发整轮解析 61 项，4 项因 HF 429 失败后逐项重试成功，合计 65/65 找到带大小/LFS SHA-256 的完整主 GGUF 清单。自动部署现在支持可信单文件或规范分片 GGUF：候选选择排除 projector/imatrix/MTP/draft，分片必须清单完整且逐片带 LFS SHA-256/大小，下载后还要逐片验证 GGUF 内部 split 元数据，整个 bundle 原子登记、启动复核和精确删除。`HF_TOKEN` 只从用户进程环境读取，并仅用于 HF Bearer 请求；不会持久化或写日志。Qwen3-0.6B 自动部署目标真实读取 65,536 bytes 后主动断开，`persisted=false`，没有下载完整权重；多模态目录当前只选择文本主 GGUF，不承诺图像/音频入口。
- `model deploy --port`、`serve status --port` 与 `serve stop --port` 使用每端口独立状态、日志和 runtime 目录；`--replace` 只替换同端口实例。`share publish --port` 选择并记录任一健康受管实例，attestation 与 Standard worker 会复验该端口；旧状态缺少字段时兼容为 `8080`。本地仍只有一份活动 share worker/状态，不能借多端口冒充多份容量。多端口状态隔离、模型在用保护和 legacy share state 已有确定性测试。2026-07-23 的隔离 E2E 使用 `18082` 完成同一 Qwen3-0.6B-Q4_0 整包下载、验证、b10064 四槽启动和 `/health`，随后旧脚本因 status 漏传端口而停止；脚本现已统一透传端口，完整 Standard job 由精确候选提交的 Actions 验收。为了遵守小模型/低流量要求，没有下载其他或第二份模型。
- 当前发行矩阵配置 macOS arm64/x86_64、Linux arm64/x86_64 和 Windows x86_64；llama.cpp release 资产选择有确定性平台映射测试。Windows ARM 没有 MindOne 正式包，安装器会明确拒绝。Linux 两个架构的 CLI release 与安装器用户态闭环已验证；Linux 真实沙盒/模型下载安装和 Windows 实际安装/模型启动仍须对应 Actions/真机验证。

上述条目是“源码已落盘且有分层证据”，不是“正式发布或 production 已部署”。真实模型证据只覆盖四槽改动前的本机 debug 单 Standard GGUF；不能替代当前四槽 argv、ModelScope 公网、外部 SMTP/浏览器、多平台 Actions、签名发布、真实 TEE 或 private 双 GGUF 证据。

### 2.13 真实 GGUF E2E 修复的四个实现缺陷

历史真实 GGUF Standard E2E 跑通过程中，定位并修复了四个此前被“slot erase 门禁”掩盖的真实缺陷（在修复 slot erase 之前，所有任务都在结算前失败，因此后续缺陷从未被触发）：

1. **受管 llama.cpp 缺少 `--slot-save-path`（`crates/mindone-engine/src/process.rs`）**：b10064 把 `/slots/{id}?action=erase` 动作端点门禁在 `--slot-save-path` 之后，仅 `--slots` 只暴露监控端点。启动参数只加了 `--slots`，导致每次请求后 slot 0 erase 返回 HTTP 501，worker 因“未确认清除正数 KV token”拒绝提交，**每个 Standard 任务都失败**。修复：在受管 runtime 目录下提供一个只用于启用该端点的托管 `--slot-save-path`（worker 只 erase、从不 save，不写 KV/Prompt 到磁盘），并把 `--slot-save-path` 加入 `--help` 能力探测（缺失即失败关闭）。
2. **策略持久化与运行期严格重读（已修复，`crates/mindone-cli/src/share.rs`、`crates/mindone-cli/src/node.rs`）**：`share publish` 在校验后通过 `save_policy` 落盘权威 `node-policy.json`；活动 worker 在领取、执行和心跳路径使用严格读取，不再以缺失文件回退默认值。运行期删除、损坏、非普通文件或符号链接均失败关闭，确保两次策略检查来自同一持久化来源。
3. **`raw_process_exists` 的 sysinfo 枚举竞态（`crates/mindone-cli/src/share.rs`）**：`kill -0` 已证明进程存在时，若 sysinfo 在 macOS 高负载/进程退出窗口枚举不到该 PID，旧逻辑硬报“无法读取进程状态”，导致 `serve stop` 偶发失败关闭。修复：`kill -0` 为存活的权威判据，sysinfo 仅用于识别 zombie；枚举不到时保守按存活处理，只有明确 Zombie 才判定已退出。
4. **计费/路由本身无缺陷，但 E2E harness 存在真实竞态**：节点资格由 15 秒心跳驱动，publish 后与节点阈值 fail-closed 暂停后都存在“服务端尚未把节点置为可路由”的窗口；`scripts/e2e-test.sh` 现在在每个推理阶段前显式等待节点成为可路由候选（online/fresh/published/valid profile，且本平台不可读的 vram/温度阈值已清零），并对创建任务前的瞬时 502/503 有界重试、对公网模型下载有界重试。这些只影响测试编排的确定性，不放宽任何服务端资格或结算判定。`/v1/completions` 用例改用真实基础模型会自然回显的补全提示（原始文本补全不套 chat 模板），仍以运行时 nonce 作为反 mock 证据。

本轮 E2E 首次运行还暴露了 CPU-only 配置被编码为未受信 `additional_args` 并触发受管 `--device` 覆盖拒绝的问题。现在 `cpu_only` 是 `ServeRequest` 的类型化受管字段，引擎层统一注入 `--device none`、零 GPU layer 和 KV/op offload 禁用参数，并清除对应环境覆盖；用户附加参数仍不能覆盖这些安全决定。定向测试覆盖类型化传递和冲突拒绝。

worker 收口还增加了三类失败关闭证据：reasoning-only 且没有可见 `content` 的结果立即失败，避免以不可见推理文本结算；协调器对 result 的确定性 HTTP 400 只触发一次不含远端 message/Prompt/Response 的脱敏 terminal failure；活动 worker 每次使用策略时都读取已持久化普通文件，运行期删除、损坏、非普通文件或符号链接均失败关闭。当前 debug 隔离 E2E 在这些修复后从头退出 0。

## 3. 已取得但不能冒充最终结果的证据

当前 v39 已有隔离 PostgreSQL 17 组合证据与全 workspace 结果；它们仍不替代真实模型或外部发布：

| 阶段性验证 | 结果 | 限制 |
|---|---:|---|
| 历史 fresh v36 PostgreSQL 组合 gate | `41/41`，无 skip | 历史隔离库 `mindone_gate_0036_full_20260719b`；不证明 v37 |
| 历史 v36 各 binary | `11+3+10+2+1+2+5+1+1+1+1+1+2` | postgres、三套 ledger、role、runtime、schema v31..v36、router |
| 历史 v36 metadata | `36|1|36|t` | 历史 fresh 库的真实 `_sqlx_migrations` 查询 |
| fresh v37 PostgreSQL 门禁 | `43/43`，无 skip | 隔离 PostgreSQL 17；14 个 binary，metadata `37|1|37|t` |
| 历史 fresh v34 gate / billing shape | `39/39` / `52|0|0` | 保留为 0034 阶段证据；不能覆盖或删除，也不替代 v36 结果 |
| 真实结算/失败不扣定向测试 | 通过 | 修复物理计费 fixture 后单独通过 |
| fresh v39 PostgreSQL 组合 gate | `49/49`，无 skip | 一次性 PostgreSQL 17；16 个 binary 各用独立数据库，持久库 metadata `39|1|39|t` |
| fast 空闲整机优先定向回归 | `1/1` | 2026-07-22 一次性 PostgreSQL 17、随机 loopback 端口、无持久卷；覆盖 fast 在两端都有物理 spare slot 时仍排队、空闲后按 TPS 选择、slow 聚合与全满排队，容器已删除 |
| 当前 workspace fmt / check / strict Clippy / tests | 通过 | 31 个 result set，`589 passed / 0 failed / 5 ignored`，退出 0 |
| 当前 CLI/TUI | CLI lib `175/0/1`；40 叶子/10 分类、多端口、平台资产映射通过 | 回环与真实 macOS capability 用例在未受额外沙箱限制的本机运行；已退出 worker 的回收测试已去除 2 秒调度窗口依赖 |
| common bounded-file tests / Clippy | `24/24` / 通过 | evidence TOCTOU 共用层定向证据 |
| operator billing / quality 定向测试 | `4/4` / `4/4` | evidence 接入证据；当前 workspace strict Clippy 已通过 |
| v35 SSE 单元/包级门禁 | protocol `45/45`、CLI `130`、coordinator `105/105` | CLI 另有 1 ignored；相关 package 与 schema_v35 定向证据 |
| v35 SSE PostgreSQL schema | `1/1` | 验证密文、只追加、重放边界和最小 ACL；另已进入 fresh-v36 gate |
| 贡献进度/匿名榜定向门禁 | protocol `1`、coordinator `3`、CLI `1`、PostgreSQL `1/1` | 小 cohort、人数粒度和并列 midrank 定向证据；另已进入 fresh-v36 gate |
| 0036 audited SLA exclusion | protocol `2`、operator `4`、公式 `5`、命令 `2`、PostgreSQL `1/1` | 定向验证协议、审计入口、公式、schema 与 ACL；另已进入 fresh-v36 gate |
| ModelScope repo-files discovery | CLI model `11/11`、download `5/5`、mock `5/5` | 官方 API 形状与安全失败边界已验证；真实公网 artifact 待 smoke |
| llama.cpp audited 默认版本 | `2/2` | 省略版本固定 `b10064`、精确 registry 选择；全 workspace 门禁已通过 |
| 本地受管四槽 policy | share 并发/刷新 `2/2`，engine 参数 `1/1` | slot 0 与贡献 slot 1..3 隔离；`max_concurrent=1..3` 对应真实槽；双任务使用不同 `id_slot`、分别 erase，会话轮换不回退 |
| 独立 serve 请求后清理代理 | proxy 清理定向测试、贡献双槽并发、CPU-only/清理定向测试与 engine strict Clippy 通过 | 当前 workspace 验证强制 slot 0 与逐槽清理；最近一次真实 b10064/GGUF E2E 早于四槽/统一 KV 参数变更，发布前须重跑 |
| Standard SSE / 真实 GGUF E2E | 历史 debug 隔离执行退出 0 | fresh PostgreSQL v37、双账号/device、b10064、Qwen3-0.6B-Q4_0、非流式双端点、两类 SSE、游标故障恢复、密文、三轨唯一结算、策略拒绝零结算、Regulated 流式拒绝、日志扫描和清理；早于本轮四槽/统一 KV 参数变更，不能冒充当前引擎 argv 的真实证明 |
| Unix 安装 URL 负例 smoke | 通过 | userinfo/query/fragment/伪 loopback 等拒绝边界 |
| CI/Compose 与首次外部 Actions | 当前树本地通过；首次 Actions 总体失败 | macOS arm64/x86_64、Windows x86_64 原生编译和 RustSec/cargo-deny 已成功；Linux cfg、无 `rg` Runner、PostgreSQL 夹具已在当前树修复并复验，完整历史 Gitleaks 本地无泄漏；须推送修复后重新取得外部全绿 |
| 当前二进制 release archive smoke | 通过 | `mindone 1.0.1` / `aarch64-apple-darwin`；归档 SHA-256、安装、`--check`、重装、中文 help、doctor JSON、保留数据卸载和 purge 均通过；unsigned local tar.gz |

不要把复用库的失败或成功与 fresh gate 混在一起。旧共享库和全部证据库包含 private key/catalog/global reserve 等故意持久化状态；不得 drop、truncate、清理或复用。需要新的组合证据时，必须先确认另一个库名从未存在，再新建并只运行一轮。每个测试内部的精确 replay/冲突和并发断言才是相应幂等行为证据。

`scripts/e2e-test.sh` 已在四槽改动前的 debug 工作树实际从头运行并退出 0。除 profile provision/replay、OpenAI chat 与 `/v1/completions`、receipt/ledger 和领取后策略变化外，它还先确定性完成 public canary worker 终态，再验证两端点 Standard SSE 的连续 event ID、唯一 `[DONE]`、AEAD 密文、故障注入后的非零游标恢复和唯一 settlement。其恢复测试是代理到 coordinator 的恢复且保持同一 downstream 连接，并不等于公开 API 已提供客户端重新 POST 的 resume token；本轮四槽 argv 仍须复用小模型重跑。

## 4. 精确停止点和最可能的首个失败

当前 fresh-v39 `49/49`、workspace `589/0/5`、Linux arm64/x86_64 release 用户态闭环、macOS arm64 隔离源码安装/裸命令 PTY smoke、首次 Actions 的 macOS/Windows 原生编译、Windows x86_64 MSVC 交叉审计与 OpenAI JSON/SSE 网关数据库 E2E 已通过。精确停止点是推送本轮 CI 修复并取得完整 Actions 全绿、创建新的正式 Release、提交独立 Cloudflare Tunnel/DNS 并做公网验收、本轮四槽/统一 KV 的小模型真实 E2E、Windows 真机安装、Linux 真实沙盒/模型下载、ModelScope 公网链、外部邮箱链、private 双 GGUF、真实 TEE、平台签名和 production live 切换；历史数据库不得重复使用。

剩余最可能暴露差异的边界依次是：

1. Windows/Linux 安装/部署真机与 ModelScope 公网差异；
2. private hidden 双真实 GGUF 的错误权重、替换、超时、重放、错设备和跨实例仲裁；
3. 外部 SMTP/浏览器/CLI 签名 poll 与 Cloudflare 公网 TLS E2E；
4. 真实 TEE/GPU/平台签名及 production 维护窗口升级。

已经取得的 v34、v35、v36 和其他证据库全部保留。不要 drop、truncate 或“清理后复用”它们，也不要用禁用生产 trigger、放宽 runtime role、持久化 Response 明文、固定 SSE 响应或仅写状态文件来换取绿灯。

## 5. 后续任务顺序

### P0-A：当前树编译级预检（已通过）

当前 fmt、all-target/all-feature check 与 strict Clippy 已通过；修改后仍可用下列单进程命令复验：

```bash
cd /Users/beluga/Documents/MindOne
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=1

cargo +1.88 fmt --all -- --check
git diff --check
cargo +1.88 check --locked --offline \
  --workspace --all-targets --all-features -j1
```

serve 定向结果已和 P0-C 的 workspace 门禁共同通过；保留以下命令便于修改后复验：

```bash
cargo +1.88 test --locked --offline -j1 \
  -p mindone-cli --lib serve_proxy::tests -- --test-threads=1
cargo +1.88 test --locked --offline -j1 \
  -p mindone-cli --lib cli::tests::parses_internal_serve_proxy_identity_and_ports \
  -- --exact --test-threads=1
cargo +1.88 test --locked --offline -j1 \
  -p mindone-engine --lib process::tests -- --test-threads=1
cargo +1.88 test --locked --offline -j1 \
  -p mindone-cli --lib engine::tests -- --test-threads=1
cargo +1.88 test --locked --offline -j1 \
  -p mindone-cli --lib node::tests::policy_rejects_tag_and_concurrency \
  -- --exact --test-threads=1

cargo +1.88 clippy --locked --offline -j1 \
  -p mindone-engine --all-targets --all-features -- -D warnings
cargo +1.88 clippy --locked --offline -j1 \
  -p mindone-cli --all-targets --all-features -- -D warnings
```

不要同时启动 PostgreSQL gate、Docker build 或模型下载。定向通过后仍必须执行 P0-C 的 workspace 级门禁。

### P0-B：保护全部历史证据，只在全新临时 PostgreSQL 17 上复验

fresh-v37 门禁已经取得 `43/43`、无 skip、metadata `37|1|37|t`。当前 v39 先用唯一临时 PostgreSQL 17 完成定向门禁；因当时 Docker VM 空间不足，数据目录使用仓库外 `/private/tmp` 一次性 bind，完成后已清理。随后完整 gate 使用另一个唯一容器 `mindone-fresh-v39-20260722c` 和 1 GiB tmpfs，16 个 binary 各建独立数据库，得到 `48/48`、无 skip；持久库 metadata 为 `39|1|39|t`，会自建临时库的测试由用例内部核对并清理。标签复验后该容器和 tmpfs 已删除，数据不可恢复。`mindone_gate_0036_full_20260719b`、`mindone_gate_0037_full_20260722a` 及 `mindone-pg-final-20260718` 都属于历史证据现场；禁止再对它们执行 `createdb`、测试、迁移、drop、truncate 或任何写操作。

OpenAI SSE 落盘后又使用 `mindone-final-v39-20260722a` 在独立 1 GiB tmpfs 上重跑同一 16-binary 门禁，结果仍为 `48/48`、无 skip，主集成库 metadata `39|1|39|t`；标签复验后容器与 tmpfs 已删除。另一个只跑网关精确 E2E 的临时容器也已删除。上述测试数据均不可恢复，production 与历史证据容器均未触碰。

本轮 TUI 重做和速度档调度回归加入后，使用唯一容器 `mindone-fresh-v39-20260722b`、512 MiB tmpfs 与 `127.0.0.1:55445` 再次串行运行 16 个 binary；每个 binary 使用全新独立数据库，结果为 `49/49`、无 skip，主集成库 metadata `39|1|39|t`。容器标签、端口与 tmpfs 复核后已停止并删除，测试数据不可恢复；production 容器未迁移、重启或写入。

2026-07-23 又为 live v26 创建并校验 `.mindone/backups/production-before-0027-0039-20260722T174308Z/mindone-v26.dump`，在独立 PostgreSQL 17 tmpfs 恢复后保持 `26|1|26|t` 与零业务行。SQLx 首次拒绝 migration 14 checksum 漂移；取回部署时多一个末尾空行的 488 字节 blob 后 checksum 精确一致，重建二进制在恢复副本完成 `26→39`，0037/0038/0039 结构均已核对。一次性容器已删除，备份保留；live coordinator 从未因演练停止，仍为 v26。

确需复验时，只能启动一个全新、唯一命名的 PostgreSQL 17 临时容器：固定已审计镜像 digest，宿主端口只绑定经预检空闲的 `127.0.0.1` 端口，数据目录使用 `tmpfs`，并加本轮唯一测试 label。一次性随机数据库密码只保留在当前进程环境；退出 trap 只能在容器名和 label 同时匹配时删除本轮容器。不得挂载 volume，不得连接 Compose production，不得把旧容器或旧证据库当作 fresh gate。容器健康后，为下列每个 binary 创建一个从未使用的独立数据库，并分别设置其 `DATABASE_URL`、`MINDONE_REQUIRE_POSTGRES_TESTS=1`、`CARGO_INCREMENTAL=0` 和 `CARGO_BUILD_JOBS=1`。不要让多个 binary 共用数据库。

串行运行全部 coordinator integration binary；每个 binary 也只用一个线程。以下是单个 binary 的模板，必须为列表中的每项换用新的 `database_name` / `DATABASE_URL`：

```bash
test_name='schema_v39'
database_name='mindone_v39_schema_v39_本轮唯一后缀'
# 由临时 PostgreSQL 的 owner 在该临时服务器中创建 $database_name。
MINDONE_REQUIRE_POSTGRES_TESTS=1 \
DATABASE_URL="postgres://<临时owner>@127.0.0.1:<临时端口>/$database_name" \
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
cargo +1.88 test --locked --offline -j1 \
  -p mindone-coordinator --test "$test_name" \
  -- --nocapture --test-threads=1
```

完整列表为 `postgres_integration`、`ledger_heads`、`ledger_integrity`、`ledger_migration`、`database_role`、`runtime_schema`、`schema_v31`..`schema_v39`、`router`。

历史 v36 数量是：`postgres_integration 11`、`ledger_heads 3`、`ledger_integrity 10`、`ledger_migration 2`、`database_role 1`、`runtime_schema 2`、`schema_v31 5`、`schema_v32 1`、`schema_v33 1`、`schema_v34 1`、`schema_v35 1`、`schema_v36 1`、`router 2`，总计 `41`。v37 额外运行 `schema_v37`，共 14 个 binary；当前 v39 再增加 `schema_v38` 与 `schema_v39`，共 16 个 binary。没有 `DATABASE_URL` 的 skip 不算通过。全部测试后必须在本轮新容器内查询 `SELECT max(version),min(version),count(*),bool_and(success) FROM public._sqlx_migrations`，当前应核对 `39|1|39|t`；不要查询或修改任何历史容器。

历史 v37 实际 metadata 为 `37|1|37|t`，14 个 binary 合计 `43/43`。当前 v39 的 16 个 binary 各用独立数据库，合计 `49/49`、无 skip。不要把整套测试重复运行在同一共享库上：`database_role` 会故意建立错误 HMAC commitment，private/catalog/global reserve 等测试也会留下跨请求状态；此前共享库广跑出现的 4 个 private evaluation 失败正是无效隔离导致，不能算产品回归。后续组合证据继续使用“一次性服务器 + 每 binary 独立数据库”。

`schema_v34`（以及采用同一 harness 的后续 schema 测试）会创建并清理自己生成的临时数据库，因此测试账号需要 `CREATEDB`，PostgreSQL 需要支持 `DROP DATABASE ... WITH (FORCE)`。它只能删除带自身随机前缀的临时库，不能改为清理共享证据库。

### P0-C：全量 Rust 与静态门禁

编译级预检通过后串行运行；不要同时运行数据库 gate、Docker build 或模型下载：

```bash
cargo +1.88 fmt --all -- --check
git diff --check

find . -path ./target -prune -o -type f -name '*.sh' -print0 \
  | xargs -0 -n1 sh -n

cargo +1.88 check --locked --offline \
  --workspace --all-targets --all-features -j1
cargo +1.88 clippy --locked --offline \
  --workspace --all-targets --all-features -j1 -- -D warnings
cargo +1.88 test --locked --offline \
  --workspace --all-targets --all-features -j1 -- \
  --test-threads=1

sh scripts/validate-private-v2-compose.sh
```

逐项记录 pass/fail/ignored/skip；平台能力不可用必须明确写成未验证或拒绝，不能静默算通过。

### P0-D：真实 GGUF E2E（历史树已通过，四槽 argv 待重跑）

本轮使用 `55439/18892/18082/19092` 四个独立 loopback 端口、`MINDONE_E2E_PROFILE=debug`、`MINDONE_E2E_CPU_ONLY=1` 和 fresh PostgreSQL v37，从头执行后退出 0。后续修改引擎、worker、代理、SSE 或结算路径时，先确认建议端口都空闲再复验；如果任一端口已被占用就选择新的 loopback 端口，不得停止现有服务：

```bash
lsof -nP -iTCP:55439 -sTCP:LISTEN
lsof -nP -iTCP:18892 -sTCP:LISTEN
lsof -nP -iTCP:18082 -sTCP:LISTEN
lsof -nP -iTCP:19092 -sTCP:LISTEN

MINDONE_E2E_POSTGRES_PORT=55439 \
MINDONE_E2E_COORDINATOR_PORT=18892 \
MINDONE_E2E_LLAMA_PORT=18082 \
MINDONE_E2E_PROXY_PORT=19092 \
MINDONE_E2E_PROFILE=debug \
MINDONE_E2E_CARGO_JOBS=1 \
MINDONE_E2E_CPU_ONLY=1 \
MINDONE_E2E_KEEP_TMP=0 \
CARGO_INCREMENTAL=0 \
CARGO_BUILD_JOBS=1 \
sh scripts/e2e-test.sh
```

必须看到真实 llama.cpp b10064 和真实 GGUF 推理，且覆盖：

- 两个隔离 `MINDONE_HOME`、两个账号、节点 publish/serve/heartbeat、消费者代理；
- audited profile 首次写入与完全相同幂等 replay；
- `/v1/chat/completions` 和 `/v1/completions` 都返回真实模型结果；
- 两个端点的 `stream:true` 都返回真实 `text/event-stream` 增量和唯一 `[DONE]`；Regulated 明确拒绝流式且不回退；
- worker 按连续 sequence 幂等上传，数据库只见 AEAD ciphertext；脚本强制 coordinator stream 查询断开后，代理在同一 downstream 连接内以非零游标恢复且不重复/丢失事件，最终 result/结算仍只发生一次；这不等于公开 API 已支持客户端重新 POST resume token；
- receipt 中 profile/evidence/weights/token/GPU/VRAM 三分项与 provision 结果一致；
- 准备金、消费者扣费、节点 quota、contribution、网络 reserve 和 ledger 守恒；
- 第二次策略检查：领取后改变策略时 llama HTTP 未发生、没有成功提交或结算；
- 本机请求精确 erase slot 0，贡献任务精确 erase 获分配的 slot 1..3；任一清理失败时不提交和不结算；
- 日志不含 Prompt、Response、nonce 或 secret 明文；
- stop/unpublish/logout 和测试容器清理只影响脚本创建的资源。

当前脚本是已取得真实运行证据的单 GGUF Standard E2E。private hidden 的双 GGUF、错误模型/替换权重/超时/重放/错设备/跨实例仲裁仍需要独立真实 harness；模拟响应不能作为 v1.0.0 最终验收。脚本默认 `KEEP_TMP=0`，只允许清理由本轮创建的容器、临时 home 和测试数据。

### P0-E：ModelScope 真实公网 artifact smoke

本地 mock 已通过，但尚未验证真实公网响应。先在 ModelScope 官方页面选择一个体积可控、许可允许测试、清单明确提供 `Sha256` 的 GGUF/safetensors；不要把示例仓库名或大模型默认当作已批准下载。使用独立临时 home，显式填写以下三个值后运行：

```bash
export MINDONE_MODELSCOPE_REPO='owner/repository'
export MINDONE_MODELSCOPE_BRANCH='master'
export MINDONE_MODELSCOPE_FILE='path/to/model.gguf'
export MINDONE_MODELSCOPE_SMOKE_HOME="$(mktemp -d /tmp/mindone-modelscope-smoke.XXXXXX)"

MINDONE_HOME="$MINDONE_MODELSCOPE_SMOKE_HOME" \
  /Users/beluga/Documents/MindOne/target/debug/mindone model download \
  --platform modelscope \
  --repo "$MINDONE_MODELSCOPE_REPO" \
  --branch "$MINDONE_MODELSCOPE_BRANCH" \
  --file "$MINDONE_MODELSCOPE_FILE" \
  --name modelscope-smoke

MINDONE_HOME="$MINDONE_MODELSCOPE_SMOKE_HOME" \
  /Users/beluga/Documents/MindOne/target/debug/mindone model verify modelscope-smoke
MINDONE_HOME="$MINDONE_MODELSCOPE_SMOKE_HOME" \
  /Users/beluga/Documents/MindOne/target/debug/mindone model list
```

记录实际 repo、revision、file、官方清单 SHA、下载校验和模型结构验证结果。只清理由 `mktemp` 创建且已经核对的 `$MINDONE_MODELSCOPE_SMOKE_HOME`；如果公网 API、清单字段或 SHA 缺失，应记录为真实失败并修复或明确拒绝，不能回退信任 ETag/文件 ID，也不能手填未知哈希换取成功。

### P0-F：release 和安装闭环

使用最终构建的当前平台二进制重跑：

```bash
sh scripts/release-archive-smoke.sh \
  /Users/beluga/Documents/MindOne/target/debug/mindone
```

该脚本只证明本机 unsigned tar.gz、checksum、本地 HTTP 安装、`--check`、重装、中文 help、doctor、默认保留数据卸载和 `--purge-data`。它不证明 GitHub Release、Actions、SBOM、Sigstore、Apple/Windows 签名或 notarization。

还需人工审计并处置生产代码中的 `TODO`、`FIXME`、`todo!`、`unimplemented!`、`panic!`、硬编码 secret、假余额、假推理、固定成功响应；测试和文档命中不能机械删除。

### P1：仍需实现或最终验证的产品行为

- **SLA 可审计排除（migration 0036）**：已实现；历史 fresh-v36/v37 证据之外，当前 fresh-v39 `49/49` 与 workspace `589/0/5` 也已通过。节点或 worker 的 `error_class` 永不自动排除。
- **Windows 最高可用隔离**：当前只真实应用并报告 `KILL_ON_JOB_CLOSE` Job Object，等级保持 Experimental；尚未建立 AppContainer supervisor，不能把 capability 探测冒充已应用。
- **Regulated 并发 prepare ready demand**：现有事务锁和 capacity check 能防止实际超卖，但本次尚未持久化的 prepare 请求不计入 contribution-routing 的 ready demand。若要让并发 prepare 触发贡献破平局，需同事务、可审计的 demand reservation，不能进程内简单 `+1`。
- **Standard SSE 最终门禁**：实现、runtime role/CI latest、定向测试、fresh-v37、workspace 与历史 debug 真实 GGUF/SSE E2E 已通过；历史真实执行覆盖密文、chunk 不结算、两端点唯一 final settlement 和同一 downstream 连接中的非零游标故障恢复，不宣称客户端重新 POST resume。四槽 argv 仍待复验。
- **独立 serve 请求后清理**：管理代理、all-or-nothing/engine-dead 回收、slot 0 强制绑定、贡献双槽独立 erase 与全 workspace 门禁已通过；历史真实 b10064/GGUF 终态清理早于四槽参数变更。只承诺受管 slot erase 和 MindOne 自有缓冲 best-effort 清理，不冒充 GPU 驱动内存物理清零。
- **ModelScope 公网链**：官方 repo-files discovery 和本地 mock 已实现；真实公网 artifact smoke 尚未完成。
- **多本地模型**：按端口并行的状态、日志、runtime 与停止/状态管理已实现并有确定性测试；没有额外下载第二个模型做并行真机启动，不能把状态隔离测试写成双模型推理 E2E。
- **OpenAI 公网网关**：JSON 与 `stream:true` 的真实 PostgreSQL 事务 E2E 均通过；SSE 覆盖连续密文 data、唯一 `[DONE]` 和最终结算。公网 TLS/Cloudflare 仍待外部验证，客户端重连续传不是公开合同。

### P1-A：SLA 可审计排除的已实现合同

`0036_audited_sla_exclusions.sql` 已按以下合同实现；后续修改不得用节点自报错误或状态文件直接修改 SLA：

- 新增只追加 `sla_exclusion_events`，同一 job 最多一条审计决定；类别只允许 `content_policy_refusal` 和 `force_majeure`，且 job 必须已经是 `failed` 或 `cancelled` 终态。`UPDATE`、`DELETE`、`TRUNCATE` 全部拒绝。
- 唯一写入口为 coordinator-only `sla-exclusion-record` 运维命令和 `SECURITY DEFINER` 数据库函数。函数使用全局幂等/advisory lock 与 job row lock，完全相同请求返回 replay；同幂等键不同请求、同 job 不同决定都确定性冲突。
- 请求 fingerprint 必须绑定 job、category、operator、reason、idempotency key 和 evidence SHA-256。evidence 复用 `mindone-common` 的 bounded-file 原语，要求规范绝对路径、非 symlink 普通文件、非空和读取前后身份一致；数据库不保存本地路径，也不保存 Prompt/Response 明文。
- runtime role 对事件表没有直接 INSERT/UPDATE/DELETE，对非 allowlist 函数没有 EXECUTE；普通 CLI 不直连数据库，也不暴露伪造入口。operator 命令的 help/status/error 保持简体中文。
- 公开治理统计固定为：`total_terminal = succeeded + failed + cancelled`；`cancelled` 原本就不进入 SLA 分母；只有已审计且状态为 `failed` 的事件从 failed 中排除；`included_denominator = succeeded + (failed - audited_failed_exclusions)`，成功分子为 `succeeded`。若为 cancelled 记录审计事件，它只计入公开类别说明，不得再次缩小分母。
- API/协议公开 total terminal、included denominator、excluded total 和按类别计数，并将 observation scope 升为稳定 v2；新增字段使用 serde default 保持旧客户端解码兼容，所有计数使用整数。
- 已增加 migration shape/只追加/ACL、函数幂等与冲突、非法终态/类别、evidence、治理公式、命令和旧协议兼容的确定性测试；节点 `error_class` 不进入排除逻辑。
- 历史 fresh-v36 数据库 `mindone_gate_0036_full_20260719b` 已查询到 `36|1|36|t` 并完成 `41/41`；migration latest、runtime schema、CI 和 role-init 当前已推进到 `0001..0039`。fresh-v37 `43/43` 与 debug 真实 GGUF/SSE E2E 是历史证据；当前 v39 以每 binary 独立数据库的 `49/49` 组合门禁为准。

### P1-B：文档一致性

README 与下列文档已同步为 v39 口径；历史 v36/v37 数据库结果仅作分阶段证据保留，不代表当前树或 production：

- `docs/API.md`
- `docs/CLI_COMPLIANCE.md`
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/OPERATIONS.md`
- `docs/SECURITY.md`
- `docs/INSTALL.md`

重点删除或修正：bare SHA private 描述、旧 migration latest、旧测试数量、旧 `C_base` 未选择状态，以及把本地 unsigned smoke 描述成正式发布的措辞。

### P2：production 和外部操作

以下不是本轮本地实现可以自行宣称完成的项目：

- production v26 -> 当前最终 schema（工作树目标 v39）：active jobs/routes、可恢复备份和隔离 `26→39` 演练已完成；live 停 writer、再次备份、owner migrator、role-init、runtime 切换与验收仍未执行，因为停止 coordinator 会造成短时 API 中断，须对该具体风险单独明确确认。
- 生产 profile 数值：必须由 operator 根据独立证据和容量/费率评审发布；不要把 E2E 示例数字复制到生产。
- Regulated/TEE：没有真实硬件、固件、collateral、verifier、adapter、allowlist 和消费者复验时必须失败关闭；macOS 不能伪装 TEE。
- GitHub OAuth、push、PR、Actions、tag、Release、合并、Cloudflare tunnel 和公网切流都需要明确授权与真实外部证据。
- 多平台包、Apple/Windows 签名、notarization、SBOM/Sigstore 和公网 TLS 尚无最终证据。

## 6. 不得回退的验收行为

- 普通用户可见 UI、help、status 和错误保持简体中文；API 字段、路径和结构化日志键保持稳定英文。
- 生产代码不使用 `panic!`、`todo!`、`unimplemented!`，普通错误返回 `Result`。
- CLI 不直连数据库；账户和任务操作通过 coordinator API，operator-only 数据库命令留在 coordinator 二进制。
- 跨主机只允许 TLS；HTTP 仅限明确 loopback 开发。
- GGUF/safetensors 做结构和大小验证；Pickle 等危险反序列化格式硬拒绝。
- 不记录 Prompt/Response 明文，不提交 token、密码、OAuth secret、数据库凭据、私钥、模型、本地配置、备份或测试数据库。
- 所有金额使用整数 microquota；账本只追加；准备金、结算、profile provisioning、result 和释放必须事务、幂等、可审计。
- 节点 telemetry 不能决定账单金额；`server_reference_upper_bound_v1` 必须明确称为服务器参考上界，不得宣传成真实 GPU 计量或执行证明。
- profile 缺失/过期/不匹配/上界不足时失败关闭；最高 active version 不适用时不能回退旧 profile。
- 省略 llama.cpp 版本时必须精确选择 audited `b10064`；更新安装不能遮蔽默认。受管进程必须固定 slot 0 本机、slot 1..3 贡献并显式启用统一 KV；policy 只接受 `max_concurrent=1..3`，越界配置必须拒绝。
- 领取前和推理前两次策略检查保持；slot erase 失败不得成功提交或结算。
- contribution 只在真实拥堵、cohort 足够、近同分时破平局；不能覆盖质量、成本、信任和健康硬过滤。
- 匿名荣誉榜在 cohort 小于 5 时必须整表抑制，永不返回 user/device/node/model 标识、Prompt/Response 或精确低样本记录；并列节点共享 midrank 档位。
- Standard SSE 事件必须连续、幂等、有界并以 AEAD 密文静态保存；Regulated 不支持时明确拒绝，chunk 不能触发结算，消费者断开不能导致双结算。
- SLA 排除只能来自 operator 审计事件；节点或 worker 自报错误类别不得直接缩小公开 SLA 分母。
- legacy 历史可读，但 0034 之后的新 job/route/receipt 必须完整 v1；不能通过伪造 allowlist 或回填历史快照绕过。

## 7. Git 收口

最终提交前：

1. 重新列出并逐路径检查全部 untracked 文件，排除 `target/`、模型、secret、数据库、日志、备份和本地配置；不要依赖本文撰写时的数量。
2. 保留三个规格输入，除非用户明确要求归档：`mindone_cli_1.0.0.md`、`mindone_1.0.0_副本.md`、`mindone_mvp.md`。
3. 不使用 `git add .`；按已审阅路径精确 stage。
4. 运行 `git diff --cached --check`，再查看 `git diff --cached --stat` 和 secret scan。
5. 只有用户授权且本地门禁真实完成后才 commit/push/PR；未授权时只报告工作树状态。

## 8. 完成定义

只有以下项目全部满足，才能称 MindOne v1.0.0 MVP 完成：

- fresh v39 全部 16 个 coordinator integration binary（含 `schema_v35`..`schema_v39`、速度档调度和跨 catalog 真重叠双 `PgPool` 回归）已在一次性 PostgreSQL 17 上各用独立数据库真实通过，合计 `49/49`、无 skip，持久库 metadata `39|1|39|t`；
- SLA 与 API Key 事件保持只追加、operator/API 边界、幂等、最小 ACL 和治理合同；migration/latest/CI/role-init/Compose/E2E/文档持续一致为 v39；
- 0034 preflight、legacy preservation、三表 insert guard、数据库 role allowlist 和运行时 checksum fail-closed 均有真实 PostgreSQL 证据；
- 当前树 fmt、workspace check、strict Clippy、workspace tests、Shell 和 private Compose validator 全绿，ignored/skip 被如实列出；
- 真实 GGUF Standard E2E 在非冲突端口通过，并证明 profile、冻结计费、receipt、账本、策略二检和 slot erase；
- private hidden 双真实模型的正确/错误权重、重放、超时、错设备和跨实例仲裁完成真实验收；
- 当前最终二进制的 release/install/uninstall 闭环通过，静态安全扫描无未处置生产命中；
- API、CLI、运维、安全、安装和实施计划与最终 schema 行为及明确未实现项一致；
- 外部 Actions/多平台/签名/发布/Cloudflare/production 取得真实证据，或被明确标为尚未完成，不能从完成定义中删除；
- 最终 staged 文件集合可解释且不含 secret、模型、数据库、备份、日志或构建产物。

即使全部本地门禁通过，也不自动授权 production 升级、push、合并、tag、Release 或公网切流。
