# MindOne

MindOne 是一个开源、纯公益的 AI 算力与模型共享网络。它使用中心化协调控制面和分布式本地执行面：消费者通过本地 OpenAI 兼容代理提交任务，贡献节点主动连接协调服务器并使用本机受管引擎推理，系统以整数 microquota、贡献值和网络准备金进行可审计结算。

> [!IMPORTANT]
> 当前工作树已推进到连续 schema `0001..0039`。公开 `v1.0.1` 的 Release 专属重复门禁因把 `DATABASE_URL` 注入通用并行 workspace 测试而失败；标签保留且不会移动。修复版 `v1.0.2` 已把通用测试与专用 PostgreSQL 环境隔离，本机无数据库 workspace 门禁和独立 PostgreSQL 17 的 `13/13` 集成门禁均通过。**源码已经公开，但 GitHub Release 尚未产出；只允许在同一个精确候选提交的完整 CI 与 Security 全绿后创建新标签**。
>
> fresh-v37 的 `43/43`、workspace `556/0/5` 和真实 GGUF E2E 是新增 0038/0039、模型目录与公网网关之前的历史证据。当前树已通过全 workspace check/strict Clippy、全 workspace `590/0/5`，并在一次性 PostgreSQL 17 中以每 binary 独立数据库完成 fresh-v39 `49/49`；API Key 网关的非流式与 Standard SSE 事务 E2E 均已通过。公开 Actions 已真实通过 macOS arm64/x86_64、Linux x86_64/arm64 与 Windows x86_64 原生编译，以及 Windows 安装/卸载、macOS Seatbelt 和 Linux 四层沙盒门禁；`v1.0.2` 本机归档又通过 SHA-256、安装、更新检查、重装、默认卸载和 purge 闭环。Qwen3-0.6B 自动部署目标仍只做 64 KiB 日常有界探测；同一小模型已在当前 macOS 隔离 E2E 中完成整包下载、SHA-256/结构验证和非默认端口健康启动，公开 Linux E2E 又以当前四槽参数跑完双账号动态推理、两类 SSE、结算、策略拒绝及清理，只在最终日志审计暴露了测试脚本仍固定查找默认端口日志名。脚本现改为使用 `serve --json` 返回的权威 `log_path` 并扫描其轮转代；最终发行证据仍必须来自同一精确候选提交的完整 CI 与 Security。公网 TLS 另须在独立 Tunnel 创建后验收。准确停止点见 [续接文档](docs/HANDOFF.md)。
>
> GitHub 仓库、`main`、旧 `v1.0.0`/`v1.0.1` 标签和 raw 安装器现已公开；旧标签保留且不会强制移动。Security workflow 与 CI 的既有通过项证明核心质量、fresh-v39/PostgreSQL、五个原生目标、macOS Seatbelt、Linux 四层沙盒和 Unix release smoke 可运行；本补丁序列又修复原生 Linux file secret 的固定 UID 读取、PowerShell information stream 捕获、无桌面 Linux 的真实 keyutils 凭证库，以及非默认端口的 share 绑定。`v1.0.2` 标签和 Release 仍受“精确候选提交的 CI 与 Security 必须同时全绿”约束。
>
> 本机 production 当前仍健康运行于 `127.0.0.1:18787`，数据库是 schema v26。已完成只读备份、PostgreSQL 17 恢复验证和隔离副本 `v26→v39` 真实迁移演练，但尚未获得会造成短时 API 中断的维护窗口确认，因此 live 没有停机、迁移或替换二进制。未经明确维护窗口、任务排空、生产 profile 配置和 owner 授权，不得切换 live。

## 仓库内容

- 简体中文 `mindone` CLI；
- Rust/Axum 协调服务器和 operator-only 运维命令；
- PostgreSQL migration、只追加事件、receipt 和可重算账本；
- GGUF/safetensors 安全验证及危险反序列化格式拒绝；
- 隔离安装的 llama.cpp、受管本地服务和请求后 slot erase；
- 节点心跳、租约、重试、精确设备绑定和两次策略检查；
- application RTT、两阶段定点路由、Tier 和双轨经济；
- public canary、签名 private hidden catalog 和跨实例仲裁；
- OpenAI-compatible 本地代理，覆盖 chat、completions 和 Standard SSE；
- 服务端权威贡献进度和隐私阈值匿名荣誉榜；
- Docker、Cloudflare、安装、发布和 CI 模板。

## 关键行为合同

- 用户界面、帮助、状态和普通错误使用简体中文；协议字段、API 路径和结构化日志键保持稳定英文。
- 金额全部使用整数 microquota；准备金、结算、profile provisioning 和结果提交在事务中完成，账本和审计事件只追加、幂等、可重算。
- 领取任务前和真正调用推理引擎前各检查一次节点策略；策略变化必须在 llama HTTP 前失败关闭。
- 同账号不同设备不能接管同一 node、model instance、lease 或 private challenge。
- private v2 只保存 domain-separated HMAC commitment，不保存 raw catalog identifier、bare prompt SHA、bare expected SHA、Prompt 或 Response 明文。
- private 预算由 PostgreSQL 按固定锁序执行；跨 catalog global reserve 不能退化为单进程状态。
- 省略 llama.cpp 版本时精确选择 audited `b10064`；受管进程固定为四个隔离 slot：slot 0 只供本机代理，slot 1..3 供贡献任务，`max_concurrent` 只能在 `1..=3` 内收紧，不能用节点自报扩张容量。
- 受管 llama.cpp 显式启用统一 KV 缓存，避免固定四槽把单请求上下文静态切成四份；本机请求精确 erase slot 0，贡献请求精确 erase 获分配的 slot 1..3，清理失败不得提交成功或结算。
- 跨主机网络使用 TLS；HTTP 只允许明确的 loopback 开发源站。
- Standard payload 是 Base64/Base64URL JSON，不具保密性，不能承载敏感或受监管数据。
- Regulated 只有在真实硬件、固件、collateral、verifier、adapter、allowlist、固定路由和消费者复验完整通过时成立；缺项时失败关闭，不回退 Standard。

完整边界见 [安全文档](docs/SECURITY.md) 和 [ADR](docs/adr/)。

## 物理参考上界计费

当前选择的计费合同是 `server_reference_upper_bound_v1`，不是节点实际 GPU 计量，也不是硬件执行证明。金额由协调器授权的输入 token 上界、最大输出 token 上界和 operator 发布的不可变参考 profile 决定；Token、参考 GPU 时间和参考显存积分三个分项分别向上取整，再得到冻结的 `C_base`。节点上报的实际 token、GPU、显存和 TPS 不进入金额。

- 0032：增加不可变 `billing_profiles`、legacy allowlist，以及 job、Regulated route、receipt 的完整 26 字段冻结快照。
- 0033：增加服务器侧 `billing-profile-record` 唯一写入口；profile 和只追加 operator audit 原子写入，支持精确幂等 replay，runtime role 不能直接 INSERT profile。
- 0034：升级前拒绝仍可执行的旧任务和未过期 prepared route；保留终态 legacy 历史；所有新 job、route、receipt 必须携带完整 v1 snapshot。
- 0035：为 Standard 流式任务增加只追加、AEAD 静态保护的事件通道；chunk 不结算，最终 result 仍是唯一结算入口。相关 package、`schema_v35` 定向测试和 fresh-v37 数据库组合门禁已通过；历史 debug 隔离 E2E 已用真实 GGUF 验证 chat/completions 两类 SSE、游标故障恢复、密文事件和唯一终态结算。
- 0036：增加只追加 `sla_exclusion_events` 和 coordinator-only 审计写入口；只有已审计的失败任务能缩小公开 SLA 分母，cancelled 审计只进入类别计数，节点或 worker 自报的 `error_class` 永不自动排除。migration shape、幂等/冲突、ACL、治理公式和协议兼容均有定向测试，且已纳入 fresh-v36 `41/41` 数据库门禁。
- 0037：增加邮箱/password 身份与邮箱验证，但不建立浏览器 bearer 通道。CLI 仍统一使用 Ed25519 Device Flow；浏览器只把已验证账户授权给终端显示的 12 位 `user_code`，最终 `/v1/auth/device/poll` 必须验证设备签名后才返回令牌。

仓库不内置生产费率。Development/Production 缺少 profile、profile 过期、模型权重不匹配或最高 active version 上界不足时必须失败关闭，不能回退旧 profile。当前实现保存 evidence 文件 SHA-256、请求/profile fingerprint 和 operator audit；不要把它描述成“签名 profile”。

公式、冻结和轮换语义见 [续接文档](docs/HANDOFF.md#23-0032物理参考上界计费合同)。

## 贡献路由

`contribution-routing-v1` 只在以下条件同时满足时用最近 30 天贡献值的确定性 midrank percentile 破近同分：

- 唯一节点 cohort 至少 5 个；
- 数据库可见 ready demand 大于服务端计算的 free slots；
- 候选基础路由分位于最佳值 2% 内。

质量、成本、信任、健康、策略和容量硬过滤始终优先。非拥堵、小 cohort 或非近同分时保持原路由顺序；节点自报并发量不能扩张服务端容量。

`mindone share stats` 还会使用服务端权威累计贡献值展示固定宽度里程碑进度条；JSON 输出保留整数 microquota、区间和 `progress_ppm`，不混入 ANSI。全网荣誉榜只返回匿名档位和人数下界，不返回 user/device/node/model 标识或精确低样本记录；贡献 cohort 小于 5 时整表抑制，并列节点共享 midrank 档位。协议兼容、协调器纯逻辑、CLI 和 fresh PostgreSQL 路径已纳入当前证据；最终 workspace 门禁与四槽确定性回归已通过，真实 GGUF/SSE E2E 属于四槽改动前的历史证据。

## 当前验证状态

当前可诚实复用的结果是阶段性证据，而不是最终发布证明：

| 验证 | 阶段性结果 | 当前含义 |
|---|---:|---|
| 历史 fresh v36 PostgreSQL 组合 gate | `41/41`，无 skip | 历史隔离库 `mindone_gate_0036_full_20260719b`；不证明当前 v39 |
| 历史 v36 migration metadata | `36|1|36|t` | 历史 fresh 数据库 `_sqlx_migrations` 查询 |
| fresh v37 PostgreSQL 组合 gate | `43/43`，无 skip | 隔离 PostgreSQL 17；14 个 coordinator integration binary，metadata `37|1|37|t` |
| fresh v39 PostgreSQL 组合 gate | `49/49`，无 skip | 一次性 PostgreSQL 17；16 个 binary 各用独立数据库，持久库 metadata `39|1|39|t` |
| 当前 workspace fmt / check / strict Clippy / tests | 通过 | 31 个 result set，`590 passed / 0 failed / 5 ignored`，退出 0；ignored 保留外部资源与平台能力边界 |
| common bounded-file tests / Clippy | `24/24` / 通过 | evidence TOCTOU 共用层定向证据 |
| operator billing / quality | `4/4` / `4/4` | 当前 evidence 接入定向证据 |
| v35 SSE package tests | protocol `45/45`、CLI `130`、coordinator `105/105` | CLI 另有 1 ignored；相关 package check/Clippy 已通过 |
| v35 SSE PostgreSQL schema | `1/1` | 真实 PostgreSQL 定向验证密文、只追加和最小 ACL；另已进入 fresh-v36 组合 gate |
| 贡献进度/匿名榜定向测试 | protocol `1`、coordinator `3`、CLI `1`、PostgreSQL `1/1` | 小 cohort 抑制、人数粒度和并列 midrank 的定向证据 |
| 0036 audited SLA exclusion | protocol `2`、operator `4`、公式 `5`、命令 `2`、PostgreSQL `1/1` | 定向验证协议兼容、审计入口、公式与 schema/ACL；另已进入 fresh-v36 组合 gate |
| ModelScope 官方 repo-files discovery | CLI model `11/11`、download `5/5`、mock `5/5` | 官方 API 形状、本地可信 SHA 与消歧逻辑已验证；真实公网 artifact smoke 仍待 |
| llama.cpp 默认版本与精确选择 | `2/2` | 省略 `--version` 固定 audited `b10064`；更新版本不会遮蔽受管默认 |
| 本地受管并发策略 | share 并发/刷新 `2/2`，engine 参数 `1/1` | slot 0 与贡献 slot 1..3 隔离；`max_concurrent=1..3` 对应真实独立槽，并发任务使用不同 `id_slot` 且分别确认 erase |
| 独立 serve 请求后清理代理 | proxy 清理、贡献双槽并发、CPU-only/清理定向测试与 engine strict Clippy 通过 | workspace 验证 slot 0 强制绑定及 slot 1..3 独立清理；公开 Linux E2E 已用当前四槽/统一 KV 参数走到 stop/unpublish 完成，精确候选终态仍受完整 CI 门禁约束 |
| Standard SSE / 真实 GGUF E2E | 历史 debug 从头通过；当前公开 Linux E2E 已完成真实业务链 | 当前四槽参数已实际覆盖 PostgreSQL v39、双账号/device、真实 b10064 + Qwen3-0.6B-Q4_0、非流式双端点、两类 SSE、游标故障恢复、密文、三轨唯一结算、策略拒绝零结算、Regulated 流式拒绝与清理；最终日志审计现按权威非默认端口日志路径及轮转代执行 |
| Unix 安装 URL 负例 smoke | 通过 | 拒绝凭据、query、fragment、伪 loopback 等 |
| CI/开发 Compose 门禁 | 当前树与公开 Actions 已通过 | production Compose TLS/connector 隔离已在公开 Linux Runner 验证；独立 Cloudflare Tunnel、DNS 与公网请求仍须另行验收 |
| 当前二进制 release archive smoke | 通过 | `mindone 1.0.2` / `aarch64-apple-darwin`；验证归档 SHA-256、安装、`--check`、重装、中文 help、doctor JSON、默认保留数据卸载与 purge；仅为 unsigned local smoke |

历史 fresh-v36 `41/41` 与 fresh-v37 `43/43` 是可信的阶段证据，但不能证明当前 v39、完整 Rust workspace、真实模型链或外部发布。当前 0038/0039 已在全新隔离 PostgreSQL 17 上取得上述定向证据；旧共享测试库和所有证据库包含故意持久化的状态，不得 drop、truncate、清理或复用。

`scripts/e2e-test.sh` 的历史 debug 工作树曾从头退出 0；公开 Linux Actions 随后用当前四槽/统一 KV 参数实际跑完 fresh PostgreSQL v39、两个账号/device、真实 llama.cpp `b10064` 与 `Qwen3-0.6B-Q4_0.gguf`，并覆盖 public canary worker 终态、chat 与 `/v1/completions` 非流式、两类 SSE、同一 downstream 连接中的非零游标故障恢复、Standard AEAD ciphertext、消费/节点贡献/网络准备金三轨唯一结算、执行前策略改变拒绝且零结算、Regulated `stream:true` HTTP 400 拒绝，以及 stop/unpublish 清理。最后的 Prompt/Response 日志扫描会从 `serve --json` 的权威 `log_path` 精确定位非默认端口日志并扫描轮转代；该恢复断言不表示公开 API 支持客户端重新 POST resume token。

本轮真实执行还暴露并修复了 CPU-only 参数边界：`cpu_only` 现在是 `ServeRequest` 的类型化受管策略，由引擎层注入设备与 offload 禁用参数，不再编码成可被安全校验拒绝的未受信 `additional_args`。确定性测试另覆盖 reasoning-only、无可见 `content` 的响应立即失败关闭，协调器对 result 的确定性 HTTP 400 转为一次脱敏 terminal failure，以及活动 worker 的策略文件在运行期被删除、损坏或替换为符号链接时失败关闭。

这些是本机 debug、单 Standard GGUF 的隔离证据，不代表 GitHub Actions、正式签名发布、外部 SMTP/浏览器链、真实 TEE、private hidden 双 GGUF 或 production 部署已经通过。

## 后续收口顺序

后续改动先读 [docs/HANDOFF.md](docs/HANDOFF.md)，并按以下顺序收口：

1. 每次先采集 Git、端口和 Docker 状态，保护 production `18787` 与全部证据库。
2. 修改源码后串行重跑 fmt、workspace check、strict Clippy、workspace tests 和相关 fresh PostgreSQL 门禁；当前基线为 workspace `590/0/5` 与 fresh-v39 `49/49`。
3. 后续修改引擎、worker、代理、SSE 或结算路径时，在不冲突的 loopback 端口重跑真实 GGUF E2E；当前四槽/统一 KV 路径与端口感知日志审计以精确候选提交的 Actions 终态为发行依据。
4. 模型下载测试优先使用 `model probe --deployment` 的 64 KiB 上限；只有明确需要时才在独立临时 `MINDONE_HOME` 完成完整 artifact smoke，并另建 private hidden 双真实 GGUF harness。
5. 修改发行相关源码后重跑 release archive/install/uninstall smoke；当前 `aarch64-apple-darwin` 二进制闭环已通过。
6. GitHub 与 Cloudflare 只按已经明确授权的对象继续；production 仍必须另取包含停机风险的维护窗口确认，并在备份恢复演练、任务排空和回滚方案齐备后切换。

## 从源码验证

需要 Rust 1.88、Docker 和 Docker Compose。本机内存压力高，命令必须串行：

```bash
cd /Users/beluga/Documents/MindOne
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=1

cargo +1.88 fmt --all -- --check
git diff --check
cargo +1.88 check --locked --offline \
  --workspace --all-targets --all-features -j1
cargo +1.88 clippy --locked --offline \
  --workspace --all-targets --all-features -j1 -- -D warnings
cargo +1.88 test --locked --offline \
  --workspace --all-targets --all-features -j1 -- \
  --test-threads=1
```

当前工作树已取得 fmt/check/strict Clippy、workspace `590 passed / 0 failed / 5 ignored` 和 fresh-v39 `49/49`。当前平台 release smoke 与 debug 隔离真实模型 E2E 仍是 0038/0039 前的历史证据；未设置 `DATABASE_URL` 的 skip 不算数据库通过。

## 本地开发

本地开发 Compose 使用独立 loopback 端口，不得占用现有 `8787` 或 production `18787`：

```bash
export MINDONE_DEV_POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export MINDONE_DEV_STANDARD_DATA_KEY="$(openssl rand -hex 32)"
export MINDONE_COORDINATOR_HOST_PORT=18789

docker compose --env-file /dev/null \
  -f deploy/docker-compose.dev.yml up -d --build
curl "http://127.0.0.1:${MINDONE_COORDINATOR_HOST_PORT}/health"
curl "http://127.0.0.1:${MINDONE_COORDINATOR_HOST_PORT}/ready"
```

开发栈会先由同镜像的一次性 `database-migrator` 以数据库 owner 连接完成当前镜像内的连续 migration（当前目标 `0001..0039`）；只有该服务成功退出后 coordinator 才启动。因此全新空卷可直接启动，而迁移失败不会伪装成 ready。容器内监听始终是 `8787`，`MINDONE_COORDINATOR_HOST_PORT` 只修改 loopback 宿主端口。

仓库还提供 `scripts/mvp-dev-smoke.sh` 编排开发栈 smoke。脚本默认生成一次性开发凭据；调用者需要覆盖时，Secret 只接受专用环境变量 `MINDONE_DEV_POSTGRES_PASSWORD` 和 `MINDONE_DEV_STANDARD_DATA_KEY`，旧的命令行 Secret 参数会在启动 Docker 前拒绝且不回显原值。诊断材料只写入仓库外由 `mktemp` 创建的 `0700` 目录，并通过退出与信号清理路径删除；CLI 检查统一绑定该目录下的隔离 `MINDONE_HOME`，不读取真实用户会话或改写默认配置。`scripts/mvp-dev-smoke-contract-test.sh` 已在本机通过并接入 CI，验证凭据注入、CLI Home 隔离、目录权限、退出清理与 Docker 构建上下文边界；它使用本地命令替身，不等于本轮已经重跑完整 Docker smoke。

生产 Secret、TLS、private v2 和 Cloudflare 的分层验证见 [运维文档](docs/OPERATIONS.md)。

## 数据库和升级边界

目录当前包含连续 `0001..0039`。runtime 会对 migration 版本、描述、成功状态和 checksum 精确失败关闭；常驻 coordinator 不自动迁移数据库。

production 仍为 v26。数据库 owner 必须显式运行 `mindone-coordinator database-migrate`，常驻应用只使用最小权限 runtime role。升级 v26 -> 当前最终 schema（工作树目标 v39）前必须：

1. 获得维护窗口授权并停止所有 writer；
2. 完成可恢复备份和隔离恢复演练；
3. 排空或取消 `queued/leased/retry` 任务并按账本释放准备金；
4. 消费、作废或等待旧 prepared Regulated route 过期；
5. 准备独立 private Secret/预算和经审核的生产 billing profile；
6. 在隔离副本验证 migration、runtime role、health/ready、401 和回滚方案。

0034 的存在不等于 production 可直接升级。

## 安装与基本使用

正式 SemVer 标签（例如 `v1.0.0`）进入稳定通道，带 `-rc.1` 的标签只创建预发布。Apple/Windows 签名和 notarization 必须按发行物真实状态披露。

```bash
curl -fsSL https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.sh \
  | sh -s -- --launch
```

`--launch` 安装并校验成功后在交互式终端直接进入 TUI；非交互环境只执行真实帮助页验证。安装器默认只把安装目录写入当前用户的受管 shell PATH 块（Windows 为用户 PATH），新终端可直接输入裸 `mindone`；受控环境可用 `--no-modify-path` / `-NoModifyPath` 关闭。父 shell 无法被子脚本反向修改，因此若不使用 `--launch` 且要在当前 Unix 终端立即调用，可执行：

```bash
export PATH="$HOME/.local/bin:$PATH"
mindone --version
mindone doctor
mindone auth login # 全新配置默认连接 https://api.holarchic.cn
mindone engine detect
mindone engine install --name llama.cpp
mindone model deploy auto
```

公开仓库和 raw 安装器已经可匿名读取：[GitHub 仓库](https://github.com/beluga383/MindOne)、[Unix 安装器](https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.sh) 和 [Windows 安装器](https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.ps1)。`v1.0.0` 与 `v1.0.1` 标签均因各自 Release 门禁失败而保留且不会强制移动，下一补丁版使用 `v1.0.2`。在新 Release 资产实际生成前，远程安装器会继续失败关闭，不能把 raw 脚本可达冒充二进制已经发布。完整安装、升级和卸载步骤见 [docs/INSTALL.md](docs/INSTALL.md)。

### 终端图形界面（TUI）

在交互式终端中直接输入 `mindone`（或显式 `mindone ui`）即可打开新版终端工作台。顶部展示账户、信任级别和协调器，主体分为 Space、Action、Overview、Activity，底部保留安全命令预览。10 类动作精确覆盖 CLI 的 40 个公开叶子命令，并支持紧凑/宽屏响应式布局。`M` 打开 65 模型选择器，`R` 生成本机推荐，`D` 自动部署推荐首项，`?` 打开界内帮助；`1-9` 与 `0` 对应 10 个 Space。

```bash
mindone            # 交互式终端：打开图形界面
mindone ui         # 显式打开图形界面
mindone <命令>     # 带子命令时按命令行处理，行为不变
```

选中动作后可在编辑区补齐或修改完整参数，因此 TUI 能执行 CLI 的全部公开叶子能力，并复用同一套本地化 Clap 校验与业务处理函数。模型选择器只负责目录、硬件推荐和安全地构造部署命令；真正下载时仍实时核验 HF 产物、SHA-256、GGUF 结构和内存预算。编辑器支持单引号、双引号和反斜杠安全分词，输入不会交给 shell，也不会执行变量、管道、重定向或命令替换；隐藏的内部 `__worker` 命令会被拒绝。认证、写入及启动/停止等生命周期动作执行前必须再次按 `y` 确认。命令执行期间 TUI 会退出备用屏幕和 raw 模式，回到普通终端承载交互、`-v/--verbose` 日志或长期运行的输出，命令结束后自动恢复工作台；结果区保留原始输出和 `exit_code`，退出 TUI 时进程返回最近一次业务命令的退出码。在管道、重定向或非交互环境中，裸 `mindone` 回退为显示帮助，`mindone ui` 返回“需要交互式终端”的明确错误。

2026-07-22 另在仓库外的隔离安装根执行真实 `cargo install --locked --path crates/mindone-cli --root <临时目录>`：最小 PATH 下裸 `mindone --version` 与非交互裸 `mindone` 均退出 0，真实 80×24 PTY 中裸 `mindone` 进入上述工作台并由 `q` 正常恢复终端、退出 0。该证据覆盖当前 macOS arm64 源码安装；Linux/macOS/Windows 的原生 Actions 另有分层证据，但正式远程安装仍依赖尚未产出的 Release 资产。

同日当前源码还在 Linux arm64、Rust 1.88、无网络且源码只读的容器中通过全 workspace check；CLI library `173/0/1`、入口 `4/0/0`、Linux 适用的二进制合同 `7/0/0` 均通过，release 裸命令和 80×24 PTY TUI 分别以 0 退出。运行过程中发现并修复了业务单元测试误依赖桌面 DBus/Secret Service 的问题：仅测试环境改用内存 SecretStore，production 仍只使用系统凭证库。

同日 Windows x86_64 MSVC 交叉门禁也已补齐：经官方哈希校验的 `cargo-xwin 0.23.0`、Microsoft SDK/CRT 与 `llvm-mingw 20260616` 工具链完成全 workspace/all-target/all-feature check 和 `-D warnings` 严格 Clippy；实际 release 产物为 17 MiB `PE32+ console x86-64`。项目的 `.cargo/config.toml` 对 Windows target 固定启用静态 CRT，导入表不含 `VCRUNTIME140.dll`、`MSVCP*.dll` 或 `api-ms-win-crt-*`，同时确认三个 Job Object API 存在。公开 `windows-latest` job 随后通过原生编译、`dumpbin`、PowerShell 安装/替换、PATH 无损合同、安全拒绝和默认/purge 卸载；交互 TUI、Credential Manager、Job Object 生命周期与真实模型启动仍由用户 Windows 真机验收。

## 文档

- [当前停止点、后续任务与验收行为](docs/HANDOFF.md)
- [CLI 逐命令/逐参数合规矩阵](docs/CLI_COMPLIANCE.md)
- [API](docs/API.md)
- [安装](docs/INSTALL.md)
- [模型目录与一键部署](docs/MODELS.md)
- [运维](docs/OPERATIONS.md)
- [安全](docs/SECURITY.md)
- [多人协作](docs/COLLABORATION.md)
- [ADR](docs/adr/)
- [原始规格与当前执行边界](docs/specs/README.md)
- [实施计划](docs/IMPLEMENTATION_PLAN.md)（v39 最终 gate 结果以 `docs/HANDOFF.md` 的真实回填为准）

## 参与贡献

每位贡献者使用独立分支并通过 Pull Request 合并，不直接推送 `main`。详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

代码以 Apache License 2.0 发布。模型权重不属于本仓库，下载和使用时必须遵守各模型许可证。
