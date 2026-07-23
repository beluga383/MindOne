# MindOne 协调服务器 API

版本：v1.0.2<br>
本地开发基址：`http://127.0.0.1:8787`<br>
目标公网基址：`https://api.holarchic.cn`；根域 `https://holarchic.cn` 保留现有官网，只有部署方完成 API 子域的 Cloudflare、TLS、鉴权和端口审计后才可声明实际上线

除 `/health`、`/ready`、设备登录、刷新、只读透明度报告，以及仅在 email provider 下挂载的同源 `/auth/*` 浏览器页面外，所有 `/v1` 接口都要求 Bearer 凭证。`mna_` 短期访问令牌用于账户/节点/管理接口；`mok_` API Key 只允许模型发现和 OpenAI 推理端点，不能访问节点、额度或运维接口：

```http
Authorization: Bearer <短期访问令牌>
Content-Type: application/json
```

访问令牌和刷新令牌在数据库中只保存带服务器 pepper 的 HMAC-SHA-256 摘要。访问令牌默认 15 分钟失效；刷新时同时轮换访问令牌、刷新令牌和一次性 refresh challenge。服务器不记录 Authorization、Prompt、Response 或请求体。受管引擎当前只接受经过审计的 llama.cpp b10064：启动前必须确认其精确支持 `--log-disable` 与 slot 动作端点所需的 `--slot-save-path`，随后固定注入这些参数、清除日志环境覆盖并拒绝高级配置重新打开请求日志；若能力探测失败则拒绝启动。worker 上报失败时，守护日志只保留 `job_id`、稳定 `error_type` 和 HTTP status，不记录远端不受信 `/error/message` 正文。

## 通用错误

```json
{
  "ok": false,
  "code": 40,
  "error": {
    "type": "insufficient_quota",
    "message": "可用额度不足"
  }
}
```

稳定业务码：

| code | 含义 |
|---:|---|
| 1 | 通用、参数、冲突或服务错误 |
| 10 | 登录、令牌或权限失败 |
| 30 | 硬件证明、本机 verifier、报告绑定或 Regulated envelope 失败 |
| 40 | 可用额度不足 |
| 50 | 节点策略拒绝 |

服务器还使用标准 HTTP 状态码，例如 `400`、`401`、`403`、`404`、`409`、`413`、`429`、`503`。

## OpenAI 兼容推理与 API Key

### `POST|GET /v1/api-keys`、`DELETE /v1/api-keys/{id}`

这三个管理动作只接受已登录设备的 `mna_` 访问令牌。创建请求为
`{"name":"production"}`；响应中的 `mok_...` Secret 只返回一次，数据库只保存带
服务器 pepper 的 HMAC-SHA-256、12 字符前缀和审计元数据。列表不返回 Secret；
DELETE 为幂等撤销，created/revoked 事件只追加。Key 绑定创建 session/device，注销
会话、撤销设备或撤销 Key 都会使推理认证失败。

### `GET /v1/models`

接受 `mna_` 或 `mok_`。OpenAI `data` 列表对每个实际在线且通过门禁的模型返回
`name-fast`、`name`、`name-slow`；响应暂时还保留 `models` 实例明细供 MindOne CLI
兼容。`-fast` 只选择 `active_count=0` 的整台空闲贡献端，再按真实 TPS 排序；无后缀
保留原有质量/健康排序，但也只选择整台空闲贡献端。因此 standard/fast 不会被调度到
已有贡献任务的同一进程，物理上尚有 slow slot 也不静默降档或争抢算力。`-slow` 才会
在服务端真实容量内优先把任务放到已有负载的节点，并在所有候选都达到上限时排队。
官方贡献客户端为本机代理保留 slot 0，并为贡献任务提供三个相互隔离的 slot 1..3；
节点主可用 `max_concurrent=1..3` 收紧容量，服务端只能按真实租约和有效心跳收缩容量，
不能按节点自报扩张。standard/fast 没有整台空闲贡献端，或 slow 的真实贡献 slot 全满
时，任务保持 `queued/retry`，按原 `priority DESC, created_at ASC` 队列等待；公网同步调用
超过协调器有界等待时间后会取消任务并事务释放预留额度，而不是留下永久占款。

### `POST /v1/chat/completions`、`POST /v1/completions`

目标 Base URL 为 `https://api.holarchic.cn/v1`，认证为
`Authorization: Bearer mok_...`。非流式响应采用 OpenAI JSON；`stream=true` 返回
`text/event-stream`，透传经服务端校验并以 AEAD 静态保护的真实 OpenAI data 增量，
以数据库连续 `sequence` 作为 SSE `id`，空闲时发送注释 keepalive，并且只输出一次
`data: [DONE]`。网关创建真实 Standard job，沿用额度预留、节点选择、两次策略检查、
结果验证和事务结算；等待超时时会取消未终态任务并在同一事务释放预留额度，然后在
SSE 中返回 OpenAI error data 和 `[DONE]`。公开网关不接受客户端 resume token 或
`Last-Event-ID` 续传；断线重连会创建新请求，不能把协调器内部游标恢复描述成公开重放 API。

## 健康检查

### `GET /health`

进程存活检查，不访问数据库。

### `GET /ready`

执行真实的 PostgreSQL `SELECT 1`。数据库不可访问时返回 `503 database_not_ready`。

## 公开透明度与 SLA 聚合

### `GET /v1/transparency/report?window_days=30`

无需登录。`window_days` 默认 30，允许 1 到 366。报告窗口上界取自同一 PostgreSQL 可重复读、只读事务的数据库时钟，协调器在该事务中直接聚合权威账本和任务状态，不读取状态文件，也不返回用户、节点、设备、IP 前缀或 ASN 标识符。

响应包含：

- `contributor_rewards`：按窗口内 receipt 的 `node_user_id` 聚合贡献账户，`contributing_accounts` 是不同贡献账户数，不是物理节点数。`spendable_quota` 分别报告 `node_quota_micro` 奖励的总额、最小值、中位数、P90 和最大值；它表示窗口内获得的可消费额度，不是账户当前余额。`contribution_points` 用同样五项统计报告不可消费的 `contribution_micro` 贡献积分。两条轨道不会相加。
- `contributor_rewards` 的两条分布共用 5 个贡献账户的隐私阈值。少于阈值时 `distribution_available=false`，两条轨道的十个统计值同时返回 `null`；达到阈值时同时返回真实聚合值。该抑制仅降低小样本暴露风险，不构成匿名性或差分隐私保证。
- `anti_abuse.blocked_assessments`：窗口内服务端权威 `decision=block` 决策数，不是被封用户数。
- `reserve`：当前准备金余额，以及窗口内只追加准备金账本的流入和流出。
- `sla`：窗口内已经被协调器接纳的任务队列 cohort。有效分母仅为当前已经到达 `succeeded` 或 `failed` 的任务；排队、租约、重试任务单列为 pending，取消任务单列且不进入分母。成功率和 99.5% 目标均使用整数 ppm。

`quota_exhaustion_before_admission`、`malformed_request_before_admission` 和 `unsupported_model_or_no_route_before_admission` 不产生任务行，因此不进入 cohort。只有 coordinator-only、只追加的 `sla_exclusion_events` 能把已经失败的 `content_policy_refusal` 或 `force_majeure` 从公开 SLA 分母排除；节点/worker 自报错误类别没有此权限，cancelled 事件只进入类别计数。没有终态任务时成功率与 `target_met` 返回 `null`。

## 身份认证

### 邮箱浏览器页面（仅 `MINDONE_AUTH_PROVIDER=email`）

以下页面与 coordinator 同源，不返回 API bearer token：

- `GET|POST /auth/register`：注册规范化邮箱账户，并发送一次性验证邮件；数据库只保存验证 token 的带服务器 pepper HMAC。
- `GET /auth/verify-email?token=...`：只显示显式确认页，不修改邮箱状态，避免邮件安全扫描器自动激活账户。
- `POST /auth/verify-email`：用户在同源确认页提交一次性验证值后激活邮箱。请求日志只记录 `/auth/verify-email` path，不记录 query 或表单正文。
- `GET|POST /auth/login`：用户登录后，手工输入 CLI 终端显示的 12 位 `user_code`，把该账户授权给一个尚未过期的 email Device Flow。

CLI 收到的 `verification_uri` 必须精确为 coordinator 同源 `/auth/login`，且没有 query 或 fragment。用户应先核对浏览器 origin，再手工输入终端代码；不要相信邮件、聊天或陌生网页提供的代码。浏览器只设置 flow 的授权状态，不接收 access/refresh token。最终令牌仍只能由下面的 `/v1/auth/device/poll` 在验证 CLI 的 Ed25519 设备签名后返回。

password reset 尚未实现；当前没有 `/auth/forgot-password`、`/auth/reset-password` 或等价公开合同。

### `POST /v1/auth/device/start`

启动 OAuth 2.0 Device Flow。生产环境只允许显式配置并完成启动校验的 GitHub 或 email 提供者；`local-development` 仅限 development/test。

CLI 必须提交规范小写十六进制的 Ed25519 公钥和算法，用于服务端绑定、轮换与私钥持有证明；生产和本地开发提供者都不允许省略：

```json
{
  "device_public_key": "<64 个小写十六进制字符>",
  "device_key_algorithm": "ed25519"
}
```

GitHub 用户身份始终来自 GitHub Device Flow，客户端提交的公钥不能覆盖 provider subject。

响应字段：`flow_id`、`user_code`、`verification_uri`、`expires_in`、`interval`、`device_challenge`。`device_challenge` 是服务端使用 CSPRNG 生成的 32 字节一次性 challenge，以小写十六进制编码。

### `POST /v1/auth/device/poll`

```json
{
  "flow_id": "019...",
  "device_key_signature": "<Ed25519 签名的 128 个小写十六进制字符>"
}
```

签名消息使用版本化域分离格式，绑定 `flow_id`、随机 challenge、原始公钥和 `ed25519` 算法；服务端在调用 OAuth provider 和更新轮询时间前先验证签名，错误 flow 或重放到另一登录流都会失败。等待授权时返回 `202`；授权成功后返回短期 `access_token`、可轮换 `refresh_token`、一次性 `refresh_challenge`、用户信息和服务端计算的 `device_key_fingerprint`。CLI 必须核对该指纹后才可把会话、challenge 与私钥写入系统凭证库。轮询间隔由服务端强制执行。

### `POST /v1/auth/refresh`

```json
{
  "refresh_token":"mnr_...",
  "device_key_signature":"<128 个小写十六进制字符>"
}
```

签名使用域 `MindOne refresh key possession v1`，绑定服务端上次返回的 32 字节
`refresh_challenge`、当前 refresh token 的 SHA-256、原始 Ed25519 公钥与算法。服务端
联表读取会话绑定的未撤销设备密钥并验证签名；单独窃取 refresh token 无法刷新。
成功后在同一事务中轮换访问令牌、刷新令牌和 challenge；旧 token、旧 challenge 或
旧签名重放均返回 `401`。迁移前没有 challenge 的旧会话 fail closed，必须重新登录。

### `POST /v1/auth/logout`

```json
{"refresh_token":"mnr_..."}
```

撤销对应会话及其绑定设备密钥；同一设备密钥绑定的其他活动会话也一并撤销。重复使用同一真实刷新令牌注销是幂等操作，但随机或不存在的刷新令牌返回 `401`，不会伪报成功。

### `GET /v1/auth/status`

使用当前 Bearer token 返回服务端权威身份、会话登录/最近使用时间、绑定设备密钥指纹及撤销状态、注册节点数量和最佳节点信任等级。登录设备目前没有独立 attestation 证据，因此顶层 `trust_level` 明确返回 `unverified`；节点信任放在 `best_node_trust_level`，CLI 探测到的本地 sandbox 能力也必须另列，不能冒充服务端认证结果。

`local-development` 提供者只可在 `MINDONE_ENV=development|test` 时显式启用。它以原始 Ed25519 公钥字节的 SHA-256 作为确定性 subject，与服务端展示的设备指纹使用完全相同的算法：同一设备重复登录仍映射到同一账户，不同设备映射到不同账户。它用于离线集成测试，绝不是生产认证回退路径，也不接受客户端直接指定任意 subject。

### `POST /v1/auth/attestation/challenge`

为当前用户拥有、且已经发布模型实例的 Linux 节点创建一次性硬件证明挑战：

```json
{
  "node_id":"019...",
  "model_instance_id":"019...",
  "provider":"amd_sev_snp",
  "sandbox_policy_hash":"<64位小写SHA-256>",
  "runtime_binary_hash":"<64位小写SHA-256>",
  "ephemeral_public_key":"<32字节X25519公钥的小写十六进制>",
  "key_origin":"tee_runtime"
}
```

`provider` 只允许 `amd_sev_snp` 或 `intel_tdx`。服务器必须已经为对应 provider 配置固定 verifier 路径，以及沙盒策略、运行时和 TEE measurement allowlist，否则 fail-closed。响应中的 64 字节 `report_data` 绑定 challenge、节点、模型实例、一次性 nonce、策略哈希、运行时哈希、模型权重哈希、临时 X25519 公钥和 `key_origin`。Regulated 数据面只接受 `tee_runtime`；旧的 CLI 软件密钥来源 `control_software` 即使报告状态是 verified 也不能启用 Regulated。

### `POST /v1/auth/attestation/submit`

```json
{
  "challenge_id":"019...",
  "provider":"amd_sev_snp",
  "evidence_kind":"snp_extended_report",
  "evidence":"<厂商证据的标准base64>"
}
```

AMD 只接受 `snp_extended_report`，Intel TDX 只接受 `tdx_quote`；裸 TDREPORT 明确拒绝。服务器在事务中锁定并一次性消费 challenge，通过固定外部 verifier 验证 REPORTDATA、硬件签名、证书链、TCB、collateral 和 TEE measurement。只有全部通过才把节点升级为有期限的 `enhanced`；失败、过期或重放均不升级。Linux CLI 通过固定绝对路径 `MINDONE_TEE_RUNTIME_PATH` 调用 TEE runtime adapter；凭证库只保存不透明 `key_handle`，不接收或保存 TEE X25519 私钥。

## 节点

### `POST /v1/nodes/register`

```json
{
  "alias":"m4-node",
  "hardware_profile":{
    "operating_system":"macos",
    "operating_system_version":"15",
    "architecture":"aarch64",
    "cpu_model":"Apple Silicon",
    "cpu_logical_cores":10,
    "ram_total_mib":16384,
    "gpus":[],
    "cuda_available":false,
    "metal_available":true,
    "sandbox_mechanisms":["seatbelt"]
  },
  "reject_tags":["private"],
  "max_concurrent":1,
  "gpu_temp_limit_c":null,
  "vram_reserve_mib":2048
}
```

协调器会对结构通过验证且沙盒机制无重复项的 `hardware_profile` 应用固定软件能力矩阵：macOS 的 Seatbelt/App Sandbox 为 `standard_limited`，且 macOS 最高只到该等级；Linux 同时声明 Namespaces、seccomp-BPF 和 Landlock 为 `standard`，仅 Namespaces + seccomp-BPF 为 `standard_limited`；Windows 声明 Job Objects、AppContainer 或 Hyper-V 时为 `experimental`；其余为 `unverified`。官方 CLI 不从“可用能力”填充该字段，只把当前 llama-server 启动计划确认的 `applied` 集合映射到协议：当前官方 Windows 路径仅在监督进程实际创建并持续持有 Job Object 时上报 `job_objects`，没有该监督进程时上报空集合；它不实现或上报 AppContainer/Hyper-V，Job Object 也只约束进程生命周期，不宣称文件系统或网络沙箱。

即使是未修改的官方 CLI 上报的 `standard` / `standard_limited`，也只是客户端对本次启动状态的观测自报；协调器没有远程观测软件沙箱是否真实生效，主机 root 或篡改客户端仍可伪报。这不是远程证明、设备身份或机密计算证据，不能产生 `enhanced`，也不能启用 Regulated 数据面。

新节点保持 `offline/awaiting_first_heartbeat`，直到服务端收到第一份有效心跳，杜绝 worker 启动前的短暂接单窗口。同一用户重复注册同一 `alias` 是幂等恢复操作：返回原 `node_id`，刷新硬件和策略并重新进入等待首心跳状态，不会创建重复节点，也不能夺取其他用户的节点。重复注册只在绑定的硬件报告仍为 verified、未过期、collateral 未过期且逐项验证仍有效时保留 `enhanced`；否则按当前软件矩阵降级并清除过期绑定。`gpu_temp_limit_c: null` 表示平台没有配置温控策略；设置整数阈值后，服务端会要求温度指标并采用 5°C 恢复滞回。

### `POST /v1/nodes/{node_id}/heartbeat`

```json
{
  "tps_milli":12500,
  "ttft_ms":180,
  "coordinator_rtt_ms":24,
  "current_concurrent":0,
  "gpu_temp_c":62,
  "vram_used_mib":4096,
  "vram_total_mib":16384,
  "error_rate_ppm":0,
  "draining":false,
  "policy": {
    "reject_tags":["private"],
    "max_concurrent":1,
    "gpu_temp_limit_c":null,
    "vram_reserve_mib":2048
  }
}
```

可选 `policy` 是 CLI 当前策略的完整快照。服务器在同一事务中校验并更新它，使领取前和续租前使用的拒绝标签、并发、温度及显存阈值与节点本地一致。不传时保留服务端现有策略。

官方 CLI 在 `share publish` 时持久化 `runtime/node-policy.json`，活动 worker 的领取前、执行前和心跳路径只从这份文件生成快照。文件缺失、损坏、符号链接、非普通文件或内容无效时 CLI 以 code 50 失败关闭，不用默认允许策略继续心跳、领取或执行。这里的“不传时保留”只描述第三方/旧客户端的 wire 兼容语义，不是官方 worker 的策略 fallback。

温度、显存保留或并发阈值触发时，服务器把节点置为 `paused` 并停止调度。已配置温度阈值但缺少温度指标时按 fail-closed 暂停；阈值为 `null` 时不检查温度。温度暂停后必须降到阈值以下 5°C 才恢复，避免临界值抖动。

`coordinator_rtt_ms` 是 worker 用单调时钟测得的**上一次成功心跳应用层往返时间**，范围为 `1..=60000` 毫秒；它包含连接/TLS、协调器处理、完整响应读取和 JSON 解码，不是纯链路 ping、用户端到端延迟或服务端主动测量。首次心跳省略该字段；401、刷新 Token、超时、HTTP 错误或坏响应均不生成样本，重试只计成功的第二次请求，绝不写 0 或用 TTFT 回填。该字段是可被节点影响的弱路由信号，不进入 Trust、Tier、结算或执行证明。

`tps_milli`、`ttft_ms`、`vram_used_mib` 和 `vram_total_mib` 仍只是最近一次心跳的节点自报瞬时样本，不参与任务指纹。任务完成请求另带 `execution_telemetry`：CLI 从执行前绑定复验到推理结束每 250ms best-effort 采样主机可见 GPU 设备集合总占用，并提交该窗口内观测峰值与采样数。Standard worker 把经授权的非流式请求在本机内部转为 llama.cpp SSE，用单调时钟记录从 HTTP 请求开始到首个非空 `content`、`reasoning_content` 或 completion `text` delta 到达的实测 TTFT，再重建原非流式 OpenAI 响应；初始 `assistant` role 事件不计作首 Token。`reasoning_content` 只参与首 Token 观测，chat 最终第一条 choice 仍必须有非空可见 `content`；reasoning-only 输出由 worker 本地作为执行失败提交。无首 Token 时保留 `null`，若终态 usage 反而声称生成了 Token 则整个结果失败关闭，不再用 prompt timing 派生估算。TPS 仍来自引擎终态 timing；这两个值都是 node-reported，不是协调器独立测得或经硬件签名的证明。设备集合峰值不是当前 job 的独占显存归因，短于采样间隔的尖峰也可能遗漏；平台或 timing 不可读时必须保留 `null`/0，服务端记为 `insufficient_evidence`，不得用心跳值补造指标。

协调器把每个已结算任务的原始遥测、发布模型 `size_bytes`、节点注册时自报的设备总显存和同模型/同硬件声明 cohort 历史基线写入只追加表，并由服务端生成 warning/critical 异常账本；相同结果幂等重放不会重复追加，改变遥测会触发绑定冲突。这个机制只做风险筛查，不改变结算、Tier 或贡献奖励。Standard 与 Enhanced 当前都属于 node-reported risk signal：没有 job/report/model/runtime 绑定的硬件签名，也没有可验证 GPU 计数器，因此 `no_anomaly_observed` 只表示保守基线下未观察到偏差，不是模型/GPU 执行证明。

### `GET /v1/nodes/{node_id}/stats`

返回已经进入终态的真实 attempt 去重任务数、成功/失败 attempt、最近指标、最佳 Tier、Trust、可用额度收益、贡献值和时间戳。最佳 Tier 只从仍为 `published` 且未被 canary 隔离的实例计算；没有合格实例时为 `null`，不得继续展示已取消发布或已隔离实例的历史 Tier。正在执行的 lease 不提前增加 `requests`，避免把领取后的即时计数变成任务类型标签。`uptime_seconds` 是两次相邻、由协调器接收且间隔不超过 90 秒的心跳之间的累计秒数；首个心跳前为 `null`，最后一次心跳之后不按墙钟增长，因此不是 `now-created_at` 伪在线时长。只允许节点所有者查看；CLI 仍可把本地 worker 进程运行时长单独列出。

`instance_canary_risk` 返回该节点仍发布或 draining 的精确实例聚合状态、连续失败数、恢复进度和固定阈值，使节点主能看到路由隔离并修复后恢复。它不返回 challenge ID、单次题目、答案、分数或任务级指纹；但是阈值转换本身在完成后可观察，因此不得把它描述为抗分类的隐蔽评测。任务级显存/延迟指纹和即时精确告警仍只保留在协调器内部只追加审计表。

`honor` 使用 `node-honor-v1` 服务端口径：贡献 percentile 在累计贡献大于零的全网节点 cohort 内用 midrank 计算，少于 5 个节点时抑制；下一贡献里程碑从 1 quota 起按十倍递增；连续零故障天数按 UTC 终态任务日计算，缺失日或 failed/expired 都会打断。CLI 只展示服务端字段，不从本地计数虚构排名或连续天数。`next-tier TPS` 仍不属于此接口。

## 模型

### `POST /v1/models/publish`

```json
{
  "node_id":"019...",
  "name":"tinyllama-test",
  "alias":"tinyllama-m4",
  "format":"gguf",
  "weights_hash":"<64位小写SHA-256>",
  "size_bytes":123456789,
  "context_length":2048,
  "benchmark_normalized":0,
  "glicko_normalized":0,
  "evaluation_samples":0,
  "base_cost_per_1k_micro":1000000,
  "tags":["chat","test"]
}
```

只接受 `gguf` 和 `safetensors` 元数据。文件头和完整结构仍必须由节点 CLI 在发布前验证；服务器不会把扩展名当作安全证明。三个质量兼容字段必须全部为 `0`；任何非零值返回 `400 client_quality_forbidden`，发布者和首个模型 owner 都不能通过此 API 自授 benchmark、Glicko 样本或 Tier。

权威质量状态只允许由服务器侧 `mindone-coordinator quality-record` 更新。该命令不接受裸分数：它重新计算真实 artifact 的 SHA-256，验证短期 `mindone-quality-evidence-v1` statement 与 pinned evaluator Ed25519 公钥签名，再把只追加 `model_quality_events` 和 `quality_evidence_audits` 在同一事务提交，并运行 Glicko-2、质量融合、冷启动门槛、相对排名和 Tier 滞回。内部原始评分函数为 crate-private，不存在公共 HTTP 写入口；完整 manifest 与命令合同见 `docs/OPERATIONS.md`。

在线 Standard worker 本身不是可信 evaluator。部署期私有 catalog 可以由独立 evaluator 签名并提供未公开 Prompt 与目标权重行为指纹，但 worker 的实际输出仍来自不可信节点。private hidden 的结果只进入按 evaluator key fingerprint、模型权重和 case family 隔离的只追加跨实例仲裁，public canary 只进入精确实例风险状态；两者都不直接改变共享 canonical 模型的 benchmark、Glicko 或 Tier，避免一个恶意贡献者污染其他诚实实例。若未来要把在线样本输入全局质量，仍必须发布新的、可回放且信任边界更强的策略版本。

`base_cost_per_1k_micro` 为兼容字段，但 v1 只接受唯一服务端基准 `1,000,000`；协调器写库使用自身常量，迁移与数据库约束也强制该值。它不再直接决定新任务金额。新任务必须匹配由服务器运维命令 `mindone-coordinator billing-profile-record` 发布的、有效期内且覆盖授权输入/输出上限的不可变物理参考 profile；没有合格 profile 时任务创建失败关闭。发布者、首个 owner 和后续贡献者都不能选择费率、profile、参考硬件或证据，越界或其他兼容字段数值返回 `400 client_base_cost_forbidden`。

`name + weights_hash` 是跨贡献者共享的 canonical 模型标识，因此多个用户的节点可以承载同一模型；任何贡献者都不能覆盖服务端定价或质量状态。同一节点、同一模型重复发布同一 `alias` 会原位恢复既有实例并返回原 `model_instance_id`；若该别名已经绑定到另一模型则返回 `409`。

### `GET /v1/models?name=<name>&limit=100`

列出仍处于 `published` 的模型实例及节点状态。

### `DELETE /v1/models/{model_instance_id}`

立即停止新任务调度。已有租约时返回 `draining`；最后一个租约以 result、fail 或终态超时收口后，服务端在同一事务自动转为 `unpublished`，不要求客户端再次调用。

## 隐蔽实例审计

不存在 `/v1/evaluations/*` 公共路由。协调器按 `MINDONE_EVALUATION_DRAW_DENOMINATOR` 的 CSPRNG 抽样（生产默认分母为 `8`），把挑战混入普通 `POST /v1/jobs/claim`；worker 继续使用相同的 `/renew`、`/result` 和 `/fail`。claim/result/fail 的 endpoint、HTTP 成功状态与 JSON 字段集合不包含 `kind`、challenge token、score、passed 或其他显式评价标签。挑战与普通 Standard job 都使用 UUIDv4，避免 UUIDv7 时间戳成为类型标签。

private `hidden_benchmark` 的题库格式仍是仓库外、部署方受控目录中的短期 `mindone-private-evaluation-catalog-v1`。这里的 catalog `v1` 是签名文件格式，不是数据库 challenge 的 commitment 版本。catalog statement 由 pinned evaluator Ed25519 公钥验证，绑定 evaluator、有效期、行为归一化版本，以及每条 entry 的目标 `model_weights_sha256`、私有 Prompt、期望行为 SHA-256、固定推理 seed 和输出上限。加载器限制目录/文件类型、符号链接、Unix 写权限、4 MiB 文件大小、4096 条 entry、30 天最长有效期和 Prompt/输出边界；格式、签名或时效任一无效都失败关闭。

迁移 `0031_private_hidden_hmac_budget.sql` 之后，新签发的 private challenge 使用 `private_commitment_version=2`。协调器只有在独立、版本化的 Secret 文件中读出 32-byte HMAC key，且完整显式预算和 PostgreSQL key-state commitment 通过启动事务门禁后，才会获得 private issuance capability；原始 HMAC key 不进入数据库，不能通过环境变量内联，也不能复用 Token pepper 或 Standard data key。签发时以域分离 HMAC-SHA-256 绑定 catalog statement、catalog ID、entry、case family、evaluator ID/公钥、Prompt、期望行为、账号、登录设备和节点，再与 `model_id + model_instance_id + node_id + job_id`、模型权重、随机 nonce、授权 Token、推理 seed 和初始租约时效共同进入 challenge binding。v2 行的原始 catalog/entry/case/evaluator 标识符以及裸 `prompt_hash`、`expected_hash` 必须为 `NULL`；数据库只保存 keyed commitments、绝对有效期和完成生命周期所需的非敏感绑定。entry、Prompt 与行为的全局唯一索引作用于 keyed commitments，因此 catalog 改 ID、时间或重新签名也不能重新消费已经暴露的样本。

迁移 `0030_node_device_binding.sql` 把节点、普通 attempt 和隐藏 challenge 绑定到领取请求的精确登录设备密钥；节点 owner/既有 device binding，以及 attempt/challenge 的 claim identity 都不可变。`0030` 与 `0031` 都要求维护窗口内没有活动租约，并按 `nodes → jobs/job_attempts/model_evaluation_challenges` 的固定顺序加锁，避免迁移检查与真实 node-first claim 形成谓词竞态或锁升级死锁。

private v2 签发先在同一个 PostgreSQL 事务中、任何 availability/冲突快照之前取得全局 `pg_advisory_xact_lock`，并持有到 challenge 与 `issued` event 一并提交或回滚。协调器随后对受控 catalog 目录的全部 entry（而不只是当前模型权重候选）计算唯一键冲突并集：legacy v1 与 v2 的 entry、Prompt 和 expected/behavior 任一已经消费都会排除该 entry，同一 entry 多键命中只扣减一次；`remaining_catalog_entries` 因此反映跨 catalog 可复用内容冲突后的真实剩余量。之后再按固定 `catalog → account → device → node` 顺序锁定四级 budget scope，检查四项小时上限、账号/设备/节点 cooldown 与 `global_reserve_entries`；任一拒绝都与“无可用 private entry”一样只回退 public canary，不泄露原因。

跨 catalog 真重叠、两个独立 `PgPool` 的回归已进入隔离 PostgreSQL 17 的 fresh-v37 `43/43` 门禁：一个 catalog 消费的 Prompt/行为冲突必须减少另一个 catalog 的全局 remaining，并在 reserve 边界区分 returning 与未见 identity。全局 advisory transaction lock 和数据库唯一索引分别提供多副本串行化与最终冲突防线；这仍不是抗 Sybil 证明，也不能据此激活 private production。

catalog Prompt 只在部署期受控文件和发给目标 worker 的 Standard payload 中出现；协调器数据库和日志不保存 Prompt、期望响应或实际响应明文。结果按 `utf8-trim-v1` 归一化后验证其 v2 expected commitment；终态清除服务端 nonce seed，只保留 keyed commitments、评分和审计元数据。若 HMAC/预算启动门禁未准备、catalog 未配置、缺失、无效、过期、没有匹配权重的 entry 或已经耗尽，协调器只能签发 `challenge_kind=canary` 的有限公开模板，绝不能签发新的 private v1 行或把 fallback 冒充 private hidden。

private result、显式 fail、renew、请求过期和租约过期在触发任何 v2 持久化变更前，都必须持有由 HMAC key-state 启动门禁签发的 opaque terminal capability；后台 sweeper 使用 prepared `AppState`，只持有裸数据库连接池的兼容入口明确排除 v2。终态事务会写入 `model_authenticity_arbitration_events`；仲裁按模型权重、evaluator key commitment 和 case-family commitment 隔离，只使用每个不同 `model_instance_id` 的最新观察生成 `pending`、`corroborated` 或 `disputed` 快照，事件拒绝 UPDATE/DELETE。主动 `/fail` 或沉默超时都计为失败，不能绕过跨实例仲裁。相同机制还写入 exact-instance canary 风险流：连续 3 次失败隔离新的消费者路由，隔离实例仍可经 ordinary jobs wire 接受恢复探针，连续 2 次成功解除；每个信号、隔离和恢复转换只追加。协调器每 5 秒最多扫描 128 条过期 challenge，并用 `FOR UPDATE SKIP LOCKED` 支持多副本安全分摊。

`0031` 不回填迁移前的 private v1 历史行：这些行保留原始 catalog 元数据和裸 SHA-256，并继续由受限 legacy 终态兼容路径收口。它们不满足 v2 数据最小化合同，也不会成为新 private challenge 的签发格式；运维和审计必须按 `private_commitment_version IS NULL` 与 `=2` 明确区分。

这个合同只声明“执行前和提交接口没有专用 wire 标签”，不承诺 Prompt 语义、领取时序、流量分布或完成后的经济状态不可区分。private hidden 和 public canary 都不创建消费者、不扣额度、不铸贡献值且不生成 receipt；真实零结算可能在完成后暴露类别，系统不会伪造消费者、余额或账本来掩盖。private catalog、行为指纹与跨实例仲裁提高了软件层真实性审计能力，但 Standard worker 仍可被篡改，模型哈希和输出仍由节点路径提供；`corroborated` 不是 TEE、硬件签名或可验证计算证明，也不进入 canonical benchmark、Glicko 或 Tier。

> 仓库提供 private catalog 与相关代码（private HMAC v2 落于 migration `0031`，当前工作树连续为 `0001..0039`），不代表任何现有 production 已启用。2026-07-23 的本机 live production 已在无活动任务/prepared route、可恢复备份和隔离演练基础上完成 v26→v39，0037 认证/ACL、0038 速度字段与 0039 API Key 最小权限均已核对；但它没有挂载 private catalog、独立 key 或完整预算。当前 fresh-v39 另以每 binary 独立数据库完成 `49/49`、无 skip；production private 配置与真实模型验收完成前，仍不能对该部署声称启用 private Hidden Benchmark。

## 任务与租约

`encrypted_payload` 与 `result_ciphertext` 是为协议兼容保留的稳定字段名。Standard 数据面实际传输的是 Base64/Base64URL 编码 JSON，节点结果也是 Base64 编码 JSON；Base64 不是加密，协调器和执行节点可恢复明文。因此 Standard 不得用于敏感或受监管任务，也不得把节点曾经通过远程证明等同于这个 Standard 任务已经启用 E2EE。Regulated 是下面列出的独立、显式且失败关闭的 API 流程。

协调器写 PostgreSQL 时会把 Standard payload/result 转成 `mindone-standard-aead-v1` authenticated-encryption envelope，并把创建幂等指纹保存为密钥域分离 HMAC；claim、结果校验和消费者读取时再恢复原 wire Base64。AEAD 的 AAD 绑定 job ID 与 payload/result 方向，错密钥、错任务、字段互换或篡改会失败关闭。这只减少数据库、快照和新备份中的静态明文暴露：协调器进程、消费者、执行节点、TLS 终点和持有静态保护密钥的主体仍可见数据，也不会追溯擦除旧 WAL、dead tuple 或历史备份。

### `POST /v1/jobs`

```json
{
  "virtual_model":"auto",
  "encrypted_payload":"<Standard路径为base64编码JSON，非密文>",
  "payload_encoding":"base64",
  "tags":["chat"],
  "estimated_input_tokens":128,
  "max_output_tokens":256,
  "idempotency_key":"consumer-request-uuid",
  "priority":0
}
```

第一阶段先硬过滤名称/能力、上下文、在线实例、节点策略和可用状态，再调用公共 accounting 路由按融合质量 50%、用途标签匹配 30%、归一化成本 20% 确定 canonical 模型；同分按稳定模型 ID。创建任务时锁定账户并预留按 High Tier 计算的最大可能费用；可用余额不足返回 code 40。同一用户重复提交相同幂等键不会重复预留。

Standard `/v1/jobs` 明确拒绝 `payload_encoding=regulated_aead_v1`。调用方不能把 Regulated envelope 塞入 Standard 字段绕过 prepare、本机复验或固定节点绑定。

### `POST /v1/jobs/regulated/prepare`

Regulated 必须先准备一次性固定路由；不能通过 Standard `/v1/jobs` 自动升级：

```json
{
  "virtual_model":"auto",
  "tags":["regulated"],
  "estimated_input_tokens":128,
  "max_output_tokens":256,
  "idempotency_key":"prepare-request-uuid",
  "priority":0
}
```

协调器只选择在线、未满载、策略允许且具有未过期 `tee_runtime` 硬件报告的 Enhanced 节点，并固定 `node_id`、`model_instance_id`、`report_id`。响应返回原始厂商 evidence、challenge nonce、REPORTDATA、measurement、策略/运行时/模型哈希、TEE X25519 公钥和两分钟内的 route 到期时间，供消费者本机复验。消费者必须使用固定本机 verifier 重新验证原始 evidence 的签名、证书链、TCB、collateral、measurement allowlist、REPORTDATA 和时间；缺少 verifier/allowlist 或任一结论不成立均返回 code 30。

prepared route 也计入节点 `max_concurrent`，防止并发 prepare 超额承诺。相同幂等键只有请求指纹完全相同才返回原 route；修改模型、标签、Token 上限或优先级返回 `409 idempotency_binding_mismatch`。

### `POST /v1/jobs/regulated`

消费者本机复验成功后生成一次性 X25519 密钥，使用 HKDF-SHA-256 和 ChaCha20-Poly1305 加密请求：

```json
{
  "route_id":"019...",
  "envelope":{
    "version":1,
    "algorithm":"x25519-hkdf-sha256-chacha20poly1305",
    "direction":"request",
    "route_id":"019...",
    "report_id":"019...",
    "model_instance_id":"019...",
    "sender_public_key":"<消费者临时X25519公钥，小写hex>",
    "nonce":"<12字节随机nonce，base64url无padding>",
    "ciphertext":"<AEAD ciphertext+tag，base64url无padding>"
  },
  "idempotency_key":"regulated-create-uuid"
}
```

固定 AAD 绑定方向、route、report、模型实例和模型权重哈希；全零共享秘密、全零公钥/nonce、篡改、方向错误或绑定错配均拒绝。协调器在一个数据库事务内锁定并消费一次性 route、预留额度并创建固定节点任务，只保存 opaque envelope，不解密 Prompt。route 重放返回 `409 regulated_route_replay`，不会创建第二个任务或重复预留；创建幂等键相同但 envelope 不同返回 `409 idempotency_binding_mismatch`。

节点 worker 不把 Regulated 任务交给普通 llama 进程。只有同一报告绑定的 TEE runtime adapter 可用不透明 `key_handle` 执行 `infer`，并返回 `direction=result`、由同一 TEE 公钥回封的 envelope。协调器校验结构和 route/report/model/public-key 绑定后结算，消费者最终在本机解密。报告或固定节点在领取前失效时，任务以 `attestation` 失败收口、完整释放 reservation 且不扣费，不会迁移到其他节点或降级成 Standard。

CLI 代理仅在显式使用 `quota use --confidentiality regulated` 时走此流程；默认 `standard` 仍是 Base64 JSON。当前仓库测试覆盖软件密码学、篡改/AAD/报告错配/过期/重放/错误节点和 PostgreSQL 原子性；没有目标 SNP/TDX 硬件时真实硬件端到端用例保持 fail-closed，不能据此声称某一部署已经完成硬件 E2E 验收。

新任务使用 `server_reference_upper_bound_v1`。协调器在创建任务时冻结授权输入上界 `I`、最大输出上界 `O` 和当时有效的物理参考 profile；节点上报的实际 token、GPU 时间、显存或吞吐量不进入金额。令 `B = I + O`，则：

```text
G = fixed_gpu_time_us + ceil(B × gpu_time_us_per_1k_tokens / 1000)
V = G × reference_vram_mib

C_token = ceil(B × token_rate_micro_per_1k / 1000)
C_gpu   = ceil(G × gpu_rate_micro_per_second / 1000000)
C_vram  = ceil(V × vram_rate_micro_per_gib_second / (1024 × 1000000))
C_base  = C_token + C_gpu + C_vram
```

三个分项分别向上取整后再相加；创建时按 High Tier 对同一冻结基础成本预留最大用户扣款。结算只验证 `actual_input_tokens <= I`、`actual_output_tokens <= O`，不会按较小实际用量降价；随后由公共 accounting crate 按实际结算 Tier 对用户扣费向上取整，并按 Trust 对节点可用额度和贡献值向下取整。全程只使用整数 microquota，不使用浮点金额。荣誉账单的 `billing` 对象完整返回 profile ID/version/fingerprint/evidence/有效期、授权上限、三个参考参数、三个整数费率、`B/G/V`、三个成本分项和 `base_cost_micro`；顶层 `base_cost_micro` 必须与嵌套快照一致。

### `GET /v1/jobs/{job_id}`

消费者可查看状态、Base64 编码结果和结算后的 `receipt_id`；当前承接节点可查看任务状态，但不能读取消费者结果副本。

### `POST /v1/jobs/{job_id}/stream`

仅当前 Standard SSE 租约的节点设备可按连续序号追加真实上游事件：

```json
{
  "node_id":"019...",
  "attempt":1,
  "sequence":0,
  "idempotency_key":"stream:<job>:1:0",
  "kind":"data",
  "event_data":"{\"id\":\"...\",\"object\":\"chat.completion.chunk\",\"choices\":[...]}"
}
```

`kind` 只允许 `data` 或 `upstream_done`；后者不携带 `event_data`，且必须位于至少一个真实 data 事件之后。任务必须原本请求 `stream:true`，并固定 `max_attempts=1`；Regulated 明确返回 `stream_not_supported`，不会降级。服务端校验租约、attempt、精确设备绑定、OpenAI SSE JSON 形状、单事件/累计大小上限和严格连续 `sequence`。相同序号或幂等键只有完整内容一致才返回 `idempotent_replay=true`，任何变更或 `upstream_done` 后追加都冲突。data 正文只以 Standard AEAD envelope 持久化，数据库不保存明文；`upstream_done` 本身不结算，唯一终态仍由后续 `/result` 提交产生。

### `GET /v1/jobs/{job_id}/stream?from_sequence=0&limit=8`

只有任务消费者可读取 Standard SSE；`from_sequence` 为包含式游标，`limit` 为 `1..=32`。响应示例：

```json
{
  "job_id":"019...",
  "status":"leased",
  "attempt":1,
  "events":[{"sequence":0,"event_data":"{...}"}],
  "next_sequence":1,
  "has_more":false,
  "upstream_done":false
}
```

消费者按 `next_sequence` 继续读取即可从数据库连接或下游读取故障恢复，不会重复已确认事件；终态失败时还会返回稳定 `error_class` 和受限 `error_message`。这提供服务端持久游标，但不声称任意 OpenAI 客户端重新 POST 原始推理请求即可自动接续；CLI 本地代理负责把该读取协议转换成一条有序 SSE 响应和唯一 `[DONE]`。

### `POST /v1/jobs/claim`

```json
{"node_id":"019...","model_instance_id":"019..."}
```

`model_instance_id` 是 worker 当前实际服务的精确实例。Standard 与 Regulated 的第二阶段使用同一确定性排名：Trust 25%、最近心跳健康/时效 20%、上一次成功协调器心跳 RTT 15%、TPS capacity 15%、`current_concurrent/max` 可用负载 15%、错误率可靠性 10%。已报告的 RTT 在 `1..=1000ms` 内按越低越优计分，超过 1000ms 的候选被过滤；旧 worker 没有 RTT 时仍可兼容参与，但该项得 0，绝不从 TTFT 回填。TTFT 只保留为本机优化与任务风险指纹，不再冒充网络延迟。其余硬过滤包括拒绝标签、并发、温度、显存、90 秒失联和不可用实例；同分按 node ID、instance ID。只有当前全局排名胜出且同时匹配请求 `node_id + model_instance_id` 的 worker 能通过 `FOR UPDATE OF jobs SKIP LOCKED` 领取任务，其他节点得到 `204`；首选节点失联、达到并发上限或策略否决时，下一名自动成为 fallback，避免永久饥饿。写入租约前还会在 canary 状态串行化后对精确实例取得共享行锁并最终复核 `published`：claim 先完成时并发 unpublish 会等待并看到新租约，unpublish 先完成时 claim 返回 `204`。

领取前还会收口已经耗尽尝试次数的过期租约：任务标记失败、attempt 标记过期、完整释放 reservation，并自动完成 draining 实例。普通队列领取前也可能按抽样混入上一节的实例挑战；没有任何可领取工作时返回 `204`。

### `POST /v1/jobs/{job_id}/renew`

```json
{"node_id":"019..."}
```

只有未过期的当前租约可续期；续期前再次检查节点策略。

### `POST /v1/jobs/{job_id}/result`

```json
{
  "node_id":"019...",
  "idempotency_key":"result-uuid",
  "result_ciphertext":"<Standard路径为base64编码JSON，非密文>",
  "actual_input_tokens":128,
  "actual_output_tokens":80,
  "execution_telemetry": {
    "ttft_ms":320,
    "tps_milli":12500,
    "peak_vram_mib":6144,
    "vram_sample_count":18
  }
}
```

任务完成、消费者扣费、节点可用额度、贡献值、网络准备金、账本、荣誉账单、任务遥测和异常账本在同一 PostgreSQL 事务中提交。相同结果幂等键只结算一次；幂等 commitment 同时绑定 job、node、model instance、attempt、结果键和全部遥测，重放时改变任一遥测字段都会拒绝。上报用量不得超过创建任务时授权的上限。migration 27 之后新增的 quota、contribution 和 reserve ledger 行统一使用 canonical v2：数据库以版本化域、账本 scope、稳定 ID/账户/request/idempotency/type、整数金额及前后余额、PostgreSQL 微秒时间、`prev_hash` 和排序 metadata 从持久化行重新计算 `entry_hash`，任意不一致 hash 都被 BEFORE trigger 拒绝。迁移前的 legacy v1 行保留原 hash、链头和空 metadata，不追溯伪装成可由当前行完整重算的 v2。

在 Standard 路径中，`actual_input_tokens`、`actual_output_tokens`、结果和 `execution_telemetry` 都由承接节点上报；协调器执行租约、身份、幂等、授权上限与服务端风险基线检查，但没有硬件签名或可验证计算证明。Enhanced 路径当前也没有把任务遥测升级为 attested GPU evidence。receipt、账本哈希、`settlement_hash` 和风险 verdict 证明的是协调器记录之间的一致性，不是推理真实发生、Token 计数精确、模型输出正确或显存归属的密码学证明。

普通任务和经相同 jobs wire 混入的 public/private 评价任务都要求 chat 第一条 choice 含非空文本；只有 `reasoning_content`、空 content、结果结构/usage/模型绑定错误均会确定性返回 HTTP 400（通常 `error.type=invalid_job_result`）。官方 worker 不会主动等到租约过期：本地 reasoning-only 会直接走 `/fail`；若结果上传才收到 400，则补交一份使用稳定失败幂等键、固定 `error_class=model`、`retryable=false` 的脱敏 `/fail`，不复制协调器响应 message。HTTP 409、5xx 或传输错误不触发该终态转换；脱敏失败提交本身仍无法确认时由既有租约过期路径收口。

成功响应是只确认 worker 提交已接受的最小 ACK，不返回经济字段、receipt、风险 verdict 或评价结果：

```json
{"job_id":"<uuidv4>","status":"succeeded","idempotent_replay":false}
```

这里的 `status` 不表示模型答案正确。消费者从 `GET /v1/jobs/{job_id}`、quota history 和 receipt API 读取真实任务终态与结算。早期 v1 worker 省略 `execution_telemetry` 时仍可提交；服务器把全部指标记为未知并得到 `insufficient_evidence`，不会伪造为 0。

### `POST /v1/jobs/{job_id}/fail`

```json
{
  "node_id":"019...",
  "idempotency_key":"failure-uuid",
  "error_class":"engine",
  "error_message":"引擎进程退出",
  "retryable":true
}
```

成功接收失败报告时只返回同形 ACK：

```json
{"job_id":"<uuidv4>","accepted":true,"idempotent_replay":false}
```

可重试错误使用有界退避和最大尝试次数。最终失败完整释放预留额度、真实扣费为 0 且不生成扣费账本；这些经济事实通过消费者任务状态/账本查询，而不是塞进 worker ACK。

## 额度和准备金

production 新账户的 `spendable_micro` 固定从 `0` 开始，注册和任何公共 HTTP API 都不会自动赠额。协调器不注册 HTTP admin/grant 路由；启动网络供应时，只能由持有服务器进程配置和 `DATABASE_URL` 的运维者执行 `mindone-coordinator quota-grant`。该命令在一个数据库事务中锁定既有账户、追加 `operator_grant` quota 账项、更新余额并写入只追加 `operator_quota_grants` 审计记录；不存在的用户会被拒绝。完整命令和参数边界见 `docs/OPERATIONS.md`。

运营赠额是任务结算公式之外、显式且可归责的外生启动供给，不生成 job、receipt、节点贡献或准备金流，也不冒充任务结算。相同幂等键和完全相同请求返回原记录；改变用户、金额、运维者或理由会冲突。

### `GET /v1/quota/balance`

返回 `spendable_micro`、`reserved_micro`、`available_micro`、`contribution_micro`、节点 Tier 和准备金余额。

### `GET /v1/quota/history`

查询参数：`limit`（1–200）、`cursor`、`after`、`before`。时间使用 RFC 3339。返回可用额度与贡献值的只追加账本记录和 `next_cursor`。每项完整公开 canonical 输入：`ledger` scope、`account_id`、`id`、`request_id`、`idempotency_key`、`entry_type`、整数 `delta_micro`、`balance_before_micro`、`balance_after_micro`、数据库微秒精度 `created_at`、`prev_hash`、`hash_version`、排序字符串 `metadata` 和 `entry_hash`；结算相关记录还包含不参与账本 hash、可直接传给 receipt API 的 `receipt_id`。

`recomputation_status=canonical_v2_recomputable` 的行可由上述字段按 migration 27 的 length-prefixed schema 重算；官方 CLI 会在显示前调用与 writer 相同的 `mindone-accounting` verifier，篡改或版本/类型不一致会失败关闭，并在文本输出中标记“canonical-v2-已本地复算”。`recomputation_status=legacy_v1_unverifiable` 只允许对应 `hash_version=1` 与空 metadata，明确表示迁移前缺少原始 metadata、不能按当前 schema 重算；CLI 保留并标记该行，但绝不显示为验证成功。单页 history 按时间倒序且可能交错两种 ledger，因此本地复算证明每行内容与 `entry_hash` 一致，不冒充已下载完整连续链或外部锚定证明。

### `GET /v1/quota/receipts/{receipt_id}`

只允许消费者或贡献节点查看，返回 `server_reference_upper_bound_v1` 的完整嵌套 `billing` 快照、基础成本、Tier、Trust、用户扣费、节点额度、贡献值、准备金和结算哈希。迁移前历史账单可以没有 `billing`；所有新账单必须存在，且嵌套与顶层基础成本一致。该哈希没有外部时间戳、独立签名或公开链锚定，不应表述为第三方可验证的执行证明。

### `GET /v1/reserve`

返回准备金流入、流出、余额和允许用途。准备金只能用于验证、失败重算、带宽补贴和高峰保障；任何释放必须先锁定余额、提供非空审计引用并追加独立账本。v1 不公开准备金释放 HTTP 路由；持有完整服务器环境和数据库访问权的运维者只能执行 `mindone-coordinator reserve-release`。该命令把用途、金额、reference、operator、理由、幂等键、reserve ledger 与只追加 `operator_reserve_releases` 审计原子绑定，余额不足或同键变更请求会拒绝。完整参数边界见 `docs/OPERATIONS.md`。
