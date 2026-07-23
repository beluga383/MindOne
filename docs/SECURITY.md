# MindOne 安全说明

## 支持范围

v1.0.x 接受安全修复。报告问题时请附影响版本、平台、最小复现和预期边界，不要附真实凭证或个人 Prompt。

优先使用 GitHub Private vulnerability reporting。若仓库尚未启用该功能，请先只提交不含利用细节的私有联系请求，不要公开 0-day、Token 或可直接利用的 payload。

## 威胁模型

MindOne 防御：

- 危险模型反序列化、文件路径穿越与伪扩展
- 推理进程对非授权文件和进程能力的访问
- 消费者重复提交、节点重复领取/结算、租约重放
- 节点与租约的跨账号设备替换、旧节点未重新绑定就恢复接单
- Regulated prepared route 重放、错误节点领取、报告/模型/AAD 绑定篡改
- 节点伪报模型哈希、策略绕过和资源阈值越界
- Token 明文落盘、数据库令牌明文、日志泄露 Prompt/Response
- 额度并发透支、账本篡改和准备金超额释放

不承诺防御 GPU 微架构侧信道、底层驱动/内核 0-day、国家级物理取证和模型本身的记忆泄露。

## 模型

- 只登记经结构验证的 GGUF 与 safetensors。
- `.pkl/.pickle/.pt/.pth/.ckpt` 等任意代码反序列化格式硬拒绝。
- 下载使用 HTTPS、临时文件、续传、SHA-256、结构验证和原子重命名。
- 扩展名不是安全证据；magic、长度、偏移、shape 和数据范围都必须验证。

## 沙盒与信任

官方 CLI 从当前推理进程启动计划的 `applied` 集合生成服务状态和节点登记，只报告本次启动实际应用的机制，不把内核支持、能力探测或计划中的机制写成已应用。Linux 只有实际组合应用 namespace、seccomp-bpf 与 Landlock 才是 Standard，降级路径只报告真正应用的子集；macOS 只有实际 Seatbelt/App Sandbox 才能达到 Standard-Limited，且最高仍为 Standard-Limited；当前官方 Windows 路径只在监督进程实际创建并持续持有 Job Object 时报告该机制，等级仍为 Experimental。Windows Job Object 只约束进程生命周期，不构成或宣称文件系统、网络沙箱；未使用监督进程时不报告已应用机制。

Linux 回环服务与宿主共享 network namespace，但 seccomp 只允许 Unix/IPv4/IPv6 的 TCP stream socket（默认协议或 TCP），拒绝 UDP、raw、其他 socket 类型/协议、主动 `connect` 和 `io_uring` 建立路径。已接受的回环 TCP 连接可使用 `sendto`/`sendmsg` 发回健康检查与推理响应；由于主动连接和非 stream socket 都被拒绝，这不开放引擎主动外连。原生 Linux gate 同时真实验证回环响应成功、主动 TCP 连接失败和 UDP socket 创建失败。

受管 llama.cpp 的 CPU-only 是类型化启动策略，不是可由高级参数拼接的字符串。macOS Seatbelt 路径始终生效；其他平台在显式 `cpu_only: true` 时生效。管理器固定注入 `--device none`、`--n-gpu-layers 0`、`--no-kv-offload` 和 `--no-op-offload`，拒绝高级配置中的设备/GPU/offload 覆盖，并从子进程环境移除 `LLAMA_ARG_DEVICE`、`LLAMA_ARG_N_GPU_LAYERS`、`LLAMA_ARG_KV_OFFLOAD`、`LLAMA_ARG_NO_KV_OFFLOAD` 与 `LLAMA_ARG_NO_OP_OFFLOAD`。因此父进程环境或 YAML 不能悄悄重新启用 Metal/GPU，也不能把不受信 `--device` 冒充受管 CPU-only。

`share publish` 会把实际生效策略写入本地 `runtime/node-policy.json`。活动 worker 在领取前、执行前和心跳/状态路径只读取这份持久化策略；文件缺失、损坏、是符号链接、不是普通文件，或内容不满足 `max_concurrent=1..3` 与标签规范化约束时一律 fail-closed，不回退到默认允许策略。默认策略只用于未发布时的初始化或显式配置流程。

协调器依据 `hardware_profile.sandbox_mechanisms` 分类 Standard/Standard-Limited，但即使该字段来自未修改的官方客户端，也只是节点对本次启动状态的客户端观测自报，服务器没有独立观测这些软件沙箱，更不是远程证明。物理主机 root 或篡改客户端仍可伪报；只有下面经过厂商证据验证的 TEE 路径才能产生 Enhanced。

`auth attest` 在 Linux 上只接受 AMD SEV-SNP extended report 或 Intel TDX Quote，裸 TDREPORT 被拒绝。一次性 challenge 把节点、模型实例、nonce、沙盒策略哈希、运行时哈希、模型权重哈希、X25519 临时公钥和密钥来源绑定到 REPORTDATA；服务器通过固定 verifier 验证硬件签名、证书链、TCB、collateral 和 TEE measurement allowlist，并在事务中消费 challenge 防重放。没有支持硬件或服务端验证配置时退出 30，不使用软件随机值模拟 Enhanced。

仓库实现的是严格的 verifier/TEE adapter 调用边界、绑定检查和失败关闭状态机，不自带一份可替代厂商验证栈的“万能证明器”，也不证明任何线上主机已经具备合格硬件。Enhanced/Regulated 能力必须来自目标部署上的真实证据与固定配置，不能由构建成功、单元测试或数据库状态推断。

Regulated 只接受由固定 `MINDONE_TEE_RUNTIME_PATH` adapter 生成、且来源为 `tee_runtime` 的不透明密钥句柄。已有软件 `AttestationKeyRecord` 属于 `control_software`，不能升级成 Regulated。adapter 还必须运行在可访问对应 SNP/TDX guest 证明设备的主机；路径缺失、符号链接、设备缺失、输出超限、超时或绑定字段不一致全部 fail-closed。适配器协议使用有界 stdin/stdout、固定 JSON schema、清空环境且不经过 shell。

## 凭证与数据

- CLI Token 和设备私钥存入系统凭证库，不写入 `config.toml`。macOS 使用 Keychain、Windows 使用 Credential Manager，Linux 桌面默认使用 Secret Service；无桌面 Linux 可显式设置 `MINDONE_LINUX_CREDENTIAL_STORE=keyutils`，把 Secret 放入当前内核 keyring session。keyutils 不落盘，但重启或 session 回收后需要重新登录；未知值会失败关闭，不能回退为明文文件或进程内假凭证库。
- 数据库只存带 pepper 的 token HMAC/hash，访问令牌短期有效，刷新令牌可轮换和撤销。
- CLI 没有数据库凭据。
- email provider 不建立浏览器 bearer 通道：CLI 始终使用 Ed25519 Device Flow，同源 `/auth/login` 不带 query/fragment，用户核对 origin 后手工输入终端随机 12 位 `user_code`；浏览器只授权待处理 flow，最终 `/v1/auth/device/poll` 必须验证 CLI 设备签名后才返回 access/refresh token。不要把邮件、聊天或陌生网页给出的代码输入登录页。
- 邮箱验证 token 只保存带服务器 pepper 的 HMAC；验证链接 GET 只显示确认页，只有用户显式同源 POST 才消费 token，防止邮件安全扫描器自动激活账户。query 与表单正文均不进入 request tracing；邮箱规范化后唯一，password 只保存内存硬化 hash。production 公开基址必须 HTTPS，SMTP 只允许 TLS/STARTTLS，并在 email provider 启动时验证必填项、发件人和传输构造参数后失败关闭。password reset 尚未实现，辅助发信函数不构成公开产品流程。
- 结构化日志脱敏 Authorization、cookie、Token、password、Prompt、Response 和 URL userinfo。受管引擎只接受经过审计的 llama.cpp b10064，启动前必须从有界 `--help` 能力探测中确认精确的 `--log-disable`、`--parallel`、`--kv-unified`、`--slots`、`--slot-save-path` 与 `--no-cache-prompt`，随后固定四个 slot、显式使用统一 KV 缓存、启用 slot 动作端点、禁用 prompt cache、清除相关 `LLAMA_*` 环境覆盖并拒绝高级配置覆盖日志或清理合同；能力不成立即拒绝启动。统一 KV 避免固定四槽把单个 standard/fast 或本机请求的上下文静态切成四份；slot 0 只供本机代理，slot 1..3 只供贡献任务。b10064 把 `/slots/{id}?action=erase` 门禁在 `--slot-save-path` 之后，因此受管服务固定提供一个只用于启用该动作端点的托管目录（worker 只调用 erase、从不 save，不向磁盘写入 KV/Prompt）；缺少该能力时请求后 slot erase 会返回 HTTP 501，成功结果因此拒绝提交和结算。每次启动还会安全清理活动日志及 5 代轮转文件，避免旧 Prompt/Response 残留。
- worker 上报结果失败时，守护日志只记录 `job_id`、稳定 `error_type` 和 HTTP status，不记录远端不受信 JSON `/error/message`、响应 body 或 URL userinfo；CLI 前台仍返回经过边界控制的中文可操作错误。
- chat SSE 的 `reasoning_content` 可以作为首 Token/TTFT 观测，但最终第一条 choice 仍必须含非空可见 `content`。只有 reasoning、没有可见答案时，worker 在本地把执行标记为失败，不上传一个必然被拒绝的结果。协调器对绕过本地检查的普通或评价 chat 结果仍以 HTTP 400、`invalid_job_result` 失败关闭；worker 收到确定性结果 400 后会补交一份固定、不可重试且不含远端正文的幂等 `/fail`，避免主动把租约或 canary 留到过期，同时不把不受信错误消息写入日志或审计。若失败提交因传输故障仍无法确认，既有租约过期收口继续生效。
- 协调器不记录 Prompt/Response 明文。Standard wire 仍只是 Base64 编码 JSON，不具备端到端保密性；PostgreSQL 中的 Standard payload/result 使用独立主密钥经 HKDF 子键分离后的 AES-256-GCM v1 envelope，AAD 绑定 job 与方向，创建指纹使用独立 HMAC 子键。该静态保护不覆盖协调器/节点/消费者运行时、网络库或 serde 的内部副本，也不会追溯擦除旧 WAL、dead tuple 和历史备份。
- CLI worker 会在真实 create/decode、本机 llama HTTP body、响应累计和结果序列化路径上用 `Zeroizing` 或析构清零自己拥有的可控字节缓冲，并在请求对象离开作用域时清理可逆 Base64 字段。本机代理强制使用 `/slots/0`，贡献任务从 1..3 中独占分配一个 slot；每次受管推理不论成功或失败都会同步调用该精确 slot 的 `?action=erase`。只有回执绑定同一 slot 且确认清除正数 KV token 时成功结果才可提交和结算。b10064 上游会移除该 sequence 并清空 prompt token 表，这属于可验证的逻辑 KV 清理，不证明 CUDA/Metal/allocator 物理页已逐字节覆写。这些动作都是 best-effort 生命周期收敛，不承诺清除 reqwest、TLS、serde、系统 socket、分配器、驱动或模型引擎其他内部副本。
- Regulated 使用消费者一次性 X25519、HKDF-SHA-256 和 ChaCha20-Poly1305。随机 nonce 不得全零；共享秘密全零硬拒绝；临时私钥、共享秘密和解密缓冲使用零化容器。AAD 固定绑定方向、route、report、模型实例和模型权重哈希。
- 协调器只保存 opaque Regulated envelope，并在事务中一次性消费固定 route；它不持有解密密钥。节点 worker 也不解密载荷，解密、推理和结果回封必须全部由同一报告绑定的 TEE runtime adapter 完成。消费者复验原始 evidence 后在本机加密并最终解密结果。
- 消费者本机 verifier 与策略/运行时/measurement allowlist 是强制依赖；缺失或过期、REPORTDATA/证书链/TCB/collateral 不匹配均退出 30。服务端曾验证报告不能替代消费者本机复验。
- Standard 与 Regulated 没有自动回退：Standard 明确不是加密；Regulated 的报告/节点失效会无扣费失败，不能迁移到另一个节点或降级成 Standard。
- Standard 节点上报实际 Token 和结果；协调器只校验租约、身份、幂等和创建时授权上限。receipt、结算哈希与哈希链是协调器内的审计和防重复机制，不是远程执行、用量或输出正确性的密码学证明。
- 仓库中的确定性测试与 PostgreSQL 集成测试不能替代真实 SNP/TDX 硬件验收。没有目标硬件时 Regulated 保持 fail-closed；部署方只有在自己的硬件、固件、verifier、collateral 和 adapter 上完成端到端验证后，才能把该部署用于受监管数据。
- canonical 模型质量没有公共 HTTP 写入口。服务器侧 `quality-record` 只接受短期 Ed25519 签名 statement，并复核真实 artifact SHA-256 与 pinned evaluator 公钥；裸分数、过期 evidence、签名或 artifact 不匹配均 fail-closed。evaluator 私钥必须留在独立评测系统，不能放进协调器环境或仓库。
- 准备金释放没有公共 HTTP 写入口。服务器侧 `reserve-release` 必须绑定 operator、理由、用途、reference 和全局幂等键；余额更新、reserve ledger 与只追加 operator 审计在同一事务提交，数据库触发器拒绝 UPDATE/DELETE。

## 在线实例审计与任务遥测

- 协调器不提供 `/v1/evaluations/*` 公共路由。服务端挑战只经普通 `/v1/jobs/claim`、`/renew`、`/result` 和 `/fail` 混入，claim 必须精确绑定 `node_id + model_instance_id`。migration `0030` 还把节点、普通 attempt 和隐藏 challenge 绑定到发起领取的账号与精确 device key；节点 owner/既有设备绑定和领取身份不可变。result/fail 只返回不含分数或经济字段的最小 ACK。
- public `canary` 与 private `hidden_benchmark` 是两种不同信任口径。public canary 使用仓库内有限模板和随机参数，只驱动 exact-instance 的有界风险处置；private hidden 只来自仓库外部署目录中的短期 `mindone-private-evaluation-catalog-v1`，statement 必须通过 pinned evaluator Ed25519 公钥签名、时效、schema、大小和条目边界验证。catalog 未配置、缺失、无效、过期、权重不匹配或耗尽时只能退回 public canary，不能把公开模板标成 hidden。
- `mindone-private-evaluation-catalog-v1` 的 `v1` 是签名文件格式；migration `0031` 新签发的 private challenge 则固定为 `private_commitment_version=2`。private entry 把目标权重、私有 Prompt、`utf8-trim-v1` 行为 SHA-256、固定推理 seed 和输出上限纳入签名；challenge 再以独立、域分离 HMAC-SHA-256 绑定 catalog statement/ID/entry、case family、evaluator ID/key、Prompt、期望行为、账号、设备和节点，并绑定 `model_id + model_instance_id + node_id + job_id`、模型权重、随机 nonce、授权 Token 与初始租约时效。v2 数据库行中的原始 catalog/evaluator 标识符和裸 `prompt_hash`/`expected_hash` 必须为 `NULL`，全局一次性约束只使用 keyed commitments，降低离线字典枚举和 catalog 关联暴露。
- private HMAC key 只允许从规范绝对路径、受保护且格式精确的 Secret 文件读取；该版本化文件编码 32-byte key material。禁止 inline 环境变量、符号链接、宽权限路径、与 Token pepper 或 Standard data key 复用。PostgreSQL 只保存域分离的 key commitment，不保存 key。协调器必须在启动事务中对齐唯一 key-state，随后才签发 opaque runtime capability；result、fail、renew、请求/租约过期、后台 sweep 和仲裁在任何 v2 持久化变更前都要求 terminal capability。裸连接池的兼容 sweeper 只能处理 public canary 与 legacy v1，不能结束 v2 challenge。
- private v2 签发在任何 availability 快照之前取得全局 PostgreSQL advisory transaction lock，并持有到 challenge/`issued` event 提交或回滚；随后才按 `catalog → account → device → node` 固定顺序锁定 budget scope。remaining 以受控 catalog 目录全部 entry 为集合，对 legacy v1/v2 的 entry、Prompt 和 expected/behavior 唯一键冲突做按 entry ordinal 去重的并集扣减，而不是只数当前 catalog ID 或当前模型候选。四级小时上限、账号/设备/节点 cooldown 与 `global_reserve_entries` 都在同一事务判断；缺少 HMAC、任一预算字段或门禁不一致只能回退 public canary。migration `0030`/`0031` 自身也统一按 node-first 顺序阻断 claim，并要求没有活动普通/隐藏租约后才继续。
- 跨 catalog 真重叠、两个独立 `PgPool` 的 reserve 回归已进入隔离 PostgreSQL 17 的 fresh-v37 `43/43` 门禁，覆盖另一 catalog 的冲突进入全局 remaining、returning/未见 identity、串行化与失败回滚边界。这些预算不是抗 Sybil 证明；数据库唯一索引仍是最终冲突防线。
- private 结果按行为 commitment 判定；错误结果、主动 `/fail` 和沉默超时都原子追加跨实例真实性仲裁。v2 仲裁按模型权重、evaluator key commitment 与 case-family commitment 隔离，以不同 `model_instance_id` 形成 `pending`、`corroborated` 或 `disputed` 快照，事件拒绝 UPDATE/DELETE。public/private 信号同时进入 exact-instance 风险状态：连续 3 次失败隔离新的消费者路由，隔离实例仍可经 ordinary jobs wire 接受恢复探针，连续 2 次成功解除；所有信号和转换只追加审计。
- `0031` 不把历史 private v1 行伪装成 v2：迁移前行保留裸 SHA-256 与原始 catalog 元数据，只由 legacy 兼容终态路径收口；新 private challenge 不再以 v1 格式签发。运维查询、导出和保留策略必须按 commitment version 区分两种数据暴露边界。
- 在线 Standard worker 仍不是可信执行环境。private catalog 和仲裁不会让节点自报模型哈希、输出或遥测变成硬件证明；`corroborated` 不是 TEE、硬件签名或可验证计算证明。private hidden 与 public canary 都不创建消费者、不扣款、不铸造贡献值、不生成 receipt，也不更新共享 canonical 模型的 benchmark、Glicko 或 Tier。公共 wire 没有专用评价标签，但这不保证 Prompt 语义、时序、流量或完成后的真实零经济状态不可分类；不得伪造消费者、余额、receipt 或账本来掩盖该事实。
- 源码具备 private catalog/HMAC/budget 边界（migration `0031`，当前工作树整体为连续 `0001..0039`），不代表 live production 已启用。当前 fresh-v39 已在一次性 PostgreSQL 17 上让 16 个 binary 各用独立数据库完成 `49/49`、无 skip，覆盖 API Key ACL、速度档调度与 OpenAI JSON/SSE 网关事务 E2E。2026-07-23 本机 live production 已迁移到 39 并通过 runtime ACL 与公网身份验收，但仍没有挂载 catalog、独立 HMAC key 或完整预算；旧节点 device rebind、真实模型和 private 双 GGUF 验收完成前，只能按 public canary 能力描述该部署。
- 2026-07-22 的 macOS arm64 debug E2E 已在独立 PostgreSQL 17、两个隔离 `MINDONE_HOME` 和测试 Keychain 中通过：真实下载并执行 llama.cpp b10064 与 Qwen3-0.6B-Q4_0 GGUF，完成非流式 chat/completions、两个端点的 SSE 增量与连续游标、游标数据库故障恢复、Standard AEAD/HMAC 静态存储、公开 canary 收口、领取后策略复核零结算、三轨唯一结算、Regulated `stream:true` 明确拒绝、日志明文扫描和资源清理。它早于 0038/0039，且使用 `local-development` 与 CPU-only Seatbelt，只证明这次隔离本机链路；不替代 email SMTP/浏览器流程、公网 HTTPS、生产 v26→v39 升级、GPU/其他平台、真实 private catalog 多实例仲裁或 SNP/TDX Regulated 硬件验收。
- `execution_telemetry` 的 TTFT 是 worker 用单调时钟实测的“本地 HTTP 请求开始到首个非空生成 delta”；初始 role 事件不计入，无首 Token 时保留未知，不使用 prompt timing 派生估算。TPS 来自引擎自报终态 timing，峰值显存是主机可见 GPU 设备集合的 best-effort 周期采样；Standard 与 Enhanced 路径目前都没有任务绑定的硬件签名或可验证 GPU 计数器。它们只是 node-reported risk signals，不是推理执行证明、Token/性能精确性证明或当前 job 的独占显存归因，不影响结算、贡献奖励或 Tier。

## 网络

跨主机通信只允许 HTTPS/WSS。HTTP 仅限回环开发 origin。若部署方启用 Cloudflare，允许公开的目标只有协调器 API；PostgreSQL、llama-server、本地代理和管理端口不得公开。仓库中的 Compose/Tunnel 示例不等于某个公网域名已部署或已通过端口审计。

节点只建立出站连接。`coordinator_rtt_ms` 是节点对上一次成功 heartbeat HTTP 调用的单调时钟应用层 RTT，包含连接/TLS、服务端处理、完整读取和 JSON 解码；它不是纯网络 ping、服务端主动测量或密码学证明。首次/失败/401 心跳不生成样本，缺失不写 0，也不从 TTFT 回填。该节点自报信号只用于 15% 的弱路由项，不进入 Trust、Tier、结算、账本或执行证明。

## 账本

全部金额为整数 microquota。job 完成和 quota、contribution、reserve 三类账本在一个 PostgreSQL 事务提交；ledger 表通过数据库机制拒绝更新/删除，幂等键和行锁防止重复结算与透支。migration 27 之后的新行使用 canonical v2：数据库 BEFORE trigger 从版本化域、账本 scope、稳定 ID/账户/request/idempotency/type、整数 delta 与前后余额、PostgreSQL 微秒时间、`prev_hash` 和排序 metadata 重新计算 `entry_hash`，并拒绝调用方提交的任意不一致 64 位 hash。迁移前 legacy v1 行保留原 hash、链关系和空 metadata，不追溯伪装为可以按 v2 完整重算；该链仍只证明协调器账务记录一致性，不证明节点真实执行、Token 用量或输出正确性。

## 发行物

自动发布会生成 SHA-256 清单、SPDX SBOM、Sigstore 清单签名和 GitHub provenance；标签发行还会复跑依赖与完整 Git 历史 Secret 扫描。只有实际配置相应 Secret 时才会生成并验证 Apple Developer ID 或 Windows Authenticode 签名；macOS notarization 仍需单独完成。未签名状态会写入发行包，安装说明不会要求关闭 Gatekeeper、SmartScreen 或系统安全机制。
