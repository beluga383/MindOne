# MindOne 协调服务器运维

## 安全边界

- 本机源码启动的协调服务默认只监听 `127.0.0.1:8787`；基础生产 Compose 的本机维护模式使用独立回环端口 `127.0.0.1:18787`，不得占用或修改现有 `8787` 服务。
- Docker 容器内部监听 `0.0.0.0:8787`。公网 Cloudflare overlay 会完全移除宿主机端口映射，只允许专用 connector 通过同主机 internal 网络访问 origin；PostgreSQL 从不发布宿主机端口。
- 若需要公网服务，只使用新建且部署方实际验证过的 MindOne 专用 Cloudflare Tunnel。不要复用或修改现有 tunnel/route，也不要发布 PostgreSQL、llama-server、节点管理端口或本地推理端口。仓库配置只是部署模板，不证明任何 hostname 已上线。
- 官方 API 目标域名是 `api.holarchic.cn`；根域 `holarchic.cn` 保留现有官网。Tunnel 只在 API 子域把整站路径 `/*` 转发到容器内 `http://coordinator:8787`；外部 HTTPS 443 对应 `/health`、`/ready`、`/auth/*` 和 `/v1/*`。不得把根域整站切给协调器，也不得为 API Key、模型或聊天另开宿主端口。
- 跨主机客户端必须使用 HTTPS。回环 HTTP 只用于本机 origin 和健康检查。
- 日志只包含方法、路径、状态、延迟和结构化错误；不得提高到会记录请求体、Authorization、Prompt 或 Response 的级别。
- 限流分别按访问令牌摘要和客户端地址计数，任一桶超限即拒绝；只有 accepted socket 的直连 peer 精确命中 `MINDONE_TRUSTED_PROXY_IPS` 时才采信 Cloudflare `CF-Connecting-IP`。宿主机 Docker 网关由所有本机进程共享，不能代表 cloudflared 身份，禁止加入 allowlist。

公开与本地端口必须保持以下映射：

| 范围 | 地址/端口 | 用途 |
|---|---|---|
| 公网 API | `https://api.holarchic.cn:443` | 唯一协调器公开入口；Base URL 为 `https://api.holarchic.cn/v1`，覆盖 `/v1/models`、`/v1/chat/completions`、`/v1/completions`、`/v1/api-keys` 及同源 `/health`、`/ready`、`/auth/*`；根域官网不转发 |
| Tunnel origin | `http://coordinator:8787` | 仅 Docker internal 网络，由专用 cloudflared 访问 |
| 宿主维护 | `127.0.0.1:18787` | 基础生产 Compose 的本机维护入口；公网 overlay 会移除它 |
| 用户本地推理 | `127.0.0.1:8080` 及用户选择的其他端口 | `model deploy` / `serve run` 的受管 llama.cpp；不得公网发布 |
| 用户本地消费代理 | `127.0.0.1:9090` 或用户指定端口 | `quota use` 的本机 OpenAI 兼容代理；不得作为协调服务器公网 API |

PostgreSQL `5432` 不发布宿主或公网端口。额外模型服务端口只存在于贡献者自己的设备；贡献发布当前只绑定默认 `8080` 实例。

## 必需配置

| 变量 | 默认值 | 说明 |
|---|---|---|
| `DATABASE_URL` | 无 | PostgreSQL URL；production 的所有 TCP 连接必须使用带受信 CA 的 `sslmode=verify-full`；只有 Unix socket 可以不使用 TLS |
| `MINDONE_DB_MAX_CONNECTIONS` | `10` | 单个进程的 PostgreSQL 连接池上限，只接受 `1..=32`；`mindone_app` 的角色级连接上限固定为 32，多副本与 operator 的连接池总和也不得超过该上限 |
| `MINDONE_ENV` | `production` | `production`、`development` 或 `test` |
| `MINDONE_BIND` | `127.0.0.1:8787` | 监听地址 |
| `MINDONE_ALLOW_NON_LOOPBACK` | `false` | 仅容器内部显式设为 `true` |
| `MINDONE_AUTH_PROVIDER` | `github` | `github`、`email`，或仅开发/测试用 `local-development` |
| `MINDONE_PUBLIC_URL` | `http://127.0.0.1:8787` | email provider 的同源公开基址；production 必须是无 userinfo/query/fragment 的 HTTPS origin，loopback HTTP 仅限 development/test |
| `MINDONE_GITHUB_CLIENT_ID` | 无 | GitHub OAuth App Client ID；GitHub 模式必需 |
| `MINDONE_GITHUB_SCOPE` | `read:user` | Device Flow scope；需要邮箱时才显式追加 `user:email` |
| `MINDONE_SMTP_HOST` / `MINDONE_SMTP_PORT` | 无 | email provider 必需；SMTP 主机和 `1..=65535` 端口 |
| `MINDONE_SMTP_SECURITY` | `starttls` | `tls` 或 `starttls`；`plain` 只允许 development/test、显式 `MINDONE_SMTP_ALLOW_INSECURE_DEV=true` 且 host 为 loopback 或 `mailhog` |
| `MINDONE_SMTP_USERNAME` / `MINDONE_SMTP_PASSWORD` | 无 | 可选认证对；必须同时配置或同时省略，密码不得写入仓库、argv 或日志 |
| `MINDONE_SMTP_FROM_EMAIL` | 无 | email provider 必需的发件地址 |
| `MINDONE_SMTP_FROM_NAME` | `MindOne` | 发件显示名 |
| `MINDONE_TOKEN_PEPPER` | 无 | 生产环境必需，至少 32 个随机字符 |
| `MINDONE_STANDARD_DATA_KEY_FILE` | 无 | 首选且启动必需；内容为恰好 64 位小写 hex 的独立 32-byte Secret。本机源码和普通宿主路径必须是规范绝对普通文件、父链无符号链接，源文件只能 owner 访问（通常 `0600`，只读可 `0400`），父目录不得允许 group/other 写入；Compose `/run/secrets` 单文件挂载例外见下文 |
| `MINDONE_STANDARD_DATA_KEY` | 无 | 兼容开发/E2E 的 inline 形式；与 `_FILE` 互斥，生产优先使用 Secret 文件 |
| `MINDONE_TRUSTED_PROXY_IPS` | `127.0.0.1,::1` | 可提交 `CF-Connecting-IP` 的直连代理精确 IP，逗号分隔，最多 32 个；不接受 CIDR |
| `MINDONE_ASN_MAP_PATH` | 无 | 可选的部署方控制 ASN JSON 普通文件绝对路径；未配置时明确降级为无 ASN 信号 |
| `MINDONE_ACCESS_TOKEN_SECONDS` | `900` | 生产环境最大 3600 秒 |
| `MINDONE_REFRESH_TOKEN_SECONDS` | `2592000` | 刷新令牌生命周期 |
| `MINDONE_REQUEST_BODY_LIMIT_BYTES` | `1048576` | 请求体上限 |
| `MINDONE_REQUEST_TIMEOUT_SECONDS` | `30` | 请求超时 |
| `MINDONE_REQUESTS_PER_MINUTE` | `120` | 单实例按访问令牌与客户端地址分别计数的每分钟上限 |
| `MINDONE_JOB_LEASE_SECONDS` | `60` | 任务租约时长 |
| `MINDONE_MAX_JOB_RETRIES` | `3` | 首次尝试后的最大重试次数 |
| `MINDONE_EVALUATION_DRAW_DENOMINATOR` | `8` | 生产每次普通 claim 用 CSPRNG 以 `1/N` 概率混入精确实例挑战；只允许 `1..=10000`，不建立专用 evaluation API |
| `MINDONE_EVALUATION_INSTANCE_COOLDOWN_SECONDS` | `60` | 同一模型实例两次评价领取之间的服务端冷却；只允许 `1..=3600`，测试配置使用 1 秒但生产不得设为 0 |
| `MINDONE_QUALITY_EVALUATOR_KEYS_DIR` | 无 | 可选；执行 `quality-record` 时必需，生产 Hidden Benchmark 也从该目录读取受信 evaluator Ed25519 公钥与固定文件名 `private-evaluation-catalog-v1.json`。目录、catalog 及公钥文件不得是符号链接，Unix 上不得允许 group/other 写入 |
| `MINDONE_PRIVATE_EVALUATION_HMAC_KEY_FILE` | 无 | private v2 commitment 的独立 HMAC Secret 文件。inline `MINDONE_PRIVATE_EVALUATION_HMAC_KEY` 永远拒绝；文件必须是规范绝对普通文件，严格为 `mindone-private-hidden-hmac-v1:<64 位小写 hex>\n`，且不得复用 token pepper 或 Standard data key。有效 private catalog、既有 key-state 或任何 v2 状态都会令它成为启动必需项 |
| `MINDONE_PRIVATE_EVALUATION_CATALOG_HOURLY_LIMIT` | 无 | private catalog 每小时发行上限，只允许 `1..=4096`；六项预算必须作为完整组显式配置 |
| `MINDONE_PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT` | 无 | 单账号每小时 private 发行上限，只允许 `1..=4096` |
| `MINDONE_PRIVATE_EVALUATION_DEVICE_HOURLY_LIMIT` | 无 | 单设备每小时 private 发行上限，只允许 `1..=4096` |
| `MINDONE_PRIVATE_EVALUATION_NODE_HOURLY_LIMIT` | 无 | 单节点每小时 private 发行上限，只允许 `1..=4096` |
| `MINDONE_PRIVATE_EVALUATION_COOLDOWN_SECONDS` | 无 | 同一 private scope 的发行冷却，只允许 `1..=86400` 秒 |
| `MINDONE_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES` | 无 | 全局保留的未发行 catalog 条目数，只允许 `0..=4095`；`0` 必须是 operator 的显式决定，不是默认值 |

生产环境启动时，如果所选 provider 的必需项、token pepper、Standard 数据密钥或数据库 URL 缺失，进程会直接拒绝启动。GitHub 模式要求 Client ID；email 模式要求合法 HTTPS `MINDONE_PUBLIC_URL`，并在路由构造前验证 SMTP 必填项、发件人地址和传输构造参数；它只挂载同源 `/auth/register`、`/auth/login`、`/auth/verify-email` 页面。邮箱验证 GET 只显示确认页，用户显式 POST 后才消费 token。`local-development` 在 production 环境会被强制拒绝。测试进程可在构造的 test config 中把抽样分母设为 `0` 以显式关闭；生产环境变量不接受 `0`，不得把测试逃生阀当作部署配置。

邮箱部署可在完整环境变量与 Secret 文件就绪后运行 `./verify-config.sh`。脚本从自身规范目录定位 `Cargo.toml`，通过 locked/offline Cargo 构建并复用当前源码的 `mindone-coordinator config-check` Rust 启动合同，不会从调用者工作目录执行同名二进制。默认模式会读取并验证配置和 Secret 文件，但不连接数据库、SMTP 或其他外部服务，也不回显配置值。只有运维者显式运行 `./verify-config.sh --live` 时，命令才连接 PostgreSQL，在只读事务中把 `public._sqlx_migrations` 的版本、描述、成功状态和 checksum 与当前二进制逐项比较，并建立一次不发送邮件的 SMTP 会话。两种模式都不迁移数据库、不发送验证邮件；live 成功也不等于浏览器注册、真实投递和设备签名 poll 的完整外部 E2E 已通过。

email 登录仍是 Ed25519 Device Flow：CLI 终端显示 12 位 `user_code`，用户核对 origin 后在浏览器手工输入；浏览器只授权 flow，不收 bearer，最终 `/v1/auth/device/poll` 必须设备签名。验证 token 只以 HMAC 保存，request tracing 不记录 query。password reset 尚未实现，不得把内部发信 helper 宣称为可用运维恢复流程。

未配置质量目录、没有有效 private catalog 且数据库从未建立 private v2 key-state/数据的基础栈，可以不配置 private HMAC 与六项预算并继续生成公开 canary；这种部署不得宣称已经启用 Hidden Benchmark。六项预算只要出现任一项就必须全部出现，任何空值、缺项或越界值都会在连接数据库前失败。有效 catalog 会要求 HMAC 与完整预算；数据库一旦存在 key-state 或 v2 数据，即使随后移除 catalog，也必须继续提供同一 HMAC，缺失或误换都会在监听端口前失败关闭。

显式设置 `MINDONE_TRUSTED_PROXY_IPS` 会替换默认值。基础 Compose 只保留容器自身的 `127.0.0.1`/`::1`；它不会信任宿主机 origin 请求携带的 Cloudflare 头。本机 2026-07-18 的受控测试证明，宿主机访问回环发布端口时，容器看到的是 `mindone_edge` 网关 `172.21.0.1`。这个结果只能证明请求来自宿主机，不能证明请求来自 cloudflared：任意本机进程都能走同一 NAT 路径并伪造 `CF-Connecting-IP`。因此不得把 `172.21.0.1`、其他 Docker 网关、私网段或 CIDR 加入 allowlist。

公网 overlay 使用独立 internal `/29`：协调器固定为 `172.31.255.2`，专用 cloudflared 固定为 `172.31.255.3`，且 origin 没有宿主机端口。overlay 把 allowlist 精确替换为 `172.31.255.3`。该网络只连接这两个受限容器；拥有 Docker daemon 管理权限的主体仍属于主机管理员信任边界。若默认子网与现有网络冲突，必须在首次部署前把 subnet、两个固定 IP 和 allowlist 作为同一次受审变更，不得临时放宽为网关或 CIDR。

ASN 映射只在启动时从本地文件加载，不调用外部 IP/ASN 查询服务，也不接受客户端 ASN 字段。格式固定为：

```json
{
  "version": 1,
  "entries": [
    {"cidr": "203.0.113.0/24", "asn": 64500},
    {"cidr": "2001:db8::/32", "asn": 64501}
  ]
}
```

CIDR 必须是规范网络地址，前缀不得重复，ASN 范围为 1 到 4294967294，文件最大 8 MiB、最多 100000 条。路径必须是已存在的绝对普通文件，不能是符号链接；Unix 上不得允许 group/other 写入。配置文件但加载失败时服务拒绝启动；未配置时日志写入 `asn_signal_available=false`，不伪称 ASN 可用。容器部署若启用此项，还必须由部署方把文件只读挂载到同一绝对路径；仓库不会内置或下载一份可能过期的映射。

生成只含十六进制字符、可安全放入 PostgreSQL URL 和环境变量的本机 secret 示例：

```bash
openssl rand -hex 32
```

不要把输出写入 Git、shell 历史、工单或聊天记录。生产环境应通过部署平台 Secret 管理器注入。

仓库 Compose 模板为了本机单用户部署兼容性，仍从权限受限且 Git 忽略的 `deploy/.env` 注入数据库 owner/runtime 两个独立密码和 token pepper；这些值会出现在容器进程环境和有权限执行 `docker inspect` 的管理员视图中，因此不等同于 Docker Secret。两个数据库密码都应分别使用 URL-safe 随机值，禁止复用。宿主 `deploy/secrets/` 必须保持 `0700`，Standard 数据密钥和 private HMAC 源文件必须分别保持 `0600`，并以两个不同的只读单文件挂载进入 `/run/secrets`；private HMAC 只挂载给常驻 coordinator，不授予不执行 private claim 的 migrator、role-init 或 quality operator。Docker/Compose 在容器 `/run/secrets` 中可能把这种只读文件呈现为 root 所有的 `0444` 或 `0644`；配置只对这个固定容器 Secret 目录接受该表现形式，因为镜像只运行一个 UID/GID `10001:10001` 的非 root coordinator、文件本身只读且没有第二个工作负载。这个例外绝不允许把宿主源文件或其他普通 key 文件放宽为 `0644`。共享主机或更高等级生产环境必须改用平台 Secret 管理器或凭据文件适配器，并限制 Docker daemon 权限。PostgreSQL 私钥、CA 私钥、Standard 数据密钥、private HMAC 和 cloudflared token 只放在 Git/Docker build context 都忽略的 `deploy/secrets/` 或等价仓库外 Secret 存储，不进入环境值或 argv。不要把 `docker compose config` 的完整输出写入日志，因为它会展开数据库密码与 token pepper；`scripts/validate-private-v2-compose.sh` 只使用临时合成占位值，并验证渲染结果不包含 private HMAC 文件内容。

## 本机源码启动

```bash
export MINDONE_ENV=production
export MINDONE_AUTH_PROVIDER=github
export MINDONE_GITHUB_CLIENT_ID='<OAuth Client ID>'
export MINDONE_TOKEN_PEPPER='<至少32字符随机值>'
export MINDONE_STANDARD_DATA_KEY_FILE='/规范绝对路径/standard-data-key'

# 第一步：只由数据库 owner 执行结构迁移和受控旧数据升级
export DATABASE_URL='postgres://mindone:<owner密码>@127.0.0.1:5432/mindone?sslmode=verify-full&sslrootcert=/绝对路径/ca.crt'
cargo run -p mindone-coordinator -- database-migrate

# 第二步：部署方先为 mindone_app 配置独立 LOGIN 凭据，再以 runtime 角色启动
export DATABASE_URL='postgres://mindone_app:<runtime密码>@127.0.0.1:5432/mindone?sslmode=verify-full&sslrootcert=/绝对路径/ca.crt'
cargo run -p mindone-coordinator
```

`database-migrate` 是唯一允许执行嵌入 SQLx schema migrations 的应用入口，必须使用数据库 owner；当前源码和由它构建的二进制要求精确应用 `0001..0039`。它还会在受控事务中最多每批 100 行地把旧 Standard Base64 payload/result 回填为 AEAD v1，并把已有的 64 位旧 SHA-256 幂等指纹转换为 keyed HMAC；任一行异常会回滚并令迁移失败。数据库首次绑定不可变 key commitment，后续运行用常量时间比较验证密钥，误换密钥会在 `/ready` 可用前失败。

常驻服务器、`quota-grant`、`quality-record`、`billing-profile-record`、`reserve-release` 和 `sla-exclusion-record` 都不得执行 schema migration。它们先在只读事务中把 `public._sqlx_migrations` 的版本、描述、成功状态和 checksum 与当前二进制逐项精确比较；缺表、少版本、多版本、失败记录、遮蔽或 checksum 漂移都会失败关闭。通过结构校验后只允许执行 Standard 旧数据保护所需的数据升级，不创建、修改或删除数据库对象。`config-check --live` 更严格地只做上述只读结构比较，不执行数据升级。源码部署必须先显式运行 owner `database-migrate` 并完成 `mindone_app` LOGIN/最小权限配置，不能为了省略这一步而让 runtime 使用 owner URL。当前树已把查询限定到 `public`、撤销 runtime TEMP，并用真实 PostgreSQL drift/遮蔽负例验证失败关闭。

本机 live production 仍运行已经验收的 `0001..0026` schema 与对应旧二进制；它没有应用 `0027`..`0039`。因此把当前 `0001..0039` 二进制直接指向该数据库时，server 和全部 runtime/operator 子命令会在只读 schema 比较阶段拒绝运行。在完成停写、可恢复备份和隔离恢复演练，并由 owner 显式执行 `database-migrate` 之前，不得把 live coordinator 切换到当前二进制，也不得通过手改 `_sqlx_migrations`、放宽 runtime 权限或继续使用 owner URL 绕过拒绝。2026-07-18 的 role-init 与真实 LOGIN/TLS 证据是 live v26 的历史运行证据；它不证明 live 已升级到 v39。

## 节点 worker 运行门禁

受管 llama.cpp 的 CPU-only 必须由 `ServeRequest.cpu_only` 和平台策略生成。macOS Seatbelt 路径无条件采用该策略；其他平台只有显式配置 `cpu_only: true` 时采用。最终 argv 必须同时包含 `--device none`、`--n-gpu-layers 0`、`--no-kv-offload` 与 `--no-op-offload`。高级配置中的 `--device`、GPU layer 或 KV/op offload 开关均被拒绝；启动子进程前还会清除 `LLAMA_ARG_DEVICE`、`LLAMA_ARG_N_GPU_LAYERS`、`LLAMA_ARG_KV_OFFLOAD`、`LLAMA_ARG_NO_KV_OFFLOAD` 和 `LLAMA_ARG_NO_OP_OFFLOAD`。排障时不要把这些参数塞回 `additional_args`；应检查受管启动错误和实际进程状态。

同一受管进程固定 `--parallel 4 --kv-unified`：公开回环代理强制使用 slot 0，贡献 worker 只分配 slot 1..3，并在每个终态请求后核验对应 erase 回执。节点 policy 的 `max_concurrent` 只接受 `1..=3`；standard/fast 必须等整台贡献端空闲，slow 才能使用剩余贡献槽。若启动能力探测缺少 `--kv-unified`、slot 动作端点或禁用 prompt cache 的参数，服务必须失败关闭，不能退回静态分割上下文或无清理模式。

发布时 CLI 会原子保存 `runtime/node-policy.json`。活动 worker 的领取前、执行前、心跳和状态路径要求它是可安全读取的普通文件；缺失、损坏、符号链接、非普通文件或非法值均按 code 50 失败关闭，不会改用默认允许策略。修复流程是先停止共享，再运行 `mindone node policy set` / `mindone node threshold set` 或重新 `share publish` 生成受控文件，随后重新发布；不要手工用符号链接或宽权限替代文件。领取后策略变化会在执行前再次复核，拒绝任务时释放预留额度且不生成收据。

chat SSE 可用 `reasoning_content` 记录首 Token 时间，但只有可见 `content` 非空才可形成成功结果。reasoning-only 输出由 worker 本地走受控 `/fail`；若协调器仍以 HTTP 400 确定性拒绝普通或评价结果，worker 会补交一份固定、不可重试且幂等的脱敏 `/fail`，不复制远端 message，也不主动把租约/canary 留到过期。HTTP 409 租约冲突和 5xx/传输错误不会被误写成模型失败；失败提交本身仍无法确认时由既有租约过期路径收口。

### 0027 canonical 账本哈希版本边界

`0027_canonical_ledger_hashes.sql` 不改写既有 quota、contribution 或 reserve 链。迁移前的行保持原 `entry_hash`、`prev_hash`、链头和计数，统一标记为 `hash_version=1`、`metadata={}`，这是不可重算的 legacy v1；缺少当时 metadata 时不得伪造重算结果。迁移后的新行只允许 `hash_version=2`。v2 使用带域分隔的 length-prefixed UTF-8 canonical byte stream，覆盖 scope、ID、账户、request、幂等键、类型、整数 microquota、前后余额、PostgreSQL 微秒时间、前序哈希及按 UTF-8 字节排序的受限 string metadata。

数据库 `BEFORE INSERT` trigger 会从持久化行内容自行重算 v2 SHA-256：调用方省略 `entry_hash` 时由 trigger 填入，提供任意 64 位值或修改任一受承诺字段时都会拒绝。随后才执行 `0024` 的权威链头/余额 trigger，两者处于同一语句事务并共同回滚。v1 与 v2 可以在同一只追加链中连续存在，但只有 v2 能由数据库当前行完整重算；两者都只证明数据库内账本承诺、顺序和余额一致性，不是节点实际执行或输出正确性的证明。

旧库中 Standard 行的 `standard_request_fingerprint IS NULL` 会故意令启动失败：没有原始创建请求的可信指纹就不能重建等价 HMAC，升级代码不会编造值、跳过该行或把损坏状态冒充已保护。升级窗口前必须在只读备份上先检查：

```sql
SELECT id, status
FROM jobs
WHERE confidentiality_mode = 'standard'
  AND standard_request_fingerprint IS NULL;
```

结果必须为空才能直接升级。若命中，先停写并保留可恢复备份，逐行从可信的旧数据库备份或受审原始请求记录恢复**准确的旧 64 位小写指纹**；无法证明原值时，不得填随机哈希，应由数据负责人决定把旧环境保持离线留存，或按正式数据处置流程退役受影响数据后再升级。处置完成后重复查询并进行恢复演练，再允许新二进制启动。

回填只保护更新后的活动页和之后生成的备份，不是安全擦除：旧明文可能仍在 WAL、dead tuple、存储快照和历史备份中。升级后必须按数据保留策略轮换或销毁旧备份与 WAL；严格场景应迁入使用新密钥的新卷或新集群。v1 不支持仅修改环境变量的在线密钥轮换；不得直接替换密钥文件。密钥疑似泄露时应停写，在受审离线流程中用旧密钥解密、以新密钥重加密全部 Standard 行并更新版本化 commitment，验证恢复后再销毁旧副本。

## 生产初始额度与受控赠额

production 注册账户始终为 `0` 余额，不存在自动注册赠额，也不存在 HTTP admin 路由。为了让首批消费者能创建任务，持有协调器服务器环境与数据库访问权的运维者可以在已经运行的生产容器中执行：

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml exec -T coordinator \
  mindone-coordinator quota-grant \
  --user-id '<既有用户UUID>' \
  --amount-micro 1000000 \
  --idempotency-key 'launch-2026-0001' \
  --operator 'ops/oncall@example.com' \
  --reason '生产网络首批供应启动额度'
```

本机源码运维可在同一套完整服务器环境变量下把最后一段替换为 `cargo run -p mindone-coordinator -- quota-grant ...`。`amount-micro` 必须在 `1..=1000000000000`；幂等键和 operator 必须是 1 到 128 字节、以字母或数字开头的受限 ASCII 标识符；理由必须为 8 到 512 个字符且没有首尾空白或控制字符。目标用户及其额度账户必须已经存在。

命令不会执行 migration；它先按上述 runtime 路径严格校验现有 schema，随后在单一事务中串行化幂等键、锁定账户、读取最后一条 quota 哈希、追加 `operator_grant`、更新余额并写入 `operator_quota_grants`。审计表和账本都禁止 UPDATE/DELETE，数据库触发器还会核对用户、金额、前后余额、幂等键、账本 ID、entry hash 与账户终值。完全相同的重试返回同一 grant/ledger 且 `idempotent_replay=true`；同键变更任一请求字段会拒绝。每次审批使用新的可追踪幂等键，不要共享 `DATABASE_URL` 给 CLI 用户。

这笔额度是任务结算公式之外的显式外生启动供给，不产生虚假 job、receipt、准备金或节点贡献。额度进入账户后，后续任务仍严格使用正常预留、扣款和通缩结算公式。

## 受控计费、质量、准备金与 SLA 运维

协调器不提供计费 profile、质量写入、准备金释放或 SLA 排除的 HTTP admin 路由。这些能力只能由持有完整服务器环境和数据库访问权的运维者执行服务器二进制子命令；命令不会执行 schema migration，只会先按 runtime 路径严格校验 owner 已完整应用且未漂移的 schema，再把业务变更与只追加 operator 审计放在同一个 PostgreSQL 事务中。

### 物理计费 profile

新任务只接受 `server_reference_upper_bound_v1`。没有与 canonical 模型匹配、在有效期内且覆盖授权输入/输出上限的 profile 时，Standard 与 Regulated 创建都失败关闭；发布者提供的兼容 `base_cost_per_1k_micro` 不决定金额。独立计费评测先生成非空 evidence 文件，运维者再执行：

```bash
mindone-coordinator billing-profile-record \
  --model-id '<canonical模型UUID>' \
  --profile-version 1 \
  --reference-hardware-class 'nvidia-h100-sxm-80gb' \
  --maximum-input-tokens 4096 \
  --maximum-output-tokens 1024 \
  --fixed-gpu-time-us 100000 \
  --gpu-time-us-per-1k-tokens 2000000 \
  --reference-vram-mib 81920 \
  --token-rate-micro-per-1k 1000 \
  --gpu-rate-micro-per-second 2000 \
  --vram-rate-micro-per-gib-second 3000 \
  --evidence-file '/规范绝对路径/billing-evidence.bin' \
  --valid-from '2026-08-01T00:00:00Z' \
  --valid-until '2026-09-01T00:00:00Z' \
  --operator 'ops/billing' \
  --reason '依据独立硬件基准发布八月参考费率' \
  --idempotency-key 'billing-h100-2026-08-v1'
```

evidence 必须是规范绝对普通文件，非空且不超过 1 GiB；数据库只保存 SHA-256。profile version 为同一模型不可变正整数；参考类别、operator 和幂等键有受限长度/字符集，理由为 8..512 字符，时间最多微秒精度且结束晚于开始。命令先用公共 accounting crate 验证全部上界、溢出和 High Tier 最大准备金，再由 `SECURITY DEFINER` 函数原子写入不可变 profile 与只追加 operator audit。完全相同请求返回原记录；同键变更或同模型 version 冲突均拒绝。

### 私有 Hidden Benchmark catalog

`0028_private_hidden_benchmark.sql` 的 legacy v1 行为真正的私有模型真实性挑战增加执行绑定、一次性 catalog identity/commitment 和只追加跨实例仲裁；这些历史行会保存 catalog/entry/case family/evaluator 标识以及裸 Prompt/预期行为 SHA-256，但不保存私有 Prompt、预期响应或实际响应明文。当前 `0031` private commitment v2 的新行必须把这些原始标识和裸哈希全部置为 `NULL`，只保存域分离 keyed commitments、模型/实例/节点绑定、授权上限、绝对有效期和完成生命周期需要的非敏感状态。同一 keyed entry、Prompt 或行为不能跨 catalog 重复消费。只有同一权重、同一 evaluator key commitment 和同一 case-family commitment 至少出现两个不同实例，仲裁才可能成为 `corroborated` 或 `disputed`；单实例永远只是 `pending`，仲裁事件禁止 UPDATE/DELETE。

真实题库必须由独立 evaluator 在仓库外生成，固定文件名为 `private-evaluation-catalog-v1.json`，schema 为 `mindone-private-evaluation-catalog-v1`。statement 绑定 `catalog_id`、`evaluator_id`、签发/失效时间、`utf8-trim-v1` 行为规范及每条 entry 的目标模型权重 SHA-256、私有 Prompt、预期行为 SHA-256、推理 seed 和最大输出 Token；外层用对应 `<evaluator_id>.pub` 的 Ed25519 私钥签署域分隔消息。私钥不得进入协调器、Compose、仓库或 catalog 目录。catalog 最大 4 MiB、最多 4096 条、有效期最长 30 天；格式、存储权限、签名、有效期、目标权重或一次性约束任一不满足时，该次抽样只能降级为公开 canary，绝不能把仓库内模板冒充 Hidden Benchmark。

基础 `deploy/docker-compose.yml` 不挂载 evaluator 目录或 private HMAC，所以在没有历史 v2 状态的全新数据库上只具备公开 canary。生产要启用 Hidden Benchmark，必须先在仓库外的受控目录放入真实签名 catalog 和匹配的受信公钥，再生成一份与 token pepper、Standard data key 都不同的 32-byte private HMAC。Secret 文件必须精确以版本前缀开头、以一个 LF 结束；下面的命令不回显材料，并用 shell noclobber 拒绝覆盖既有文件：

```bash
install -d -m 0700 /srv/mindone-secrets
(umask 077; set -C; {
  printf '%s' 'mindone-private-hidden-hmac-v1:'
  openssl rand -hex 32
} > /srv/mindone-secrets/private-evaluation-hmac-key)
chmod 0600 /srv/mindone-secrets/private-evaluation-hmac-key
```

也可把文件放在 Git 与 Docker build context 已明确排除的 `deploy/secrets/`，但 `.env` 应填写规范绝对宿主路径。不要用 `echo` 拼接、不要删掉末尾 LF、不要写入大写 hex，也不要把该材料复制到 `MINDONE_PRIVATE_EVALUATION_HMAC_KEY`、catalog、evaluator 私钥目录或 Standard key 文件。接着在 `deploy/.env` 填写 HMAC 宿主路径以及容量/威胁模型评审批准的六项预算；项目规格没有批准任何生产数值，因此这里故意不提供可复制的数字：

```dotenv
MINDONE_PRIVATE_EVALUATION_HMAC_KEY_HOST_FILE=/srv/mindone-secrets/private-evaluation-hmac-key
MINDONE_PRIVATE_EVALUATION_CATALOG_HOURLY_LIMIT=<批准后的正整数>
MINDONE_PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT=<批准后的正整数>
MINDONE_PRIVATE_EVALUATION_DEVICE_HOURLY_LIMIT=<批准后的正整数>
MINDONE_PRIVATE_EVALUATION_NODE_HOURLY_LIMIT=<批准后的正整数>
MINDONE_PRIVATE_EVALUATION_COOLDOWN_SECONDS=<批准后的正整数秒>
MINDONE_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES=<批准后的非负整数>
```

最后在常驻 coordinator 的普通 `up` 中叠加 `deploy/docker-compose.quality-operator.yml`：

```bash
export MINDONE_QUALITY_KEYS_HOST_DIR='/srv/mindone-operator/trusted-quality-keys'
export MINDONE_QUALITY_EVIDENCE_HOST_DIR='/srv/mindone-operator/quality-evidence-staging'
docker compose --env-file deploy/.env \
  -f deploy/docker-compose.yml \
  -f deploy/docker-compose.quality-operator.yml \
  up -d
```

该 overlay 把同一个仓库外受信目录只读挂载给常驻 `coordinator` 与一次性 `quality-operator`；只有 coordinator 会在普通 claim 中加载 catalog。private HMAC 则作为独立 Compose Secret，只读挂载到 coordinator 固定路径 `/run/secrets/mindone_private_evaluation_hmac_key`，文件内容不会成为环境变量；六项预算只进入 coordinator 环境。`quality-record` 不调用 private runtime prepare 或 claim，所以 quality operator 按最小权限既不获得 HMAC，也不获得 private 预算。evidence 暂存目录只挂载给 operator。

叠加 overlay 时，Compose 的 `:?` 插值会对缺 HMAC 宿主路径、空预算或任意预算缺项直接失败；完整渲染后，coordinator 仍会验证精确文件格式、权限、独立性、数据库 key-state 与预算范围，并在开始监听前失败关闭。无效、过期或签名错误的 catalog 按协议只能退回公开 canary，但不能绕过 key lifecycle 或把 fallback 宣称为 private。未叠加 overlay 的全新基础栈仍可运行 public canary；一旦数据库已有 key-state/v2 行，移除 overlay 或换 key 会按设计拒绝启动。

只做 Compose 接线审计、不接触运行中容器时，执行：

```bash
scripts/validate-private-v2-compose.sh
```

脚本使用权限受限的临时合成 Secret 和占位环境，验证基础栈可渲染、overlay 缺 key/逐项缺预算全部拒绝、完整 overlay 可渲染、HMAC 只授予 coordinator、Secret 内容不出现在渲染结果，以及 Git/Docker 排除规则存在。它不会执行 `up`、`run`、`build`、`start`、`stop` 或 Cargo；真实部署仍须在隔离环境验证启动失败/成功和脱敏日志，不能把静态渲染当作 production 运行证据。

### 签名质量 evidence

`quality-record` 不接受命令行裸分数。独立 evaluator 必须先生成真实评价 artifact，并用固定 Ed25519 私钥签署一个 `mindone-quality-evidence-v1` manifest。私钥不得交给协调器；协调器只读取 `MINDONE_QUALITY_EVALUATOR_KEYS_DIR/<evaluator_id>.pub` 中的 32 字节公钥小写十六进制。manifest 示例：

```json
{
  "statement": {
    "schema": "mindone-quality-evidence-v1",
    "evaluator_id": "quality-lab-1",
    "model_id": "00000000-0000-0000-0000-000000000000",
    "idempotency_key": "quality-2026-07-18-0001",
    "observed_at": "2026-07-18T08:00:00Z",
    "valid_until": "2026-07-18T09:00:00Z",
    "artifact_sha256": "<真实 artifact 的 64 位小写 SHA-256>",
    "measurement": {
      "event_kind": "hidden_benchmark",
      "score_normalized": 820000,
      "sample_count": 100
    }
  },
  "signature": "<128 位小写 Ed25519 signature>"
}
```

签名消息固定为字节串 `mindone:quality-evidence:v1\0 || compact_statement_json`；`compact_statement_json` 是上面 `statement` 对象按字段声明顺序、无额外空白的 UTF-8 JSON。可选 `measurement` 还包括 `{"event_kind":"canary","passed":true}` 和 `{"event_kind":"blind_evaluation","opponent_rating_milli":1500000,"opponent_deviation_milli":200000,"outcome":"win"}`。`observed_at`/`valid_until` 必须是 RFC 3339，有效期不超过 24 小时，且提交时尚未过期。

生产提交使用同一个 tracked override `deploy/docker-compose.quality-operator.yml`。先在仓库外准备两个已经存在的规范绝对目录：受信目录放 `<evaluator_id>.pub`，若启用 Hidden Benchmark 还必须放真实签名的 `private-evaluation-catalog-v1.json`；evidence 暂存目录只放本批次 quality manifest 与 artifact。两者都不得是符号链接，必须允许容器 UID `10001` 只读访问且不得允许 group/other 写入。evaluator 私钥始终留在独立签名环境，**不得**复制到任一目录、`deploy/.env`、Compose Secret 或容器。确认线上 `coordinator` 已使用同一 overlay 就绪，并且当前镜像标签没有被重建或重新指向后执行：

```bash
export MINDONE_QUALITY_KEYS_HOST_DIR='/srv/mindone-operator/trusted-quality-keys'
export MINDONE_QUALITY_EVIDENCE_HOST_DIR='/srv/mindone-operator/quality-2026-07-18-0001'
docker compose --env-file deploy/.env \
  -f deploy/docker-compose.yml \
  -f deploy/docker-compose.quality-operator.yml \
  --profile operator run --rm --no-deps quality-operator \
  quality-record \
  --evidence-file '/run/mindone-quality/evidence/evidence.json' \
  --artifact-file '/run/mindone-quality/evidence/evaluation-artifact.json' \
  --operator 'ops/oncall@example.com' \
  --reason '独立评测实验室批次 quality-2026-07-18-0001'
```

overlay 中的 `quality-operator` 因 `operator` profile 不参与普通 `up`；但 `coordinator` override 会在叠加该文件时生效，负责只读加载私有 catalog。operator 的默认命令只显示 `quality-record --help` 后退出，真实写入必须由上面的 `run` 显式覆盖命令。它以 `pull_policy: never` 复用线上 coordinator 的同一 `MINDONE_COORDINATOR_IMAGE`，没有端口、没有 `edge`/公网网络、根文件系统只读且只接入 internal `backend`。`--no-deps` 防止运维命令自行新建一套数据库，因此线上 PostgreSQL 不可用时命令应直接失败。两个宿主目录只读映射到固定容器路径；Compose 合同没有 evaluator 私钥、private HMAC 或 private 预算授予 quality operator。

协调器会重新流式计算 artifact SHA-256、验证短期 statement 与 pinned evaluator 公钥签名，然后调用现有质量融合、Glicko-2、同名全 cohort 相对排名和 Tier 滞回事务。`model_quality_events`、`quality_evidence_audits` 与派生的 `model_tier_transition_events` 原子提交；转换审计绑定源质量事件、cohort commitment、percentile 和策略版本。首次提交成功后，完全相同的重试直接核对已提交审计，因此即使 statement 随后过期或 evaluator 公钥已经轮换，仍返回原事件且 `idempotent_replay=true`；新幂等键始终验证当前时效与当前 pinned 公钥，同键变更或没有签名审计的旧裸事件会 fail-closed。artifact 最大 1 GiB，manifest 最大 64 KiB；二者必须是规范绝对路径的非符号链接普通文件。trusted keys 目录自身及全部父目录都不得允许 group/other 写入。

### 准备金释放

准备金只允许 `result-validation`、`failed-retry`、`bandwidth-subsidy` 和 `peak-guarantee` 四种用途：

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
  exec -T coordinator mindone-coordinator reserve-release \
  --purpose result-validation \
  --amount-micro 250000 \
  --reference 'validation/case-2026-0001' \
  --idempotency-key 'reserve-2026-0001' \
  --operator 'ops/oncall@example.com' \
  --reason '支付独立结果复核批次 validation/case-2026-0001'
```

该命令只在已经运行并通过就绪检查的 production coordinator 内执行，不需要也不应挂载质量 evidence。`amount-micro` 必须在 `1..=1000000000000`。事务会锁定单例准备金账户，余额不足即拒绝；成功时追加独立 `reserve_ledger` 与 `operator_reserve_releases`，审计绑定用途、金额、reference、operator、理由、幂等键和 ledger hash。完全相同的重试返回同一 release/operator audit；同键任一字段变化都会冲突。不得向普通 CLI 用户分发 `DATABASE_URL` 或把这些服务器运维子命令包装成公开 HTTP 接口。

### SLA 审计排除

SLA 排除只允许已经进入 `failed` 或 `cancelled` 的任务，并且类别仅为 `content-policy-refusal` 或 `force-majeure`。节点或 worker 自报的 `error_class`、普通模型失败、超时或性能差不会自动排除。运维者必须先取得独立、非空、规范绝对普通文件 evidence，再执行：

```bash
mindone-coordinator sla-exclusion-record \
  --job-id '<终态任务UUID>' \
  --category content-policy-refusal \
  --evidence-file '/规范绝对路径/sla-incident-evidence.bin' \
  --operator 'ops/governance' \
  --reason '独立审计确认该失败属于内容政策拒绝' \
  --idempotency-key 'sla-exclusion-2026-0001'
```

evidence 最大 1 GiB，数据库只保存 SHA-256；operator、理由和幂等键使用与其他运维入口相同的受限合同。`SECURITY DEFINER` 函数在同一事务持有全局幂等 advisory lock 与 job row lock，只追加 `job_sla_exclusion_events`。完全相同请求返回原事件；同键变更或同一任务试图写入第二个决定均冲突。该事件只影响 SLA 统计中经审计的排除计数，不改写任务、账本、receipt、额度或节点收益。

## Docker Compose

当前 Docker Compose 需要 Compose v2。基础服务、一次性数据库 migrator 和一次性质量运维服务共享 `MINDONE_COORDINATOR_IMAGE`；执行迁移或运维命令期间不得重建或重新标记该镜像。

下面的启动配方**只适用于全新 checkout、全新 Compose project 和空 volume，或已经完成本节全部备份/恢复演练并获得明确升级批准的维护窗口**。当前本机 `mindone` project 仍运行 production v26，严禁在其 `deploy/.env`、volume 或默认 project name 上复制执行。新部署必须先确认目标 project/volume 从未存在；既有部署必须跳到“live v26 到当前 v39 的下一次升级”，不能让 `up` 隐式触发当前 v39 migrator。

```bash
test ! -e deploy/.env
test ! -e deploy/secrets/postgres-tls
test ! -e deploy/secrets/standard-data-key
MINDONE_NEW_PROJECT="mindone-new-$(date +%Y%m%d%H%M%S)"
scripts/generate-postgres-tls.sh
(umask 077; set -C; openssl rand -hex 32 > deploy/secrets/standard-data-key)
(umask 077; set -C; : > deploy/.env)
cp deploy/.env.example deploy/.env
chmod 0600 deploy/.env
# 编辑 deploy/.env，分别填入 owner/runtime 数据库密码、GitHub Client ID、token pepper，并确认密钥文件路径
docker compose -p "$MINDONE_NEW_PROJECT" --env-file deploy/.env \
  -f deploy/docker-compose.yml up -d --build
docker compose -p "$MINDONE_NEW_PROJECT" --env-file deploy/.env \
  -f deploy/docker-compose.yml ps
curl -fsS http://127.0.0.1:18787/health
curl -fsS http://127.0.0.1:18787/ready
```

生产数据库固定拆成两个登录角色：`mindone` 是数据库 owner，只提供给 PostgreSQL 健康检查、一次性 `database-migrate` 和一次性角色授权服务；常驻 `coordinator` 与 `quality-operator` 固定使用 `mindone_app`，不持有 owner 密码。启动门禁顺序为 `postgres healthy → database-migrator 成功 → database-role-init 成功 → coordinator`。migrator 使用 owner URL 执行 `mindone-coordinator database-migrate`，完成 schema migration 与 Standard 旧数据回填后退出；role-init 随后通过 TLS 与 `PG*` 环境连接，幂等创建或轮换 `mindone_app`，刷新现有表和序列权限，设置 owner 的默认权限，并显式撤销 runtime 对 `public` schema 的 CREATE 权限。设计目标是 runtime 对 `public._sqlx_migrations` 仅保留启动校验所需的 `SELECT`，并且无 TEMP、成员关系、对象 ownership 或其他旁路；业务 trigger 的执行不要求向 runtime 授予 public 函数 EXECUTE。密码由 `psql \getenv` 读取并作为 SQL literal 引用，不进入命令行 argv。

两个 one-shot 服务都只连接 internal `backend`，没有发布端口，根文件系统只读，丢弃全部 capabilities，启用 `no-new-privileges` 且 `restart: "no"`。`docker compose ps -a` 中它们在每次成功部署后应显示退出码 `0`；任一失败都会阻止 coordinator 启动。不要通过手工跳过 dependency、把 owner URL 复制给 coordinator，或为让 runtime 自行迁移而恢复 DDL 权限。

> 当前运行门禁：role-init 已把密码、角色属性和全部 ACL/default ACL 刷新放入同一事务。2026-07-18 已在 live v26 production 镜像上实际通过真实 `mindone_app` LOGIN、TLS `verify-full`、密码隔离和 ACL 检查；这只证明本机 `0001..0026` loopback production，不证明当前源码的 `0027`..`0039` 已部署。角色全局连接上限为 32，所有常驻副本和 operator 的连接池总和不得超过该上限。

### 既有生产卷升级角色拆分

2026-07-18 已对本机既有 17/17 production 卷完成实际升级。升级前备份位于 `.mindone/backups/production-before-0018-0026-20260718T093857Z/`，custom dump 已恢复到隔离数据库，迁移状态和全部 public 表行数与源库一致；随后又使用同一份备份、临时非生产 Standard data key 和当前 coordinator 镜像在隔离环境完成真实 `17 → 26` 演练。投入运行的镜像 ID 前缀为 `dcee3dc…`。生产 key 在演练通过后才单独生成并挂载，没有进入演练容器、数据库备份或日志。

实际切换保留原 PostgreSQL volume，由 owner migrator 应用 `0018..0026`，再由 role-init 设置 runtime LOGIN 和完整 ACL；`database-migrator` 与 `database-role-init` 的退出码均为 `0`，PostgreSQL 与 coordinator 均为 healthy。loopback 验收得到 `/health=200`、`/ready=200`、匿名受保护 API `=401`，迁移状态精确为 `26|1|26|t`。真实新连接确认 current user 为 `mindone_app` 且使用 TLS；角色为 `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 32`，无成员边、对象 ownership、TEMP、schema/database CREATE、额外数据库 CONNECT、public function EXECUTE 或 migration 写权限，现有表/sequence 与 owner 默认 ACL 符合最小权限合同。owner/runtime 密码相互独立，错误密码、交叉密码和明文 TCP 均被拒绝。升级时 `jobs=0`，升级后的 Standard legacy 行数也为 `0`；不可变 key commitment 已建立，并由 coordinator 启动前的密钥比较和 `/ready` 成功共同验证。coordinator 只发布 `127.0.0.1:18787`，PostgreSQL 没有宿主端口。

这次成功记录不改变后续升级规范：既有 `mindone-postgres` volume 通常不需要删除或重建，但升级前必须停写、完成可恢复备份并确认当前 `MINDONE_POSTGRES_PASSWORD` 与卷内既有 `mindone` owner 密码一致；`POSTGRES_PASSWORD` 对已有 volume 不会自动修改 owner 密码。然后配置一个与 owner 密码不同的 `MINDONE_POSTGRES_APP_PASSWORD`，由 migrator 先完成 schema/旧数据升级，由 role-init 再创建或转换并轮换 `mindone_app` 登录凭据，最后才允许 coordinator 启动。每次验收仍必须检查两个 one-shot 退出码为 `0`、精确 migration metadata 和 `/ready=200`，不能把本次证据外推到未来镜像或其他数据库。

Standard data key 不得与数据库 dump 放在同一目录、同一存储或同一访问策略下。当前 live key 与上述数据库备份保持分离；与该 key 对应的独立加密恢复副本及其异地、分权托管仍需由部署方安排并完成恢复演练，不能把 live Secret 文件本身当作已完成的密钥备份。

如果 owner 密码本身也需要轮换，必须先在受控维护连接中用旧 owner 凭据执行审计过的 `ALTER ROLE mindone PASSWORD ...`，再原子更新部署 Secret；只改 `.env` 会导致健康检查、migrator 和 role-init 全部认证失败。runtime 密码则由每次 role-init 的幂等 `ALTER ROLE mindone_app ...` 应用。迁移可能不可逆，失败时保留现场并从升级前备份演练恢复，不得用 `down --volumes` 或手改 `_sqlx_migrations` 作为回滚。

### live v26 到当前 v39 的下一次升级

上面的 `17 → 26` 是已经完成且应保留的历史事实；live production 仍精确为 `0001..0026`，没有应用 `0027`..`0039`。当前 fresh-v39 已在一次性 PostgreSQL 17 上让 16 个 binary 各用独立数据库通过 `49/49`、无 skip，但仍不能替代 live 升级。下一次切换必须重新为当前 v26 卷停写并创建升级前备份，在隔离恢复库中演练 `26 → 39`，并验证 0037 邮箱授权、0038 speed class、0039 HMAC-only API Key/只追加事件及最小 ACL。

隔离演练通过后，才允许在维护窗口依次执行：停止旧 coordinator 写入、排空或取消 `queued/leased/retry` 任务并按账本释放准备金、消费/作废/等待旧 prepared Regulated route 过期、再次核对/保存可恢复备份、由 owner `database-migrate` 应用 `0027`..`0039`、运行 role-init 刷新新表/函数权限、再启动当前 runtime。启动后必须核对 metadata 与当前嵌入 migrations 精确一致、两个 one-shot 退出码 `0`、`mindone_app` 最小权限、`/ready=200`、legacy v1 行保持不变，以及 0037/0038/0039 的表、列、约束与 ACL；不得为了验收编造账户、额度、账本或网络样本。

证书脚本每次生成新的 3072-bit RSA CA/server 密钥，server SAN 固定覆盖 Compose DNS `postgres` 与本机健康检查名称；它拒绝覆盖已有目录。`deploy/secrets/postgres-tls` 默认为 `0700`，私钥为 `0600`。CA 私钥只用于签发/轮换且不会挂载进容器；PostgreSQL 只获得 server cert/key 与 CA 证书，协调器只获得 CA 证书。

`deploy/.env`、`deploy/secrets/`、真实 Cloudflare 配置及质量运维公钥/evidence 暂存目录均不得提交或进入 Docker build context。质量材料必须直接放在仓库外；Git/Docker ignore 中的 `deploy/trusted-quality-keys`、`deploy/quality-evidence` 和 `deploy/operator-staging` 只是误放兜底，不是受支持路径。生产前应确认忽略规则生效，并把 Secret 文件权限限制为仅当前用户可读。Compose 的 `backend` 网络为 internal，PostgreSQL 没有 `ports` 映射。协调器容器使用只读根文件系统、非 root 用户、丢弃全部 Linux capabilities，并启用 `no-new-privileges`。

生产 Compose 的 PostgreSQL 显式启用 TLS、最低 TLS 1.2，并使用单独 `pg_hba`：TCP 只允许 `hostssl` + SCRAM，所有 `hostnossl` 明文 TCP 显式拒绝。PostgreSQL 健康检查和协调器都使用专用 CA 的 `sslmode=verify-full`；证书私钥由 root 入口脚本复制进 tmpfs、改为 postgres 所有且 `0600` 后再降权启动官方 entrypoint。production 配置会解析 SQLx 最终连接参数：任意 TCP host（包括 loopback）若不是 `sslmode=verify-full` 就拒绝启动，query 中的 `host` 覆盖也不能绕过；只有 Unix socket 不经过 TCP，可以不使用 TLS。部署还必须使用受信 CA、匹配主机名、防火墙和最小权限账号。

基础生产模板的本机维护模式使用宿主机 `18787`，容器内端口始终为 `8787`。公网 Cloudflare overlay 通过 `!reset []` 完全移除这个发布端口；Dashboard origin 直接使用容器 DNS `http://coordinator:8787`。不要把宿主机 `18787` 配成公网 tunnel origin，也不要停止或覆盖现有 `8787` 服务。

基础生产 Compose 把协调器接入普通 `edge` 网络以访问 GitHub OAuth；PostgreSQL 只接入 internal `backend`，无法借此出站或被公网访问。Cloudflare overlay 会完全替换协调器的基础网络集合：internal `tunnel_edge` 是 connector 到 origin 的唯一数据路径，协调器改从只属于自己的 `coordinator_egress` 出站，cloudflared 则从独立 `cloudflare_egress` 出站；两个容器不共享任何非 internal 网络。

### 镜像 digest 更新

Dockerfile 的 Rust builder、Debian runtime，以及生产 PostgreSQL、role-init 和开发 PostgreSQL 使用的镜像都同时保留可读 tag 并固定 Docker Official Image 的多架构 **index digest**。不要固定某个 `linux/amd64` 或 `linux/arm64` 的单架构 manifest digest，否则另一平台会失效。更新时：

固定基础镜像 digest 只防止基础文件系统与入口脚本静默漂移；runtime 层的 `apt-get install` 仍读取构建时的 Debian 仓库，因此当前镜像不是逐位可复现构建。若发布流程要求严格复现，还必须使用经过留存验证的 Debian snapshot、固定包版本并保留相应来源元数据；这不能只靠 tag 或基础镜像 digest 解决。

1. 在 Docker Hub 官方 tag 页面确认目标 tag、发布时间及 `Multi-platform / Index digest`。
2. 把同一个 PostgreSQL index digest 同步更新到生产和开发 Compose。
3. 分别验证 `linux/amd64` 与 `linux/arm64` manifest 存在，并由 CI 构建两种架构；不要以本机单架构 `docker image inspect` 作为唯一证据。
4. 运行下面的无 Secret Compose 解析和正常 Rust 测试；构建通过后再由部署负责人安排重建窗口。

```bash
install -m 0600 /dev/null /tmp/mindone-standard-data-key-validation
install -d -m 0700 \
  /tmp/mindone-quality-keys-validation \
  /tmp/mindone-quality-evidence-validation
printf '%s\n' '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a' \
  > /tmp/mindone-standard-data-key-validation
MINDONE_POSTGRES_PASSWORD='compose-validation-only-32-bytes' \
MINDONE_POSTGRES_APP_PASSWORD='compose-validation-only-app-password' \
MINDONE_GITHUB_CLIENT_ID='compose-validation-client-id' \
MINDONE_TOKEN_PEPPER='compose-validation-only-token-pepper' \
MINDONE_POSTGRES_TLS_DIR='/tmp/mindone-postgres-tls-validation' \
MINDONE_STANDARD_DATA_KEY_FILE='/tmp/mindone-standard-data-key-validation' \
docker compose --env-file /dev/null -f deploy/docker-compose.yml config --quiet
MINDONE_POSTGRES_PASSWORD='compose-validation-only-32-bytes' \
MINDONE_POSTGRES_APP_PASSWORD='compose-validation-only-app-password' \
MINDONE_GITHUB_CLIENT_ID='compose-validation-client-id' \
MINDONE_TOKEN_PEPPER='compose-validation-only-token-pepper' \
MINDONE_POSTGRES_TLS_DIR='/tmp/mindone-postgres-tls-validation' \
MINDONE_CLOUDFLARED_TOKEN_FILE='/tmp/mindone-cloudflared-token-validation' \
MINDONE_STANDARD_DATA_KEY_FILE='/tmp/mindone-standard-data-key-validation' \
docker compose --env-file /dev/null -f deploy/docker-compose.yml \
  -f deploy/docker-compose.cloudflared.yml config --quiet
MINDONE_POSTGRES_PASSWORD='compose-validation-only-32-bytes' \
MINDONE_POSTGRES_APP_PASSWORD='compose-validation-only-app-password' \
MINDONE_GITHUB_CLIENT_ID='compose-validation-client-id' \
MINDONE_TOKEN_PEPPER='compose-validation-only-token-pepper' \
MINDONE_POSTGRES_TLS_DIR='/tmp/mindone-postgres-tls-validation' \
MINDONE_STANDARD_DATA_KEY_FILE='/tmp/mindone-standard-data-key-validation' \
MINDONE_QUALITY_KEYS_HOST_DIR='/tmp/mindone-quality-keys-validation' \
MINDONE_QUALITY_EVIDENCE_HOST_DIR='/tmp/mindone-quality-evidence-validation' \
docker compose --env-file /dev/null -f deploy/docker-compose.yml \
  -f deploy/docker-compose.quality-operator.yml \
  --profile operator config --quiet
MINDONE_DEV_POSTGRES_PASSWORD='compose-validation-only-32-bytes' \
MINDONE_DEV_STANDARD_DATA_KEY='5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a' \
docker compose --env-file /dev/null -f deploy/docker-compose.dev.yml config --quiet
```

### 可重复的本地开发栈

开发 Compose 显式使用 `local-development` Device Flow，不要求 GitHub Client ID。PostgreSQL 同时接入专用非 internal `host-db` 网络以启用 Docker 的宿主机端口转发，但端口仍严格绑定在 `127.0.0.1:55432`，仅供本机 Cargo 集成测试连接；生产 Compose 仍完全不发布数据库端口。开发 coordinator 在容器内固定监听 `8787`，`MINDONE_COORDINATOR_HOST_PORT` 只选择 loopback 宿主映射端口，不会改变容器健康检查的目标。

```bash
export MINDONE_DEV_POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export MINDONE_DEV_STANDARD_DATA_KEY="$(openssl rand -hex 32)"
export MINDONE_COORDINATOR_HOST_PORT=18789
docker compose --env-file /dev/null -f deploy/docker-compose.dev.yml up -d --build
curl -fsS "http://127.0.0.1:${MINDONE_COORDINATOR_HOST_PORT}/ready"
DATABASE_URL="postgres://mindone:${MINDONE_DEV_POSTGRES_PASSWORD}@127.0.0.1:55432/mindone_dev" \
  cargo test -p mindone-coordinator --test postgres_integration -- --nocapture
```

开发数据库密码和独立 Standard 数据密钥必须由调用者通过环境注入，Compose 不提供固定默认值；示例使用 URL-safe 随机十六进制值。`deploy/docker-compose.dev.yml` 是明确的本机 loopback 开发例外，仍由单一 `mindone` 数据库用户执行迁移和运行服务，不创建 `mindone_app`；不得把这个单用户权限模型复制到生产 Compose。同镜像的一次性 `database-migrator` 会在 PostgreSQL healthy 后显式执行 `database-migrate`；它成功退出前 coordinator 不会启动，迁移失败因而不可能伪装成 ready。这使全新空卷可直接启动，也保留常驻进程不自动迁移的边界。开发用户名前缀和初始额度只存在于这个明确标记的本地开发文件中。开发账户 subject 由每台设备公钥的 SHA-256 确定，因此消费者和节点使用不同设备密钥时会得到不同账户。初始额度只在每个账户首次创建时发放，并在同一事务追加 `bootstrap_grant` 哈希账本；它绝不会成为 production 默认值。

停止服务但保留数据库：

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml down
```

删除数据库卷属于不可恢复操作，日常停止或升级不要添加 `--volumes`。

## 健康与就绪

```bash
curl -fsS http://127.0.0.1:18787/health
curl -fsS http://127.0.0.1:18787/ready
lsof -nP -iTCP:18787 -sTCP:LISTEN
```

- `/health` 成功只能证明进程存活。
- `/ready` 成功证明当前实例可执行数据库查询；生产容器健康检查与发布验收都以此为就绪门禁。
- 节点是否在线必须另外查看心跳和 `/v1/nodes/{node_id}/stats`。
- Cloudflare 专用 connector 与公网 hostname/route 是另外两层检查；不能用 origin `/ready` 代替。

配置公开 hostname 后，`mindone doctor` 会把 connector、origin 和公网 route 作为一个不冒充 ready 的三层检查执行：未部署专用 connector 时明确警告；一旦发现 connector，任何配置、健康、origin 或公网身份不一致都会失败关闭。

```bash
mindone config set cloudflare.hostname api.<用户已有域名>
mindone doctor
```

1. **专用 connector 层**：只按 Compose label 查找 `project=mindone`、`service=cloudflared` 的唯一容器，不枚举或选择其他 tunnel；要求容器 `running/healthy`，且镜像是 `cloudflare/cloudflared:<version>@sha256:<64hex>`。只检测到 cloudflared binary、找不到受控容器或 Docker 不可验证都不会被报告为 ready；身份不唯一、状态异常、未固定 digest 或已有 connector 却未配置 hostname 会失败。
2. **loopback origin 层**：只选择同一 project 的唯一 `service=coordinator` 容器，要求其 `running/healthy`，再在容器内请求 `http://127.0.0.1:8787/ready`。响应必须是有界的 MindOne JSON identity，即 `status=ready`、`service=mindone-coordinator` 和非空版本。
3. **公网 hostname/route 层**：只请求配置 hostname 的 `https://<hostname>/ready`，强制 HTTPS、不跟随 redirect、限制连接/总超时和 8 KiB 响应体；要求成功状态、合法 `CF-Ray`、同样的 MindOne identity，并且 identity 与 loopback origin 完全一致。缺少 `CF-Ray`、TLS/route 失败或版本/服务身份不同都会失败，避免把指向其他 origin 的 DNS 误报为当前部署。

doctor 三层通过证明“受控 connector → 当前 origin → Cloudflare HTTPS hostname”的身份链，不证明 OAuth Device Flow 或授权 API 合同。公网发布验收仍须按下文额外验证匿名受保护接口为 `401`，并确认没有暴露其他端口。

## Cloudflare Tunnel

宿主机 cloudflared 经回环发布端口访问容器时，所有本机进程共享同一个 Docker/Colima gateway peer，因此不能安全转发客户端地址。生产只支持 `docker-compose.cloudflared.yml` 的专用 connector 模式，并且必须在 Zero Trust Dashboard **新建 MindOne 专用 remotely-managed tunnel**；不得复用、停止或修改现有 aistudio/其他 tunnel、route、LaunchAgent 或 token。

在 Dashboard 为新 tunnel 创建 Public Hostname，用户确认 hostname 后把 Service/Origin 精确设置为：

```text
http://coordinator:8787
```

Dashboard 提供的 connector token 不得放入命令行或环境变量。先创建一个仅当前用户可读的空文件，用编辑器粘贴 token（单行），不要使用会进入 shell history 的 `echo <token>`：

```bash
install -d -m 0700 deploy/secrets/cloudflared
install -m 0600 /dev/null deploy/secrets/cloudflared/token
${EDITOR:-vi} deploy/secrets/cloudflared/token
```

`.env` 的 `MINDONE_CLOUDFLARED_TOKEN_FILE` 只保存文件路径。Compose 把内容作为 `/run/secrets/cloudflared_token` 只读挂载，cloudflared 使用 `--token-file` 读取；token 不出现在 argv、容器环境或仓库 YAML。启动前先做静态解析；不要把完整 config 输出写入日志：

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
  -f deploy/docker-compose.cloudflared.yml config --quiet
docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
  -f deploy/docker-compose.cloudflared.yml up -d --build
```

只发布协调 API，例如 `https://api.<用户已有域名>`。overlay 下 origin 不在宿主机发布，因此本地就绪检查在容器内执行；再分别验证 connector 与公网：

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
  -f deploy/docker-compose.cloudflared.yml exec -T coordinator \
  curl -fsS http://127.0.0.1:8787/ready
docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
  -f deploy/docker-compose.cloudflared.yml ps
curl -fsS https://api.<域名>/health
curl -fsS https://api.<域名>/ready
curl -sS -o /tmp/mindone-unauthorized.json -w '%{http_code}\n' \
  https://api.<域名>/v1/quota/balance
```

只有容器内和公网 `/ready` 都返回 `200`、connector 为 running/healthy，才能证明这三层路径就绪。最后一项在没有 Token 时应为 `401`。不得修改 Nameserver、删除现有 DNS、开启付费功能或暴露 5432/8787/18787/8080/9090。

## 数据库备份和恢复

备份应使用专用只读账号并加密保存：

```bash
pg_dump --format=custom --no-owner --no-acl "$DATABASE_URL" > mindone-$(date +%Y%m%d).dump
```

备份必须与对应 Standard 数据密钥版本建立受控映射并分别加密托管；缺少原密钥时，恢复后的协调器会因 key commitment 不匹配而拒绝启动。不要把密钥和数据库备份放在同一存储或同一访问策略下，也不要把密钥内容写进备份脚本、文件名或日志。

恢复前先在隔离数据库验证备份：

```bash
createdb mindone_restore_test
pg_restore --no-owner --no-acl --dbname mindone_restore_test mindone-YYYYMMDD.dump
```

额度、贡献值和准备金账本有数据库触发器禁止 UPDATE/DELETE。不要临时禁用触发器修账；更正必须追加可审计的补偿记录。

## Token 和凭据轮换

- 修改 `MINDONE_TOKEN_PEPPER` 会让所有现存访问令牌和刷新令牌失效，应在维护窗口执行并通知用户重新登录。
- cloudflared token 只为新建的 MindOne 专用 tunnel 使用；轮换时通过 Dashboard 生成新 token、更新权限受限文件并只重建 connector，禁止读取或复用其他 tunnel token。
- GitHub Client ID 不是 secret，但 OAuth 配置变更仍需记录。
- runtime 数据库密码轮换时更新 `MINDONE_POSTGRES_APP_PASSWORD` 并重新执行完整 Compose 门禁；role-init 成功修改 `mindone_app` 后 coordinator 才会重建。owner 密码按“既有生产卷升级角色拆分”的受控顺序单独轮换，不能只改 `.env`。
- 注销接口把会话标记为撤销；定期清理过期设备登录流程和过期会话时不得删除账本。

协调器服务启动后会运行隐藏租约过期扫描：固定每 5 秒最多处理 128 条，使用 `FOR UPDATE SKIP LOCKED` 支持多副本并发。SIGTERM/Ctrl-C 会先通知该任务停止启动新事务，再等待服务退出。若结构化日志持续出现“隐藏任务过期扫描失败”，应检查 PostgreSQL 连通性、连接池和锁等待；不要通过手工改写 challenge、风险事件或账本绕过收口。

## 测试与故障排查

无需 PostgreSQL 的检查：

```bash
cargo fmt --manifest-path crates/mindone-coordinator/Cargo.toml -- --check
cargo clippy -p mindone-coordinator --all-targets -- -D warnings
cargo test -p mindone-coordinator
```

真实 PostgreSQL 集成测试只在设置 `DATABASE_URL` 时运行完整场景。当前源码连续 `0001..0039`。当前一次性 PostgreSQL 17 上的 16 个 coordinator integration binary 各用独立数据库，合计 **49/49**、无 skip；持久库 metadata 为 `39|1|39|t`，会自建临时库的 migration 测试在用例内部核对后清理。独立数据库用于避免 `database_role` 的故意错误 HMAC commitment 和 private 状态污染其他 binary；未设置 `DATABASE_URL` 时的 skip 不算通过。

每个 binary 必须使用独立、从未使用的测试数据库；不要把下面同一个 URL 循环复用。单项模板：

```bash
test_name='schema_v39'
MINDONE_REQUIRE_POSTGRES_TESTS=1 \
DATABASE_URL='postgres://<临时owner>@127.0.0.1:<临时端口>/<该binary专用数据库>' \
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
cargo test --locked -j1 -p mindone-coordinator \
  --test "$test_name" -- --nocapture --test-threads=1
```

依次运行 `postgres_integration`、`ledger_heads`、`ledger_integrity`、`ledger_migration`、`database_role`、`runtime_schema`、`schema_v31`..`schema_v39`、`router`。`database_role` 会故意建立错误 HMAC commitment，private 测试也会留下状态，因此共享数据库的后续失败没有组合门禁意义。

十六套测试共同覆盖迁移、设备绑定 Device Flow、权威 auth status、稳定节点/模型别名恢复、可选温度策略和 5°C 滞回、动态策略同步、`SKIP LOCKED` 领取、事务结算、账本 head/完整性/迁移、legacy v1 保持与 canonical v2 数据库重算/伪造拒绝、数据库 owner/runtime 分离、runtime schema drift、Standard 升级事务回滚、物理计费 profile/cutover、Standard SSE、SLA 排除、v37 邮箱身份与 ACL、v38 速度字段、v39 API Key/只追加事件/最小 ACL、荣誉账单发现、准备金受控释放、公开 canary、真实签名 private catalog 的模型绑定/一次性消费/重放拒绝/跨实例仲裁、隐藏 result/fail/后台 expiry 的 draining 自动收口、后台 sweep 幂等、最终失败零扣费、终态租约过期 reaper、额度不足以及设备键级令牌撤销。没有 `DATABASE_URL` 时测试会明确跳过外部数据库操作；发布验收必须设置 `MINDONE_REQUIRE_POSTGRES_TESTS=1` 并检查 16 个测试二进制的实际通过数。

2026-07-22 还使用当前工作树 debug 二进制完成了一次隔离 macOS arm64 真实 E2E：独立 PostgreSQL 17 达到 `37|1|37|t`，两个隔离 Home/Keychain 登录，官方 llama.cpp b10064 与 Qwen3-0.6B-Q4_0 GGUF 在受管 CPU-only Seatbelt 中运行；非流式 chat/completions、chat/completions SSE、连续游标及数据库连接故障恢复、ciphertext-only 事件、公开 canary 收口、领取后策略变化的失败零结算、三轨账本/收据唯一结算、Regulated stream 拒绝、日志明文扫描与退出清理均通过。该 E2E 使用 `local-development`，没有验证真实 SMTP/浏览器 email 登录、公网/生产、GPU/其他 OS、private catalog 多实例结果或 SNP/TDX 硬件路径；这些仍需目标部署独立验收。

故障定位顺序：

1. `/health` 是否成功。
2. `/ready` 是否成功。
3. PostgreSQL 容器和连接数是否正常。
4. OAuth provider 是否可访问、Device Flow 是否过期或轮询过快。
5. 节点最近心跳、策略阈值、租约和模型发布状态。
6. 结构化日志中的 request path、status 和数据库错误；不要收集用户载荷。
