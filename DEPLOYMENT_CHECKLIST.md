# MindOne v39 身份、推理 API 与速度调度部署清单

> 本清单面向当前 MVP/发布草案，不是生产上线批准。邮箱密码只授权既有 Ed25519 Device Flow；浏览器不接收 bearer，password reset 尚未实现。完整说明见 `DEPLOYMENT_EMAIL_AUTH.md`、`docs/OPERATIONS.md` 和 `docs/SECURITY.md`。

## 0. 先确认边界

- [ ] 当前源码 migration 连续为 `0001..0039`。
- [ ] 没有把历史 fresh-v36 `41/41`、fresh-v37 `43/43` 或 production v26 状态写成当前 v39 已通过/已部署。
- [ ] 没有计划创建 `password_reset_tokens`、`web_login_sessions` 或浏览器 bearer session。
- [ ] 没有调用不存在的 `/v1/auth/email/login`、`/v1/auth/web/*`、`/v1/auth/request-password-reset` 或 `/v1/auth/reset-password`。
- [ ] 用户流程明确要求手工输入自己终端显示的 12 位 `user_code`。
- [ ] 忘记密码被标为“尚无自动恢复流程”，由部署方走受审人工流程。

## 1. 环境变量

### Coordinator 核心配置

- [ ] `MINDONE_ENV=production`（隔离测试使用 `test` 或 `development`）。
- [ ] `MINDONE_AUTH_PROVIDER=email`。
- [ ] `MINDONE_BIND` 使用预期监听地址；公网源站不得绕过受控 TLS 入口。
- [ ] `MINDONE_PUBLIC_URL` 是用户实际访问的 origin。
- [ ] `DATABASE_URL` 使用数据库 owner 或 runtime 对应的正确连接；不要使用旧名 `MINDONE_DATABASE_URL`。
- [ ] `MINDONE_TOKEN_PEPPER` 是至少 32 字符的独立随机 Secret。
- [ ] `MINDONE_STANDARD_DATA_KEY_FILE` 指向受保护的独立 256-bit key 文件；仅受限开发环境才使用 inline `MINDONE_STANDARD_DATA_KEY`。

### SMTP 配置

- [ ] `MINDONE_SMTP_HOST` 与 `MINDONE_SMTP_PORT` 已设置。
- [ ] `MINDONE_SMTP_FROM_EMAIL` 是提供商允许的发件地址。
- [ ] `MINDONE_SMTP_FROM_NAME` 已按产品需要设置。
- [ ] `MINDONE_SMTP_USERNAME` 与 `MINDONE_SMTP_PASSWORD` 同时配置或同时留空。
- [ ] production 使用 `MINDONE_SMTP_SECURITY=tls` 或 `starttls`。
- [ ] production 没有设置 `MINDONE_SMTP_ALLOW_INSECURE_DEV=true`。
- [ ] 测试环境如使用 Mailhog，只有在 `MINDONE_SMTP_SECURITY=plain`、`MINDONE_SMTP_ALLOW_INSECURE_DEV=true` 且 host 为精确 `mailhog` 或 loopback 时启用明文。

### 禁止项

- [ ] Token pepper、SMTP 密码、数据库凭据、Standard data key、私钥不在 Git、镜像层、命令行参数或日志中。
- [ ] Token pepper、Standard data key 与 private Hidden Benchmark HMAC key 互不复用。
- [ ] 不把 Secret 直接回显到终端，也不把完整 `docker compose config` 输出写入日志。

## 2. 传输与公开 origin

- [ ] production `MINDONE_PUBLIC_URL` 使用 HTTPS。
- [ ] public URL 不含 userinfo、额外 path、query 或 fragment。
- [ ] 公网唯一 API hostname 为 `api.holarchic.cn:443`；`holarchic.cn` 根域继续服务现有官网，不把根域整站转给 Coordinator。
- [ ] Cloudflare Public Hostname 不设置 path 过滤，整个 `api.holarchic.cn/*` 转到 Docker internal origin `http://coordinator:8787`，并保持原始路径不剥离：`/health`、`/ready`、`/auth/*`、`/v1/*` 到源站仍为同一路径。
- [ ] 远程 SDK 的 Base URL 精确为 `https://api.holarchic.cn/v1`；模型、聊天和补全分别使用 `/v1/models`、`/v1/chat/completions`、`/v1/completions`。
- [ ] 基础维护模式只发布 `127.0.0.1:18787 -> coordinator:8787`；叠加公网 overlay 后该宿主端口映射被 `!reset []` 完全移除，Tunnel 不使用 `18787` 作为 origin。
- [ ] PostgreSQL `5432` 无宿主/公网映射；用户设备的本地模型 `127.0.0.1:8080`/其他选择端口和本地额度代理 `127.0.0.1:9090`/其他选择端口也不作为公网 Coordinator 入口。
- [ ] `/auth/login`、`/auth/register`、`/auth/verify-email` 与 Coordinator 同源。
- [ ] CLI 收到的 `verification_uri` 精确指向同源 `/auth/login`，且无 query/fragment。
- [ ] 跨主机 PostgreSQL 使用 TLS `verify-full`；loopback/Unix socket 例外符合运维文档。
- [ ] PostgreSQL、llama-server 和内部管理端口不直接暴露公网。
- [ ] 只有受信直连代理 IP 才允许提供 `CF-Connecting-IP`；不信任任意 `X-Forwarded-For`。

## 3. 数据库 migration 与角色

- [ ] 升级前已停写、排空活动任务/路由，并完成可恢复备份和隔离恢复演练。
- [ ] 数据库 owner 显式运行 `mindone-coordinator database-migrate`。
- [ ] 常驻 Coordinator 使用 `mindone_app` runtime role，不使用 owner URL。
- [ ] `_sqlx_migrations` 精确包含成功的 `0001..0039`，描述和 checksum 与当前二进制一致。
- [ ] `users` 包含 `email`、`password_hash`、`email_verified_at`。
- [ ] `email_verification_tokens` 只包含 HMAC token 字段，不包含 raw `token`、邮箱副本或 bearer。
- [ ] `auth_device_flows` 包含 `email_authorized_user_id`、`email_authorized_at` 和 email 格式约束。
- [ ] `password_reset_tokens` 与 `web_login_sessions` 不存在。
- [ ] `jobs.speed_class` 只接受 `fast`、`standard`、`slow`，ready queue 索引存在。
- [ ] `inference_api_keys` 只保存 HMAC/前缀而不保存完整 Key，`inference_api_key_events` 保持只追加。
- [ ] PUBLIC 无新增敏感表权限；runtime role 权限与 `deploy/postgres-ensure-runtime-role.sh` 合同一致。
- [ ] 未手改 `_sqlx_migrations`，未通过放宽 ACL 绕过 runtime schema 门禁。

只在受控连接中检查结构，不要把带密码的数据库 URL 写入 shell 历史或文档。推荐使用部署方的 Secret 注入和 `psql --no-psqlrc`。

## 4. 应用启动门禁

- [ ] 在完整邮箱环境下先运行 `./verify-config.sh`；它复用当前 coordinator 的离线启动合同且不连接外部服务。
- [ ] 仅在受控维护环境显式运行 `./verify-config.sh --live`；确认其只读 schema 精确比较和不发信 SMTP 会话通过。
- [ ] Coordinator 在缺少或不安全 SMTP 配置时拒绝 email provider 启动。
- [ ] production 的 HTTP public URL、SMTP plain 或不安全数据库传输被拒绝。
- [ ] `/health` 返回 200 只表示进程存活；`/ready` 返回 200 才表示 runtime schema/密钥门禁通过。
- [ ] email provider 之外不挂载 `/auth/register`、`/auth/login`、`/auth/verify-email`。
- [ ] 请求 body 有明确大小上限和超时。
- [ ] Web auth 独立限流与全局 API 限流均启用；多副本部署另有共享 WAF/代理策略。

## 5. 安全行为验收

### 注册与邮箱验证

- [ ] `GET /auth/register` 返回同源注册页和安全响应头。
- [ ] `POST /auth/register` 只接受严格 JSON 字段，拒绝未知字段。
- [ ] 密码只保存 Argon2id hash，日志和错误不含密码。
- [ ] 验证邮件包含一次性 24 小时 token；数据库只保存 HMAC。
- [ ] 验证链接的 GET 只显示确认页且不写数据库，邮件安全扫描器不能自动激活账户。
- [ ] 只有用户显式同源 POST 才消费 token；token 只能消费一次，过期 token 被拒绝。
- [ ] HTTP tracing 中只有 `/auth/verify-email` path，没有 token query 或 POST 表单正文。

### Ed25519 Device Flow

- [ ] CLI 调用 `/v1/auth/device/start` 时提交规范 Ed25519 公钥和算法。
- [ ] 返回值含随机 12 位十六进制 `user_code`、无 query/fragment 的同源 `/auth/login`、flow ID 和设备 challenge。
- [ ] 浏览器页面警告用户只输入自己终端显示的代码。
- [ ] `POST /auth/login` 要求邮箱、密码和 `user_code`，只授权一个未过期 pending flow。
- [ ] 浏览器成功响应不包含 access token、refresh token 或可兑换 bearer 的 session ID。
- [ ] `/v1/auth/device/poll` 缺少、篡改或使用错误 Ed25519 签名时拒绝。
- [ ] 只有设备签名通过后 poll 才一次性交付 token；并发或重复完成同一 flow 被拒绝。
- [ ] CLI 核对返回的设备指纹，并只把会话/私钥写入系统凭证库。
- [ ] 没有“Web 登录失败后回退到无设备证明登录”的行为。

### 响应与日志

- [ ] Web 页面响应含 CSP、`X-Frame-Options: DENY`、`Cache-Control: no-store`、`Referrer-Policy: no-referrer` 和 `X-Content-Type-Options: nosniff`。
- [ ] 日志不含密码、完整邮箱验证 URL、query、邮件正文、user code、设备 challenge、Authorization、bearer、Prompt 或 Response。
- [ ] 限流与失败响应使用稳定英文结构字段和简体中文普通错误。

### 推理 API Key 与三档速度

- [ ] 登录用户可通过 `/v1/api-keys` 创建、列出和撤销自己的推理 Key；Secret 只返回一次。
- [ ] 注销会话、撤销设备或撤销 Key 后，`mok_` 推理认证立即失败。
- [ ] `GET /v1/models` 只列出在线且通过门禁的模型，并生成 `-fast`、无后缀、`-slow` 三种名称。
- [ ] `-fast` 只选整台空闲贡献端，再按真实 TPS；没有整台空闲端时保持排队，即使忙节点还有物理 slot 也不与既有任务争抢。
- [ ] 无后缀保持既有质量、健康与贡献近同分破局合同，但与 fast 一样只使用整台空闲贡献端，避免多槽让标准请求退化。
- [ ] `-slow` 只在服务端真实容量与 `max_concurrent=1..3` 内聚合；slot 0 本机代理与贡献 slot 1..3 必须隔离、逐请求精确 erase，不得按节点自报扩张容量。
- [ ] 所有节点满载时任务保持 `queued/retry`；公网等待超时后取消任务并事务释放预留额度。
- [ ] `/v1/chat/completions` 与 `/v1/completions` 的 JSON/SSE、唯一终态结算及错误形状已用真实数据库路径验收。

## 6. 自动合同与人工 E2E

2026-07-22 已通过的真实 llama.cpp/GGUF E2E 使用两个隔离 Home/Keychain 和 `local-development` provider；它验证了本地 Device Flow、推理/流式/结算/策略/清理链路，但没有连接 SMTP，也没有执行下面的 email 注册、邮件确认和同源浏览器授权。因此该证据不能勾选本节的 email 人工链路，也不能替代公网或 production 验收。

### 不接触真实凭据的自动检查

```bash
./test-email-auth.sh
./test-cli-web-login.sh
bash -n test-email-auth.sh test-cli-web-login.sh
```

- [ ] 上述脚本退出 0。
- [ ] 已理解它们主要验证静态/config/Rust 合同，不会创建账户、读取邮件或提取 token。

### fresh-v39 数据库门禁

- [ ] 使用从未使用过的隔离 PostgreSQL 数据库。
- [ ] 设置 `MINDONE_REQUIRE_POSTGRES_TESTS=1`，数据库测试没有 skip。
- [ ] 串行运行 16 个 coordinator integration binary，包括 `schema_v37`、`schema_v38`、`schema_v39`、`runtime_schema`、`database_role`、`router` 和完整 PostgreSQL integration 集合；每个 binary 使用独立数据库。
- [ ] 记录实际通过数和 migration metadata；不预填、不复用历史 v36/v37 结果。
- [ ] 测试完成只清理由本次 gate 明确创建的数据库/容器。

### 隔离 SMTP/浏览器/CLI 人工链路

- [ ] 使用 `deploy/docker-compose.test.yml` 的隔离 Postgres/Mailhog/Coordinator 栈或等价测试环境。
- [ ] 用测试邮箱注册并在 Mailhog/受控邮箱中查看验证邮件。
- [ ] 人工打开验证链接，确认邮箱状态变化。
- [ ] 运行 `mindone auth login`，核对 origin，并手工输入终端 12 位码。
- [ ] 确认 CLI 的 Ed25519 poll 完成并把会话写入隔离凭证命名空间。
- [ ] 确认浏览器响应和数据库均没有 bearer 明文。
- [ ] 完成后只清理该测试创建的账户、隔离卷和凭证命名空间；不要连接 production。

## 7. 运维与恢复

- [ ] 监控 `/ready`、数据库连接、SMTP 发送失败率、注册/验证/授权的成功与拒绝计数。
- [ ] 指标标签不含邮箱、user code、验证 token、设备 challenge 或 bearer。
- [ ] 为邮箱验证记录制定保留与过期清理策略。
- [ ] 已接受当前注册事务同步等待 SMTP 的限制，或在上线前实现事务型 outbox。
- [ ] 已制定 SMTP 成功但数据库提交失败时的失效邮件处置说明。
- [ ] 账户恢复采用受审人工流程；没有向用户承诺 password reset。
- [ ] 数据库备份与 Standard data key 分离存储、分权访问，并完成真实恢复演练。
- [ ] production v26 到 v39 只有在明确维护窗口授权后才执行；测试成功不构成生产升级授权。

## 8. 发布判定

以下任一项未满足时，不得宣称 v1.0.0 正式发布或邮箱登录已完成生产验收：

- [ ] 当前 workspace fmt、check、strict Clippy 和 tests 全部按最终树退出 0。
- [ ] fresh-v39 全部 PostgreSQL gate 无 skip 通过。
- [ ] API Key JSON/SSE 与 fast/standard/slow 满载排队调度使用真实 PostgreSQL 路径通过。
- [ ] 隔离 SMTP + 浏览器 + CLI Ed25519 完整链路通过。
- [ ] 公网 HTTPS、受信代理、端口不可见和限流边界通过外部验收。
- [ ] production 升级另有备份、恢复演练、排空、回滚和 owner 授权。
- [ ] 文档明确保留 password reset 未实现、浏览器无 bearer、当前仍是 MVP/发布草案。
