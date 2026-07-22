# MindOne v37 邮箱身份与设备登录阶段总结

> 状态：MVP 收口中的实现摘要，不是 v1.0.0 正式发布声明。当前发布与测试证据以 `README.md`、`docs/HANDOFF.md` 和 `docs/CLI_COMPLIANCE.md` 为准。

## 当前合同

邮箱和密码只负责在同源浏览器页面中确认用户身份，并授权一条已经由 CLI 发起、绑定 Ed25519 公钥的 Device Flow：

1. CLI 生成或使用设备 Ed25519 密钥，调用 `POST /v1/auth/device/start`。
2. Coordinator 返回同源 `/auth/login`、随机 12 位十六进制 `user_code` 和设备 challenge。登录 URL 不携带 query、fragment 或授权秘密。
3. 用户核对浏览器 origin，并手工输入自己终端显示的 `user_code`、已验证邮箱和密码。
4. 浏览器只把该账户绑定到尚未过期的 pending flow，不签发、不接收 bearer token。
5. CLI 通过 `POST /v1/auth/device/poll` 提交 Ed25519 私钥持有证明；只有签名通过后，Coordinator 才一次性交付 access/refresh token。
6. CLI 把 token、refresh challenge 和设备私钥存入操作系统凭证库，不写入 `config.toml`。

所有认证提供者都走这一条 Device Flow。邮箱模式没有第二套 Web bearer session，也不会在失败后回退到绕过设备签名的登录路径。

## 已落盘的实现

### Schema 0037

`migrations/0037_email_password_auth.sql` 在连续 `0001..0037` schema 上增加：

- `users.email`、`users.password_hash`、`users.email_verified_at`；
- 规范化、唯一的邮箱约束；
- `email_verification_tokens`，只保存带服务器 pepper 的 43 字符 HMAC，不保存原始验证 token、邮箱副本或 bearer；
- `auth_device_flows.email_authorized_user_id` 与 `email_authorized_at`；
- email flow 的 HMAC provider code、12 位用户码、同源登录 URL 和 pending 用户码唯一约束；
- `mindone_app` 对新增表的显式最小运行权限。

0037 不创建 `password_reset_tokens`、`web_login_sessions` 或其他浏览器 bearer 会话表。

### 密码与验证

`crates/mindone-coordinator/src/password.rs` 使用 Argon2id，参数为 `m=19456`、`t=2`、`p=1`。哈希和验证经有界 semaphore 进入 `spawn_blocking`，避免阻塞 Tokio worker 或无界并行占用内存。

邮箱验证 token：

- 由 CSPRNG 生成，原始值只出现在发出的验证邮件和浏览器请求中；
- 数据库只保存 HMAC-SHA256 结果；
- 默认 24 小时过期；
- 邮件链接的 GET 只展示确认页，避免安全扫描器自动激活账户；
- 用户显式同源 POST 后，通过行锁和 `used_at` 实现一次性消费。

密码重置尚未实现。当前没有 forgot/reset password 路由、数据表或邮件流程，文档和客户端不得宣称可用。忘记密码时只能使用部署方受审的人工恢复流程。

### SMTP

`crates/mindone-coordinator/src/email.rs` 使用稳定的 `MINDONE_SMTP_*` 配置：

- 支持 SMTP 认证、implicit TLS 和 STARTTLS；
- production 禁止 `plain`；
- development/test 的明文 SMTP 只有在显式设置 `MINDONE_SMTP_ALLOW_INSECURE_DEV=true`，且主机为 loopback 或精确 `mailhog` 时才允许；
- 用户名和密码必须同时配置或同时留空；
- 连接和发送均有超时，错误响应不暴露 SMTP 凭据或内部详情；
- email provider 在 Coordinator 启动阶段检查必需 SMTP 配置。

当前注册流程在数据库事务内发送验证邮件，发送失败会回滚账户，避免无法重试的半成品记录。它仍不是事务型 outbox：SMTP 已接受邮件后若数据库提交失败，可能产生失效邮件；大规模或高可靠部署应先实现持久 outbox、幂等投递和重试。

### 浏览器路由

仅在 `MINDONE_AUTH_PROVIDER=email` 时挂载：

| 路由 | 方法 | 当前行为 |
|---|---|---|
| `/auth/register` | `GET` / `POST` | 显示注册页；创建待验证邮箱账户并发送验证邮件 |
| `/auth/verify-email?token=...` | `GET` | 只展示显式确认页，不修改邮箱状态 |
| `/auth/verify-email` | `POST` | 消费一次性验证值并激活邮箱 |
| `/auth/login` | `GET` / `POST` | 要求邮箱、密码和终端 12 位用户码；只授权 pending Device Flow |
| `/v1/auth/device/start` | `POST` | 创建绑定 Ed25519 公钥的 Device Flow |
| `/v1/auth/device/poll` | `POST` | 验证设备签名后一次性交付 CLI 会话 |

不存在 `/v1/auth/email/login`、`/v1/auth/web/*`、`/v1/auth/request-password-reset` 或 `/v1/auth/reset-password`。

Web 认证路由使用独立的每客户端地址每分钟 10 次限流，并统一增加 CSP、`frame-ancestors 'none'`、`X-Frame-Options: DENY`、`Cache-Control: no-store`、`Referrer-Policy: no-referrer` 和 `X-Content-Type-Options: nosniff`。HTTP tracing 只记录 method 和 path，不记录可能包含验证 token 的 query，也不记录请求正文、密码、Prompt 或 Response。

## CLI 与 TUI

`mindone auth login` 对 GitHub、email 和本地开发提供者都使用同一 Ed25519 Device Flow。浏览器无法领取 bearer；CLI 还会核对服务器返回的设备密钥指纹后才把会话写入系统凭证库。

交互式 `mindone` 或 `mindone ui` 现提供 10 类、40 个公开 CLI 叶子命令。新版响应式工作台包含 SPACE、ACTION、OVERVIEW、ACTIVITY 与 COMMAND 区域，并提供 65 模型选择器、本机推荐和自动部署快捷操作。TUI 使用同一 Clap 命令树和 `app::execute`，不经过 shell，并拒绝隐藏的 `__worker`；认证、写入和生命周期动作执行前会二次确认。

CPU-only 现在通过 `ServeRequest.cpu_only` 类型化传入引擎层，由受管启动逻辑固定 device、GPU layer 与 KV/op offload 参数并清除对应环境覆盖；它不再编码进未受信 `additional_args`。worker 对 reasoning-only 且没有可见 `content` 的结果立即失败；协调器对 result 的确定性 HTTP 400 只触发一次脱敏 terminal failure，不复制远端 message、Prompt 或 Response。`share publish` 会持久化权威策略，活动 worker 在运行期遇到策略文件缺失、损坏、非普通文件或符号链接时失败关闭。

## 配置边界

核心变量使用当前稳定名称：

- `MINDONE_ENV=production|development|test`
- `MINDONE_AUTH_PROVIDER=email`
- `MINDONE_PUBLIC_URL=https://...`
- `DATABASE_URL=postgres://...`
- `MINDONE_TOKEN_PEPPER`
- `MINDONE_STANDARD_DATA_KEY_FILE`（生产优先）或受限开发环境中的 `MINDONE_STANDARD_DATA_KEY`
- `MINDONE_SMTP_HOST`、`MINDONE_SMTP_PORT`
- `MINDONE_SMTP_USERNAME`、`MINDONE_SMTP_PASSWORD`
- `MINDONE_SMTP_FROM_EMAIL`、`MINDONE_SMTP_FROM_NAME`
- `MINDONE_SMTP_SECURITY=tls|starttls`

production 的 `MINDONE_PUBLIC_URL` 必须是无 userinfo、path、query、fragment 的 HTTPS origin。跨主机数据库连接必须使用 TLS `verify-full`；只有明确的 loopback 开发 HTTP 例外。

## 验证资源与真实证据边界

- `test-email-auth.sh`：静态认证/schema/Compose 合同检查；可选 live 模式只做只读 readiness 页面检查。
- `test-cli-web-login.sh`：运行 CLI Device Flow URI 与签名绑定的定向 Rust 测试，不执行旧 Web bearer 登录。
- `deploy/docker-compose.test.yml`：隔离 PostgreSQL、Mailhog 与 email Coordinator 测试栈模板。
- `TEST_EMAIL_AUTH.md`：人工注册、收信、验证、用户码授权和 CLI 签名 poll 的验收步骤。
- `DEPLOYMENT_EMAIL_AUTH.md`：当前生产配置和安全边界。

脚本存在或静态合同通过，不等于 SMTP + 浏览器 + CLI 跨进程链路已经通过。本阶段的 fresh-v37 历史证据为 `43/43`、workspace 为 `556/0/5`；当前总体验证已推进到 fresh-v39 `49/49` 与 workspace `587/0/5`，但它们仍不能代替真实 SMTP、浏览器交互和 CLI 签名 poll 的外部 E2E。

Standard 真实模型链已有另一组独立证据：当前 debug 工作树的 CPU-only `scripts/e2e-test.sh` 使用 fresh PostgreSQL v37、两个隔离 Home/账号/device、官方 llama.cpp `b10064` 和 `Qwen3-0.6B-Q4_0.gguf` 从头退出 0。它确定性完成 public canary worker 终态，并覆盖 chat/completions 非流式、两类 SSE、故障注入后的非零游标恢复、Standard AEAD 密文、消费/节点贡献/网络准备金三轨唯一结算、执行前策略改变拒绝零结算、Regulated `stream:true` 拒绝、Prompt/Response 日志扫描和本轮资源清理。

该结果只证明本机 debug、单 Standard GGUF。它不代表 GitHub Actions、正式签名发布、外部 SMTP/浏览器 Device Flow、真实 TEE、private hidden 双 GGUF 或 production 部署；SSE 恢复也不表示客户端可以重新 POST resume token。

## 当前限制

- password reset 未实现；
- 没有事务型邮件 outbox；
- 过期邮箱验证记录尚无独立清理任务；
- 应用限流是单实例内存状态；多副本和公网部署仍需受信反向代理/WAF 的协同边界；
- 真实 SMTP、浏览器用户交互和完整签名 poll 仍需隔离环境端到端验收；
- 当前仍是 MVP/发布草案，不是 v1.0.0 正式发布，也不表示 production 已升级到 schema v37。

## 下一步

1. 在隔离 Mailhog/SMTP 环境中人工完成注册、收信、GET 确认页、POST 消费、手输 12 位码与 CLI Ed25519 poll。
2. 当前 debug 单 GGUF/SSE E2E 与 `aarch64-apple-darwin` release/install/uninstall smoke 已通过；相关源码改变后重跑，并另建 private 双 GGUF harness。
3. 设计事务型 outbox 与受审账户恢复流程；在实现前继续明确标记 password reset 不可用。
4. 完成外部 Actions、签名、真实 TEE 和公网链验证；只有在维护窗口、备份恢复演练和明确授权后，才考虑 production v26 到 v37 的升级。
