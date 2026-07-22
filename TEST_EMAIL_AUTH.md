# MindOne 邮箱认证测试指南

本文只覆盖当前已实现的邮箱注册、邮箱验证和设备绑定登录。CLI 不存在独立的“Web bearer 登录”：所有认证提供者统一使用 Ed25519 Device Flow。

## 安全流程

1. CLI 为本次登录生成 Ed25519 密钥，调用 `POST /v1/auth/device/start`。
2. Coordinator 返回无 query、无 fragment 的同源 `/auth/login` 和 12 位十六进制 `user_code`。
3. 用户只在浏览器页面手工输入自己终端显示的 `user_code`、邮箱和密码。
4. 浏览器只把既有的 pending flow 标记为已授权，不接收 access token 或 refresh token。
5. CLI 调用 `POST /v1/auth/device/poll`，并提交设备私钥签名。Coordinator 验签后才一次性交付会话。

邮箱验证链接包含一次性验证值；数据库只保存其带服务端 pepper 的 HMAC。邮件链接的 `GET` 只显示确认页，防止邮件安全扫描器自动激活账户；用户必须在同源页面显式提交 `POST` 才会消费验证值。不要把验证链接复制到终端、测试输出、工单或日志中。

## 自动合同测试

在仓库根目录运行：

```bash
./test-email-auth.sh
./test-cli-web-login.sh
```

前者验证服务端、migration 与 Compose 的安全合同；后者运行 CLI 浏览器地址单测。两者都不会注册用户、读取 Mailhog 邮件、启动浏览器、伪造设备签名或执行真实登录，因此不能当作端到端认证证据。

## 本机手工 E2E

### 1. 准备一次性测试环境

测试 Compose 只发布 loopback 端口，并用 `MINDONE_SMTP_ALLOW_INSECURE_DEV=true` 显式允许 `plain` SMTP 连接精确的 `mailhog` 服务。这个开关和 `plain` 只允许 development/test，严禁复制到生产环境。

```bash
export MINDONE_DEV_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export MINDONE_TOKEN_PEPPER="$(openssl rand -hex 32)"
export MINDONE_DEV_STANDARD_DATA_KEY="$(openssl rand -hex 32)"
docker compose -f deploy/docker-compose.test.yml up -d --build --wait
docker compose -f deploy/docker-compose.test.yml ps
curl --fail --silent --show-error http://127.0.0.1:8787/health
curl --fail --silent --show-error http://127.0.0.1:8787/ready
```

如果修改 `MINDONE_COORDINATOR_HOST_PORT`，必须同时把 `MINDONE_PUBLIC_URL` 设置为浏览器可访问的同一 loopback origin。

也可只执行无敏感数据的只读就绪合同：

```bash
MINDONE_EMAIL_LIVE_READINESS=1 ./test-email-auth.sh
```

### 2. 注册并验证邮箱

1. 浏览器打开 `http://127.0.0.1:8787/auth/register`。
2. 使用专用测试邮箱注册，不要使用生产账号或复用密码。
3. 浏览器打开 `http://127.0.0.1:8025`，在 Mailhog UI 内直接点击验证链接。
4. 确认最初页面只要求“确认并激活账户”，再由本人显式提交表单。
5. 确认提交后页面显示验证成功。不要提取、打印或复制链接中的一次性验证值。

### 3. 发起 CLI 登录

CLI 服务地址由非敏感配置管理，不使用旧的 `MINDONE_COORDINATOR_URL`：

```bash
cargo +1.88 build --locked --release -p mindone-cli
./target/release/mindone config set server.url http://127.0.0.1:8787
./target/release/mindone auth login
```

验收要点：

- 终端显示 12 位十六进制用户码和无参数的 `http://127.0.0.1:8787/auth/login`。
- 浏览器地址不得包含 `?` 或 `#`，页面要求手工输入终端用户码。
- 输入邮箱、密码和完全一致的用户码后，页面只提示回到终端。
- CLI 完成带 Ed25519 签名的轮询并保存会话；浏览器响应中不得出现 bearer。
- `./target/release/mindone auth status` 返回服务端真实身份和设备密钥指纹。

无图形环境可使用 `mindone auth login --no-open`，再在受信任浏览器手工访问终端显示的地址。

### 4. 反向场景

- 错误、过期或已消费的用户码必须拒绝。
- 未验证邮箱、错误密码必须拒绝，且错误响应不得泄露账户是否存在。
- 把 `/auth/login` 改成其他 origin、HTTP 公网地址，或添加 query/fragment，CLI 必须拒绝打开。
- 停止 Mailhog 后，注册应明确失败，不能留下声称可用的半成品账户。
- 仅 `GET` 邮箱验证链接不得激活账户；首次同源 `POST` 才消费验证值，重复提交不得创建第二个账户或第二条会话。
- 最终 poll 缺少、篡改或使用其他设备的 Ed25519 签名时必须拒绝。

## 可观测性检查

只查看状态和脱敏日志，不搜索或输出请求 query、密码、邮件正文、access token 或 refresh token：

```bash
docker compose -f deploy/docker-compose.test.yml ps
docker compose -f deploy/docker-compose.test.yml logs coordinator
```

`/auth/verify-email` 的 query 必须从 HTTP tracing span 中剥离，POST 表单正文也不得记录；认证日志只应包含稳定路径、状态和脱敏错误。

## 清理

测试数据库只含专用测试数据时，可删除该测试 Compose 的 volume：

```bash
docker compose -f deploy/docker-compose.test.yml down -v
unset MINDONE_DEV_POSTGRES_PASSWORD MINDONE_TOKEN_PEPPER MINDONE_DEV_STANDARD_DATA_KEY
```

不要用通配路径删除 CLI 配置。若需清除测试会话，使用 `mindone auth logout`；无法连接测试服务时，再按 CLI 配置文档确认精确文件后处理。

## 尚未自动化的证据

Mailhog 收信、真实浏览器表单、人工核对 12 位用户码以及 CLI 私钥签名的完整跨进程链路仍需手工执行。自动合同通过不等于这些外部步骤已通过。
