# MindOne 邮箱认证部署指南

## 当前能力与边界

邮箱 provider 已实现：

- 浏览器注册：`GET/POST /auth/register`；
- 邮箱验证：`GET /auth/verify-email` 只显示确认页，`POST /auth/verify-email` 才消费验证值；
- 浏览器授权既有设备流程：`GET/POST /auth/login`；
- CLI 统一使用 `POST /v1/auth/device/start` 与 `POST /v1/auth/device/poll`。

密码恢复端点尚未实现，不应在产品说明、监控或客户端中宣称可用。需要恢复账户时采用经审计的人工运维流程。

浏览器登录不会签发或接收 bearer。Coordinator 只在 CLI 对本次 challenge 提交有效 Ed25519 私钥签名后，通过标准 device poll 一次性交付会话。Provider 给 CLI 的登录地址固定为同源 `/auth/login`，不得包含 query 或 fragment；用户必须手工输入终端显示的 12 位十六进制用户码。

邮箱验证的一次性值只出现在发送给用户的验证链接和该次浏览器 GET/POST 中，数据库只持久化 HMAC。GET 不写数据库，避免邮件安全扫描器自动激活账户；只有用户在同源页面显式 POST 才消费验证值。HTTP 请求 tracing 必须只记录路径，不记录 query 或表单正文。

## 必需配置

稳定环境变量如下：

```bash
MINDONE_ENV=production
MINDONE_BIND=127.0.0.1:8787
MINDONE_ALLOW_NON_LOOPBACK=false
DATABASE_URL='postgres://mindone_app:<数据库密码>@db.example:5432/mindone?sslmode=verify-full&sslrootcert=/run/secrets/postgres_ca'

MINDONE_AUTH_PROVIDER=email
MINDONE_PUBLIC_URL=https://api.example.com
MINDONE_TOKEN_PEPPER=<至少32字符，由Secret管理器注入>
MINDONE_STANDARD_DATA_KEY_FILE=/run/secrets/mindone_standard_data_key

MINDONE_SMTP_HOST=smtp.example.com
MINDONE_SMTP_PORT=587
MINDONE_SMTP_USERNAME=<SMTP用户名>
MINDONE_SMTP_PASSWORD=<SMTP密码>
MINDONE_SMTP_FROM_EMAIL=noreply@example.com
MINDONE_SMTP_FROM_NAME=MindOne
MINDONE_SMTP_SECURITY=starttls
```

规则：

- 生产 `MINDONE_PUBLIC_URL` 必须为 HTTPS 的 origin，不能包含凭据、路径、query 或 fragment。
- 生产数据库跨主机连接必须使用 TLS 验证；常驻 Coordinator 使用最小权限 runtime role，migration 使用独立 owner。
- `MINDONE_SMTP_SECURITY` 只接受 `tls`、`starttls`，以及仅 development/test 可用的 `plain`；后者还必须显式设置 `MINDONE_SMTP_ALLOW_INSECURE_DEV=true`，且主机只能是 loopback 或精确的 `mailhog` 服务名。
- SMTP 用户名和密码必须同时配置或同时留空；生产通常必须同时配置。
- Token pepper、数据库凭据、SMTP 密码和 Standard data key 不得进入 Git、镜像层、Compose 文件或日志。优先使用平台 Secret、只读挂载文件和独立密钥轮换流程。
- Token pepper 与 Standard data key 不得复用。

本机 Mailhog 测试配置参见 `deploy/docker-compose.test.yml`。该文件显式设置 `MINDONE_ENV=development` 和 `MINDONE_SMTP_ALLOW_INSECURE_DEV=true`，且 `plain` SMTP 只发生在 Compose 内部网络。

## 数据库迁移

只使用应用内置、向前追加的 migration：

```bash
mindone-coordinator database-migrate
```

`0037_email_password_auth.sql` 增加规范化邮箱、Argon2id 密码哈希、邮箱验证 HMAC 记录，以及现有 `auth_device_flows` 上的邮箱授权字段。它不创建保存 access token/refresh token 的 Web 会话表。

部署流程必须是：

1. 在隔离数据库副本上恢复并验证可用备份。
2. 用数据库 owner 运行当前二进制的 `database-migrate`。
3. 刷新并核对 runtime role 对新增对象的最小权限。
4. 用 runtime role 启动 Coordinator，并等待 `/ready`。
5. 按 `TEST_EMAIL_AUTH.md` 完成真实 SMTP、浏览器和 CLI Device Flow 验收。

不要手写 `ALTER TABLE`/`DROP TABLE` 模拟迁移或回滚。需要回滚时停止写入并从已验证备份恢复到兼容版本；任何旧二进制兼容性都必须先在隔离副本演练，不能仅靠降级镜像推断。

## 启动门禁

选择 `MINDONE_AUTH_PROVIDER=email` 时，Coordinator 会在启动阶段验证 SMTP 必填项、发件人地址和传输构造参数。配置缺失、发件人无效、凭据只配一半，或 production 使用 `plain` 时必须拒绝启动；真实 DNS、连接和投递能力仍由发布 E2E 验证。

完整环境变量与 Secret 文件就绪后，先从仓库根目录执行 `./verify-config.sh`。它通过 locked/offline Cargo 构建当前源码并运行 `mindone-coordinator config-check`：默认只读取并验证配置，不连接 PostgreSQL、SMTP 或其他外部服务。只有运维者显式执行 `./verify-config.sh --live` 时，才会在只读事务中逐项比对 `public._sqlx_migrations`，并建立一次不发送邮件的 SMTP 会话。两种模式都不迁移数据库、不发送验证邮件，也不回显 Secret 或数据库 URL；live 成功仍不能替代真实邮件投递、浏览器授权和 CLI 设备签名 E2E。

反向代理应满足：

- 外部只提供 HTTPS；origin 默认只监听 loopback 或受控内部网络；
- 保留正确的客户端地址链，并只信任明确配置的代理；
- 对 `/auth/register`、`/auth/login` 和 `/auth/verify-email` 使用应用速率限制；
- 不记录 URL query、请求体、密码、邮件正文或 Authorization header；
- 响应设置 `Referrer-Policy: no-referrer`，认证页面也声明 no-referrer；
- 不缓存认证页面和认证响应。

最小 Nginx 示例（证书与速率数值需按容量评审）：

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate /run/secrets/tls.crt;
    ssl_certificate_key /run/secrets/tls.key;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        add_header Referrer-Policy "no-referrer" always;
        add_header Cache-Control "no-store" always;
    }
}
```

## 发布验收

```bash
curl --fail --silent --show-error http://127.0.0.1:8787/health
curl --fail --silent --show-error http://127.0.0.1:8787/ready
curl --fail --silent --show-error https://api.example.com/auth/login >/dev/null
```

随后执行手工 E2E，确认：

- 注册邮件真实送达，验证链接的 GET 只展示确认页，用户显式 POST 后才在受信任浏览器中一次消费；
- CLI 显示的地址是完全同源的 `/auth/login` 且没有 query/fragment；
- 浏览器要求手工输入 12 位十六进制用户码，且响应不含 bearer；
- CLI 最终 poll 使用 Ed25519 签名并得到与设备密钥指纹一致的真实会话；
- 错误密码、未验证邮箱、过期/错误用户码和无效设备签名均被拒绝；
- 日志没有密码、完整邮箱验证链接、query、邮件正文或 bearer。

自动脚本：

```bash
./test-email-auth.sh
./test-cli-web-login.sh
```

这些脚本验证静态、Compose 和单元合同，不替代 Mailhog/真实 SMTP 与浏览器 E2E。

## 监控与故障处理

监控进程存活、数据库就绪、SMTP 发送失败率、注册/验证/设备授权的成功与拒绝计数。指标标签不得包含邮箱、用户码、验证值、设备 challenge 或 bearer。

- `/health` 成功仅表示进程存活；发布门禁使用 `/ready`。
- 邮件未发送：核对 SMTP DNS/TLS、端口、成对凭据与发件人授权，不输出密码测试命令。
- 登录页无法打开：核对 `MINDONE_PUBLIC_URL` 与外部 HTTPS origin；不要通过添加 query 传用户码。
- CLI 持续 pending：核对用户手工输入的是自己终端的当前用户码，并检查 flow 是否过期；不要在日志中搜索或打印该码。
- 邮箱未验证：用户在邮件客户端内重新打开当前验证邮件；目前没有自助重发或密码恢复端点，不要伪造数据库状态。

## 测试 Compose

测试环境使用 PostgreSQL、Mailhog、一次性 migrator 和带 `/ready` healthcheck 的 Coordinator。必须使用本轮唯一 Compose project，避免与 production、历史证据或其他测试栈重名；固定 loopback 端口 `55433`、`1025`、`8025` 和选定的 Coordinator 端口也必须先确认未占用。下面的命令只适用于准备新建的隔离测试栈：

```bash
export MINDONE_EMAIL_TEST_PROJECT="mindone-email-e2e-$(date +%Y%m%d%H%M%S)"
export MINDONE_DEV_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export MINDONE_TOKEN_PEPPER="$(openssl rand -hex 32)"
export MINDONE_DEV_STANDARD_DATA_KEY="$(openssl rand -hex 32)"
export MINDONE_COORDINATOR_HOST_PORT=18790

case "$MINDONE_EMAIL_TEST_PROJECT" in
  mindone-email-e2e-[0-9]*) ;;
  *) printf '错误：测试 project 名称不安全。\n' >&2; exit 1 ;;
esac
for port in 55433 1025 8025 "$MINDONE_COORDINATOR_HOST_PORT"; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | grep -q .; then
    printf '错误：loopback 测试端口 %s 已被占用。\n' "$port" >&2
    exit 1
  fi
done

docker compose --project-name "$MINDONE_EMAIL_TEST_PROJECT" \
  --env-file /dev/null -f deploy/docker-compose.test.yml up -d --build --wait
```

测试结束后只删除上面精确命名的本轮 project 资源，并清除当前 shell 变量。不得把 project 名改成 `mindone`，也不得对任何既有 project 运行 `down -v`：

```bash
case "$MINDONE_EMAIL_TEST_PROJECT" in
  mindone-email-e2e-[0-9]*)
    docker compose --project-name "$MINDONE_EMAIL_TEST_PROJECT" \
      --env-file /dev/null -f deploy/docker-compose.test.yml down -v
    ;;
  *) printf '错误：拒绝清理未确认的 Compose project。\n' >&2; exit 1 ;;
esac
unset MINDONE_EMAIL_TEST_PROJECT MINDONE_DEV_POSTGRES_PASSWORD \
  MINDONE_TOKEN_PEPPER MINDONE_DEV_STANDARD_DATA_KEY \
  MINDONE_COORDINATOR_HOST_PORT
```

最后更新：2026-07-22。
