#!/usr/bin/env bash
# 邮箱认证安全与部署合同测试；不创建账户、不读取邮件、不提取或回显令牌。

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
COMPOSE_FILE="$SCRIPT_DIR/deploy/docker-compose.test.yml"

fail() {
    printf '邮箱认证合同失败：%s\n' "$1" >&2
    exit 1
}

require_text() {
    file=$1
    pattern=$2
    description=$3
    grep -Eq -- "$pattern" "$file" || fail "$description"
}

reject_text() {
    file=$1
    pattern=$2
    description=$3
    if grep -Eq -- "$pattern" "$file"; then
        fail "$description"
    fi
}

WEB_AUTH="$SCRIPT_DIR/crates/mindone-coordinator/src/web_auth.rs"
AUTH_PROVIDER="$SCRIPT_DIR/crates/mindone-coordinator/src/auth.rs"
ROUTER_SOURCE="$SCRIPT_DIR/crates/mindone-coordinator/src/lib.rs"
CLI_AUTH="$SCRIPT_DIR/crates/mindone-cli/src/auth.rs"
MIGRATION="$SCRIPT_DIR/migrations/0037_email_password_auth.sql"

require_text "$AUTH_PROVIDER" 'verification_uri\.set_path\("/auth/login"\)' \
    'email provider 必须返回同源 /auth/login'
require_text "$AUTH_PROVIDER" 'verification_uri\.set_query\(None\)' \
    'email verification_uri 必须清除 query'
require_text "$AUTH_PROVIDER" 'verification_uri\.set_fragment\(None\)' \
    'email verification_uri 必须清除 fragment'
require_text "$AUTH_PROVIDER" 'random_email_user_code' \
    'email Device Flow 必须生成独立 user_code'
require_text "$WEB_AUTH" 'user_code: String' \
    '浏览器登录必须要求用户手工输入终端 user_code'
require_text "$WEB_AUTH" 'email_authorized_user_id' \
    '浏览器登录只能标记既有 Device Flow 已授权'
require_text "$WEB_AUTH" 'verify_email_page' \
    '邮箱验证 GET 必须只渲染显式确认页'
require_text "$WEB_AUTH" 'Form<VerifyEmailToken>' \
    '邮箱验证值必须由显式表单 POST 才能消费'
require_text "$WEB_AUTH" 'method=\\"post\\"' \
    '邮箱验证确认页必须使用 POST 表单'
reject_text "$ROUTER_SOURCE" 'get\(crate::web_auth::verify_email_handler\)' \
    '邮箱验证 GET 不得直接调用消费处理器'
require_text "$CLI_AUTH" 'device_key_possession_message' \
    'CLI 最终轮询必须构造设备密钥持有证明'
require_text "$CLI_AUTH" 'signing_key\.sign' \
    'CLI 最终轮询必须使用 Ed25519 私钥签名'
require_text "$MIGRATION" 'token_hash TEXT NOT NULL UNIQUE' \
    '邮箱验证令牌必须只以 HMAC 哈希字段落库'
reject_text "$MIGRATION" '(access_token|refresh_token)[[:space:]]+(TEXT|VARCHAR|BYTEA)|CREATE[[:space:]]+TABLE[[:space:]]+web_login_sessions' \
    '邮箱迁移不得声明 bearer 列或建立 Web bearer 会话表'

if ! command -v docker >/dev/null 2>&1; then
    fail '缺少 docker，无法验证测试 Compose 配置'
fi

# 以下均为显式的静态合同占位值，只用于 Compose 插值，不连接服务且不写入文件。
MINDONE_DEV_POSTGRES_PASSWORD='contract-only-not-a-database-secret' \
MINDONE_TOKEN_PEPPER='contract-only-token-pepper-not-a-secret' \
MINDONE_DEV_STANDARD_DATA_KEY='1111111111111111111111111111111111111111111111111111111111111111' \
    docker compose -f "$COMPOSE_FILE" config --quiet

printf '邮箱认证静态与 Compose 合同通过。\n'
printf '真实 Mailhog、浏览器输入和 Ed25519 Device Flow 仍须按 TEST_EMAIL_AUTH.md 手工验收。\n'

if [ "${MINDONE_EMAIL_LIVE_READINESS:-0}" = '1' ]; then
    BASE_URL="${MINDONE_EMAIL_BASE_URL:-http://127.0.0.1:8787}"
    case "$BASE_URL" in
        http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*|https://*) ;;
        *) fail 'MINDONE_EMAIL_BASE_URL 只允许 HTTPS 或本机 loopback HTTP' ;;
    esac
    curl --fail --silent --show-error --max-time 5 "$BASE_URL/health" >/dev/null
    curl --fail --silent --show-error --max-time 5 "$BASE_URL/ready" >/dev/null
    curl --fail --silent --show-error --max-time 5 "$BASE_URL/auth/login" >/dev/null
    printf '只读存活、就绪与无参数登录页检查通过；未执行认证 E2E。\n'
fi
