#!/usr/bin/env bash
# CLI 邮箱 Device Flow 合同测试；不会启动浏览器、登录或接触任何 bearer。

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
CLI_AUTH="$SCRIPT_DIR/crates/mindone-cli/src/auth.rs"

fail() {
    printf 'CLI 邮箱 Device Flow 合同失败：%s\n' "$1" >&2
    exit 1
}

grep -Fq 'SigningKey::generate' "$CLI_AUTH" \
    || fail '登录必须为本次设备流程生成 Ed25519 密钥'
grep -Fq '/v1/auth/device/start' "$CLI_AUTH" \
    || fail '登录必须从标准 Device Flow 启动'
grep -Fq '/v1/auth/device/poll' "$CLI_AUTH" \
    || fail '登录必须经标准 Device Flow 轮询'
grep -Fq 'device_key_signature' "$CLI_AUTH" \
    || fail '轮询请求必须携带设备私钥签名'
grep -Fq 'url.query().is_some()' "$CLI_AUTH" \
    || fail '浏览器 URL 必须拒绝 query'
grep -Fq 'url.fragment().is_some()' "$CLI_AUTH" \
    || fail '浏览器 URL 必须拒绝 fragment'
if grep -Eq 'try_web_login|/v1/auth/web/status|web_login_sessions' "$CLI_AUTH"; then
    fail 'CLI 不得保留绕过设备密钥证明的旧 Web bearer 轮询'
fi

cd "$SCRIPT_DIR"
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
    cargo +1.88 test --locked --offline -p mindone-cli \
    auth::tests::verification_uri_is_strict_and_never_needs_a_command_shell \
    -- --exact --test-threads=1

printf 'CLI 邮箱 Device Flow 合同通过。\n'
printf '该脚本没有执行登录；真实浏览器与 Coordinator 联调请按 TEST_EMAIL_AUTH.md 手工验收。\n'
