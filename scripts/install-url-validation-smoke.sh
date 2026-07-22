#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
temp_base=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
test_root=$(mktemp -d "$temp_base/.mindone-install-url-smoke.XXXXXX")
case "$test_root" in
    "$temp_base"/.mindone-install-url-smoke.*) ;;
    *) printf '%s\n' '无法确认安装 URL 测试临时目录' >&2; exit 1 ;;
esac

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

home_dir="$test_root/home"
install_dir="$home_dir/bin"
mkdir -p "$home_dir"

expect_rejected() {
    case_name=$1
    release_url=$2
    expected_text=$3
    log_file="$test_root/$case_name.log"
    if HOME="$home_dir" \
       MINDONE_INSTALL_DIR="$install_dir" \
       MINDONE_RELEASE_URL="$release_url" \
       MINDONE_INSTALL_ALLOW_LOOPBACK_HTTP=1 \
         sh "$script_dir/install.sh" >"$log_file" 2>&1; then
        printf '恶意发行地址未被拒绝：%s\n' "$case_name" >&2
        return 1
    fi
    if ! grep -F "$expected_text" "$log_file" >/dev/null; then
        printf '发行地址拒绝原因不符合预期：%s\n' "$case_name" >&2
        sed -n '1,80p' "$log_file" >&2
        return 1
    fi
    test ! -e "$install_dir/mindone"
}

expect_rejected userinfo \
    'https://user:password@example.invalid/releases' \
    '发行地址不得内嵌用户名或密码'
expect_rejected query \
    'https://example.invalid/releases?channel=stable' \
    '不得包含查询参数或片段'
expect_rejected fragment \
    'https://example.invalid/releases#stable' \
    '不得包含查询参数或片段'
expect_rejected missing_host \
    'https:///releases' \
    '发行地址缺少主机名'
expect_rejected backslash \
    'https://example.invalid\@attacker.invalid/releases' \
    '发行地址不得包含反斜杠'
expect_rejected fake_loopback \
    'http://localhost:18083@attacker.invalid/releases' \
    '发行地址不得内嵌用户名或密码'
expect_rejected invalid_loopback_port \
    'http://127.0.0.1:65536/releases' \
    '端口必须在 1..65535'

printf '%s\n' 'Unix 安装器发行 URL 安全边界通过'
